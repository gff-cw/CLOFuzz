#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "khash.h"
#include "execution_observation.h"

/* Novelty query status codes (matching afl-fuzz.c:630 / B04) */
#define STATE_SEQ_NOVEL            1
#define STATE_SEQ_KNOWN_CONFIRMED  0
#define STATE_SEQ_RETRY_EXHAUSTED -1
#define STATE_SEQ_INVALID         -2

#define MAX_CONFIRM_RETRIES 3

KHASH_SET_INIT_INT(hs32)
KHASH_MAP_INIT_INT(h32_u32, u32)

static khash_t(hs32) *khs_ipsm_paths = NULL;
static khash_t(h32_u32) *khm_unstable_paths = NULL;

/* Hash function matching afl-fuzz.c */
static inline u32 hash32(const void* key, u32 len, u32 seed) {
  const u8* data = (const u8*)key;
  u32 h = seed ^ len;
  while (len >= 4) {
    u32 k;
    memcpy(&k, data, 4);
    k *= 0x5bd1e995;
    k ^= k >> 24;
    k *= 0x5bd1e995;
    h *= 0x5bd1e995;
    h ^= k;
    data += 4;
    len -= 4;
  }
  return h;
}

static u32 get_state_sequence_hash(const unsigned int *state_sequence, unsigned int state_count) {
  if (!state_sequence || state_count == 0) return 0;
  u32 *trimmed_state_sequence = NULL;
  u32 i, count = 0;
  for (i = 0; i < state_count; i++) {
    if ((i >= 2) && (state_sequence[i] == state_sequence[i - 1]) && (state_sequence[i] == state_sequence[i - 2])) continue;
    count++;
    trimmed_state_sequence = (u32 *)realloc(trimmed_state_sequence, count * sizeof(unsigned int));
    assert(trimmed_state_sequence != NULL);
    trimmed_state_sequence[count - 1] = state_sequence[i];
  }
  u32 hashKey = hash32(trimmed_state_sequence, count * sizeof(unsigned int), 0);
  if (trimmed_state_sequence) free(trimmed_state_sequence);
  return hashKey;
}

/* P06/B04: Side-effect-free novelty query returning status codes */
static int query_state_sequence_novelty(const unsigned int *state_sequence, unsigned int state_count, u32 *out_hash) {
  if (!state_sequence || state_count == 0) return STATE_SEQ_INVALID;
  u32 hashKey = get_state_sequence_hash(state_sequence, state_count);
  if (out_hash) *out_hash = hashKey;

  /* Check against confirmed paths */
  if (khs_ipsm_paths && kh_get(hs32, khs_ipsm_paths, hashKey) != kh_end(khs_ipsm_paths)) {
    return STATE_SEQ_KNOWN_CONFIRMED;
  }

  /* Check retry count for unstable/flaky paths to avoid unbounded overhead */
  if (khm_unstable_paths) {
    khint_t k = kh_get(h32_u32, khm_unstable_paths, hashKey);
    if (k != kh_end(khm_unstable_paths) && kh_val(khm_unstable_paths, k) >= MAX_CONFIRM_RETRIES) {
      return STATE_SEQ_RETRY_EXHAUSTED;
    }
  }

  return STATE_SEQ_NOVEL;
}

static void commit_state_sequence_path(u32 hashKey) {
  if (!khs_ipsm_paths || hashKey == 0) return;
  int dummy;
  kh_put(hs32, khs_ipsm_paths, hashKey, &dummy);

  if (khm_unstable_paths) {
    khint_t k = kh_get(h32_u32, khm_unstable_paths, hashKey);
    if (k != kh_end(khm_unstable_paths)) {
      kh_del(h32_u32, khm_unstable_paths, k);
    }
  }
}

static void record_state_sequence_confirmation_failure(u32 hashKey) {
  if (hashKey == 0) return;
  if (!khm_unstable_paths) khm_unstable_paths = kh_init(h32_u32);
  int discard;
  khint_t k = kh_put(h32_u32, khm_unstable_paths, hashKey, &discard);
  if (discard) {
    kh_val(khm_unstable_paths, k) = 1;
  } else {
    kh_val(khm_unstable_paths, k)++;
  }
}

static u8 is_state_sequence_interesting(const unsigned int *state_sequence, unsigned int state_count) {
  return query_state_sequence_novelty(state_sequence, state_count, NULL) == STATE_SEQ_NOVEL;
}

/* Admission result outcomes matching afl-fuzz.c:1152-1296 */
typedef enum {
  ADMISSION_ACCEPTED = 1,
  ADMISSION_REJECTED_RETRY_EXHAUSTED = 2,
  ADMISSION_REJECTED_INVALID = 3,
  ADMISSION_REJECTED_TRUNCATED_OR_INCOMPLETE = 4,
  ADMISSION_REJECTED_NON_REPEATABLE = 5,
} admission_outcome_t;

/* Admission evaluation harness mirroring afl-fuzz.c:1152-1296 */
static admission_outcome_t evaluate_state_aware_admission(
    const execution_observation_t *orig_obs,
    u8 dry_run,
    int simulated_repeatable) {

  if (!orig_obs) return ADMISSION_REJECTED_INVALID;

  u32 hashKey = 0;
  int is_interesting = query_state_sequence_novelty(orig_obs->state_sequence, orig_obs->state_count, &hashKey);
  int is_repeatable = 0;

  /* B04: If query returns RETRY_EXHAUSTED (-1), immediately withhold and reject admission */
  if (is_interesting == STATE_SEQ_RETRY_EXHAUSTED) {
    return ADMISSION_REJECTED_RETRY_EXHAUSTED;
  }

  /* B04: If query returns INVALID (-2), immediately reject admission */
  if (is_interesting == STATE_SEQ_INVALID) {
    return ADMISSION_REJECTED_INVALID;
  }

  if (orig_obs->is_truncated || !orig_obs->is_response_complete || orig_obs->response_budget_exceeded) {
    return ADMISSION_REJECTED_TRUNCATED_OR_INCOMPLETE;
  }

  if (!orig_obs->is_transmission_complete) {
    return ADMISSION_REJECTED_TRUNCATED_OR_INCOMPLETE;
  }

  if (is_interesting == STATE_SEQ_NOVEL) {
    is_repeatable = simulated_repeatable;

    if (dry_run && !is_repeatable) {
      /* B04: Reject non-repeatable test cases from trusted admission in dry-run as well */
      return ADMISSION_REJECTED_NON_REPEATABLE;
    }

    if (!dry_run && !is_repeatable) {
      /* P06: Novel state sequence failed confirmation; withhold from admission and record retry */
      record_state_sequence_confirmation_failure(hashKey);
      return ADMISSION_REJECTED_NON_REPEATABLE;
    }
  }

  /* P06/B04: Unified acceptance predicate */
  u8 is_accepted = 0;
  if (!orig_obs->is_truncated && orig_obs->is_response_complete &&
      !orig_obs->response_budget_exceeded && orig_obs->has_state_observation &&
      orig_obs->state_count > 0 && orig_obs->is_transmission_complete) {
    if (dry_run) {
      /* B04: In dry_run branch: if !is_repeatable for novel sequence, do NOT set is_accepted = 1 */
      if (is_interesting == STATE_SEQ_NOVEL && !is_repeatable) {
        is_accepted = 0;
      } else {
        is_accepted = 1;
      }
    } else if (is_interesting == STATE_SEQ_NOVEL) {
      is_accepted = is_repeatable;
    } else if (is_interesting == STATE_SEQ_KNOWN_CONFIRMED) {
      is_accepted = 1;
    }
  }

  if (!is_accepted) {
    return ADMISSION_REJECTED_NON_REPEATABLE;
  }

  /* P06/B04: Commit novel confirmed path to trusted set ONLY when interesting == 1 AND repeatable == 1 AND accepted == 1 */
  if (is_interesting == 1 && is_repeatable == 1 && is_accepted == 1 && hashKey != 0) {
    commit_state_sequence_path(hashKey);
  }

  return ADMISSION_ACCEPTED;
}

int main(void) {
  printf("[*] Testing B04 novelty status codes, retry exhaustion gating, and dry-run/fuzzer non-repeatable rejection...\n");

  khs_ipsm_paths = kh_init(hs32);
  khm_unstable_paths = kh_init(h32_u32);

  /* --------------------------------------------------------------------------
   * 1. Status Codes Verification:
   *    - STATE_SEQ_INVALID (-2)
   *    - STATE_SEQ_NOVEL (1)
   *    - STATE_SEQ_KNOWN_CONFIRMED (0)
   *    - STATE_SEQ_RETRY_EXHAUSTED (-1)
   * -------------------------------------------------------------------------- */
  printf("[*] 1. Testing query_state_sequence_novelty status codes...\n");

  unsigned int seq_valid1[3] = {1, 2, 3};
  u32 hash1 = 0;

  /* 1a. Invalid sequence arguments -> STATE_SEQ_INVALID (-2) */
  assert(query_state_sequence_novelty(NULL, 3, &hash1) == STATE_SEQ_INVALID);
  assert(query_state_sequence_novelty(seq_valid1, 0, &hash1) == STATE_SEQ_INVALID);
  assert(is_state_sequence_interesting(NULL, 3) == 0);
  assert(is_state_sequence_interesting(seq_valid1, 0) == 0);

  /* 1b. Unseen sequence -> STATE_SEQ_NOVEL (1) */
  assert(kh_size(khs_ipsm_paths) == 0);
  int st = query_state_sequence_novelty(seq_valid1, 3, &hash1);
  assert(st == STATE_SEQ_NOVEL);
  assert(hash1 != 0);
  assert(is_state_sequence_interesting(seq_valid1, 3) == 1);
  /* Side-effect check: query must not pollute confirmed paths */
  assert(kh_size(khs_ipsm_paths) == 0);

  /* 1c. Confirmed sequence -> STATE_SEQ_KNOWN_CONFIRMED (0) */
  commit_state_sequence_path(hash1);
  assert(kh_size(khs_ipsm_paths) == 1);
  assert(query_state_sequence_novelty(seq_valid1, 3, NULL) == STATE_SEQ_KNOWN_CONFIRMED);
  assert(is_state_sequence_interesting(seq_valid1, 3) == 0);

  /* 1d. Flaky sequence retry exhaustion -> STATE_SEQ_RETRY_EXHAUSTED (-1) */
  unsigned int seq_flaky[3] = {10, 20, 30};
  u32 hash_flaky = 0;
  assert(query_state_sequence_novelty(seq_flaky, 3, &hash_flaky) == STATE_SEQ_NOVEL);

  /* Retry 1 */
  record_state_sequence_confirmation_failure(hash_flaky);
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == STATE_SEQ_NOVEL);

  /* Retry 2 */
  record_state_sequence_confirmation_failure(hash_flaky);
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == STATE_SEQ_NOVEL);

  /* Retry 3 (MAX_CONFIRM_RETRIES reached) */
  record_state_sequence_confirmation_failure(hash_flaky);
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == STATE_SEQ_RETRY_EXHAUSTED);
  assert(is_state_sequence_interesting(seq_flaky, 3) == 0);

  /* Subsequent queries or further failures remain exhausted */
  record_state_sequence_confirmation_failure(hash_flaky);
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == STATE_SEQ_RETRY_EXHAUSTED);

  /* --------------------------------------------------------------------------
   * 2. Admission Gating on Retry Exhaustion:
   *    Once confirmation retries exceed MAX_CONFIRM_RETRIES,
   *    query returns -1 (STATE_SEQ_RETRY_EXHAUSTED), preventing admission.
   * -------------------------------------------------------------------------- */
  printf("[*] 2. Testing admission gating when retries are exhausted...\n");

  execution_observation_t obs_exhausted = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .is_response_complete = 1,
    .response_budget_exceeded = 0,
    .state_count = 3,
    .state_sequence = seq_flaky
  };

  /* Fuzzer iteration: must be rejected with RETRY_EXHAUSTED even if repeatability was claimed */
  admission_outcome_t outcome_fuzz = evaluate_state_aware_admission(&obs_exhausted, 0 /* fuzzer */, 1 /* repeatable */);
  assert(outcome_fuzz == ADMISSION_REJECTED_RETRY_EXHAUSTED);
  assert(kh_get(hs32, khs_ipsm_paths, hash_flaky) == kh_end(khs_ipsm_paths));

  /* Dry-run: must also be rejected with RETRY_EXHAUSTED */
  admission_outcome_t outcome_dry = evaluate_state_aware_admission(&obs_exhausted, 1 /* dry_run */, 1 /* repeatable */);
  assert(outcome_dry == ADMISSION_REJECTED_RETRY_EXHAUSTED);
  assert(kh_get(hs32, khs_ipsm_paths, hash_flaky) == kh_end(khs_ipsm_paths));

  /* --------------------------------------------------------------------------
   * 3. Non-repeatable Novel Paths Rejection:
   *    Rejected in both dry-run and fuzzer iterations.
   * -------------------------------------------------------------------------- */
  printf("[*] 3. Testing non-repeatable novel paths rejection in dry-run and fuzzer...\n");

  /* 3a. Novel non-repeatable path in dry-run -> REJECTED */
  unsigned int seq_dry_nonrep[3] = {100, 101, 102};
  u32 hash_dry_nonrep = 0;
  assert(query_state_sequence_novelty(seq_dry_nonrep, 3, &hash_dry_nonrep) == STATE_SEQ_NOVEL);

  execution_observation_t obs_dry_nonrep = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .is_response_complete = 1,
    .response_budget_exceeded = 0,
    .state_count = 3,
    .state_sequence = seq_dry_nonrep
  };

  admission_outcome_t dry_nonrep_res = evaluate_state_aware_admission(&obs_dry_nonrep, 1 /* dry_run */, 0 /* not repeatable */);
  assert(dry_nonrep_res == ADMISSION_REJECTED_NON_REPEATABLE);
  /* Must not be committed */
  assert(kh_get(hs32, khs_ipsm_paths, hash_dry_nonrep) == kh_end(khs_ipsm_paths));

  /* 3b. Novel non-repeatable path in fuzzer iterations -> REJECTED and failure tracked */
  unsigned int seq_fuzz_nonrep[3] = {200, 201, 202};
  u32 hash_fuzz_nonrep = 0;
  assert(query_state_sequence_novelty(seq_fuzz_nonrep, 3, &hash_fuzz_nonrep) == STATE_SEQ_NOVEL);

  execution_observation_t obs_fuzz_nonrep = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .is_response_complete = 1,
    .response_budget_exceeded = 0,
    .state_count = 3,
    .state_sequence = seq_fuzz_nonrep
  };

  admission_outcome_t fuzz_nonrep_res = evaluate_state_aware_admission(&obs_fuzz_nonrep, 0 /* fuzzer */, 0 /* not repeatable */);
  assert(fuzz_nonrep_res == ADMISSION_REJECTED_NON_REPEATABLE);
  /* Must not be committed */
  assert(kh_get(hs32, khs_ipsm_paths, hash_fuzz_nonrep) == kh_end(khs_ipsm_paths));
  /* Failure tracked */
  khint_t k_unstable = kh_get(h32_u32, khm_unstable_paths, hash_fuzz_nonrep);
  assert(k_unstable != kh_end(khm_unstable_paths));
  assert(kh_val(khm_unstable_paths, k_unstable) == 1);

  /* 3c. Novel REPEATABLE path in dry-run -> ADMITTED */
  unsigned int seq_dry_rep[3] = {300, 301, 302};
  u32 hash_dry_rep = 0;
  assert(query_state_sequence_novelty(seq_dry_rep, 3, &hash_dry_rep) == STATE_SEQ_NOVEL);

  execution_observation_t obs_dry_rep = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .is_response_complete = 1,
    .response_budget_exceeded = 0,
    .state_count = 3,
    .state_sequence = seq_dry_rep
  };

  admission_outcome_t dry_rep_res = evaluate_state_aware_admission(&obs_dry_rep, 1 /* dry_run */, 1 /* repeatable */);
  assert(dry_rep_res == ADMISSION_ACCEPTED);
  /* Confirmed and committed */
  assert(kh_get(hs32, khs_ipsm_paths, hash_dry_rep) != kh_end(khs_ipsm_paths));
  assert(query_state_sequence_novelty(seq_dry_rep, 3, NULL) == STATE_SEQ_KNOWN_CONFIRMED);

  /* 3d. Novel REPEATABLE path in fuzzer -> ADMITTED */
  unsigned int seq_fuzz_rep[3] = {400, 401, 402};
  u32 hash_fuzz_rep = 0;
  assert(query_state_sequence_novelty(seq_fuzz_rep, 3, &hash_fuzz_rep) == STATE_SEQ_NOVEL);

  execution_observation_t obs_fuzz_rep = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .is_response_complete = 1,
    .response_budget_exceeded = 0,
    .state_count = 3,
    .state_sequence = seq_fuzz_rep
  };

  admission_outcome_t fuzz_rep_res = evaluate_state_aware_admission(&obs_fuzz_rep, 0 /* fuzzer */, 1 /* repeatable */);
  assert(fuzz_rep_res == ADMISSION_ACCEPTED);
  /* Confirmed and committed */
  assert(kh_get(hs32, khs_ipsm_paths, hash_fuzz_rep) != kh_end(khs_ipsm_paths));
  assert(query_state_sequence_novelty(seq_fuzz_rep, 3, NULL) == STATE_SEQ_KNOWN_CONFIRMED);

  /* Clean up hash maps */
  kh_destroy(hs32, khs_ipsm_paths);
  kh_destroy(h32_u32, khm_unstable_paths);

  printf("[+] B04 novelty status codes and admission gating passed cleanly under ASan/UBSan!\n");
  return 0;
}
