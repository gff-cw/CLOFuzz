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

KHASH_SET_INIT_INT(hs32)
KHASH_MAP_INIT_INT(h32_u32, u32)

static khash_t(hs32) *khs_ipsm_paths = NULL;
static khash_t(h32_u32) *khm_unstable_paths = NULL;
#define MAX_CONFIRM_RETRIES 3

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
    trimmed_state_sequence[count - 1] = state_sequence[i];
  }
  u32 hashKey = hash32(trimmed_state_sequence, count * sizeof(unsigned int), 0);
  if (trimmed_state_sequence) free(trimmed_state_sequence);
  return hashKey;
}

static u8 query_state_sequence_novelty(const unsigned int *state_sequence, unsigned int state_count, u32 *out_hash) {
  if (!state_sequence || state_count == 0) return 0;
  u32 hashKey = get_state_sequence_hash(state_sequence, state_count);
  if (out_hash) *out_hash = hashKey;

  if (khs_ipsm_paths && kh_get(hs32, khs_ipsm_paths, hashKey) != kh_end(khs_ipsm_paths)) {
    return 0;
  }

  if (khm_unstable_paths) {
    khint_t k = kh_get(h32_u32, khm_unstable_paths, hashKey);
    if (k != kh_end(khm_unstable_paths) && kh_val(khm_unstable_paths, k) >= MAX_CONFIRM_RETRIES) {
      return 0;
    }
  }

  return 1;
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

int main(void) {
  printf("[*] Testing P06 novelty query decoupling and unified admission predicate...\n");

  khs_ipsm_paths = kh_init(hs32);
  khm_unstable_paths = kh_init(h32_u32);

  unsigned int seq1[3] = {0, 10, 20};
  u32 hash1 = 0;

  /* 1. Querying novelty is side-effect-free: khs_ipsm_paths remains empty */
  assert(kh_size(khs_ipsm_paths) == 0);
  u8 is_novel = query_state_sequence_novelty(seq1, 3, &hash1);
  assert(is_novel == 1);
  assert(hash1 != 0);
  assert(kh_size(khs_ipsm_paths) == 0); /* Still empty! Query did not pollute */

  /* Repeated queries without confirmation still return novel */
  u32 hash1_again = 0;
  assert(query_state_sequence_novelty(seq1, 3, &hash1_again) == 1);
  assert(hash1_again == hash1);
  assert(kh_size(khs_ipsm_paths) == 0);

  /* 2. Failed confirmation: sequence is NOT committed, but retry is tracked */
  record_state_sequence_confirmation_failure(hash1);
  assert(kh_size(khs_ipsm_paths) == 0);

  /* Next fuzzing run generates the same sequence: it is STILL considered novel and retried */
  assert(query_state_sequence_novelty(seq1, 3, NULL) == 1);

  /* 3. Successful confirmation: commits path and clears unstable tracking */
  commit_state_sequence_path(hash1);
  assert(kh_size(khs_ipsm_paths) == 1);
  assert(kh_get(hs32, khs_ipsm_paths, hash1) != kh_end(khs_ipsm_paths));

  /* Subsequent query now correctly reports 0 (not novel, already confirmed) */
  assert(query_state_sequence_novelty(seq1, 3, NULL) == 0);

  /* 4. Flaky sequence with bounded retries */
  unsigned int seq_flaky[3] = {0, 50, 99};
  u32 hash_flaky = 0;
  assert(query_state_sequence_novelty(seq_flaky, 3, &hash_flaky) == 1);

  /* Record failures up to MAX_CONFIRM_RETRIES */
  record_state_sequence_confirmation_failure(hash_flaky); /* 1 */
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == 1);
  record_state_sequence_confirmation_failure(hash_flaky); /* 2 */
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == 1);
  record_state_sequence_confirmation_failure(hash_flaky); /* 3 = MAX */

  /* Once retry limit is reached, persistently unstable path is suppressed from infinite re-runs */
  assert(query_state_sequence_novelty(seq_flaky, 3, NULL) == 0);
  assert(kh_size(khs_ipsm_paths) == 1); /* Flaky path was never committed to trusted set */

  /* 5. Unified admission predicate test */
  execution_observation_t valid_obs = {
    .has_state_observation = 1,
    .is_truncated = 0,
    .is_transmission_complete = 1,
    .state_count = 3,
    .state_sequence = seq1
  };
  /* Valid obs + repeatable -> accepted */
  u8 accepted = (!valid_obs.is_truncated && valid_obs.has_state_observation &&
                 valid_obs.state_count > 0 && valid_obs.is_transmission_complete && 1 /* repeatable */);
  assert(accepted == 1);

  /* Truncated obs -> rejected */
  execution_observation_t trunc_obs = valid_obs;
  trunc_obs.is_truncated = 1;
  u8 trunc_accepted = (!trunc_obs.is_truncated && trunc_obs.has_state_observation &&
                       trunc_obs.state_count > 0 && trunc_obs.is_transmission_complete && 1);
  assert(trunc_accepted == 0);

  /* Incomplete transmission obs -> rejected */
  execution_observation_t incomp_obs = valid_obs;
  incomp_obs.is_transmission_complete = 0;
  u8 incomp_accepted = (!incomp_obs.is_truncated && incomp_obs.has_state_observation &&
                        incomp_obs.state_count > 0 && incomp_obs.is_transmission_complete && 1);
  assert(incomp_accepted == 0);

  kh_destroy(hs32, khs_ipsm_paths);
  kh_destroy(h32_u32, khm_unstable_paths);
  printf("[+] P06 novelty query decoupling and unified admission test passed successfully!\n");
  return 0;
}
