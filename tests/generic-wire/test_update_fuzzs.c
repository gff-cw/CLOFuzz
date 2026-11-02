#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "khash.h"
#include "llvm_mode/state-tracer.h"

/* State info representation matching aflnet.h */
typedef struct {
  u32 id;
  u8 is_covered;
  u32 paths;
  u32 paths_discovered;
  u32 selected_times;
  u32 fuzzs;
  u32 score;
  u32 selected_seed_index;
  void **seeds;
  u32 seeds_count;
} state_info_t;

/* Khash definitions matching aflnet.h */
KHASH_SET_INIT_INT(hs32)
KHASH_INIT(hms, khint32_t, state_info_t *, 1, kh_int_hash_func, kh_int_hash_equal)

#define ck_alloc(sz) calloc(1, (sz))
#define ck_free(ptr) free(ptr)

/* Mock globals matching afl-fuzz.c */
static char *target_path_afl = NULL;
static void *current_fsrv = NULL;
static void *afl_fsrv = (void *)0x1000;
static void *stateafl_fsrv = (void *)0x2000;

static volatile struct state_shared *state_shared_ptr = NULL;
static u32 state_exec_id = 0;

static unsigned char *response_buf = NULL;
static unsigned int response_buf_size = 0;

static khash_t(hms) *khms_states = NULL;

/* Extractor function pointer */
static unsigned int *(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;

/* Mock extract_response_state_tracer matching afl-fuzz.c:3576 */
static unsigned int *extract_response_state_tracer(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) {
  (void)buf;
  (void)buf_size;
  if (!state_shared_ptr) {
    *state_count_ref = 0;
    return NULL;
  }
  if (state_shared_ptr->exec_id != state_exec_id) {
    *state_count_ref = 0;
    return NULL;
  }
  if (state_shared_ptr->status != STATE_TRACER_STATUS_COMPLETE &&
      state_shared_ptr->status != STATE_TRACER_STATUS_TRUNCATED) {
    *state_count_ref = 0;
    return NULL;
  }
  u32 count = state_shared_ptr->seq_len;
  if (count > state_shared_ptr->capacity) count = state_shared_ptr->capacity;
  *state_count_ref = count;
  if (count == 0) return NULL;

  unsigned int *seq = (unsigned int *)ck_alloc(count * sizeof(unsigned int));
  assert(seq != NULL);
  memcpy(seq, (const void *)state_shared_ptr->seq, count * sizeof(unsigned int));
  return seq;
}

/* Mock extract_response_codes for ASCII mode */
static unsigned int *extract_response_codes_ascii(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) {
  (void)buf;
  (void)buf_size;
  *state_count_ref = 2;
  unsigned int *seq = (unsigned int *)ck_alloc(2 * sizeof(unsigned int));
  assert(seq != NULL);
  seq[0] = 100;
  seq[1] = 200;
  return seq;
}

/* Implementation of update_fuzzs under test matching afl-fuzz.c:813-850 */
static void test_update_fuzzs(void) {
  if (extract_response_codes == extract_response_state_tracer) {
    if (!(target_path_afl ? (current_fsrv == stateafl_fsrv) : 1)) {
      /* Coverage run in dual-forkserver mode has no state tracer; do not credit unobserved visits */
      return;
    }
    if (!state_shared_ptr || state_shared_ptr->exec_id != state_exec_id ||
        (state_shared_ptr->status != STATE_TRACER_STATUS_COMPLETE &&
         state_shared_ptr->status != STATE_TRACER_STATUS_TRUNCATED)) {
      return;
    }
  }

  unsigned int state_count = 0, i;
  int discard;
  unsigned int *state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);
  if (!state_sequence || state_count == 0) return;

  /* A hash set is used so that the #paths is not updated more than once for one specific state */
  khash_t(hs32) *khs_state_ids;
  khint_t k;
  khs_state_ids = kh_init(hs32);

  for(i = 0; i < state_count; i++) {
    unsigned int state_id = state_sequence[i];

    if (kh_get(hs32, khs_state_ids, state_id) != kh_end(khs_state_ids)) {
      continue;
    } else {
      kh_put(hs32, khs_state_ids, state_id, &discard);
      k = kh_get(hms, khms_states, state_id);
      if (k != kh_end(khms_states)) {
        kh_val(khms_states, k)->fuzzs++;
      }
    }
  }
  ck_free(state_sequence);
  kh_destroy(hs32, khs_state_ids);
}

/* Helper functions */
static state_info_t *add_state(unsigned int state_id) {
  int ret;
  khint_t k = kh_put(hms, khms_states, state_id, &ret);
  state_info_t *s = (state_info_t *)calloc(1, sizeof(state_info_t));
  assert(s != NULL);
  s->id = state_id;
  s->fuzzs = 0;
  kh_val(khms_states, k) = s;
  return s;
}

static u32 get_fuzzs(unsigned int state_id) {
  khint_t k = kh_get(hms, khms_states, state_id);
  assert(k != kh_end(khms_states));
  return kh_val(khms_states, k)->fuzzs;
}

int main(void) {
  printf("[*] Testing B05 update_fuzzs logic and forkserver attribution...\n");

  khms_states = kh_init(hms);
  assert(khms_states != NULL);

  add_state(1);
  add_state(2);
  add_state(3);
  add_state(100);
  add_state(200);

  struct state_shared shm;
  memset(&shm, 0, sizeof(shm));
  shm.magic = STATE_SHARED_MAGIC;
  shm.version = STATE_SHARED_VERSION;
  shm.capacity = MAX_NUM_STATES;

  state_shared_ptr = &shm;
  extract_response_codes = extract_response_state_tracer;

  /* ========================================================================
   * 1. Single-forkserver mode (target_path_afl == NULL)
   * ======================================================================== */
  target_path_afl = NULL;

  /* 1a. Genuine COMPLETE tracer execution successfully updates fuzzs */
  state_exec_id = 10;
  shm.exec_id = 10;
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  shm.seq_len = 3;
  shm.seq[0] = 1;
  shm.seq[1] = 2;
  shm.seq[2] = 3;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 1);
  assert(get_fuzzs(2) == 1);
  assert(get_fuzzs(3) == 1);
  printf("[+] 1a: Single-forkserver COMPLETE execution credited fuzzs to states 1, 2, 3\n");

  /* 1b. Genuine TRUNCATED tracer execution also successfully updates fuzzs */
  state_exec_id = 11;
  shm.exec_id = 11;
  shm.status = STATE_TRACER_STATUS_TRUNCATED;
  shm.seq_len = 2;
  shm.seq[0] = 1;
  shm.seq[1] = 2;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 2);
  assert(get_fuzzs(2) == 2);
  assert(get_fuzzs(3) == 1);
  printf("[+] 1b: Single-forkserver TRUNCATED execution credited fuzzs to states 1, 2\n");

  /* 1c. State ID deduplication within a single execution:
         State 1 appears multiple times; fuzzs must only increment once per execution. */
  state_exec_id = 12;
  shm.exec_id = 12;
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  shm.seq_len = 4;
  shm.seq[0] = 1;
  shm.seq[1] = 2;
  shm.seq[2] = 1;
  shm.seq[3] = 1;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 3); /* Incremented by 1, not 3 */
  assert(get_fuzzs(2) == 3);
  assert(get_fuzzs(3) == 1);
  printf("[+] 1c: Deduplication confirmed: multiple visits in same run increment fuzzs only once\n");

  /* ========================================================================
   * 2. Dual-forkserver mode (target_path_afl != NULL)
   * ======================================================================== */
  char mock_afl_path[] = "/usr/local/bin/target_afl";
  target_path_afl = mock_afl_path;

  /* 2a. Pure coverage run (current_fsrv == afl_fsrv):
         Must NOT credit fuzzs, even if shm data looks valid. */
  current_fsrv = afl_fsrv;
  state_exec_id = 20;
  shm.exec_id = 20;
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  shm.seq_len = 3;
  shm.seq[0] = 1;
  shm.seq[1] = 2;
  shm.seq[2] = 3;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 3); /* Unchanged */
  assert(get_fuzzs(2) == 3); /* Unchanged */
  assert(get_fuzzs(3) == 1); /* Unchanged */
  printf("[+] 2a: Dual-forkserver coverage run (afl_fsrv) did NOT credit fuzzs\n");

  /* 2b. State tracer run (current_fsrv == stateafl_fsrv):
         Tracer run in dual-forkserver mode DOES credit fuzzs. */
  current_fsrv = stateafl_fsrv;
  test_update_fuzzs();
  assert(get_fuzzs(1) == 4);
  assert(get_fuzzs(2) == 4);
  assert(get_fuzzs(3) == 2);
  printf("[+] 2b: Dual-forkserver tracer run (stateafl_fsrv) successfully credited fuzzs\n");

  /* ========================================================================
   * 3. Rejection conditions: no fuzzs credited
   * ======================================================================== */
  current_fsrv = stateafl_fsrv;

  /* 3a. Mismatched exec_id */
  state_exec_id = 30;
  shm.exec_id = 29; /* Stale exec_id */
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  shm.seq_len = 1;
  shm.seq[0] = 1;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  printf("[+] 3a: Mismatched exec_id correctly rejected\n");

  /* 3b. Status UNAVAILABLE */
  state_exec_id = 31;
  shm.exec_id = 31;
  shm.status = STATE_TRACER_STATUS_UNAVAILABLE;
  shm.seq_len = 1;
  shm.seq[0] = 1;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  printf("[+] 3b: Status UNAVAILABLE correctly rejected\n");

  /* 3c. Status FAILED */
  state_exec_id = 32;
  shm.exec_id = 32;
  shm.status = STATE_TRACER_STATUS_FAILED;
  shm.seq_len = 1;
  shm.seq[0] = 1;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  printf("[+] 3c: Status FAILED correctly rejected\n");

  /* 3d. Status ANALYZING / IDLE */
  state_exec_id = 33;
  shm.exec_id = 33;
  shm.status = STATE_TRACER_STATUS_ANALYZING;
  shm.seq_len = 1;
  shm.seq[0] = 1;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  printf("[+] 3d: Status ANALYZING correctly rejected\n");

  /* 3e. state_shared_ptr == NULL */
  state_shared_ptr = NULL;
  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  state_shared_ptr = &shm;
  printf("[+] 3e: NULL state_shared_ptr correctly rejected\n");

  /* 3f. Empty state sequence (seq_len == 0) */
  state_exec_id = 34;
  shm.exec_id = 34;
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  shm.seq_len = 0;

  test_update_fuzzs();
  assert(get_fuzzs(1) == 4); /* Unchanged */
  printf("[+] 3f: Empty state sequence (seq_len == 0) correctly rejected\n");

  /* ========================================================================
   * 4. AFLNet ASCII response code mode
   * ======================================================================== */
  extract_response_codes = extract_response_codes_ascii;
  /* Even in dual-forkserver mode with current_fsrv == afl_fsrv, ASCII response codes
     mode operates on response_buf and is not gated by state tracer shm */
  test_update_fuzzs();
  assert(get_fuzzs(100) == 1);
  assert(get_fuzzs(200) == 1);
  printf("[+] 4: ASCII response code mode successfully credited states 100, 200\n");

  /* Cleanup */
  for (khint_t k = kh_begin(khms_states); k != kh_end(khms_states); ++k) {
    if (kh_exist(khms_states, k)) {
      free(kh_val(khms_states, k));
    }
  }
  kh_destroy(hms, khms_states);

  printf("[+] All B05 update_fuzzs tests passed successfully!\n");
  return 0;
}
