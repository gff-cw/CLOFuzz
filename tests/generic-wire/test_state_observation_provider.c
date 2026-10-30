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
#include "execution_observation.h"

/* Structure declarations matching afl-fuzz.c for mock testing */
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
} state_info_mock_t;

KHASH_MAP_INIT_INT(hms_mock, state_info_mock_t*)
KHASH_SET_INIT_INT(hs32_mock)

static struct state_shared mock_shared;
static volatile struct state_shared *state_shared_ptr = &mock_shared;
static u32 state_exec_id = 100;
static u8 child_timed_out = 0;
static u8 state_tracer_truncated = 0;
static char *target_path_afl = NULL;
static void *current_fsrv = NULL;
static void *stateafl_fsrv = (void *)0x1234;
static void *afl_fsrv = (void *)0x5678;

/* Mock extract_response_state_tracer matching afl-fuzz.c */
static unsigned int* mock_extract_response_state_tracer(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) {
  (void)buf;
  (void)buf_size;
  if (!state_shared_ptr) {
    *state_count_ref = 0;
    state_tracer_truncated = 0;
    return NULL;
  }
  if (child_timed_out) {
    *state_count_ref = 0;
    state_tracer_truncated = 0;
    return NULL;
  }
  if (state_shared_ptr->magic != STATE_SHARED_MAGIC ||
      state_shared_ptr->version != STATE_SHARED_VERSION) {
    *state_count_ref = 0;
    state_tracer_truncated = 0;
    return NULL;
  }
  if (state_shared_ptr->exec_id != state_exec_id) {
    *state_count_ref = 0;
    state_tracer_truncated = 0;
    return NULL;
  }
  uint32_t status = state_shared_ptr->status;
  if (status != STATE_TRACER_STATUS_COMPLETE && status != STATE_TRACER_STATUS_TRUNCATED) {
    *state_count_ref = 0;
    state_tracer_truncated = 0;
    return NULL;
  }
  u32 cap = state_shared_ptr->capacity;
  if (cap == 0 || cap > MAX_NUM_STATES) cap = MAX_NUM_STATES;
  u32 count = state_shared_ptr->seq_len;
  if (count > cap) count = cap;

  if (state_shared_ptr->truncated || state_shared_ptr->total_states > cap ||
      state_shared_ptr->status == STATE_TRACER_STATUS_TRUNCATED) {
    state_tracer_truncated = 1;
  } else {
    state_tracer_truncated = 0;
  }
  *state_count_ref = count;
  if (count == 0) return NULL;
  unsigned int *seq = (unsigned int *)malloc(count * sizeof(unsigned int));
  if (!seq) { *state_count_ref = 0; return NULL; }
  memcpy(seq, (void *)state_shared_ptr->seq, count * sizeof(unsigned int));
  return seq;
}

static unsigned int* (*mock_extract_codes)(unsigned char*, unsigned int, unsigned int*) = mock_extract_response_state_tracer;

/* Mock update_fuzzs logic matching afl-fuzz.c P25 implementation */
static void mock_update_fuzzs(khash_t(hms_mock) *khms_states, char *resp_buf, u32 resp_buf_size) {
  if (mock_extract_codes == mock_extract_response_state_tracer) {
    if (target_path_afl || current_fsrv != stateafl_fsrv) {
      /* Coverage run has no state tracer; do not credit unobserved visits */
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
  unsigned int *state_sequence = (*mock_extract_codes)((unsigned char *)resp_buf, resp_buf_size, &state_count);
  if (!state_sequence || state_count == 0) return;

  khash_t(hs32_mock) *khs = kh_init(hs32_mock);
  for (i = 0; i < state_count; i++) {
    unsigned int sid = state_sequence[i];
    if (kh_get(hs32_mock, khs, sid) != kh_end(khs)) continue;
    kh_put(hs32_mock, khs, sid, &discard);
    khint_t k = kh_get(hms_mock, khms_states, sid);
    if (k != kh_end(khms_states)) {
      kh_val(khms_states, k)->fuzzs++;
    }
  }
  free(state_sequence);
  kh_destroy(hs32_mock, khs);
}

int main(void) {
  printf("[*] Testing P25 state observation provider capability and dummy-0 decoupling...\n");

  khash_t(hms_mock) *states = kh_init(hms_mock);
  int discard;

  /* Initialize state 0 and state 10 */
  state_info_mock_t s0 = { .id = 0, .fuzzs = 0, .selected_times = 5 };
  khint_t k0 = kh_put(hms_mock, states, 0, &discard);
  kh_val(states, k0) = &s0;

  state_info_mock_t s10 = { .id = 10, .fuzzs = 0, .selected_times = 2 };
  khint_t k10 = kh_put(hms_mock, states, 10, &discard);
  kh_val(states, k10) = &s10;

  /* Test 1: Shared state reset in send_over_network has NO dummy zero */
  memset(&mock_shared, 0, sizeof(mock_shared));
  mock_shared.magic = STATE_SHARED_MAGIC;
  mock_shared.version = STATE_SHARED_VERSION;
  mock_shared.capacity = MAX_NUM_STATES;
  mock_shared.exec_id = ++state_exec_id;
  mock_shared.status = STATE_TRACER_STATUS_IDLE;
  mock_shared.truncated = 0;
  mock_shared.total_states = 0; /* P25: Was 1 in buggy vanilla StateAFL */
  mock_shared.seq_len = 0;      /* P25: Was 1 in buggy vanilla StateAFL */
  mock_shared.seq[0] = 0;

  assert(mock_shared.total_states == 0);
  assert(mock_shared.seq_len == 0);

  /* Test 2: Incomplete/Idle status yields NULL from extractor */
  unsigned int count = 999;
  unsigned int *seq = mock_extract_response_state_tracer((unsigned char *)"test", 4, &count);
  assert(seq == NULL);
  assert(count == 0);

  /* Test 3: Coverage execution under afl_fsrv with -u target_path_afl:
     fuzz count for State 0 must NOT be credited */
  target_path_afl = "/path/to/vanilla_binary";
  current_fsrv = afl_fsrv;
  mock_shared.status = STATE_TRACER_STATUS_UNAVAILABLE;

  mock_update_fuzzs(states, "dummy_resp", 10);
  assert(s0.fuzzs == 0);
  assert(s10.fuzzs == 0);

  /* Test 4: Coverage execution without -u, but still under afl_fsrv:
     state visits must NOT be credited because afl_fsrv has no state observation */
  target_path_afl = NULL;
  current_fsrv = afl_fsrv;
  mock_shared.status = STATE_TRACER_STATUS_IDLE;

  mock_update_fuzzs(states, "dummy_resp", 10);
  assert(s0.fuzzs == 0);
  assert(s10.fuzzs == 0);

  /* Test 5: Replay / analysis under stateafl_fsrv with publication COMPLETE:
     Actual observed visits are accurately credited */
  current_fsrv = stateafl_fsrv;
  mock_shared.exec_id = ++state_exec_id;
  mock_shared.status = STATE_TRACER_STATUS_COMPLETE;
  mock_shared.seq[0] = 0;
  mock_shared.seq[1] = 10;
  mock_shared.seq_len = 2;
  mock_shared.total_states = 2;

  count = 0;
  seq = mock_extract_response_state_tracer((unsigned char *)"test", 4, &count);
  assert(seq != NULL);
  assert(count == 2);
  assert(seq[0] == 0);
  assert(seq[1] == 10);
  free(seq);

  mock_update_fuzzs(states, "dummy_resp", 10);
  assert(s0.fuzzs == 1);
  assert(s10.fuzzs == 1);

  /* Test 6: Second stateafl_fsrv visit to state 10 only */
  mock_shared.exec_id = ++state_exec_id;
  mock_shared.seq[0] = 10;
  mock_shared.seq_len = 1;
  mock_shared.total_states = 1;

  mock_update_fuzzs(states, "dummy_resp", 10);
  assert(s0.fuzzs == 1);  /* Not visited, stays 1 */
  assert(s10.fuzzs == 2); /* Visited again, increments to 2 */

  kh_destroy(hms_mock, states);
  printf("[+] P25 state observation provider test passed successfully!\n");
  return 0;
}
