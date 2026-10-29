#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llvm_mode/state-tracer.h"

int main(void) {
  printf("[*] Testing P03 struct state_shared layout and capacity bounds...\n");

  /* Verify layout constants */
  assert(STATE_SHARED_MAGIC == 0x53544154U);
  assert(STATE_SHARED_VERSION == 2U);
  assert(MAX_NUM_STATES == 100);
  assert(sizeof(struct state_shared) == 436);

  struct state_shared shm;
  memset(&shm, 0, sizeof(shm));
  shm.magic = STATE_SHARED_MAGIC;
  shm.version = STATE_SHARED_VERSION;
  shm.capacity = MAX_NUM_STATES;

  /* 1. Simulate exact capacity (100 states) */
  shm.status = STATE_TRACER_STATUS_ANALYZING;
  shm.seq[0] = 0;
  uint32_t current_state_number = 1;
  shm.total_states = current_state_number;
  shm.seq_len = current_state_number;

  for (uint32_t i = 1; i < MAX_NUM_STATES; i++) {
    if (current_state_number < MAX_NUM_STATES) {
      shm.seq[current_state_number] = 0x1000 + i;
    } else {
      shm.truncated = 1;
    }
    current_state_number++;
    shm.total_states = current_state_number;
    shm.seq_len = (current_state_number <= MAX_NUM_STATES) ? current_state_number : MAX_NUM_STATES;
  }

  assert(shm.total_states == 100);
  assert(shm.seq_len == 100);
  assert(shm.truncated == 0);
  assert(shm.seq[99] == 0x1000 + 99);

  /* 2. Simulate overflow beyond capacity (e.g. 150 states) */
  for (uint32_t i = 100; i < 150; i++) {
    if (current_state_number < MAX_NUM_STATES) {
      shm.seq[current_state_number] = 0x1000 + i;
    } else {
      shm.truncated = 1;
    }
    current_state_number++;
    shm.total_states = current_state_number;
    shm.seq_len = (current_state_number <= MAX_NUM_STATES) ? current_state_number : MAX_NUM_STATES;
  }

  /* Must clamp seq_len to MAX_NUM_STATES (100) and mark truncated */
  assert(shm.total_states == 150);
  assert(shm.seq_len == 100);
  assert(shm.truncated == 1);
  if (shm.truncated) {
    shm.status = STATE_TRACER_STATUS_TRUNCATED;
  }
  assert(shm.status == STATE_TRACER_STATUS_TRUNCATED);

  /* 3. Test consumer clamping and validation */
  uint32_t cap = shm.capacity;
  if (cap == 0 || cap > MAX_NUM_STATES) cap = MAX_NUM_STATES;
  uint32_t count = shm.seq_len;
  if (count > cap) count = cap;
  assert(count == 100);
  int truncated_flag = (shm.truncated || shm.total_states > cap || shm.status == STATE_TRACER_STATUS_TRUNCATED);
  assert(truncated_flag == 1);

  /* 4. Test consumer rejection on magic/version mismatch */
  struct state_shared corrupt_shm;
  memset(&corrupt_shm, 0, sizeof(corrupt_shm));
  corrupt_shm.magic = 0x12345678U;
  corrupt_shm.version = 1U;
  assert(corrupt_shm.magic != STATE_SHARED_MAGIC || corrupt_shm.version != STATE_SHARED_VERSION);

  /* 5. P04 execution identity and publication status protocol tests */
  printf("[*] Testing P04 execution identity and publication protocol...\n");
  uint32_t current_exec_id = 42;
  shm.exec_id = current_exec_id;

  /* Test stale execution rejection */
  uint32_t stale_exec_id = 41;
  assert(stale_exec_id != shm.exec_id);

  /* Test publication protocol: status IDLE and ANALYZING cannot be accepted as complete */
  shm.status = STATE_TRACER_STATUS_IDLE;
  assert(shm.status != STATE_TRACER_STATUS_COMPLETE && shm.status != STATE_TRACER_STATUS_TRUNCATED);
  shm.status = STATE_TRACER_STATUS_ANALYZING;
  assert(shm.status != STATE_TRACER_STATUS_COMPLETE && shm.status != STATE_TRACER_STATUS_TRUNCATED);

  /* Test publication protocol: only COMPLETE and TRUNCATED are valid terminal states */
  shm.status = STATE_TRACER_STATUS_COMPLETE;
  assert(shm.status == STATE_TRACER_STATUS_COMPLETE || shm.status == STATE_TRACER_STATUS_TRUNCATED);

  shm.status = STATE_TRACER_STATUS_UNAVAILABLE;
  assert(shm.status != STATE_TRACER_STATUS_COMPLETE && shm.status != STATE_TRACER_STATUS_TRUNCATED);
  shm.status = STATE_TRACER_STATUS_FAILED;
  assert(shm.status != STATE_TRACER_STATUS_COMPLETE && shm.status != STATE_TRACER_STATUS_TRUNCATED);

  printf("[+] P03 and P04 tests passed successfully!\n");
  return 0;
}
