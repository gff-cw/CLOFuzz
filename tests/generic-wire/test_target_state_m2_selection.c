#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

typedef struct {
  int start_byte;
  int end_byte;
  char modifiable;
  unsigned int *state_sequence;
  unsigned int state_count;
} mock_region_t;

struct mock_queue_entry {
  char *fname;
  mock_region_t *regions;
  u32 region_count;
};

/* Selection logic under test (matching afl-fuzz.c for P01) */
static int select_m2_for_target_state(struct mock_queue_entry *queue_cur,
                                      u32 target_state_id,
                                      u32 *out_m2_start,
                                      u32 *out_m2_count) {
  if (!queue_cur || queue_cur->region_count == 0) return 1;

  u32 M2_start_region_ID = 0, M2_region_count = 0;
  u32 i;

  if (target_state_id == 0) {
    /* P01 Case 1: Initial state context (State 0) */
    M2_start_region_ID = 0;
    M2_region_count = 0;

    for (i = 0; i < queue_cur->region_count; i++) {
      if (queue_cur->regions[i].state_count != queue_cur->regions[0].state_count) break;
      M2_region_count++;
    }
    if (M2_region_count == 0) M2_region_count = 1;

  } else {
    /* P01 Case 2: Non-zero target state */
    s32 target_reaching_region = -1;

    for (i = 0; i < queue_cur->region_count; i++) {
      u32 regionalStateCount = queue_cur->regions[i].state_count;
      if (regionalStateCount > 0 && queue_cur->regions[i].state_sequence != NULL) {
        u32 reachableStateID = queue_cur->regions[i].state_sequence[regionalStateCount - 1];
        if (reachableStateID == target_state_id) {
          target_reaching_region = (s32)i;
          break;
        }
      } else {
        /* P01/P02: Unknown boundary; do not guess */
        return 1;
      }
    }

    if (target_reaching_region < 0) return 1;

    M2_start_region_ID = (u32)(target_reaching_region + 1);
    if (M2_start_region_ID >= queue_cur->region_count) return 1;

    M2_region_count = 0;
    for (i = M2_start_region_ID; i < queue_cur->region_count; i++) {
      if (queue_cur->regions[i].state_count != queue_cur->regions[M2_start_region_ID].state_count) break;
      M2_region_count++;
    }
    if (M2_region_count == 0) M2_region_count = 1;
  }

  if (out_m2_start) *out_m2_start = M2_start_region_ID;
  if (out_m2_count) *out_m2_count = M2_region_count;
  return 0;
}

int main(void) {
  printf("[*] Testing P01 initial context and non-zero target state M2 selection...\n");

  /* Setup a test seed with 3 regions:
     Region 0: state_count = 2, seq = [0, 0x10] -> reaches 0x10
     Region 1: state_count = 3, seq = [0, 0x10, 0x20] -> reaches 0x20
     Region 2: state_count = 4, seq = [0, 0x10, 0x20, 0x30] -> reaches 0x30 */
  unsigned int seq0[] = { 0, 0x10 };
  unsigned int seq1[] = { 0, 0x10, 0x20 };
  unsigned int seq2[] = { 0, 0x10, 0x20, 0x30 };

  mock_region_t regions[3];
  memset(regions, 0, sizeof(regions));
  regions[0].state_count = 2;
  regions[0].state_sequence = seq0;
  regions[1].state_count = 3;
  regions[1].state_sequence = seq1;
  regions[2].state_count = 4;
  regions[2].state_sequence = seq2;

  struct mock_queue_entry seed = {
    .fname = "seed1",
    .regions = regions,
    .region_count = 3
  };

  u32 start = 99, count = 99;

  /* 1. Target State 0 (initial state): M1 is empty, M2 starts at region 0 */
  int res = select_m2_for_target_state(&seed, 0, &start, &count);
  assert(res == 0);
  assert(start == 0);
  assert(count == 1); /* Regions 0 and 1 have different state_counts, so count is 1 */

  /* 2. Target State 0x10 (reached by Region 0):
     M1 is Region 0. M2 starts at Region 1. */
  res = select_m2_for_target_state(&seed, 0x10, &start, &count);
  assert(res == 0);
  assert(start == 1);
  assert(count == 1);

  /* 3. Target State 0x20 (reached by Region 1):
     M1 is Regions 0..1. M2 starts at Region 2. */
  res = select_m2_for_target_state(&seed, 0x20, &start, &count);
  assert(res == 0);
  assert(start == 2);
  assert(count == 1);

  /* 4. Target State 0x30 (reached by Region 2, the terminal region):
     No subsequent messages exist to mutate while in state 0x30.
     Must reject seed (return 1). */
  res = select_m2_for_target_state(&seed, 0x30, &start, &count);
  assert(res == 1);

  /* 5. Target State 0x99 (not reached by any region):
     Must reject seed (return 1). */
  res = select_m2_for_target_state(&seed, 0x99, &start, &count);
  assert(res == 1);

  /* 6. Unknown boundary: Region 1 has missing annotation (state_count = 0) */
  regions[1].state_count = 0;
  regions[1].state_sequence = NULL;

  /* Target 0x20 cannot be reached because region 1 is unannotated */
  res = select_m2_for_target_state(&seed, 0x20, &start, &count);
  assert(res == 1);

  /* Target 0x30 cannot be safely resolved across unannotated region 1 */
  res = select_m2_for_target_state(&seed, 0x30, &start, &count);
  assert(res == 1);

  /* Target 0x10 (reached by Region 0 before unknown Region 1) succeeds! */
  res = select_m2_for_target_state(&seed, 0x10, &start, &count);
  assert(res == 0);
  assert(start == 1);

  printf("[+] All P01 target state M2 selection tests passed successfully!\n");
  return 0;
}
