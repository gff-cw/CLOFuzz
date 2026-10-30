#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

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

struct mock_queue_entry {
  u32 index;
  char *fname;
};

/* P22 implementation matching afl-fuzz.c */
static void register_state_seed_reachability(state_info_t *state, void *q) {
  if (!state || !q) return;

  for (u32 s = 0; s < state->seeds_count; s++) {
    if (state->seeds[s] == q) {
      /* Already registered for this state; idempotent, do not duplicate */
      return;
    }
  }

  state->seeds = (void **)realloc(state->seeds, (state->seeds_count + 1) * sizeof(void *));
  state->seeds[state->seeds_count] = q;
  state->seeds_count++;
}

int main(void) {
  printf("[*] Testing P22 reachability deduplication and idempotent seed registration...\n");

  state_info_t state0 = {
    .id = 0,
    .seeds = NULL,
    .seeds_count = 0
  };

  struct mock_queue_entry q1 = { .index = 1, .fname = "seed1" };
  struct mock_queue_entry q2 = { .index = 2, .fname = "seed2" };
  struct mock_queue_entry q3 = { .index = 3, .fname = "seed3" };

  /* 1. Register seed q1 for state0 */
  register_state_seed_reachability(&state0, &q1);
  assert(state0.seeds_count == 1);
  assert(state0.seeds[0] == (void *)&q1);

  /* 2. Repeated registrations of q1 across multiple regions must be idempotent */
  for (int region = 1; region < 10; region++) {
    register_state_seed_reachability(&state0, &q1);
  }
  assert(state0.seeds_count == 1);
  assert(state0.seeds[0] == (void *)&q1);

  /* 3. Register second distinct seed q2 */
  register_state_seed_reachability(&state0, &q2);
  assert(state0.seeds_count == 2);
  assert(state0.seeds[0] == (void *)&q1);
  assert(state0.seeds[1] == (void *)&q2);

  /* Repeated registrations of both q1 and q2 */
  register_state_seed_reachability(&state0, &q1);
  register_state_seed_reachability(&state0, &q2);
  register_state_seed_reachability(&state0, &q1);
  assert(state0.seeds_count == 2);

  /* 4. Register third distinct seed q3 */
  register_state_seed_reachability(&state0, &q3);
  assert(state0.seeds_count == 3);
  assert(state0.seeds[0] == (void *)&q1);
  assert(state0.seeds[1] == (void *)&q2);
  assert(state0.seeds[2] == (void *)&q3);

  /* Clean up */
  free(state0.seeds);
  printf("[+] P22 reachability deduplication tests passed successfully!\n");
  return 0;
}
