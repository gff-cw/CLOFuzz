/* Optional layer selection driven by outcomes from the existing StateAFL loop. */
#ifndef STATEAFL_PROTOCOL_SCHEDULE_H
#define STATEAFL_PROTOCOL_SCHEDULE_H

#include "protocol_runtime.h"
#define PROTO_SCHEDULE_SLOTS 64
#define PROTO_SCHEDULE_WINDOW 1024
#define PROTO_SCHEDULE_MAX_REWARD 24

enum proto_feedback {
  PROTO_FEEDBACK_QUEUE = 1,
  PROTO_FEEDBACK_MEMORY = 2,
  PROTO_FEEDBACK_CRASH = 4,
  PROTO_FEEDBACK_HANG = 8,
  PROTO_FEEDBACK_COVERAGE = 16
};

typedef struct {
  uint32_t state_id;
  uint32_t attempts[3], rewards[3]; /* Decaying learning window. */
  uint64_t last_used;
  unsigned used;
} proto_schedule_entry;

typedef struct {
  proto_schedule_entry entries[PROTO_SCHEDULE_SLOTS];
  uint64_t clock, evictions, observations, rewarded, events[5];
  uint64_t new_tuples, new_buckets;
} proto_schedule;

/* Zero-initialize once per campaign. State IDs are exact opaque StateAFL IDs;
 * LRU eviction discards learning, never combines distinct states. No heap use.
 * choose returns 0 for invalid arguments/masks; weights returns -1.
 * RNG must obey the proto_random contract. */
int proto_schedule_choose(proto_schedule *schedule, uint32_t state_id,
                          int layers, proto_random rng);
/* Exactly one observation per chosen candidate, after save_if_interesting.
 * Rejected/abandoned candidates use events=0. Raw fallback earns no reward.
 * Events are booleans for this candidate, not cumulative discovery counts. */
void proto_schedule_observe(proto_schedule *schedule, uint32_t state_id,
                            int layer, unsigned events);
/* Record counts captured from the original coverage execution before any
 * replay changes its map; this call may follow retention/calibration.
 * new_tuples counts newly reached bitmap positions; new_buckets counts positions
 * seen before whose hit-count class is new. The sets must not overlap. Counts
 * are exact per-candidate evidence, not cumulative totals. COVERAGE is derived
 * from nonzero counts; a bare flag never creates coverage evidence or reward.
 * Coverage adds min(8, 1 + floor(log2(new_tuples))) plus 1 for any new_buckets.
 * The old events add at most 15; total reward is bounded by MAX_REWARD. */
void proto_schedule_observe_outcome(proto_schedule *schedule, uint32_t state_id,
                                    int layer, unsigned events,
                                    uint32_t new_tuples, uint32_t new_buckets);
/* Read-only view; unknown states receive the initial exploration weights.
 * Disabled layers have weight 0. Each enabled layer always has weight >=16. */
int proto_schedule_weights(const proto_schedule *schedule, uint32_t state_id,
                           int layers, uint32_t weights[3]);
/* Write one JSON object to a borrowed stream. Diagnostic output only;
 * scheduler learning starts fresh on resume and is never loaded from disk. */
void proto_schedule_write(const proto_schedule *schedule, FILE *stream);

#endif
