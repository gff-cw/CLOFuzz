/* Exercise the actual AFL bitmap consumer and its optional coverage observer. */
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#include <assert.h>

int main(void) {
  static u8 trace[MAP_SIZE], other_virgin[MAP_SIZE], snapshot[MAP_SIZE];
  trace_bits = trace;
  memset(virgin_bits, 0xff, MAP_SIZE);
  memset(other_virgin, 0xff, MAP_SIZE);
  protocol_collect_coverage = 1;
  protocol_new_tuples = protocol_new_buckets = 0;
  trace[0] = 1; trace[MAP_SIZE - 1] = 8;
  assert(has_new_bits(virgin_bits) == 2);
  assert(protocol_new_tuples == 2 && protocol_new_buckets == 0);
  assert(virgin_bits[0] == 0xfe && virgin_bits[MAP_SIZE - 1] == 0xf7);
  memcpy(snapshot, virgin_bits, MAP_SIZE);
  assert(has_new_bits(virgin_bits) == 0);
  assert(protocol_new_tuples == 2 && protocol_new_buckets == 0);
  assert(!memcmp(snapshot, virgin_bits, MAP_SIZE));
  trace[0] = 2;
  assert(has_new_bits(virgin_bits) == 1);
  assert(protocol_new_tuples == 2 && protocol_new_buckets == 1);
  trace[0] = 4; trace[17] = 128;
  assert(has_new_bits(virgin_bits) == 2);
  assert(protocol_new_tuples == 3 && protocol_new_buckets == 2);
  /* The session/crash/timeout maps never supply ordinary coverage credit. */
  assert(has_new_bits(other_virgin) == 2);
  assert(protocol_new_tuples == 3 && protocol_new_buckets == 2);
  protocol_collect_coverage = 0;
  trace[23] = 1;
  assert(has_new_bits(virgin_bits) == 2);
  assert(protocol_new_tuples == 3 && protocol_new_buckets == 2);
  protocol_collect_coverage = 1;
  assert(has_new_bits(virgin_bits) == 0);
  assert(protocol_new_tuples == 3 && protocol_new_buckets == 2);
  /* One attributed candidate updates scheduling exactly once. */
  memset(&protocol_scheduler, 0, sizeof(protocol_scheduler));
  protocol_observe_candidate(42, PROTO_HEAD, PROTO_FEEDBACK_QUEUE, 3, 2);
  assert(protocol_scheduler.observations == 1);
  assert(protocol_scheduler.new_tuples == 3 && protocol_scheduler.new_buckets == 2);
  assert(protocol_scheduler.events[4] == 1);
  protocol_observe_candidate(42, 0, PROTO_FEEDBACK_QUEUE, 3, 2);
  assert(protocol_scheduler.observations == 1);
  /* The production preparation path dispatches a description-only protocol
   * into the same scheduler, retaining the real memory state as its key. */
  char error[256];
  protocol_engine = proto_load_generic("tests/generic-wire/fictional_protocol.json",
                                       error, sizeof(error));
  assert(protocol_engine);
  static const u8 replay[] = {8,0,0,0,0xa7,0,5,1,0,1,0x55,0x66};
  memcpy(protocol_base,replay,sizeof(replay));
  protocol_base_len = sizeof(replay);
  protocol_surrounding_records = 0;
  assert(proto_set_prefix(protocol_engine,NULL,0,error,sizeof(error)) == 0);
  memset(&protocol_scheduler,0,sizeof(protocol_scheduler));
  fixed_random_seed = 1;
  srandom(20261027);
  protocol_adaptive = 1;
  protocol_mode = PROTO_VALID;
  protocol_layers = PROTO_HEAD;
  target_state_id = 137;
  u8 candidate[8];memcpy(candidate,replay+4,sizeof(candidate));
  u8 *wire = candidate;u32 length = sizeof(candidate),count = 0,state = 0;
  int layer = 0;
  region_t *regions = protocol_prepare(&wire,&length,&count,&layer,&state);
  assert(regions && count == 1 && length == 8);
  assert(layer == PROTO_HEAD && state == 137 && protocol_structured_run);
  assert(wire[0] == 0xa7 && wire[3] == 1 && wire[1] == 0 && wire[2] == 5);
  assert(wire[6] == 0x55 && wire[7] == 0x66);
  uint32_t weights[3];
  protocol_observe_candidate(state,layer,PROTO_FEEDBACK_MEMORY,1,0);
  assert(protocol_scheduler.events[1] == 1 && protocol_scheduler.events[4] == 1);
  assert(protocol_scheduler.observations == 1);
  assert(proto_schedule_weights(&protocol_scheduler,137,7,weights) == 0);
  assert(weights[0] > weights[1] && weights[1] == weights[2]);
  assert(proto_schedule_weights(&protocol_scheduler,138,7,weights) == 0);
  assert(weights[0] == weights[1] && weights[1] == weights[2]);
  ck_free(regions);
  proto_free(protocol_engine);protocol_engine = NULL;
  puts("PASS: AFL bitmap novelty, replay exclusion, generic C preparation and memory/coverage scheduler attribution");
  return 0;
}
