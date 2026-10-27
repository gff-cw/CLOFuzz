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
  puts("PASS: AFL bitmap novelty, repeat/replay exclusion and C scheduler attribution");
  return 0;
}
