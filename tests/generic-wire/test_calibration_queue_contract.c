/* Production lifecycle and ranking helpers, without creating a target child. */
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#include <assert.h>

int main(void) {
  region_t regions[2] = {{0}};
  regions[0].start_byte = 0; regions[0].end_byte = 1;
  regions[1].start_byte = 2; regions[1].end_byte = 4;
  struct queue_entry measured = {0}, candidate = {0}, pending = {0};
  measured.regions = candidate.regions = pending.regions = regions;
  measured.region_count = candidate.region_count = pending.region_count = 2;
  measured.len = candidate.len = pending.len = 5;
  measured.calibration_ready = candidate.calibration_ready = 1;
  measured.exec_us = candidate.exec_us = 10;
  measured.unique_state_count = candidate.unique_state_count = 3;
  assert(queue_entry_selectable(&pending) && !queue_entry_fuzz_ready(&pending));
  assert(!queue_entry_better(&pending, &measured));
  assert(!queue_entry_better(&candidate, &measured)); /* Stable exact tie. */
  candidate.exec_us = 9;
  assert(queue_entry_better(&candidate, &measured));
  candidate.exec_us = 1000; candidate.unique_state_count = 4;
  assert(queue_entry_better(&candidate, &measured)); /* States take priority. */
  candidate.exec_us = 1; candidate.unique_state_count = 2;
  assert(!queue_entry_better(&candidate, &measured));
  candidate.exec_us = UINT64_MAX; candidate.len = UINT32_MAX;
  assert(queue_entry_cost(&candidate) == UINT64_MAX);
  candidate.unique_state_count = 3;
  assert(!queue_entry_better(&candidate, &measured));

  /* Persistent input identity preserves record boundaries as well as bytes. */
  u8 input[5] = {1, 2, 3, 4, 5};
  execution_observation_t expected;
  assert(queue_calibration_expected_wire(&measured, input, &expected) == 0);
  assert(expected.has_wire_observation && expected.is_transmission_complete);
  assert(expected.wire_count == 2 && expected.planned_messages == 2);
  assert(expected.wire[0].data == input && expected.wire[0].size == 2);
  assert(expected.wire[1].data == input + 2 && expected.wire[1].size == 3);
  free(expected.wire); /* Descriptors borrow the saved input. */
  regions[1].end_byte = 5;
  assert(queue_calibration_expected_wire(&measured, input, &expected) < 0);
  regions[1].end_byte = 4;

  static u8 trace[MAP_SIZE];
  trace_bits = trace; trace[17] = 1;
  update_bitmap_score(&measured);
  assert(top_rated[17] == &measured && measured.tc_ref == 1);
  candidate.len = 5; candidate.exec_us = 10;
  update_bitmap_score(&candidate);
  assert(top_rated[17] == &measured && !candidate.tc_ref);
  update_bitmap_score(&measured); /* Self-update preserves its reference. */
  assert(measured.tc_ref == 1);
  pending.unique_state_count = 100;
  update_bitmap_score(&pending);
  assert(top_rated[17] == &measured);
  candidate.exec_us = 9;
  update_bitmap_score(&candidate);
  assert(top_rated[17] == &candidate && !measured.tc_ref && !measured.trace_mini);

  /* Terminal isolation releases retained bitmap memory, ranking references and
     pending accounting exactly once, without claiming successful fuzzing. */
  protocol_log = tmpfile(); assert(protocol_log);
  candidate.calibration_trace = ck_alloc(MAP_SIZE);
  candidate.cal_failed = CAL_CHANCES;
  candidate.favored = 1;
  pending_not_fuzzed = 3; pending_favored = queued_favored = 2;
  quarantine_queue_entry(&candidate, "regression_retry_exhausted");
  assert(!queue_entry_selectable(&candidate) && !queue_entry_fuzz_ready(&candidate));
  assert(candidate.pending_settled && !candidate.was_fuzzed);
  assert(!candidate.calibration_trace && !candidate.trace_mini && !candidate.tc_ref);
  assert(!top_rated[17]);
  assert(pending_not_fuzzed == 2 && pending_favored == 1 && queued_favored == 1);
  quarantine_queue_entry(&candidate, "again");
  assert(pending_not_fuzzed == 2 && pending_favored == 1);
  assert(!retry_queue_calibration(NULL, &candidate, 1)); /* No file/target access. */
  assert(calculate_score(&candidate) == 0);

  /* Initial explicitly skipped entries settle under the same terminal policy. */
  pending.cal_failed = CAL_CHANCES;
  assert(!retry_queue_calibration(NULL, &pending, 1));
  assert(pending.calibration_quarantined && pending.pending_settled);
  assert(pending_not_fuzzed == 1);
  assert(!retry_queue_calibration(NULL, &pending, 1) && pending_not_fuzzed == 1);
  total_cal_cycles = total_bitmap_entries = 0;
  assert(calculate_score(&measured) == 0); /* No global division by zero. */

  rewind(protocol_log);
  char record[512]; unsigned quarantines = 0;
  while (fgets(record, sizeof(record), protocol_log))
    if (strstr(record, "\"event\":\"calibration_quarantined\"")) quarantines++;
  assert(quarantines == 2);
  fclose(protocol_log); protocol_log = NULL;
  puts("PASS: production calibration identity, readiness, terminal isolation and lexicographic ranking");
  return 0;
}
