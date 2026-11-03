/* Directly exercise production host consumers without starting a target. */
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#include <assert.h>

int main(void) {
  static struct state_shared shared;
  shared.magic = STATE_SHARED_MAGIC;
  shared.version = STATE_SHARED_VERSION;
  shared.capacity = MAX_NUM_STATES;
  shared.exec_id = shared.producer_exec_id = 17;
  shared.producer_pid = 123;
  shared.seq_len = shared.total_states = 3;
  shared.seq[0] = 0; shared.seq[1] = 42; shared.seq[2] = 88;
  shared.boundary_status = STATE_BOUNDARIES_EXPLICIT;
  shared.boundary_count = 2;
  shared.boundary_state_index[0] = 1;
  shared.boundary_state_index[1] = 2;
  __atomic_store_n(&shared.status, STATE_TRACER_STATUS_COMPLETE, __ATOMIC_RELEASE);
  state_shared_ptr = &shared;
  state_exec_id = 16;
  reset_state_execution();
  assert(state_exec_id == 17 && shared.exec_id == 17);
  assert(shared.status == STATE_TRACER_STATUS_IDLE && !shared.producer_pid);
  shared.producer_pid = 123; shared.producer_exec_id = 17;
  shared.seq_len = shared.total_states = 3;
  shared.seq[0] = 0; shared.seq[1] = 42; shared.seq[2] = 88;
  shared.boundary_status = STATE_BOUNDARIES_EXPLICIT; shared.boundary_count = 2;
  shared.boundary_state_index[0] = 1; shared.boundary_state_index[1] = 2;
  __atomic_store_n(&shared.status, STATE_TRACER_STATUS_COMPLETE, __ATOMIC_RELEASE);
  extract_response_codes = extract_response_state_tracer;
  messages_sent = complete_messages = planned_messages = 2;
  total_bytes_sent = 4;
  is_transmission_complete = is_response_complete = 1;
  response_buf = NULL; response_buf_size = 0; response_bytes = NULL;
  u8 a[] = {1, 2}, b[] = {3, 4};
  execution_wire_record_t wire[] = {{a, 2, 2}, {b, 2, 2}};
  last_execution_wire = wire; last_execution_wire_count = 2;

  /* Accepted explicit boundaries work without fabricating response bytes. */
  execution_observation_t *obs = capture_execution_observation(EXEC_PURPOSE_STATE_ANALYSIS);
  assert(obs && obs->has_state_observation && obs->has_verified_boundaries);
  assert(obs->exec_id == 17 && obs->wire[0].data != a);
  region_t regions[2] = {{0}};
  struct queue_entry q = {0};
  q.regions = regions; q.region_count = 2;
  update_region_annotations(&q, obs);
  assert(regions[0].state_count == 2 && regions[0].state_sequence[1] == 42);
  assert(regions[1].state_count == 3 && regions[1].state_sequence[2] == 88);
  u32 start = 0, count = 0;
  assert(select_state_m2(&q, 42, &start, &count) == 0 && start == 1 && count == 1);
  assert(select_state_m2(&q, 88, &start, &count) < 0); /* Terminal state. */

  /* Ordinary unmarked targets remain UNKNOWN, including a nonzero M2. */
  obs->has_verified_boundaries = 0;
  update_region_annotations(&q, obs);
  assert(!regions[0].state_count && !regions[1].state_count);
  assert(select_state_m2(&q, 42, &start, &count) < 0);
  free_execution_observation(obs);

  /* Malformed maps and stale/conflicting publications are never promoted. */
  shared.boundary_state_index[1] = 1;
  obs = capture_execution_observation(EXEC_PURPOSE_CONFIRMATION);
  assert(obs && obs->has_state_observation && !obs->has_verified_boundaries);
  free_execution_observation(obs);
  shared.producer_conflict = 1;
  obs = capture_execution_observation(EXEC_PURPOSE_CONFIRMATION);
  assert(obs && !obs->has_state_observation && obs->status == STATE_TRACER_STATUS_UNAVAILABLE);
  free_execution_observation(obs);
  shared.producer_conflict = 0;
  shared.producer_exec_id = 16;
  obs = capture_execution_observation(EXEC_PURPOSE_CONFIRMATION);
  assert(obs && !obs->has_state_observation);
  free_execution_observation(obs);

  /* Replays may change globals; feedback retains the original execution ID. */
  protocol_log = tmpfile(); assert(protocol_log);
  current_candidate_id = 9;
  current_feedback_exec_id = 17; current_feedback_executed = 1;
  state_exec_id = 99;
  protocol_observe_candidate(42, PROTO_HEAD, 0, 0, 0);
  rewind(protocol_log);
  char line[1024]; assert(fgets(line, sizeof(line), protocol_log));
  assert(strstr(line, "\"candidate_id\":9,\"exec_id\":17,"));
  assert(!strstr(line, "\"exec_id\":99"));
  fclose(protocol_log); protocol_log = NULL;

  /* Reject before has_new_bits mutates the original coverage virgin map. */
  static u8 trace[MAP_SIZE], before[MAP_SIZE];
  trace_bits = trace; trace[0] = 1;
  memset(virgin_bits, 255, MAP_SIZE); memcpy(before, virgin_bits, MAP_SIZE);
  crash_mode = 0;
  complete_messages = 1; is_transmission_complete = 0;
  assert(save_if_interesting(NULL, NULL, 0, 0) == 0);
  assert(memcmp(before, virgin_bits, MAP_SIZE) == 0);
  complete_messages = 2; is_transmission_complete = 1; is_response_complete = 0;
  assert(save_if_interesting(NULL, NULL, 0, 0) == 0);
  assert(memcmp(before, virgin_bits, MAP_SIZE) == 0);
  update_region_annotations(&q, NULL);
  last_execution_wire = NULL; last_execution_wire_count = 0;
  state_shared_ptr = NULL;
  puts("PASS: production boundary consumer, M2 selection, frozen feedback and admission contracts");
  return 0;
}
