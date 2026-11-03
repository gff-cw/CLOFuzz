#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "execution_observation.h"

static execution_observation_t *no_response(u32 id, int available) {
  execution_observation_t *obs = calloc(1, sizeof(*obs));
  assert(obs);
  u8 submitted[32];
  memset(submitted, 'Q', sizeof(submitted));
  execution_wire_record_t record = {submitted, sizeof(submitted), sizeof(submitted)};
  assert(copy_execution_wire(obs, &record, 1, 1) == 0);
  obs->exec_id = id;
  obs->messages_sent = obs->complete_messages = 1;
  obs->total_bytes_sent = sizeof(submitted);
  obs->is_transmission_complete = obs->is_response_complete = 1;
  obs->provider = STATE_OBS_PROVIDER_TRACER;
  obs->status = available ? STATE_TRACER_STATUS_COMPLETE : STATE_TRACER_STATUS_UNAVAILABLE;
  obs->has_state_observation = available;
  if (available) {
    obs->state_count = 2;
    obs->state_sequence = calloc(2, sizeof(*obs->state_sequence));
    assert(obs->state_sequence);
    obs->state_sequence[1] = 42;
    obs->has_verified_boundaries = 1;
    obs->boundary_count = 1;
    obs->boundary_state_index[0] = 1;
  }
  return obs;
}

int main(void) {
  /* No response is not proof of a missing state observation. The explicit
   * provider may publish a trace for a one-way application message. */
  char reason[256] = "";
  execution_observation_t *absent = no_response(101, 0);
  execution_observation_t *rep_absent = no_response(102, 0);
  assert(absent->response_buf == NULL && absent->response_buf_size == 0);
  assert(compare_execution_observations(absent, rep_absent, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "state observation unavailable"));

  execution_observation_t *observed = no_response(103, 1);
  execution_observation_t *rep_observed = no_response(104, 1);
  assert(observed->response_buf == NULL && observed->response_buf_size == 0);
  assert(compare_execution_observations(observed, rep_observed, reason, sizeof(reason)) == 1);

  /* Match metadata before testing state presence, so an earlier boundary
   * mismatch does not accidentally make this case pass. */
  rep_absent->has_verified_boundaries = 1;
  rep_absent->boundary_count = 1;
  rep_absent->boundary_state_index[0] = 1;
  assert(compare_execution_observations(observed, rep_absent, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "state observation presence mismatch"));

  free_execution_observation(absent);
  free_execution_observation(rep_absent);
  free_execution_observation(observed);
  free_execution_observation(rep_observed);
  puts("PASS: no-response executions require independent state evidence");
  return 0;
}
