#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "execution_observation.h"

/* The comparison and deep copy are production helpers. Each fixture owns its
 * submitted bytes, response buffers and state sequence independently. */
static execution_observation_t *observation(u32 id, u8 purpose) {
  execution_observation_t *obs = calloc(1, sizeof(*obs));
  assert(obs);
  u8 first[40], second[40], third[40];
  memset(first, 'A', sizeof(first));
  memset(second, 'B', sizeof(second));
  memset(third, 'C', sizeof(third));
  execution_wire_record_t records[] = {
    {first, sizeof(first), sizeof(first)},
    {second, sizeof(second), sizeof(second)},
    {third, sizeof(third), sizeof(third)}
  };
  assert(copy_execution_wire(obs, records, 3, 3) == 0);
  obs->exec_id = id;
  obs->exec_purpose = purpose;
  obs->messages_sent = obs->complete_messages = 3;
  obs->total_bytes_sent = 120;
  obs->is_transmission_complete = obs->is_response_complete = 1;
  obs->response_buf_size = 12;
  obs->response_buf = malloc(12);
  obs->response_bytes_count = 3;
  obs->response_bytes = malloc(3 * sizeof(*obs->response_bytes));
  obs->state_count = 3;
  obs->state_sequence = malloc(3 * sizeof(*obs->state_sequence));
  assert(obs->response_buf && obs->response_bytes && obs->state_sequence);
  memcpy(obs->response_buf, "RESP1RESP2OK", 12);
  obs->response_bytes[0] = 5;
  obs->response_bytes[1] = 10;
  obs->response_bytes[2] = 12;
  obs->has_state_observation = 1;
  obs->provider = STATE_OBS_PROVIDER_TRACER;
  obs->status = STATE_TRACER_STATUS_COMPLETE;
  obs->state_sequence[0] = 0;
  obs->state_sequence[1] = 42;
  obs->state_sequence[2] = 88;
  obs->unique_state_count = 3;
  obs->has_verified_boundaries = 1;
  obs->boundary_count = 3;
  obs->boundary_state_index[0] = 1;
  obs->boundary_state_index[1] = STATE_BOUNDARY_UNKNOWN;
  obs->boundary_state_index[2] = 2;
  return obs;
}

static void rejects(const execution_observation_t *orig,
                    execution_observation_t *rep, const char *fragment) {
  char reason[256] = "";
  assert(compare_execution_observations(orig, rep, reason, sizeof(reason)) == 0);
  assert(strstr(reason, fragment));
  free_execution_observation(rep);
}

int main(void) {
  free_execution_observation(NULL);
  char reason[256];
  assert(compare_execution_observations(NULL, NULL, reason, sizeof(reason)) == 0);
  execution_observation_t *orig = observation(1001, EXEC_PURPOSE_ORIGINAL);
  execution_observation_t *rep = observation(1002, EXEC_PURPOSE_CONFIRMATION);
  assert(orig->wire != rep->wire && orig->wire[0].data != rep->wire[0].data);
  assert(compare_execution_observations(orig, rep, reason, sizeof(reason)) == 1);
  assert(strcmp(reason, "repeatable match") == 0);
  free_execution_observation(rep);

  rep = observation(1003, EXEC_PURPOSE_CONFIRMATION);
  rep->state_sequence[1] = 99;
  rejects(orig, rep, "state trajectory mismatch");
  rep = observation(1004, EXEC_PURPOSE_CONFIRMATION);
  rep->state_count = 2;
  rejects(orig, rep, "variable state sequence length");
  rep = observation(1005, EXEC_PURPOSE_CONFIRMATION);
  rep->messages_sent = 2;
  rejects(orig, rep, "transmission count mismatch");
  rep = observation(1006, EXEC_PURPOSE_CONFIRMATION);
  rep->is_truncated = 1;
  rejects(orig, rep, "state trace truncated");
  rep = observation(1007, EXEC_PURPOSE_CONFIRMATION);
  rep->is_transmission_complete = 0;
  rejects(orig, rep, "incomplete execution");
  rep = observation(1008, EXEC_PURPOSE_CONFIRMATION);
  rep->total_bytes_sent = 100;
  rejects(orig, rep, "total bytes sent mismatch");
  rep = observation(1009, EXEC_PURPOSE_CONFIRMATION);
  rep->wire[1].data[3] ^= 1;
  rejects(orig, rep, "submitted input identity");
  rep = observation(1010, EXEC_PURPOSE_CONFIRMATION);
  rep->boundary_state_index[2] = 1;
  rejects(orig, rep, "message boundary evidence differs");
  rep = observation(1011, EXEC_PURPOSE_CONFIRMATION);
  rep->is_response_complete = 0;
  rejects(orig, rep, "incomplete execution");
  rep = observation(1012, EXEC_PURPOSE_CONFIRMATION);
  free(rep->state_sequence);
  rep->state_sequence = NULL;
  rejects(orig, rep, "state observation");
  rep = observation(1013, EXEC_PURPOSE_CONFIRMATION);
  rep->status = STATE_TRACER_STATUS_FAILED;
  rejects(orig, rep, "state observation");
  rep = observation(1014, EXEC_PURPOSE_CONFIRMATION);
  rep->provider = STATE_OBS_PROVIDER_CODES;
  rejects(orig, rep, "state observation");

  assert(orig->exec_id == 1001 && orig->messages_sent == 3);
  assert(orig->state_count == 3 && orig->state_sequence[1] == 42);
  assert(orig->response_buf_size == 12);
  assert(memcmp(orig->response_buf, "RESP1RESP2OK", 12) == 0);
  assert(orig->wire[1].data[3] == 'B');
  free_execution_observation(orig);
  puts("PASS: immutable submitted input, state and boundary observations");
  return 0;
}
