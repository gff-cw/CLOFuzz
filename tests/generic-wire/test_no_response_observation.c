#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "execution_observation.h"

int main(void) {
  printf("[*] Testing P27 distinction between model no-response and tracer observation capability...\n");

  /* 1. Construct an observation for an execution where target produced NO network responses */
  execution_observation_t *no_resp_obs = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(no_resp_obs != NULL);
  no_resp_obs->exec_id = 101;
  no_resp_obs->exec_purpose = EXEC_PURPOSE_ORIGINAL;
  no_resp_obs->messages_sent = 1;
  no_resp_obs->complete_messages = 1;
  no_resp_obs->total_bytes_sent = 32;
  no_resp_obs->is_transmission_complete = 1;
  no_resp_obs->response_buf = NULL;
  no_resp_obs->response_buf_size = 0;
  no_resp_obs->response_bytes = NULL;
  no_resp_obs->response_bytes_count = 0;

  /* Under P27, absence of response means backend tracer had no dumps;
     status is explicitly UNAVAILABLE, not state 0 or complete */
  no_resp_obs->has_state_observation = 0;
  no_resp_obs->status = STATE_TRACER_STATUS_UNAVAILABLE;
  no_resp_obs->state_count = 0;
  no_resp_obs->state_sequence = NULL;

  assert(no_resp_obs->has_state_observation == 0);
  assert(no_resp_obs->status == STATE_TRACER_STATUS_UNAVAILABLE);
  assert(no_resp_obs->state_count == 0);
  assert(no_resp_obs->state_sequence == NULL);

  /* 2. Replay run also produces no responses */
  execution_observation_t *rep_no_resp = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(rep_no_resp != NULL);
  rep_no_resp->exec_id = 102;
  rep_no_resp->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_no_resp->messages_sent = 1;
  rep_no_resp->complete_messages = 1;
  rep_no_resp->total_bytes_sent = 32;
  rep_no_resp->is_transmission_complete = 1;
  rep_no_resp->has_state_observation = 0;
  rep_no_resp->status = STATE_TRACER_STATUS_UNAVAILABLE;
  rep_no_resp->state_count = 0;
  rep_no_resp->state_sequence = NULL;

  /* 3. Confirmation comparison must REJECT confirmation because state observation is unavailable */
  char reason[256] = {0};
  int match = compare_execution_observations(no_resp_obs, rep_no_resp, reason, sizeof(reason));
  assert(match == 0);
  assert(strstr(reason, "state observation unavailable") != NULL);

  /* 4. Cross comparison: valid observation vs unavailable observation must reject */
  execution_observation_t *valid_obs = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(valid_obs != NULL);
  valid_obs->exec_id = 103;
  valid_obs->messages_sent = 1;
  valid_obs->complete_messages = 1;
  valid_obs->total_bytes_sent = 32;
  valid_obs->is_transmission_complete = 1;
  valid_obs->has_state_observation = 1;
  valid_obs->status = STATE_TRACER_STATUS_COMPLETE;
  valid_obs->state_count = 1;
  valid_obs->state_sequence = (unsigned int *)malloc(sizeof(unsigned int));
  valid_obs->state_sequence[0] = 0;

  reason[0] = '\0';
  match = compare_execution_observations(valid_obs, rep_no_resp, reason, sizeof(reason));
  assert(match == 0);
  assert(strstr(reason, "state observation presence mismatch") != NULL);

  free_execution_observation(no_resp_obs);
  free_execution_observation(rep_no_resp);
  free_execution_observation(valid_obs);

  printf("[+] P27 no-response observation test passed successfully!\n");
  return 0;
}
