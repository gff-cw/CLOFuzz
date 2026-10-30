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
  printf("[*] Testing P05 execution observation isolation and confirmation comparison...\n");

  /* 1. NULL safety */
  free_execution_observation(NULL);
  char reason[256];
  assert(compare_execution_observations(NULL, NULL, reason, sizeof(reason)) == 0);

  /* 2. Construct original observation */
  execution_observation_t *orig = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(orig != NULL);
  orig->exec_id = 1001;
  orig->exec_purpose = EXEC_PURPOSE_ORIGINAL;
  orig->messages_sent = 3;
  orig->complete_messages = 3;
  orig->total_bytes_sent = 120;
  orig->partial_bytes_tail = 0;
  orig->is_transmission_complete = 1;
  orig->response_buf_size = 12;
  orig->response_buf = (char *)malloc(12);
  memcpy(orig->response_buf, "RESP1RESP2OK", 12);
  orig->response_bytes_count = 3;
  orig->response_bytes = (u32 *)malloc(3 * sizeof(u32));
  orig->response_bytes[0] = 5;
  orig->response_bytes[1] = 10;
  orig->response_bytes[2] = 12;
  orig->has_state_observation = 1;
  orig->provider = STATE_OBS_PROVIDER_TRACER;
  orig->is_truncated = 0;
  orig->status = STATE_TRACER_STATUS_COMPLETE;
  orig->state_count = 3;
  orig->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  orig->state_sequence[0] = 0;
  orig->state_sequence[1] = 42;
  orig->state_sequence[2] = 88;
  orig->unique_state_count = 3;

  /* 3. Construct identical confirmation replay observation */
  execution_observation_t *rep_match = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(rep_match != NULL);
  rep_match->exec_id = 1002;
  rep_match->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_match->messages_sent = 3;
  rep_match->complete_messages = 3;
  rep_match->total_bytes_sent = 120;
  rep_match->partial_bytes_tail = 0;
  rep_match->is_transmission_complete = 1;
  rep_match->has_state_observation = 1;
  rep_match->provider = STATE_OBS_PROVIDER_TRACER;
  rep_match->is_truncated = 0;
  rep_match->status = STATE_TRACER_STATUS_COMPLETE;
  rep_match->state_count = 3;
  rep_match->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_match->state_sequence[0] = 0;
  rep_match->state_sequence[1] = 42;
  rep_match->state_sequence[2] = 88;
  rep_match->unique_state_count = 3;

  reason[0] = '\0';
  int match = compare_execution_observations(orig, rep_match, reason, sizeof(reason));
  assert(match == 1);
  assert(strcmp(reason, "repeatable match") == 0);
  free_execution_observation(rep_match);

  /* 4. Mismatched state trajectory */
  execution_observation_t *rep_state_diff = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_state_diff->exec_id = 1003;
  rep_state_diff->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_state_diff->messages_sent = 3;
  rep_state_diff->complete_messages = 3;
  rep_state_diff->total_bytes_sent = 120;
  rep_state_diff->is_transmission_complete = 1;
  rep_state_diff->has_state_observation = 1;
  rep_state_diff->state_count = 3;
  rep_state_diff->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_state_diff->state_sequence[0] = 0;
  rep_state_diff->state_sequence[1] = 99; /* Different state */
  rep_state_diff->state_sequence[2] = 88;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_state_diff, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "state trajectory mismatch") != NULL);
  free_execution_observation(rep_state_diff);

  /* 5. Mismatched state sequence length */
  execution_observation_t *rep_len_diff = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_len_diff->exec_id = 1004;
  rep_len_diff->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_len_diff->messages_sent = 3;
  rep_len_diff->complete_messages = 3;
  rep_len_diff->total_bytes_sent = 120;
  rep_len_diff->is_transmission_complete = 1;
  rep_len_diff->has_state_observation = 1;
  rep_len_diff->state_count = 2;
  rep_len_diff->state_sequence = (unsigned int *)malloc(2 * sizeof(unsigned int));
  rep_len_diff->state_sequence[0] = 0;
  rep_len_diff->state_sequence[1] = 42;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_len_diff, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "variable state sequence length") != NULL);
  free_execution_observation(rep_len_diff);

  /* 6. Mismatched transmission completeness */
  execution_observation_t *rep_tx_diff = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_tx_diff->exec_id = 1005;
  rep_tx_diff->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_tx_diff->messages_sent = 2; /* 2 instead of 3 */
  rep_tx_diff->complete_messages = 2;
  rep_tx_diff->total_bytes_sent = 80;
  rep_tx_diff->is_transmission_complete = 1;
  rep_tx_diff->has_state_observation = 1;
  rep_tx_diff->state_count = 3;
  rep_tx_diff->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_tx_diff->state_sequence[0] = 0;
  rep_tx_diff->state_sequence[1] = 42;
  rep_tx_diff->state_sequence[2] = 88;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_tx_diff, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "transmission count mismatch") != NULL);
  free_execution_observation(rep_tx_diff);

  /* 7. Truncation flag rejection */
  execution_observation_t *rep_trunc = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_trunc->exec_id = 1006;
  rep_trunc->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_trunc->messages_sent = 3;
  rep_trunc->complete_messages = 3;
  rep_trunc->total_bytes_sent = 120;
  rep_trunc->is_transmission_complete = 1;
  rep_trunc->has_state_observation = 1;
  rep_trunc->is_truncated = 1;
  rep_trunc->state_count = 3;
  rep_trunc->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_trunc->state_sequence[0] = 0;
  rep_trunc->state_sequence[1] = 42;
  rep_trunc->state_sequence[2] = 88;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_trunc, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "state trace truncated") != NULL);
  free_execution_observation(rep_trunc);

  /* 8. Transmission completeness flag mismatch */
  execution_observation_t *rep_comp_diff = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_comp_diff->exec_id = 1007;
  rep_comp_diff->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_comp_diff->messages_sent = 3;
  rep_comp_diff->complete_messages = 3;
  rep_comp_diff->total_bytes_sent = 120;
  rep_comp_diff->is_transmission_complete = 0; /* Mismatch */
  rep_comp_diff->has_state_observation = 1;
  rep_comp_diff->state_count = 3;
  rep_comp_diff->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_comp_diff->state_sequence[0] = 0;
  rep_comp_diff->state_sequence[1] = 42;
  rep_comp_diff->state_sequence[2] = 88;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_comp_diff, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "transmission completeness flag mismatch") != NULL);
  free_execution_observation(rep_comp_diff);

  /* 9. Total bytes sent mismatch */
  execution_observation_t *rep_bytes_diff = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  rep_bytes_diff->exec_id = 1008;
  rep_bytes_diff->exec_purpose = EXEC_PURPOSE_CONFIRMATION;
  rep_bytes_diff->messages_sent = 3;
  rep_bytes_diff->complete_messages = 3;
  rep_bytes_diff->total_bytes_sent = 100; /* 100 vs 120 */
  rep_bytes_diff->is_transmission_complete = 1;
  rep_bytes_diff->has_state_observation = 1;
  rep_bytes_diff->state_count = 3;
  rep_bytes_diff->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  rep_bytes_diff->state_sequence[0] = 0;
  rep_bytes_diff->state_sequence[1] = 42;
  rep_bytes_diff->state_sequence[2] = 88;

  reason[0] = '\0';
  assert(compare_execution_observations(orig, rep_bytes_diff, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "total bytes sent mismatch") != NULL);
  free_execution_observation(rep_bytes_diff);

  /* 10. Verify original observation was never modified (immutability check) */
  assert(orig->exec_id == 1001);
  assert(orig->messages_sent == 3);
  assert(orig->complete_messages == 3);
  assert(orig->state_count == 3);
  assert(orig->state_sequence[0] == 0);
  assert(orig->state_sequence[1] == 42);
  assert(orig->state_sequence[2] == 88);
  assert(orig->response_buf_size == 12);
  assert(memcmp(orig->response_buf, "RESP1RESP2OK", 12) == 0);

  free_execution_observation(orig);

  printf("[+] P05 execution observation isolation tests passed successfully!\n");
  return 0;
}
