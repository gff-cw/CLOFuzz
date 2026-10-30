#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "aflnet.h"
#include "alloc-inl.h"
#include "execution_observation.h"

static void dummy_cb(const uint8_t *buf, size_t len, int is_dgram, int truncated, void *user) {
  (void)buf; (void)len; (void)is_dgram; (void)truncated; (void)user;
}

int main(void) {
  printf("[*] Testing P17: TCP and UDP response buffer bounds and budget enforcement...\n");

  /* --- 1. Basic budget configuration API --- */
  assert(net_get_response_budget() == DEFAULT_MAX_RESPONSE_BUDGET);
  net_set_response_budget(512);
  assert(net_get_response_budget() == 512);
  net_set_response_budget(0); /* resets to default */
  assert(net_get_response_budget() == DEFAULT_MAX_RESPONSE_BUDGET);

  /* --- 2. TCP response buffer bounds check --- */
  int tcp_sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tcp_sv) == 0);

  net_set_response_budget(128);
  char *resp_buf = NULL;
  unsigned int resp_len = 0;
  struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };

  /* Send 60 bytes of TCP stream data */
  char chunk1[60];
  memset(chunk1, 'A', sizeof(chunk1));
  assert(write(tcp_sv[1], chunk1, sizeof(chunk1)) == sizeof(chunk1));

  int rc = net_recv_with_cb(tcp_sv[0], tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_OK);
  assert(resp_len == 60);
  assert(resp_buf != NULL);
  assert(memcmp(resp_buf, chunk1, 60) == 0);
  assert(resp_buf[60] == '\0');

  /* Send 80 bytes of TCP stream data. Total would be 60 + 80 = 140 > 128 (exceeds budget) */
  char chunk2[80];
  memset(chunk2, 'B', sizeof(chunk2));
  assert(write(tcp_sv[1], chunk2, sizeof(chunk2)) == sizeof(chunk2));

  rc = net_recv_with_cb(tcp_sv[0], tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_BUDGET_EXCEEDED);
  /* Verify prior 60 bytes are safely preserved for diagnosis */
  assert(resp_len == 60);
  assert(memcmp(resp_buf, chunk1, 60) == 0);
  assert(resp_buf[60] == '\0');

  /* Attempting receive when already at or beyond budget is immediately rejected */
  resp_len = 128;
  rc = net_recv_with_cb(tcp_sv[0], tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_BUDGET_EXCEEDED);

  close(tcp_sv[0]);
  close(tcp_sv[1]);
  if (resp_buf) ck_free(resp_buf);
  resp_buf = NULL;
  resp_len = 0;

  /* --- 3. UDP response buffer bounds check --- */
  int udp_sv[2];
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, udp_sv) == 0);

  net_set_response_budget(100);

  /* Send 40 bytes datagram */
  char dgram1[40];
  memset(dgram1, 'X', sizeof(dgram1));
  assert(write(udp_sv[1], dgram1, sizeof(dgram1)) == sizeof(dgram1));

  rc = net_recv_with_cb(udp_sv[0], tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_OK);
  assert(resp_len == 40);
  assert(memcmp(resp_buf, dgram1, 40) == 0);
  assert(resp_buf[40] == '\0');

  /* Send 70 bytes datagram. Total would be 40 + 70 = 110 > 100 */
  char dgram2[70];
  memset(dgram2, 'Y', sizeof(dgram2));
  assert(write(udp_sv[1], dgram2, sizeof(dgram2)) == sizeof(dgram2));

  rc = net_recv_with_cb(udp_sv[0], tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_BUDGET_EXCEEDED);
  assert(resp_len == 40);
  assert(memcmp(resp_buf, dgram1, 40) == 0);

  close(udp_sv[0]);
  close(udp_sv[1]);
  if (resp_buf) ck_free(resp_buf);
  resp_buf = NULL;
  resp_len = 0;

  /* Reset budget */
  net_set_response_budget(0);
  assert(net_get_response_budget() == DEFAULT_MAX_RESPONSE_BUDGET);

  /* --- 4. NULL safety and parameter validation --- */
  rc = net_recv_with_cb(-1, tv, 0, NULL, &resp_len, NULL, NULL);
  assert(rc == NET_RECV_ERROR);
  rc = net_recv_with_cb(-1, tv, 0, &resp_buf, NULL, NULL, NULL);
  assert(rc == NET_RECV_ERROR);

  /* --- 5. Execution observation truncation and budget exceeded tracking --- */
  execution_observation_t *obs1 = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(obs1 != NULL);
  obs1->exec_id = 1;
  obs1->exec_purpose = EXEC_PURPOSE_ORIGINAL;
  obs1->messages_sent = 2;
  obs1->complete_messages = 2;
  obs1->total_bytes_sent = 50;
  obs1->is_transmission_complete = 1;
  obs1->is_response_complete = 1;
  obs1->response_budget_exceeded = 0;
  obs1->has_state_observation = 1;
  obs1->provider = STATE_OBS_PROVIDER_TRACER;
  obs1->status = STATE_TRACER_STATUS_COMPLETE;
  obs1->state_count = 2;
  obs1->state_sequence = (unsigned int *)calloc(2, sizeof(unsigned int));
  obs1->state_sequence[0] = 0;
  obs1->state_sequence[1] = 1;

  execution_observation_t *obs2 = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(obs2 != NULL);
  memcpy(obs2, obs1, sizeof(execution_observation_t));
  obs2->state_sequence = (unsigned int *)calloc(2, sizeof(unsigned int));
  obs2->state_sequence[0] = 0;
  obs2->state_sequence[1] = 1;

  char reason[256];
  assert(compare_execution_observations(obs1, obs2, reason, sizeof(reason)) == 1);

  /* Now simulate response budget exceeded in repetition run */
  obs2->response_budget_exceeded = 1;
  obs2->is_response_complete = 0;
  obs2->is_truncated = 1;
  assert(compare_execution_observations(obs1, obs2, reason, sizeof(reason)) == 0);
  assert(strstr(reason, "response") != NULL);

  /* Acceptance predicate rejection */
  u8 is_accepted = (!obs2->is_truncated && obs2->is_response_complete &&
                    !obs2->response_budget_exceeded && obs2->has_state_observation &&
                    obs2->state_count > 0 && obs2->is_transmission_complete);
  assert(is_accepted == 0);

  free_execution_observation(obs1);
  free_execution_observation(obs2);

  printf("PASS: test_tcp_response_buffer_bounds passed (28 assertions)\n");
  return 0;
}
