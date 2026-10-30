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

static void dummy_cb(const uint8_t *buf, size_t len, int is_dgram, int truncated, void *user) {
  (void)buf; (void)len; (void)is_dgram; (void)truncated; (void)user;
}

int main(void) {
  printf("[*] Testing P18: Timeout normalization, monotonic budget, and I/O status accounting...\n");

  /* --- 1. Time normalization and conversion helpers --- */
  struct timeval unnorm = { .tv_sec = 0, .tv_usec = 2500000 };
  struct timeval norm = normalize_timeval(unnorm);
  assert(norm.tv_sec == 2);
  assert(norm.tv_usec == 500000);

  struct timeval exact = { .tv_sec = 1, .tv_usec = 1000000 };
  norm = normalize_timeval(exact);
  assert(norm.tv_sec == 2);
  assert(norm.tv_usec == 0);

  struct timeval valid = { .tv_sec = 5, .tv_usec = 999999 };
  norm = normalize_timeval(valid);
  assert(norm.tv_sec == 5);
  assert(norm.tv_usec == 999999);

  struct timeval from_us = usecs_to_timeval(1500000ULL);
  assert(from_us.tv_sec == 1);
  assert(from_us.tv_usec == 500000);

  uint64_t roundtrip_us = timeval_to_usecs(from_us);
  assert(roundtrip_us == 1500000ULL);

  struct timeval zero_tv = { .tv_sec = 0, .tv_usec = 0 };
  assert(timeval_to_poll_ms(zero_tv) == 0);

  struct timeval small_tv = { .tv_sec = 0, .tv_usec = 1500 };
  assert(timeval_to_poll_ms(small_tv) == 2);

  struct timeval one_sec = { .tv_sec = 1, .tv_usec = 0 };
  assert(timeval_to_poll_ms(one_sec) == 1000);

  /* --- 2. I/O status string representations --- */
  assert(strcmp(net_io_status_to_str(NET_IO_STATUS_OK), "ok") == 0);
  assert(strcmp(net_io_status_to_str(NET_IO_STATUS_EOF), "eof") == 0);
  assert(strcmp(net_io_status_to_str(NET_IO_STATUS_TIMEOUT), "timeout") == 0);
  assert(strcmp(net_io_status_to_str(NET_IO_STATUS_SYSCALL_ERR), "syscall_error") == 0);
  assert(strcmp(net_io_status_to_str(NET_IO_STATUS_BUDGET_EXCEEDED), "budget_exceeded") == 0);

  /* --- 3. net_send with user timeout and send budget --- */
  int tcp_sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tcp_sv) == 0);

  struct timeval send_tv = { .tv_sec = 0, .tv_usec = 50000 }; /* 50ms */
  char send_data[32] = "STATEAFL_TIMEOUT_P18_TEST";
  int sent = net_send(tcp_sv[1], send_tv, send_data, (unsigned int)strlen(send_data));
  assert(sent == (int)strlen(send_data));
  assert(net_get_last_io_status() == NET_IO_STATUS_OK);

  /* --- 4. net_recv_with_cb and EOF handling --- */
  char *resp_buf = NULL;
  unsigned int resp_len = 0;
  struct timeval recv_tv = { .tv_sec = 0, .tv_usec = 20000 }; /* 20ms */

  /* Receive the sent data */
  int rc = net_recv_with_cb(tcp_sv[0], recv_tv, 50, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_OK);
  assert(resp_len == strlen(send_data));
  assert(memcmp(resp_buf, send_data, resp_len) == 0);

  /* Now close writing end to trigger EOF */
  close(tcp_sv[1]);
  rc = net_recv_with_cb(tcp_sv[0], recv_tv, 10, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_OK);
  assert(net_get_last_io_status() == NET_IO_STATUS_EOF);

  close(tcp_sv[0]);
  if (resp_buf) ck_free(resp_buf);
  resp_buf = NULL;
  resp_len = 0;

  /* --- 5. Timeout handling (no data pending on socket) --- */
  int tcp_sv2[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tcp_sv2) == 0);

  struct timeval quick_tv = { .tv_sec = 0, .tv_usec = 5000 }; /* 5ms */
  rc = net_recv_with_cb(tcp_sv2[0], quick_tv, 5, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_OK);
  assert(net_get_last_io_status() == NET_IO_STATUS_TIMEOUT);
  assert(resp_len == 0);

  close(tcp_sv2[0]);
  close(tcp_sv2[1]);

  /* --- 6. Syscall error handling --- */
  rc = net_recv_with_cb(-1, quick_tv, 0, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_ERROR);
  assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);

  /* --- 7. Budget exceeded status tracking --- */
  net_set_response_budget(16);
  resp_len = 16;
  rc = net_recv_with_cb(0, quick_tv, 0, &resp_buf, &resp_len, dummy_cb, NULL);
  assert(rc == NET_RECV_BUDGET_EXCEEDED);
  assert(net_get_last_io_status() == NET_IO_STATUS_BUDGET_EXCEEDED);
  net_set_response_budget(0); /* reset to default */

  printf("PASS: test_timeout_budget_consistency passed (24 assertions)\n");
  return 0;
}
