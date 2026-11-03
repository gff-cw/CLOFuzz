#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Exercise the actual network implementation. Only syscall failures are
 * injected; no copy of net_send/net_recv or their result predicates is used. */
static int fail_option;
static int fail_after_first_send;
static unsigned send_calls;
static size_t first_send_limit;
static int fake_clock_enabled;
static uint64_t fake_clock_ms;
static unsigned advance_after_ready_ms;

static int contract_clock_gettime(clockid_t id, struct timespec *stamp) {
  if (fake_clock_enabled && id == CLOCK_MONOTONIC) {
    stamp->tv_sec = (time_t)(fake_clock_ms / 1000ULL);
    stamp->tv_nsec = (long)((fake_clock_ms % 1000ULL) * 1000000ULL);
    return 0;
  }
  return clock_gettime(id, stamp);
}

static int contract_poll(struct pollfd *fds, nfds_t count, int timeout_ms) {
  int result = poll(fds, count, timeout_ms);
  if (result > 0 && fake_clock_enabled && advance_after_ready_ms) {
    fake_clock_ms += advance_after_ready_ms;
    advance_after_ready_ms = 0;
  }
  return result;
}

static int contract_setsockopt(int fd, int level, int option,
                               const void *value, socklen_t length) {
  if (level == SOL_SOCKET && option == fail_option) {
    errno = EIO;
    return -1;
  }
  return setsockopt(fd, level, option, value, length);
}

static ssize_t contract_send(int fd, const void *data, size_t size, int flags) {
  assert(flags & MSG_DONTWAIT);
  send_calls++;
  if (send_calls == 1 && first_send_limit && size > first_send_limit)
    size = first_send_limit;
  ssize_t result = send(fd, data, size, flags);
  if (fail_after_first_send && result > 0) fail_option = SO_SNDTIMEO;
  return result;
}

#define setsockopt contract_setsockopt
#define send contract_send
#define poll contract_poll
#define clock_gettime contract_clock_gettime
#include "../../aflnet.c"
#undef clock_gettime
#undef poll
#undef send
#undef setsockopt

static void reset_injection(void) {
  fail_option = 0;
  fail_after_first_send = 0;
  send_calls = 0;
  first_send_limit = 0;
  fake_clock_enabled = 0;
  fake_clock_ms = 0;
  advance_after_ready_ms = 0;
}

int main(void) {
  struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
  char payload[] = "contract";
  char observed[32];
  int pair[2];

  /* A failed timeout setup prevents any UDP submission and reaches the caller
   * as an error, rather than an OK byte count plus an ignored side channel. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
  reset_injection();
  fail_option = SO_SNDTIMEO;
  int flags_before = fcntl(pair[0], F_GETFL);
  assert(flags_before >= 0);
  assert(net_send(pair[0], timeout, payload, sizeof(payload)) == -1);
  assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);
  assert(send_calls == 0);
  assert(fcntl(pair[0], F_GETFL) == flags_before);
  assert(recv(pair[1], observed, sizeof(observed), MSG_DONTWAIT) == -1);
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
  close(pair[0]);
  close(pair[1]);

  /* A later setup failure preserves the exact prefix already submitted. */
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  reset_injection();
  first_send_limit = 3;
  fail_after_first_send = 1;
  flags_before = fcntl(pair[0], F_GETFL);
  assert(flags_before >= 0);
  assert(net_send(pair[0], timeout, payload, sizeof(payload)) == 3);
  assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);
  assert(send_calls == 1);
  assert(recv(pair[1], observed, sizeof(observed), MSG_DONTWAIT) == 3);
  assert(memcmp(observed, payload, 3) == 0);
  assert(fcntl(pair[0], F_GETFL) == flags_before);
  close(pair[0]);
  close(pair[1]);

  /* A failed receive setup returns non-OK without consuming queued bytes. */
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  assert(write(pair[1], payload, sizeof(payload)) == sizeof(payload));
  reset_injection();
  fail_option = SO_RCVTIMEO;
  char *response = NULL;
  unsigned response_size = 0;
  flags_before = fcntl(pair[0], F_GETFL);
  assert(flags_before >= 0);
  assert(net_recv_with_cb(pair[0], timeout, 10, &response, &response_size,
                          NULL, NULL) == NET_RECV_ERROR);
  assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);
  assert(response == NULL && response_size == 0);
  assert(fcntl(pair[0], F_GETFL) == flags_before);
  assert(recv(pair[0], observed, sizeof(observed), MSG_DONTWAIT) == sizeof(payload));
  assert(memcmp(observed, payload, sizeof(payload)) == 0);
  close(pair[0]);
  close(pair[1]);

  /* Force the initial readiness poll to consume the whole entry-time budget.
   * Both TCP and UDP must then return without issuing a send syscall. This
   * checks the actual production UDP branch without loose wall-time bounds. */
  const int kinds[] = {SOCK_STREAM, SOCK_DGRAM};
  for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    assert(socketpair(AF_UNIX, kinds[i], 0, pair) == 0);
    reset_injection();
    fake_clock_enabled = 1;
    fake_clock_ms = 1000;
    advance_after_ready_ms = 6;
    struct timeval short_timeout = {.tv_sec = 0, .tv_usec = 5000};
    assert(net_send(pair[0], short_timeout, payload, sizeof(payload)) == 0);
    assert(net_get_last_io_status() == NET_IO_STATUS_TIMEOUT);
    assert(send_calls == 0);
    assert(recv(pair[1], observed, sizeof(observed), MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    close(pair[0]);
    close(pair[1]);
  }

  /* A receive deadline with queued bytes is incomplete, unlike an idle drain.
   * The post-deadline availability probe must leave those bytes untouched. */
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  assert(write(pair[1], payload, sizeof(payload)) == sizeof(payload));
  reset_injection();
  fake_clock_enabled = 1;
  fake_clock_ms = 2000;
  advance_after_ready_ms = 6;
  struct timeval short_timeout = {.tv_sec = 0, .tv_usec = 5000};
  response = NULL;
  response_size = 0;
  assert(net_recv_with_cb(pair[0], short_timeout, 5, &response, &response_size,
                          NULL, NULL) == NET_RECV_TIMED_OUT);
  assert(net_get_last_io_status() == NET_IO_STATUS_TIMEOUT);
  assert(response == NULL && response_size == 0);
  assert(recv(pair[0], observed, sizeof(observed), MSG_DONTWAIT) == sizeof(payload));
  assert(memcmp(observed, payload, sizeof(payload)) == 0);
  close(pair[0]);
  close(pair[1]);
  reset_injection();

  puts("PASS: production transport setup errors, deadlines and partial submission contract");
  return 0;
}
