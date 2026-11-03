#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"

static uint64_t get_monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void dummy_recv_cb(const uint8_t *buf, size_t len, int is_dgram, int truncated, void *user) {
  (void)buf; (void)len; (void)is_dgram; (void)truncated; (void)user;
}

int main(void) {
  printf("[*] Testing B12 monotonic deadline budget and setsockopt error handling...\n");

  /* ========================================================================
   * 1. net_send setsockopt failure handling (not silently masked)
   * ======================================================================== */
  {
    struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };
    char test_data[] = "hello";

    /* 1a. Negative fd */
    int res = net_send(-1, tv, test_data, sizeof(test_data));
    assert(res == -1);
    assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);

    /* 1b. Regular non-socket fd (setsockopt fails with ENOTSOCK) */
    int pipe_fds[2];
    assert(pipe(pipe_fds) == 0);
    res = net_send(pipe_fds[1], tv, test_data, sizeof(test_data));
    /* setsockopt failed with ENOTSOCK; error must NOT be masked */
    assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);
    assert(res == -1);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    printf("[+] 1: net_send setsockopt failure properly sets NET_IO_STATUS_SYSCALL_ERR without masking\n");
  }

  /* ========================================================================
   * 2. net_send single monotonic deadline budget spanning poll and I/O
   * ======================================================================== */
  {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Set tiny send buffer on sender to force blocking */
    int sndbuf = 2048;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Prepare a buffer larger than socket buffer */
    size_t big_sz = 1024 * 1024; /* 1 MB */
    char *big_buf = (char *)malloc(big_sz);
    assert(big_buf != NULL);
    memset(big_buf, 'Z', big_sz);

    /* 50 ms total budget */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    uint64_t t_start = get_monotonic_ms();
    int sent = net_send(sv[0], tv, big_buf, big_sz);
    uint64_t t_elapsed = get_monotonic_ms() - t_start;

    /* Verify that net_send terminated due to deadline expiration */
    assert(sent >= 0);
    assert((size_t)sent < big_sz); /* could not send all bytes within 50ms */
    assert(net_get_last_io_status() == NET_IO_STATUS_TIMEOUT);

    /* Monotonic deadline check: elapsed time should be bounded close to budget (~50ms - ~200ms)
       and MUST NOT have been granted unbounded extra time */
    assert(t_elapsed >= 40);
    assert(t_elapsed < 1000); /* bounded, not hanging */

    free(big_buf);
    close(sv[0]);
    close(sv[1]);
    printf("[+] 2: net_send bounded by single monotonic deadline budget (%llu ms elapsed)\n", (unsigned long long)t_elapsed);
  }

  /* ========================================================================
   * 3. net_recv_with_cb setsockopt failure handling
   * ======================================================================== */
  {
    struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };
    char *resp_buf = NULL;
    unsigned int resp_len = 0;

    /* 3a. Invalid fd */
    int rc = net_recv_with_cb(-1, tv, 10, &resp_buf, &resp_len, dummy_recv_cb, NULL);
    assert(rc == NET_RECV_ERROR);
    assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);

    /* 3b. Non-socket pipe fd */
    int pipe_fds[2];
    assert(pipe(pipe_fds) == 0);
    rc = net_recv_with_cb(pipe_fds[0], tv, 10, &resp_buf, &resp_len, dummy_recv_cb, NULL);
    /* setsockopt failed with ENOTSOCK */
    assert(net_get_last_io_status() == NET_IO_STATUS_SYSCALL_ERR);
    assert(rc == NET_RECV_ERROR);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    printf("[+] 3: net_recv_with_cb setsockopt failure properly sets NET_IO_STATUS_SYSCALL_ERR\n");
  }

  /* ========================================================================
   * 4. net_recv_with_cb single monotonic deadline budget spanning poll and I/O
   * ======================================================================== */
  {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Send some data initially */
    char chunk[] = "First chunk";
    assert(write(sv[1], chunk, sizeof(chunk)) == sizeof(chunk));

    char *resp_buf = NULL;
    unsigned int resp_len = 0;
    /* 60 ms budget */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 60000 };

    uint64_t t_start = get_monotonic_ms();
    int rc = net_recv_with_cb(sv[0], tv, 30, &resp_buf, &resp_len, dummy_recv_cb, NULL);
    uint64_t t_elapsed = get_monotonic_ms() - t_start;

    assert(rc == NET_RECV_OK);
    assert(resp_len == sizeof(chunk));
    assert(resp_buf != NULL);
    assert(strcmp(resp_buf, chunk) == 0);

    /* Verify elapsed time stayed within monotonic deadline budget bounds */
    assert(t_elapsed < 1000);
    assert(net_get_last_io_status() == NET_IO_STATUS_OK || net_get_last_io_status() == NET_IO_STATUS_TIMEOUT);

    if (resp_buf) ck_free(resp_buf);
    close(sv[0]);
    close(sv[1]);
    printf("[+] 4: net_recv_with_cb operates within shared monotonic deadline budget\n");
  }

  printf("[+] All B12 monotonic deadline budget tests passed successfully!\n");
  return 0;
}
