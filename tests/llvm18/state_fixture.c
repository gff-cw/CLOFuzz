#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Plain builds retain the automatic-IO fixture. Explicit provider variants
 * require the real tracer exported by the instrumented test build. */
extern void trace_message_boundary(uint32_t ordinal) __attribute__((weak));

static __attribute__((noinline)) void fill(unsigned char *data, size_t length,
                                         uint32_t seed) {
  for (size_t i = 0; i < length; ++i) {
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    data[i] = seed;
  }
}

int main(int argc, char **argv) {
  unsigned variant = argc > 1 ? strtoul(argv[1], NULL, 10) : 0;
  const char *mode = argc > 2 ? argv[2] : "automatic";
  int explicit_boundaries = !strcmp(mode, "explicit") || !strcmp(mode, "oneway");
  int oneway = !strcmp(mode, "oneway");
  if (strcmp(mode, "automatic") && !explicit_boundaries) return 2;
  if (explicit_boundaries && !trace_message_boundary) return 3;
  unsigned responses_sent = 0;
  unsigned char *state = malloc(4096);
  unsigned char stack_state[512];
  unsigned char io[128];
  assert(state);
  fill(state, 4096, 12345);
  fill(stack_state, sizeof(stack_state), 76543);
  int fd[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
  for (unsigned round = 0; round < 3; ++round) {
    unsigned char request = round;
    /* The peer-side syscalls bypass instrumentation; one target recv consumes
     * exactly one request. Only explicit mode asserts application completion. */
    assert(syscall(SYS_write, fd[1], &request, 1) == 1);
    assert(recv(fd[0], io, sizeof(io), 0) == 1);
    fill(state, 4096, 0x12345678U + round * 1231 + variant * 19387);
    fill(stack_state, sizeof(stack_state), 0x87654321U + round * 89 + variant * 131);
    io[0] = state[round] ^ stack_state[round];
    if (explicit_boundaries) trace_message_boundary(round);
    if (!oneway) {
      assert(send(fd[0], io, 1, 0) == 1);
      responses_sent++;
      assert(syscall(SYS_read, fd[1], &request, 1) == 1);
    }
  }
  close(fd[0]);
  close(fd[1]);
  free(state);
  printf("{\"mode\":\"%s\",\"responses_sent\":%u}\n", mode, responses_sent);
  return 0;
}
