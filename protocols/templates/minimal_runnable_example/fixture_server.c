/* Controlled FC03/one-register fixture. It is independent of the model parser.
 * Build with StateAFL's wrapper for cooperative memory-boundary observations.
 * A normal compiler can also build it; that alone provides no tracer evidence. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern void trace_message_boundary(uint32_t ordinal) __attribute__((weak));

static int read_exact(int fd, uint8_t *bytes, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = recv(fd, bytes + offset, size - offset, 0);
    if (count < 0 && errno == EINTR) continue;
    if (!count) return offset ? -1 : 0;
    if (count < 0) return -1;
    offset += (size_t)count;
  }
  return 1;
}

static int write_exact(int fd, const uint8_t *bytes, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    offset += (size_t)count;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '9') return 2;
  char *end = NULL;
  errno = 0;
  unsigned long port = strtoul(argv[1], &end, 10);
  if (errno || !end || *end || port < 1024 || port > 65535) return 2;
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0) return 3;
  int reuse = 1;
  struct sockaddr_in address = {.sin_family = AF_INET,
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((uint16_t)port)};
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
      bind(listener, (const struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) {
    close(listener); return 3;
  }
  /* The heap remains live across complete application messages. Actual state
   * IDs and snapshot retention still depend on the instrumented execution. */
  volatile uint8_t *state = malloc(256);
  if (!state) { close(listener); return 3; }
  for (unsigned i = 0; i < 256; i++) state[i] = (uint8_t)(i * 17u + 1u);
  int client;
  do { client = accept(listener, NULL, NULL); } while (client < 0 && errno == EINTR);
  close(listener);
  if (client < 0) { free((void *)state); return 3; }
  for (uint32_t ordinal = 0; ordinal < 32; ordinal++) {
    uint8_t request[12];
    if (read_exact(client, request, 7) != 1) break;
    /* Only the declared bounded profile is implemented. A malformed request
     * closes the connection; no generic parser or fixture bytes are consulted. */
    if (request[2] || request[3] || request[4] || request[5] != 6 ||
        read_exact(client, request + 7, 5) != 1 || request[7] != 3 ||
        request[10] || request[11] != 1) break;
    uint16_t register_address = (uint16_t)((uint16_t)request[8] << 8 | request[9]);
    uint16_t register_value = (uint16_t)(register_address + 1u);
    uint8_t response[11] = {request[0], request[1], 0, 0, 0, 5,
                            request[6], 3, 2,
                            (uint8_t)(register_value >> 8), (uint8_t)register_value};
    for (unsigned i = 0; i < 256; i++)
      state[i] = (uint8_t)(register_address + i * 17u + ordinal + 1u);
    if (write_exact(client, response, sizeof(response))) break;
    if (trace_message_boundary) trace_message_boundary(ordinal);
  }
  close(client); free((void *)state);
  return 0;
}
