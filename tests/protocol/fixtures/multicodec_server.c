/* Loopback fixture responder for runtime integration tests. This is a test
 * double built from captured examples, not an industrial protocol server. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_codecs.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct { const char *locator; int type; size_t width; int little; } fixture_field;
typedef struct { fixture_field request, response; } fixture_copy;
typedef struct { fixture_field field; uint64_t value; } fixture_assignment;
typedef struct {
  const char *name;
  const uint8_t *request, *response;
  size_t request_size, response_size;
  const fixture_copy *copies; size_t copy_count;
  const fixture_assignment *bindings, *assignments;
  size_t binding_count, assignment_count;
} fixture;
typedef struct {
  const char *name;
  int (*validate)(const uint8_t *, size_t, char *, size_t);
  int (*field)(const uint8_t *, size_t, const char *, int, size_t, size_t *, size_t *, char *, size_t);
  int (*repair)(uint8_t *, size_t, char *, size_t);
  int (*replace)(uint8_t *, size_t *, size_t, const char *, int, const uint8_t *, size_t, char *, size_t);
  int (*frame)(const uint8_t *, size_t, size_t *, char *, size_t);
  int (*same)(const uint8_t *, size_t, const uint8_t *, size_t);
} fixture_codec;
#define CODEC(n) {#n,pc_##n##_validate,pc_##n##_field,pc_##n##_repair,pc_##n##_replace,pc_##n##_frame,pc_##n##_same_kind}
static const fixture_codec codecs[] = {CODEC(modbus), CODEC(iec104), CODEC(mms), CODEC(enip), CODEC(opcua)};
#include "multicodec_fixtures.h"

static uint64_t read_number(const uint8_t *data, size_t size, int little) {
  uint64_t value = 0;
  size_t i;
  for (i = 0; i < size; ++i) value = (value << 8) | data[little ? size - i - 1 : i];
  return value;
}
static void write_number(uint8_t *data, size_t size, int little, uint64_t value) {
  size_t i;
  for (i = 0; i < size; ++i) { data[little ? i : size - i - 1] = (uint8_t)value; value >>= 8; }
}
static int locate(const fixture_codec *codec, const uint8_t *wire, size_t n,
                  fixture_field f, size_t *at, size_t *size) {
  return codec->field(wire, n, f.locator, f.type, f.width, at, size, NULL, 0) == 1;
}
static void trace_record(int fd, const fixture *f, const uint8_t *wire, size_t n,
                         int valid, int bound, const uint8_t *response, size_t response_size) {
  static const char digits[] = "0123456789abcdef";
  char *line = malloc(2 * (n + response_size) + 512);
  size_t i, at;
  int changed = f && (n != f->request_size || memcmp(wire, f->request, n));
  if (!line) return;
  at = (size_t)sprintf(line, "{\"model\":\"%s\",\"valid\":%s,\"bound\":%s,\"changed\":%s,\"request\":\"",
                       f ? f->name : "unknown", valid ? "true" : "false",
                       bound ? "true" : "false", changed ? "true" : "false");
  for (i = 0; i < n; ++i) { line[at++] = digits[wire[i] >> 4]; line[at++] = digits[wire[i] & 15]; }
  memcpy(line + at, "\",\"response\":\"", 14); at += 14;
  for (i = 0; i < response_size; ++i) { line[at++] = digits[response[i] >> 4]; line[at++] = digits[response[i] & 15]; }
  memcpy(line + at, "\"}\n", 3); at += 3;
  (void)write(fd, line, at); free(line);
}

static int prepare_response(const fixture_codec *codec, const fixture *f,
                             const uint8_t *wire, size_t n, uint8_t *out, size_t *out_size) {
  struct patch { size_t at, size; int little; uint64_t value; } patches[64];
  size_t i, patch_count = 0;
  *out_size = f->response_size;
  if (!*out_size) return 0;
  memcpy(out, f->response, *out_size);
  for (i = 0; i < f->copy_count; ++i) {
    fixture_copy copy = f->copies[i]; size_t at, size, target, target_size;
    if (!locate(codec, wire, n, copy.request, &at, &size) || !size || size > 8 ||
        !locate(codec, out, *out_size, copy.response, &target, &target_size) || !target_size || target_size > 8) return -1;
    /* INTEGER invoke IDs can change width while every ancestor is reencoded. */
    if (!strcmp(codec->name, "mms") && !strcmp(copy.response.locator, "ber:mms.invoke")) {
      if (codec->replace(out, out_size, 65535, copy.response.locator, copy.response.type,
                         wire + at, size, NULL, 0)) return -1;
    }
  }
  for (i = 0; i < f->copy_count; ++i) {
    fixture_copy copy = f->copies[i]; size_t at, size;
    struct patch *p = &patches[patch_count++];
    if (patch_count > 64 || !locate(codec, wire, n, copy.request, &at, &size) || !size || size > 8 ||
        !locate(codec, out, *out_size, copy.response, &p->at, &p->size) || !p->size || p->size > 8) return -1;
    p->value = read_number(wire + at, size, copy.request.little); p->little = copy.response.little;
    if (p->size < 8 && p->value >> (8 * p->size)) return -1;
  }
  for (i = 0; i < f->assignment_count; ++i) {
    fixture_assignment assignment = f->assignments[i];
    struct patch *p = &patches[patch_count++];
    if (patch_count > 64 || !locate(codec, out, *out_size, assignment.field, &p->at, &p->size) || !p->size || p->size > 8) return -1;
    p->value = assignment.value; p->little = assignment.field.little;
  }
  for (i = 0; i < patch_count; ++i)
    write_number(out + patches[i].at, patches[i].size, patches[i].little, patches[i].value);
  return codec->repair(out, *out_size, NULL, 0);
}

int main(int argc, char **argv) {
  const fixture_codec *codec = NULL;
  const fixture *list;
  size_t count, used = 0;
  uint8_t *buffer, *response, *state;
  int listener, connection, log_fd, one = 1;
  struct sockaddr_in address;
  struct timeval timeout = {.tv_sec = 0, .tv_usec = 200000};
  unsigned c;
  if (argc != 4) return 2;
  for (c = 0; c < sizeof(codecs) / sizeof(codecs[0]); ++c)
    if (!strcmp(codecs[c].name, argv[1])) { codec = &codecs[c]; break; }
  if (!codec) return 2;
  list = fixture_lists[c]; count = fixture_counts[c];
  log_fd = open(argv[3], O_WRONLY | O_CREAT | O_APPEND, 0600);
  listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0 || log_fd < 0) return 3;
  signal(SIGPIPE, SIG_IGN);
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&address, 0, sizeof(address)); address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons((uint16_t)atoi(argv[2]));
  if (bind(listener, (void *)&address, sizeof(address)) || listen(listener, 1)) return 4;
  connection = accept(listener, NULL, NULL);
  if (connection < 0) return 5;
  setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  buffer = malloc(65535); response = malloc(65535); state = malloc(1024);
  if (!buffer || !response || !state) return 6;
  for (c = 0; c < 1024; ++c) state[c] = (uint8_t)((c * 113) ^ 0x95);
  while (used < 65535) {
    ssize_t received = recv(connection, buffer + used, 65535 - used, 0);
    if (received <= 0) { if (used) trace_record(log_fd, NULL, buffer, used, 0, 0, NULL, 0); break; }
    used += (size_t)received;
    while (used) {
      size_t frame_size = 0, response_size = 0, i;
      const fixture *f = NULL;
      int framed = codec->frame(buffer, used, &frame_size, NULL, 0), bound = 1;
      if (!framed) break;
      if (framed < 0) { trace_record(log_fd, NULL, buffer, used, 0, 0, NULL, 0); goto finished; }
      for (i = 0; i < count; ++i)
        if (codec->same(buffer, frame_size, list[i].request, list[i].request_size)) { f = &list[i]; break; }
      if (!f) { trace_record(log_fd, NULL, buffer, frame_size, 1, 0, NULL, 0); goto finished; }
      for (i = 0; i < f->binding_count; ++i) {
        size_t at, size; fixture_assignment binding = f->bindings[i];
        if (!locate(codec, buffer, frame_size, binding.field, &at, &size) || !size || size > 8 ||
            read_number(buffer + at, size, binding.field.little) != binding.value) bound = 0;
      }
      if (bound && prepare_response(codec, f, buffer, frame_size, response, &response_size)) goto finished;
      if (!bound) response_size = 0;
      state[0] = (uint8_t)(i + 1); state[1] = bound; state[7]++;
      if (response_size) {
        size_t first = response_size / 2;
        if (send(connection, response, first, 0) != (ssize_t)first ||
            send(connection, response + first, response_size - first, 0) != (ssize_t)(response_size - first)) goto finished;
      }
      trace_record(log_fd, f, buffer, frame_size, 1, bound, response, response_size);
      memmove(buffer, buffer + frame_size, used - frame_size); used -= frame_size;
    }
  }
finished:
  free(buffer); free(response); free(state); close(connection); close(listener); close(log_fd);
  return 0;
}
