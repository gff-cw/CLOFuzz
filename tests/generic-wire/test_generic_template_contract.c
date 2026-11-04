/* Native generic-template loader and session contracts. No target is started.
   This repair only compiles this source; assertions await execution approval. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "generic_runtime.h"
#include "native_json.h"

static uint8_t *read_bytes(const char *path, size_t *length) {
  unsigned char *data = NULL; char error[256];
  assert(nj_read_file(path, &data, length, 1048576, error, sizeof(error)) == 0);
  return data;
}

static void expect_rejected_value(const char *path, const nj_document *doc,
                                   const nj_value *value, const char *replacement) {
  char temporary[] = "/tmp/stateafl-generic-template-XXXXXX";
  int fd = mkstemp(temporary); assert(fd >= 0);
  FILE *file = fdopen(fd, "wb"); assert(file && value);
  assert(fwrite(doc->source, 1, value->start, file) == value->start);
  assert(fputs(replacement, file) >= 0);
  size_t tail = doc->length - value->end;
  assert(fwrite(doc->source + value->end, 1, tail, file) == tail);
  assert(fclose(file) == 0);
  char error[512]; gr_engine *engine = gr_load(temporary, error, sizeof(error));
  (void)path;
  assert(!engine && error[0]);
  assert(unlink(temporary) == 0);
}

static void check_example(const char *name, const char *request, int tcp, int response) {
  char model[512], fixture[512], seed[512], answer_path[512], error[512];
  const char *base = "protocols/templates/generic_wire_examples";
  snprintf(model, sizeof(model), "%s/%s/generic_wire.json", base, name);
  snprintf(fixture, sizeof(fixture), "%s/%s/fixtures/requests/%s.wire", base, name, request);
  snprintf(seed, sizeof(seed), "%s/%s/seeds/%s_twice.replay", base, name, request);
  gr_engine *engine = gr_load(model, error, sizeof(error));
  if (!engine) fprintf(stderr, "%s: %s\n", model, error);
  assert(engine && !strcmp(gr_transport(engine), tcp ? "tcp" : "udp"));
  size_t request_size, seed_size, answer_size;
  uint8_t *wire = read_bytes(fixture, &request_size), *records = read_bytes(seed, &seed_size);
  assert(seed_size == 2 * (request_size + 4));
  assert(records[0] == request_size && !records[1] && !records[2] && !records[3]);
  assert(!memcmp(records + 4, wire, request_size));
  assert(!memcmp(records, records + request_size + 4, request_size + 4));
  assert(gr_validate_sequence(engine, NULL, 0, records, seed_size, NULL, 0, error, sizeof(error)) == 0);
  gr_session_begin(engine);
  assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) == 0);
  assert(gr_commit_send(engine, error, sizeof(error)) == 0);
  if (response) {
    assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) < 0);
    snprintf(answer_path, sizeof(answer_path), "%s/%s/fixtures/responses/answer.wire", base, name);
    uint8_t *answer = read_bytes(answer_path, &answer_size);
    assert(answer_size > 5);
    answer[5] = 2; /* Wrong echoed serial must not complete the pending request. */
    if (tcp) gr_after_stream(engine, answer, answer_size);
    else gr_after_dgram(engine, answer, answer_size);
    assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) < 0);
    answer[5] = wire[5];
    if (tcp) {
      gr_after_stream(engine, answer, 3);
      assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) < 0);
      gr_after_stream(engine, answer + 3, answer_size - 3);
    } else gr_after_dgram(engine, answer, answer_size);
    free(answer);
  }
  assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) == 0);
  gr_cancel_send(engine);
  assert(gr_prepare_send(engine, wire, request_size, error, sizeof(error)) == 0);
  gr_cancel_send(engine);
  nj_document *doc = NULL;
  assert(nj_load_file(model, &doc, error, sizeof(error)) == 0);
  expect_rejected_value(model, doc, nj_get(doc->root, "online"), "false");
  expect_rejected_value(model, doc, nj_get(doc->root, "version"), "2");
  const nj_value *first = nj_get(doc->root, "messages")->items[0];
  char newline_example[256];
  snprintf(newline_example, sizeof(newline_example), "\"%s\\n\"", nj_get(first, "example_hex")->text);
  expect_rejected_value(model, doc, nj_get(first, "example_hex"), newline_example);
  const nj_value *magic_field = nj_get(nj_get(first, "grammar"), "fields")->items[0];
  expect_rejected_value(model, doc, nj_get(magic_field, "id"), "\"magic\\n\"");
  const nj_value *length_field = nj_get(nj_get(first, "grammar"), "fields")->items[1];
  expect_rejected_value(model, doc, nj_get(nj_get(length_field, "derived"), "add"), "-4");
  expect_rejected_value(model, doc, nj_get(first, "grammar"),
      "{\"kind\":\"struct\",\"fields\":[{\"id\":\"x\",\"kind\":\"bytes\",\"role\":\"head\",\"length\":1}]}");
  nj_free(doc);
  free(wire); free(records); gr_free(engine);
}

int main(void) {
  char error[512];
  gr_engine *starter = gr_load("protocols/templates/generic_wire.template.json", error, sizeof(error));
  assert(starter); gr_free(starter);
  check_example("udp_oneway", "pulse", 0, 0);
  check_example("udp_request_response", "query", 0, 1);
  check_example("tcp_request_response", "query", 1, 1);
  puts("PASS: generic template native loading, replay identity and response transactions");
  return 0;
}
