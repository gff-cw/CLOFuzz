#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "generic_wire.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static uint32_t mock_draw_val = 0;
static uint32_t mock_draw(uint32_t limit) {
  return limit ? mock_draw_val % limit : 0;
}

static size_t append_rec(uint8_t *out, size_t at, const uint8_t *wire, size_t n) {
  for (unsigned i = 0; i < 4; i++) out[at + i] = (uint8_t)(n >> (8 * i));
  memcpy(out + at + 4, wire, n);
  return at + 4 + n;
}

static proto_engine *create_test_engine(const char *schema_json, char *err, size_t cap) {
  char tmppath[] = "/tmp/stateafl-operability-XXXXXX";
  int fd = mkstemp(tmppath);
  if (fd < 0) return NULL;
  FILE *f = fdopen(fd, "wb");
  if (!f) { close(fd); unlink(tmppath); return NULL; }
  fputs(schema_json, f);
  fclose(f);
  proto_engine *pe = proto_load_generic(tmppath, err, cap);
  unlink(tmppath);
  return pe;
}

int main(void) {
  printf("[*] Testing P21: Operability, template selection, and no-op accounting...\n");
  char err[256];

  /* 1. Protocol with ONLY HEAD fields (no CONTENT fields) */
  const char *only_head_schema =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"only_head\",\n"
    "  \"online\": true,\n"
    "  \"transport\": \"udp\",\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg\",\n"
    "      \"direction\": \"request\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"0102\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"h1\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 1, \"max\": 10},\n"
    "          {\"id\": \"h2\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 1, \"max\": 10}\n"
    "        ]\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"states\": {\"initial\": \"ready\", \"transitions\": [{\"from\": \"ready\", \"message\": \"msg\", \"to\": \"ready\"}]},\n"
    "  \"limits\": {\"max_messages\": 8, \"max_repeat\": 4, \"max_bytes\": 256}\n"
    "}\n";

  proto_engine *pe_head = create_test_engine(only_head_schema, err, sizeof(err));
  CHECK(pe_head != NULL);

  uint8_t rec[64];
  uint8_t wire_head[] = {0x01, 0x02};
  size_t rec_len = append_rec(rec, 0, wire_head, sizeof(wire_head));

  const uint8_t *out = NULL;
  size_t out_len = 0;
  uint8_t candidate[] = {0x05, 0x06};

  /* Mutating CONTENT layer on only_head_schema must fail cleanly with 'layer unavailable' */
  int rc = proto_mutate(pe_head, rec, rec_len, candidate, sizeof(candidate), PROTO_VALID, PROTO_CONTENT, mock_draw, &out, &out_len, err, sizeof(err));
  CHECK(rc < 0);
  CHECK(strstr(err, "layer unavailable") != NULL);

  /* Verify stats report unavailable CONTENT */
  char stats_path[] = "/tmp/stateafl-operability-stats-XXXXXX";
  int sfd = mkstemp(stats_path);
  close(sfd);

  proto_write_stats(pe_head, stats_path);
  FILE *sf = fopen(stats_path, "r");
  CHECK(sf != NULL);
  char sbuf[1024] = {0};
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);
  unlink(stats_path);

  /* unavailable is [HEAD, CONTENT, SEQUENCE] */
  CHECK(strstr(sbuf, "\"unavailable\":[0,1,0]") != NULL);

  /* Mutating HEAD layer on only_head_schema must succeed */
  mock_draw_val = 2; /* choose value or boundary */
  rc = proto_mutate(pe_head, rec, rec_len, candidate, sizeof(candidate), PROTO_VALID, PROTO_HEAD, mock_draw, &out, &out_len, err, sizeof(err));
  CHECK(rc == 0);
  CHECK(out != NULL && out_len > 0);

  proto_free(pe_head);

  /* 2. Test unchanged vs changed accounting on fictional_protocol.json */
  proto_engine *pe_fict = proto_load_generic("tests/generic-wire/fictional_protocol.json", err, sizeof(err));
  CHECK(pe_fict != NULL);

  uint8_t seed_wire[] = {0xa7, 0x00, 0x05, 0x01, 0x00, 0x01, 0x55, 0x66};
  rec_len = append_rec(rec, 0, seed_wire, sizeof(seed_wire));
  uint8_t cand_fict[sizeof(seed_wire)];
  memcpy(cand_fict, seed_wire, sizeof(seed_wire));
  cand_fict[6] = 0x22;
  cand_fict[7] = 0x33;

  /* Attempt mutation on CONTENT.
   * Boundary mutation or draw can change payload */
  mock_draw_val = 0;
  rc = proto_mutate(pe_fict, rec, rec_len, cand_fict, sizeof(cand_fict), PROTO_VALID, PROTO_CONTENT, mock_draw, &out, &out_len, err, sizeof(err));
  if (rc != 0) fprintf(stderr, "proto_mutate CONTENT error: %s\n", err);
  CHECK(rc == 0);

  sfd = mkstemp(stats_path);
  close(sfd);
  proto_write_stats(pe_fict, stats_path);
  sf = fopen(stats_path, "r");
  CHECK(sf != NULL);
  memset(sbuf, 0, sizeof(sbuf));
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);
  unlink(stats_path);

  CHECK(strstr(sbuf, "\"changed\":[") != NULL);
  CHECK(strstr(sbuf, "\"unchanged\":[") != NULL);
  CHECK(strstr(sbuf, "\"unavailable\":[") != NULL);

  proto_free(pe_fict);

  printf("PASS: test_layer_operability_accounting passed (%u assertions)\n", checks);
  return 0;
}
