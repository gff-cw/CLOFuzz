#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "generic_runtime.h"
#include "native_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static const char *base_proto =
  "{\n"
  "  \"ir_version\": 1,\n"
  "  \"bundle_digest\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n"
  "  \"protocol_id\": \"contract_test\",\n"
  "  \"codec\": \"modbus\",\n"
  "  \"transport\": \"tcp\",\n"
  "  \"support\": {\"runtime\": true},\n"
  "  \"messages\": [\n"
  "    {\n"
  "      \"id\": \"msg_req\",\n"
  "      \"weight\": 1,\n"
  "      \"direction\": \"request\",\n"
  "      \"example\": \"000100000006010300000001\",\n"
  "      \"fields\": [\n"
  "        {\"id\": \"tx\", \"locator\": \"abs:0\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 65535, \"endian\": \"big\", \"role\": \"head\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]},\n"
  "        {\"id\": \"proto\", \"locator\": \"abs:2\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 0, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [0], \"strategies\": [\"enum\"]},\n"
  "        {\"id\": \"len\", \"locator\": \"abs:4\", \"width\": 2, \"type\": \"uint16\", \"min\": 6, \"max\": 6, \"endian\": \"big\", \"role\": \"derived\", \"mutability\": \"derived\", \"values\": [6], \"strategies\": [\"boundary\"]},\n"
  "        {\"id\": \"unit\", \"locator\": \"abs:6\", \"width\": 1, \"type\": \"uint8\", \"min\": 1, \"max\": 1, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [1], \"strategies\": [\"enum\"]},\n"
  "        {\"id\": \"func\", \"locator\": \"abs:7\", \"width\": 1, \"type\": \"uint8\", \"min\": 3, \"max\": 3, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [3], \"strategies\": [\"enum\"]},\n"
  "        {\"id\": \"addr\", \"locator\": \"abs:8\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 10, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [0], \"strategies\": [\"boundary\"]},\n"
  "        {\"id\": \"qty\", \"locator\": \"abs:10\", \"width\": 2, \"type\": \"uint16\", \"min\": 1, \"max\": 10, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]}\n"
  "      ],\n"
  "      \"dependencies\": [\n"
  "        {\"target\": \"len\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"}\n"
  "      ]\n"
  "    }\n"
  "  ]\n"
  "}\n";

static const char *base_state_matching =
  "{\n"
  "  \"ir_version\": 1,\n"
  "  \"bundle_digest\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n"
  "  \"protocol_id\": \"contract_test\",\n"
  "  \"states\": [\n"
  "    {\"id\": \"ready\"}\n"
  "  ],\n"
  "  \"initial\": \"ready\",\n"
  "  \"transitions\": [\n"
  "    {\"from\": \"ready\", \"to\": \"ready\", \"message\": \"msg_req\", \"response\": \"\"}\n"
  "  ],\n"
  "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 3, \"max_bytes\": 1024}\n"
  "}\n";

static const char *base_state_mismatched =
  "{\n"
  "  \"ir_version\": 1,\n"
  "  \"bundle_digest\": \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\",\n"
  "  \"protocol_id\": \"contract_test\",\n"
  "  \"states\": [\n"
  "    {\"id\": \"ready\"}\n"
  "  ],\n"
  "  \"initial\": \"ready\",\n"
  "  \"transitions\": [\n"
  "    {\"from\": \"ready\", \"to\": \"ready\", \"message\": \"msg_req\", \"response\": \"\"}\n"
  "  ],\n"
  "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 3, \"max_bytes\": 1024}\n"
  "}\n";

static const char *base_state_no_digest =
  "{\n"
  "  \"ir_version\": 1,\n"
  "  \"protocol_id\": \"contract_test\",\n"
  "  \"states\": [\n"
  "    {\"id\": \"ready\"}\n"
  "  ],\n"
  "  \"initial\": \"ready\",\n"
  "  \"transitions\": [\n"
  "    {\"from\": \"ready\", \"to\": \"ready\", \"message\": \"msg_req\", \"response\": \"\"}\n"
  "  ],\n"
  "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 3, \"max_bytes\": 1024}\n"
  "}\n";

int main(void) {
  printf("[*] Testing R02: Dual-file publish consistency, bundle generation verification, and atomic stats...\n");
  char err[512];

  char tmp_dir[] = "/tmp/stateafl-r02-test-XXXXXX";
  CHECK(mkdtemp(tmp_dir) != NULL);

  char proto_path[512], state_path[512], bad_state_path[512], no_digest_state[512];
  snprintf(proto_path, sizeof(proto_path), "%s/protocol_ir.json", tmp_dir);
  snprintf(state_path, sizeof(state_path), "%s/state_ir.json", tmp_dir);
  snprintf(bad_state_path, sizeof(bad_state_path), "%s/bad_state_ir.json", tmp_dir);
  snprintf(no_digest_state, sizeof(no_digest_state), "%s/no_digest_state_ir.json", tmp_dir);

  FILE *f = fopen(proto_path, "w"); CHECK(f != NULL); fputs(base_proto, f); fclose(f);
  f = fopen(state_path, "w"); CHECK(f != NULL); fputs(base_state_matching, f); fclose(f);
  f = fopen(bad_state_path, "w"); CHECK(f != NULL); fputs(base_state_mismatched, f); fclose(f);
  f = fopen(no_digest_state, "w"); CHECK(f != NULL); fputs(base_state_no_digest, f); fclose(f);

  /* 1. Test valid bundle matching */
  proto_engine *pe = proto_load(proto_path, state_path, err, sizeof(err));
  if (!pe) fprintf(stderr, "proto_load error: %s\n", err);
  CHECK(pe != NULL);
  proto_free(pe);

  /* 2. Test mismatched generation rejection */
  pe = proto_load(proto_path, bad_state_path, err, sizeof(err));
  CHECK(pe == NULL);
  CHECK(strstr(err, "bundle generation mismatch") != NULL);

  /* 3. Test one file has bundle_digest, other does not */
  pe = proto_load(proto_path, no_digest_state, err, sizeof(err));
  CHECK(pe == NULL);
  CHECK(strstr(err, "bundle generation mismatch") != NULL);

  /* 4. Test stats publication return codes and atomic behavior */
  pe = proto_load_generic("tests/generic-wire/fictional_protocol.json", err, sizeof(err));
  CHECK(pe != NULL);

  char valid_stats[512], bad_stats[512];
  snprintf(valid_stats, sizeof(valid_stats), "%s/stats.json", tmp_dir);
  snprintf(bad_stats, sizeof(bad_stats), "%s/nonexistent_dir_123/stats.json", tmp_dir);

  CHECK(proto_write_stats(pe, valid_stats) == 0);
  CHECK(access(valid_stats, F_OK) == 0);

  /* Unwritable path must return -1 explicitly */
  CHECK(proto_write_stats(pe, bad_stats) == -1);

  proto_free(pe);

  /* Cleanup */
  unlink(proto_path);
  unlink(state_path);
  unlink(bad_state_path);
  unlink(no_digest_state);
  unlink(valid_stats);
  rmdir(tmp_dir);

  printf("[+] R02 dual-file publish consistency tests passed (%u checks).\n", checks);
  return 0;
}
