#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol_runtime.h"

static int write_file_content(const char *path, const char *content) {
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  size_t len = strlen(content);
  size_t written = fwrite(content, 1, len, f);
  fclose(f);
  return written == len ? 0 : -1;
}

static const char *base_proto =
  "{\n"
  "  \"ir_version\": 1,\n"
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

static const char *base_state =
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

static void test_valid_loads(const char *proto_path, const char *state_path) {
  assert(write_file_content(proto_path, base_proto) == 0);
  assert(write_file_content(state_path, base_state) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e != NULL);
  proto_free(e);
  printf("[+] Valid IR loaded successfully\n");
}

static void test_fixed_role_mutability_mismatch(const char *proto_path, const char *state_path) {
  /* role: "fixed" with mutability: "fuzzable" */
  char buf[4096];
  snprintf(buf, sizeof(buf),
    "{\n"
    "  \"ir_version\": 1,\n"
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
    "        {\"id\": \"proto\", \"locator\": \"abs:2\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 0, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fuzzable\", \"values\": [0], \"strategies\": [\"enum\"]},\n"
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
    "}\n");

  assert(write_file_content(proto_path, buf) == 0);
  assert(write_file_content(state_path, base_state) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "fixed role and mutability mismatch") != NULL);
  printf("[+] Correctly rejected fixed role/mutability mismatch: %s\n", err);
}

static void test_derived_role_mutability_mismatch(const char *proto_path, const char *state_path) {
  /* role: "derived" with mutability: "fuzzable" */
  char buf[4096];
  snprintf(buf, sizeof(buf),
    "{\n"
    "  \"ir_version\": 1,\n"
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
    "        {\"id\": \"len\", \"locator\": \"abs:4\", \"width\": 2, \"type\": \"uint16\", \"min\": 6, \"max\": 6, \"endian\": \"big\", \"role\": \"derived\", \"mutability\": \"fuzzable\", \"values\": [6], \"strategies\": [\"boundary\"]},\n"
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
    "}\n");

  assert(write_file_content(proto_path, buf) == 0);
  assert(write_file_content(state_path, base_state) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "derived role and mutability mismatch") != NULL);
  printf("[+] Correctly rejected derived role/mutability mismatch: %s\n", err);
}

static void test_dep_writing_fixed_field(const char *proto_path, const char *state_path) {
  /* dependency writing a fixed field (proto) */
  char buf[4096];
  snprintf(buf, sizeof(buf),
    "{\n"
    "  \"ir_version\": 1,\n"
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
    "        {\"target\": \"len\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"},\n"
    "        {\"target\": \"proto\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"}\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}\n");

  assert(write_file_content(proto_path, buf) == 0);
  assert(write_file_content(state_path, base_state) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "dependency cannot write fixed field") != NULL);
  printf("[+] Correctly rejected dependency writing fixed field: %s\n", err);
}

static void test_derived_missing_writer(const char *proto_path, const char *state_path) {
  /* derived field without any dependency writer */
  char buf[4096];
  snprintf(buf, sizeof(buf),
    "{\n"
    "  \"ir_version\": 1,\n"
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
    "      \"dependencies\": []\n"
    "    }\n"
    "  ]\n"
    "}\n");

  assert(write_file_content(proto_path, buf) == 0);
  assert(write_file_content(state_path, base_state) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "derived field requires a dependency writer") != NULL);
  printf("[+] Correctly rejected derived field with missing writer: %s\n", err);
}

int main(void) {
  printf("[*] Testing P15 IR loader contract verification...\n");

  char proto_path[] = "/tmp/test_p15_proto_XXXXXX";
  char state_path[] = "/tmp/test_p15_state_XXXXXX";
  int fd_p = mkstemp(proto_path);
  int fd_s = mkstemp(state_path);
  assert(fd_p >= 0 && fd_s >= 0);
  close(fd_p);
  close(fd_s);

  test_valid_loads(proto_path, state_path);
  test_fixed_role_mutability_mismatch(proto_path, state_path);
  test_derived_role_mutability_mismatch(proto_path, state_path);
  test_dep_writing_fixed_field(proto_path, state_path);
  test_derived_missing_writer(proto_path, state_path);

  unlink(proto_path);
  unlink(state_path);

  printf("[+] All P15 IR loader contract tests passed successfully!\n");
  return 0;
}
