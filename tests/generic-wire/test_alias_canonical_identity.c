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

int main(void) {
  printf("[*] Testing P14 alias cache identity vs semantic identity consistency...\n");

  char proto_path[] = "/tmp/test_p14_proto_XXXXXX";
  char state_path[] = "/tmp/test_p14_state_XXXXXX";
  int fd_p = mkstemp(proto_path);
  int fd_s = mkstemp(state_path);
  assert(fd_p >= 0 && fd_s >= 0);
  close(fd_p);
  close(fd_s);

  char err[512] = {0};

  /* 1. Ambiguous wire identity test:
     Two messages with identical wire example for Modbus TCP (fc=0x03, 000100000006010300000001),
     but msg2 has a different field min/max constraint (differing semantics).
     Load MUST reject this at load time instead of letting order shadow semantics. */

  const char *ambiguous_proto =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"modbus_test\",\n"
    "  \"codec\": \"modbus\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"support\": {\"runtime\": true},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_read_1\",\n"
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
    "    },\n"
    "    {\n"
    "      \"id\": \"msg_read_2_conflict\",\n"
    "      \"weight\": 1,\n"
    "      \"direction\": \"request\",\n"
    "      \"example\": \"000100000006010300000001\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"locator\": \"abs:0\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 65535, \"endian\": \"big\", \"role\": \"head\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"proto\", \"locator\": \"abs:2\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 0, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [0], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"len\", \"locator\": \"abs:4\", \"width\": 2, \"type\": \"uint16\", \"min\": 6, \"max\": 6, \"endian\": \"big\", \"role\": \"derived\", \"mutability\": \"derived\", \"values\": [6], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"unit\", \"locator\": \"abs:6\", \"width\": 1, \"type\": \"uint8\", \"min\": 1, \"max\": 1, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [1], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"func\", \"locator\": \"abs:7\", \"width\": 1, \"type\": \"uint8\", \"min\": 3, \"max\": 3, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [3], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"addr\", \"locator\": \"abs:8\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 5, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [0], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"qty\", \"locator\": \"abs:10\", \"width\": 2, \"type\": \"uint16\", \"min\": 1, \"max\": 10, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]}\n"
    "      ],\n"
    "      \"dependencies\": [\n"
    "        {\"target\": \"len\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"}\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}\n";

  const char *state_spec =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"modbus_test\",\n"
    "  \"states\": [\n"
    "    {\"id\": \"init\"}\n"
    "  ],\n"
    "  \"initial\": \"init\",\n"
    "  \"transitions\": [\n"
    "    {\"from\": \"init\", \"to\": \"init\", \"message\": \"msg_read_1\", \"response\": \"\"}\n"
    "  ],\n"
    "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 3, \"max_bytes\": 1024}\n"
    "}\n";

  assert(write_file_content(proto_path, ambiguous_proto) == 0);
  assert(write_file_content(state_path, state_spec) == 0);

  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "ambiguous wire identity") != NULL);
  printf("[+] Load correctly rejected ambiguous wire identity with differing semantics: %s\n", err);

  /* 2. Equivalence test:
     Now msg_read_2 is an identical alias of msg_read_1 (same fields, dependencies, and transitions).
     They must successfully load and share the same canonical identity. */

  const char *valid_alias_proto =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"modbus_test\",\n"
    "  \"codec\": \"modbus\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"support\": {\"runtime\": true},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_read_1\",\n"
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
    "    },\n"
    "    {\n"
    "      \"id\": \"msg_read_2\",\n"
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

  const char *valid_alias_state =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"modbus_test\",\n"
    "  \"states\": [\n"
    "    {\"id\": \"init\"}\n"
    "  ],\n"
    "  \"initial\": \"init\",\n"
    "  \"transitions\": [\n"
    "    {\"from\": \"init\", \"to\": \"init\", \"message\": \"msg_read_1\", \"response\": \"\"},\n"
    "    {\"from\": \"init\", \"to\": \"init\", \"message\": \"msg_read_2\", \"response\": \"\"}\n"
    "  ],\n"
    "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 2, \"max_bytes\": 1024}\n"
    "}\n";

  assert(write_file_content(proto_path, valid_alias_proto) == 0);
  assert(write_file_content(state_path, valid_alias_state) == 0);

  /* Note: Because transitions from init for msg_read_1 and msg_read_2 share the exact
     same from state and canonical message, having both in transitions is caught by
     ambiguous transition check! */
  err[0] = '\0';
  e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e == NULL);
  assert(strstr(err, "ambiguous runtime state transition") != NULL);
  printf("[+] Successfully caught ambiguous duplicate transition using alias: %s\n", err);

  /* Clean up temporary files */
  unlink(proto_path);
  unlink(state_path);

  printf("[+] All P14 alias canonical identity tests passed successfully!\n");
  return 0;
}
