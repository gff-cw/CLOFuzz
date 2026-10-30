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
  printf("[*] Testing P10 strict execution of state transition graph...\n");

  char proto_path[] = "/tmp/test_p10_proto_XXXXXX";
  char state_path[] = "/tmp/test_p10_state_XXXXXX";
  int fd_p = mkstemp(proto_path);
  int fd_s = mkstemp(state_path);
  assert(fd_p >= 0 && fd_s >= 0);
  close(fd_p);
  close(fd_s);

  /* Protocol definition with 2 requests and 1 response:
     msg_req_a: Modbus read (FC 03) -> 000100000006010300000001
     msg_req_b: Modbus read coils (FC 01) -> 000200000006010100000001
     msg_resp_a: Modbus read response -> 0001000000050103020001
  */
  const char *proto_spec =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"p10_test\",\n"
    "  \"codec\": \"modbus\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"support\": {\"runtime\": true},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_req_a\",\n"
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
    "      \"id\": \"msg_req_b\",\n"
    "      \"weight\": 1,\n"
    "      \"direction\": \"request\",\n"
    "      \"example\": \"000200000006010100000001\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"locator\": \"abs:0\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 65535, \"endian\": \"big\", \"role\": \"head\", \"mutability\": \"fuzzable\", \"values\": [2], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"proto\", \"locator\": \"abs:2\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 0, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [0], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"len\", \"locator\": \"abs:4\", \"width\": 2, \"type\": \"uint16\", \"min\": 6, \"max\": 6, \"endian\": \"big\", \"role\": \"derived\", \"mutability\": \"derived\", \"values\": [6], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"unit\", \"locator\": \"abs:6\", \"width\": 1, \"type\": \"uint8\", \"min\": 1, \"max\": 1, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [1], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"func\", \"locator\": \"abs:7\", \"width\": 1, \"type\": \"uint8\", \"min\": 1, \"max\": 1, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [1], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"addr\", \"locator\": \"abs:8\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 10, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [0], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"qty\", \"locator\": \"abs:10\", \"width\": 2, \"type\": \"uint16\", \"min\": 1, \"max\": 10, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]}\n"
    "      ],\n"
    "      \"dependencies\": [\n"
    "        {\"target\": \"len\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"}\n"
    "      ]\n"
    "    },\n"
    "    {\n"
    "      \"id\": \"msg_resp_a\",\n"
    "      \"weight\": 1,\n"
    "      \"direction\": \"response\",\n"
    "      \"example\": \"0001000000050103020001\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"locator\": \"abs:0\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 65535, \"endian\": \"big\", \"role\": \"head\", \"mutability\": \"runtime_bound\", \"values\": [1], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"proto\", \"locator\": \"abs:2\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 0, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [0], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"len\", \"locator\": \"abs:4\", \"width\": 2, \"type\": \"uint16\", \"min\": 5, \"max\": 5, \"endian\": \"big\", \"role\": \"derived\", \"mutability\": \"derived\", \"values\": [5], \"strategies\": [\"boundary\"]},\n"
    "        {\"id\": \"unit\", \"locator\": \"abs:6\", \"width\": 1, \"type\": \"uint8\", \"min\": 1, \"max\": 1, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [1], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"func\", \"locator\": \"abs:7\", \"width\": 1, \"type\": \"uint8\", \"min\": 3, \"max\": 3, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [3], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"bc\", \"locator\": \"abs:8\", \"width\": 1, \"type\": \"uint8\", \"min\": 2, \"max\": 2, \"endian\": \"big\", \"role\": \"fixed\", \"mutability\": \"fixed\", \"values\": [2], \"strategies\": [\"enum\"]},\n"
    "        {\"id\": \"val\", \"locator\": \"abs:9\", \"width\": 2, \"type\": \"uint16\", \"min\": 0, \"max\": 65535, \"endian\": \"big\", \"role\": \"content\", \"mutability\": \"fuzzable\", \"values\": [1], \"strategies\": [\"boundary\"]}\n"
    "      ],\n"
    "      \"dependencies\": [\n"
    "        {\"target\": \"len\", \"op\": \"length_of\", \"unit\": 1, \"add\": 0, \"multiply\": 1, \"source\": \"$message\"},\n"
    "        {\"target\": \"tx\", \"op\": \"correlate_request_response\", \"message\": \"msg_req_a\", \"source\": \"tx\"}\n"
    "      ]\n"
    "    }\n"
    "  ]\n"
    "}\n";

  /* State graph:
     ready --(msg_req_a)--> awaiting_resp_a
     awaiting_resp_a --(msg_resp_a)--> ready
     ready --(msg_req_b)--> ready
  */
  const char *state_spec =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"p10_test\",\n"
    "  \"states\": [\n"
    "    {\"id\": \"ready\"},\n"
    "    {\"id\": \"awaiting_resp_a\"}\n"
    "  ],\n"
    "  \"initial\": \"ready\",\n"
    "  \"transitions\": [\n"
    "    {\"from\": \"ready\", \"to\": \"awaiting_resp_a\", \"message\": \"msg_req_a\", \"response\": \"\"},\n"
    "    {\"from\": \"awaiting_resp_a\", \"to\": \"ready\", \"message\": \"msg_resp_a\", \"response\": \"\"},\n"
    "    {\"from\": \"ready\", \"to\": \"ready\", \"message\": \"msg_req_b\", \"response\": \"\"}\n"
    "  ],\n"
    "  \"limits\": {\"max_messages\": 10, \"max_repeat\": 5, \"max_bytes\": 1024}\n"
    "}\n";

  assert(write_file_content(proto_path, proto_spec) == 0);
  assert(write_file_content(state_path, state_spec) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e != NULL);

  uint8_t wire_req_a[] = {0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01}; // 12 bytes
  uint8_t wire_req_b[] = {0x00,0x02,0x00,0x00,0x00,0x06,0x01,0x01,0x00,0x00,0x00,0x01}; // 12 bytes
  uint8_t wire_resp_a[] = {0x00,0x01,0x00,0x00,0x00,0x05,0x01,0x03,0x02,0x00,0x01}; // 11 bytes

  proto_session_begin(e);

  /* Step 1: In 'ready' state:
     - msg_req_a is valid: advances to 'awaiting_resp_a'.
  */
  err[0] = '\0';
  assert(proto_before_send(e, wire_req_a, sizeof(wire_req_a), err, sizeof(err)) == 0);
  printf("[+] Successfully executed legal send transition: ready -> awaiting_resp_a\n");

  /* Step 2: Now in 'awaiting_resp_a' state:
     - Sending msg_req_b is NOT valid in this state (no edge)!
     - Must return error, and state MUST remain in 'awaiting_resp_a'!
  */
  err[0] = '\0';
  int res = proto_before_send(e, wire_req_b, sizeof(wire_req_b), err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "request outside current semantic state") != NULL);
  printf("[+] Correctly rejected illegal send transition: %s\n", err);

  /* Step 3: Test unexpected response:
     - In 'awaiting_resp_a', receiving msg_resp_a with mismatching tx ID (e.g. 0x0099)
     - Must not correlate, must not transition!
  */
  uint8_t mismatch_resp[11];
  memcpy(mismatch_resp, wire_resp_a, sizeof(wire_resp_a));
  mismatch_resp[1] = 0x99;
  proto_after_response(e, mismatch_resp, sizeof(mismatch_resp));

  /* Still in 'awaiting_resp_a', so sending msg_req_b should still be rejected! */
  err[0] = '\0';
  res = proto_before_send(e, wire_req_b, sizeof(wire_req_b), err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "request outside current semantic state") != NULL);
  printf("[+] Uncorrelated response did not advance state or clear pending\n");

  /* Step 4: Now receive valid correlated response:
     - Must advance to 'ready'.
  */
  proto_after_response(e, wire_resp_a, sizeof(wire_resp_a));

  /* Now we are back in 'ready', so sending msg_req_b must now SUCCEED! */
  err[0] = '\0';
  assert(proto_before_send(e, wire_req_b, sizeof(wire_req_b), err, sizeof(err)) == 0);
  printf("[+] Correlated response advanced state to 'ready', allowing subsequent send\n");

  proto_free(e);
  unlink(proto_path);
  unlink(state_path);

  printf("[+] All P10 state graph strict execution tests passed successfully!\n");
  return 0;
}
