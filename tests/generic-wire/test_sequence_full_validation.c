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

static void pack_record(uint8_t *buf, size_t *offset, const uint8_t *payload, size_t len) {
  for (unsigned j = 0; j < 4; j++)
    buf[*offset + j] = (uint8_t)((len >> (8 * j)) & 0xff);
  *offset += 4;
  memcpy(buf + *offset, payload, len);
  *offset += len;
}

int main(void) {
  printf("[*] Testing P09 unified full sequence (M1 + M2 + M3) validation...\n");

  char proto_path[] = "/tmp/test_p09_proto_XXXXXX";
  char state_path[] = "/tmp/test_p09_state_XXXXXX";
  int fd_p = mkstemp(proto_path);
  int fd_s = mkstemp(state_path);
  assert(fd_p >= 0 && fd_s >= 0);
  close(fd_p);
  close(fd_s);

  /* Protocol definition with 2 messages:
     msg_a: Modbus read (FC 03) -> 000100000006010300000001
     msg_b: Modbus read coils (FC 01) -> 000200000006010100000001
  */
  const char *proto_spec =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"p09_test\",\n"
    "  \"codec\": \"modbus\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"support\": {\"runtime\": true},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_a\",\n"
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
    "      \"id\": \"msg_b\",\n"
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
    "    }\n"
    "  ]\n"
    "}\n";

  /* State graph:
     ready --(msg_a)--> state_a
     state_a --(msg_b)--> ready
     state_a --(msg_a)--> ready
     limits: max_messages: 4, max_repeat: 2, max_bytes: 64
  */
  const char *state_spec =
    "{\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"p09_test\",\n"
    "  \"states\": [\n"
    "    {\"id\": \"ready\"},\n"
    "    {\"id\": \"state_a\"}\n"
    "  ],\n"
    "  \"initial\": \"ready\",\n"
    "  \"transitions\": [\n"
    "    {\"from\": \"ready\", \"to\": \"state_a\", \"message\": \"msg_a\", \"response\": \"\"},\n"
    "    {\"from\": \"state_a\", \"to\": \"ready\", \"message\": \"msg_b\", \"response\": \"\"},\n"
    "    {\"from\": \"state_a\", \"to\": \"ready\", \"message\": \"msg_a\", \"response\": \"\"}\n"
    "  ],\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 2, \"max_bytes\": 64}\n"
    "}\n";

  assert(write_file_content(proto_path, proto_spec) == 0);
  assert(write_file_content(state_path, state_spec) == 0);

  char err[512] = {0};
  proto_engine *e = proto_load(proto_path, state_path, err, sizeof(err));
  assert(e != NULL);

  const uint8_t raw_msg_a[] = {0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01}; // 12 bytes
  const uint8_t raw_msg_b[] = {0x00,0x02,0x00,0x00,0x00,0x06,0x01,0x01,0x00,0x00,0x00,0x01}; // 12 bytes

  uint8_t m1_buf[256], m2_buf[256], m3_buf[256];
  size_t m1_len = 0, m2_len = 0, m3_len = 0;

  /* 1. Test Valid full sequence:
     M1: msg_a (ready -> state_a)
     M2: msg_b (state_a -> ready)
     M3: msg_a (ready -> state_a)
     Total messages: 3 (<= 4).
     Total bytes: 3 * (4 + 12) = 48 (<= 64).
     Repeats: msg_a: 2 (<= 2), msg_b: 1 (<= 2).
     Transitions: valid.
  */
  m1_len = m2_len = m3_len = 0;
  pack_record(m1_buf, &m1_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m2_buf, &m2_len, raw_msg_b, sizeof(raw_msg_b));
  pack_record(m3_buf, &m3_len, raw_msg_a, sizeof(raw_msg_a));

  err[0] = '\0';
  int rc = proto_validate_sequence(e, m1_buf, m1_len, m2_buf, m2_len, m3_buf, m3_len, err, sizeof(err));
  assert(rc == 0);
  printf("[+] Valid full sequence (M1 + M2 + M3) accepted\n");

  /* 2. Test max_repeat exceeded across M1 + M2 + M3:
     M1: msg_a (repeat 1)
     M2: msg_a (repeat 2)
     M3: msg_a (repeat 3) -> max_repeat is 2! Must fail!
  */
  m1_len = m2_len = m3_len = 0;
  pack_record(m1_buf, &m1_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m2_buf, &m2_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m3_buf, &m3_len, raw_msg_a, sizeof(raw_msg_a));

  err[0] = '\0';
  rc = proto_validate_sequence(e, m1_buf, m1_len, m2_buf, m2_len, m3_buf, m3_len, err, sizeof(err));
  assert(rc < 0);
  assert(strstr(err, "max_repeat exceeded across sequence") != NULL);
  printf("[+] Correctly rejected max_repeat exceeded across boundaries: %s\n", err);

  /* 3. Test max_messages exceeded across M1 + M2 + M3:
     max_messages is 4. Let's send 5 messages:
     M1: msg_a (1)
     M2: msg_b, msg_a (2)
     M3: msg_b, msg_a (2) -> total 5! Must fail!
  */
  m1_len = m2_len = m3_len = 0;
  pack_record(m1_buf, &m1_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m2_buf, &m2_len, raw_msg_b, sizeof(raw_msg_b));
  pack_record(m2_buf, &m2_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m3_buf, &m3_len, raw_msg_b, sizeof(raw_msg_b));
  pack_record(m3_buf, &m3_len, raw_msg_a, sizeof(raw_msg_a));

  err[0] = '\0';
  rc = proto_validate_sequence(e, m1_buf, m1_len, m2_buf, m2_len, m3_buf, m3_len, err, sizeof(err));
  assert(rc < 0);
  assert(strstr(err, "max_messages exceeded across sequence") != NULL);
  printf("[+] Correctly rejected max_messages exceeded across sequence: %s\n", err);

  /* 4. Test max_bytes exceeded across M1 + M2 + M3:
     max_bytes is 64. 4 messages is 4 * 16 = 64 bytes.
     Let's test exactly 4 messages of msg_a / msg_b: 64 bytes is accepted.
     M1: msg_a (ready -> state_a)
     M2: msg_b (state_a -> ready)
     M3: msg_a (ready -> state_a), msg_b (state_a -> ready)
     Total messages = 4, Total bytes = 64. Exactly at limit!
  */
  m1_len = m2_len = m3_len = 0;
  pack_record(m1_buf, &m1_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m2_buf, &m2_len, raw_msg_b, sizeof(raw_msg_b));
  pack_record(m3_buf, &m3_len, raw_msg_a, sizeof(raw_msg_a));
  pack_record(m3_buf, &m3_len, raw_msg_b, sizeof(raw_msg_b));

  err[0] = '\0';
  rc = proto_validate_sequence(e, m1_buf, m1_len, m2_buf, m2_len, m3_buf, m3_len, err, sizeof(err));
  assert(rc == 0);
  printf("[+] Exactly at max_messages (4) and max_bytes (64) accepted\n");

  /* 5. Test state transition breakdown between M2 and M3:
     M1: empty
     M2: msg_a (ready -> state_a)
     M3: msg_b is valid from state_a, but msg_b from state_a leads to ready.
     From ready, msg_b is NOT valid (only msg_a is valid from ready).
     So if M3 sends msg_b, msg_b:
     First msg_b: state_a -> ready.
     Second msg_b: ready -> msg_b is INVALID! Must fail!
  */
  m1_len = m2_len = m3_len = 0;
  pack_record(m2_buf, &m2_len, raw_msg_a, sizeof(raw_msg_a)); // ready -> state_a
  pack_record(m3_buf, &m3_len, raw_msg_b, sizeof(raw_msg_b)); // state_a -> ready
  pack_record(m3_buf, &m3_len, raw_msg_b, sizeof(raw_msg_b)); // ready -> invalid!

  err[0] = '\0';
  rc = proto_validate_sequence(e, m1_buf, m1_len, m2_buf, m2_len, m3_buf, m3_len, err, sizeof(err));
  assert(rc < 0);
  assert(strstr(err, "sequence outside state graph") != NULL);
  printf("[+] Correctly rejected discontinuous transition in M3: %s\n", err);

  proto_free(e);
  unlink(proto_path);
  unlink(state_path);

  printf("[+] All P09 full sequence validation tests passed successfully!\n");
  return 0;
}
