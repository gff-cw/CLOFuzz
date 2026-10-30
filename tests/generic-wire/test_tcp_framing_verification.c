#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generic_runtime.h"

static const char valid_modbus_json[] = "protocols/modbus_tcp/generic_wire.json";

/* Helper to write string to temporary file and load generic engine */
static gr_engine *load_from_string(const char *json_str, char *err, size_t cap) {
  char tmp_path[] = "/tmp/stateafl_p12_XXXXXX";
  int fd = mkstemp(tmp_path);
  assert(fd >= 0);
  assert(write(fd, json_str, strlen(json_str)) == (ssize_t)strlen(json_str));
  close(fd);
  gr_engine *e = gr_load(tmp_path, err, cap);
  unlink(tmp_path);
  return e;
}

int main(void) {
  printf("[*] Testing P12 generic candidate unified TCP framing verification...\n");

  char err[512] = {0};

  /* 1. Test framing validation on valid Modbus TCP engine */
  gr_engine *e = gr_load(valid_modbus_json, err, sizeof(err));
  if (!e) {
    fprintf(stderr, "Failed to load modbus_tcp: %s\n", err);
    assert(e != NULL);
  }

  /* 12-byte valid read holding registers request */
  const uint8_t valid_req[] = {
    0x00, 0x01, /* TxID: 1 */
    0x00, 0x00, /* Proto ID: 0 */
    0x00, 0x06, /* Len: 6 -> 6 + 6 = 12 */
    0x01,       /* Unit: 1 */
    0x03,       /* Func: 3 */
    0x00, 0x00, /* Addr: 0 */
    0x00, 0x01  /* Qty: 1 */
  };

  /* Verify valid request passes gr_validate_framing */
  assert(gr_validate_framing(e, valid_req, sizeof(valid_req), "valid_req", err, sizeof(err)) == 0);

  /* Case A: Truncated message where length field is out of bounds (size 5 < 4 + 2) */
  assert(gr_validate_framing(e, valid_req, 5, "truncated", err, sizeof(err)) < 0);
  assert(strstr(err, "outside message") != NULL);

  /* Case B: Length field declared length differs from actual size
     Len byte changed from 0x06 to 0x07 -> framed = 7 + 6 = 13 != 12 */
  uint8_t bad_len_req[sizeof(valid_req)];
  memcpy(bad_len_req, valid_req, sizeof(valid_req));
  bad_len_req[5] = 0x07;
  assert(gr_validate_framing(e, bad_len_req, sizeof(bad_len_req), "bad_len", err, sizeof(err)) < 0);
  assert(strstr(err, "declared length") != NULL);

  /* 2. Verify gr_before_send rejects bad framing */
  assert(gr_before_send(e, bad_len_req, sizeof(bad_len_req), err, sizeof(err)) < 0);
  assert(strstr(err, "invalid TCP framing") != NULL);

  /* 3. Verify gr_validate_sequence rejects candidate sequence with bad framing */
  uint8_t m2_buf[4 + sizeof(valid_req)];
  /* Put 4-byte LE length prefix */
  m2_buf[0] = sizeof(valid_req);
  m2_buf[1] = 0; m2_buf[2] = 0; m2_buf[3] = 0;
  memcpy(m2_buf + 4, bad_len_req, sizeof(bad_len_req));

  assert(gr_validate_sequence(e, NULL, 0, m2_buf, sizeof(m2_buf), NULL, 0, err, sizeof(err)) < 0);
  assert(strstr(err, "invalid TCP framing") != NULL);

  /* Valid m2 sequence passes */
  memcpy(m2_buf + 4, valid_req, sizeof(valid_req));
  assert(gr_validate_sequence(e, NULL, 0, m2_buf, sizeof(m2_buf), NULL, 0, err, sizeof(err)) == 0);

  /* 4. Verify gr_set_prefix (unpack) rejects input record with bad framing */
  memcpy(m2_buf + 4, bad_len_req, sizeof(bad_len_req));
  assert(gr_set_prefix(e, m2_buf, sizeof(m2_buf), err, sizeof(err)) < 0);
  assert(strstr(err, "invalid TCP framing") != NULL);

  gr_free(e);

  /* 5. Test Load-time Grammar and Framing Consistency Checks:
     a) Derived size_of add conflicts with framing add
        framing: offset 4, width 2, add 6.
        grammar: length has derived add -5 (conflicts with -6!) */
  const char conflicting_add_json[] =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"test_tcp\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"online\": true,\n"
    "  \"framing\": {\"kind\": \"length_field\", \"offset\": 4, \"width\": 2, \"byte_order\": \"big\", \"add\": 6},\n"
    "  \"messages\": [{\n"
    "    \"id\": \"msg\", \"direction\": \"request\", \"weight\": 1,\n"
    "    \"example_hex\": \"000100000007010300000001\",\n"
    "    \"grammar\": {\n"
    "      \"kind\": \"struct\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 0, \"max\": 65535},\n"
    "        {\"id\": \"proto\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"fixed\", \"expected\": 0, \"min\": 0, \"max\": 0},\n"
    "        {\"id\": \"len\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"derived\", \"min\": 0, \"max\": 65535,\n"
    "         \"derived\": {\"op\": \"size_of\", \"target\": \"$message\", \"add\": -5}},\n"
    "        {\"id\": \"rest\", \"kind\": \"bytes\", \"length\": \"rest\", \"role\": \"content\", \"min\": 1, \"max\": 10}\n"
    "      ]\n"
    "    }\n"
    "  }],\n"
    "  \"states\": {\"initial\": \"ready\", \"transitions\": [{\"from\": \"ready\", \"message\": \"msg\", \"to\": \"ready\"}]},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 2, \"max_bytes\": 1024}\n"
    "}";

  gr_engine *bad_add = load_from_string(conflicting_add_json, err, sizeof(err));
  assert(bad_add == NULL);
  assert(strstr(err, "conflicts with TCP framing add") != NULL);

  /* b) Framing width conflicts with grammar field width */
  const char conflicting_width_json[] =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"test_tcp\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"online\": true,\n"
    "  \"framing\": {\"kind\": \"length_field\", \"offset\": 4, \"width\": 4, \"byte_order\": \"big\", \"add\": 6},\n"
    "  \"messages\": [{\n"
    "    \"id\": \"msg\", \"direction\": \"request\", \"weight\": 1,\n"
    "    \"example_hex\": \"000100000007010300000001\",\n"
    "    \"grammar\": {\n"
    "      \"kind\": \"struct\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 0, \"max\": 65535},\n"
    "        {\"id\": \"proto\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"fixed\", \"expected\": 0, \"min\": 0, \"max\": 0},\n"
    "        {\"id\": \"len\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"derived\", \"min\": 0, \"max\": 65535,\n"
    "         \"derived\": {\"op\": \"size_of\", \"target\": \"$message\", \"add\": -6}},\n"
    "        {\"id\": \"rest\", \"kind\": \"bytes\", \"length\": \"rest\", \"role\": \"content\", \"min\": 1, \"max\": 10}\n"
    "      ]\n"
    "    }\n"
    "  }],\n"
    "  \"states\": {\"initial\": \"ready\", \"transitions\": [{\"from\": \"ready\", \"message\": \"msg\", \"to\": \"ready\"}]},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 2, \"max_bytes\": 1024}\n"
    "}";

  gr_engine *bad_width = load_from_string(conflicting_width_json, err, sizeof(err));
  assert(bad_width == NULL);
  assert(strstr(err, "conflicts with grammar field width") != NULL);

  /* c) Framing offset conflicts with grammar derived rule offset (or direction differences) */
  const char misaligned_offset_json[] =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"test_tcp\",\n"
    "  \"transport\": \"tcp\",\n"
    "  \"online\": true,\n"
    "  \"framing\": {\"kind\": \"length_field\", \"offset\": 2, \"width\": 2, \"byte_order\": \"big\", \"add\": 6},\n"
    "  \"messages\": [{\n"
    "    \"id\": \"msg\", \"direction\": \"request\", \"weight\": 1,\n"
    "    \"example_hex\": \"000100000007010300000001\",\n"
    "    \"grammar\": {\n"
    "      \"kind\": \"struct\",\n"
    "      \"fields\": [\n"
    "        {\"id\": \"tx\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 0, \"max\": 65535},\n"
    "        {\"id\": \"proto\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"fixed\", \"expected\": 0, \"min\": 0, \"max\": 0},\n"
    "        {\"id\": \"len\", \"kind\": \"uint\", \"width\": 2, \"byte_order\": \"big\", \"role\": \"derived\", \"min\": 0, \"max\": 65535,\n"
    "         \"derived\": {\"op\": \"size_of\", \"target\": \"$message\", \"add\": -6}},\n"
    "        {\"id\": \"rest\", \"kind\": \"bytes\", \"length\": \"rest\", \"role\": \"content\", \"min\": 1, \"max\": 10}\n"
    "      ]\n"
    "    }\n"
    "  }],\n"
    "  \"states\": {\"initial\": \"ready\", \"transitions\": [{\"from\": \"ready\", \"message\": \"msg\", \"to\": \"ready\"}]},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 2, \"max_bytes\": 1024}\n"
    "}";

  gr_engine *bad_misaligned = load_from_string(misaligned_offset_json, err, sizeof(err));
  assert(bad_misaligned == NULL);
  assert(strstr(err, "conflicts with global TCP framing offset") != NULL);

  printf("[+] P12 generic candidate unified TCP framing verification tests passed successfully!\n");
  return 0;
}
