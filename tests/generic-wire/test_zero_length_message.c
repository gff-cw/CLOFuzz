/* Unit test for R01: zero-length message, zero-length field, and empty sequence contract handling. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "generic_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static uint32_t dummy_rng(uint32_t limit) { (void)limit; return 0; }

static proto_engine *load_json_profile(const char *json_content, char *error, size_t cap) {
  char path[] = "/tmp/stateafl-zero-len-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) { snprintf(error, cap, "tempfile creation failed"); return NULL; }
  FILE *f = fdopen(fd, "wb");
  if (!f) { close(fd); remove(path); snprintf(error, cap, "tempfile open failed"); return NULL; }
  fputs(json_content, f);
  fclose(f);
  proto_engine *e = proto_load_generic(path, error, cap);
  remove(path);
  return e;
}

int main(void) {
  char err[512];
  size_t count = 0;

  /* ------------------------------------------------------------- */
  /* Part 1: Replay parser rejecting zero-length wire records & empty sequences */
  /* ------------------------------------------------------------- */

  /* 1a. Empty buffer (count == 0 bytes) */
  CHECK(proto_records_validate(NULL, 0, &count, err, sizeof(err)) < 0);
  CHECK(strstr(err, "empty or oversized") != NULL);

  uint8_t dummy[16] = {0};
  CHECK(proto_records_validate(dummy, 0, &count, err, sizeof(err)) < 0);
  CHECK(strstr(err, "empty or oversized") != NULL);

  /* 1b. Record with z == 0 (LE32 length is 0) */
  uint8_t zero_rec[4] = {0, 0, 0, 0};
  CHECK(proto_records_validate(zero_rec, sizeof(zero_rec), &count, err, sizeof(err)) < 0);
  CHECK(strstr(err, "invalid replayable record length") != NULL);

  /* 1c. Valid record with z == 2 followed by 2 bytes */
  uint8_t valid_rec[6] = {2, 0, 0, 0, 0x12, 0x34};
  count = 0;
  CHECK(proto_records_validate(valid_rec, sizeof(valid_rec), &count, err, sizeof(err)) == 0);
  CHECK(count == 1);

  /* 1d. Record sequence where second record has z == 0 */
  uint8_t mixed_rec[10] = {2, 0, 0, 0, 0x12, 0x34,  0, 0, 0, 0};
  count = 0;
  CHECK(proto_records_validate(mixed_rec, sizeof(mixed_rec), &count, err, sizeof(err)) < 0);
  CHECK(strstr(err, "invalid replayable record length") != NULL);

  /* ------------------------------------------------------------- */
  /* Part 2: Generic-wire grammar accepting zero-length wire messages */
  /* ------------------------------------------------------------- */

  /* 2a. Message definition where grammar accepts 0 bytes (zero-length wire message) */
  const char *zero_wire_accepting_profile =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"zero_wire_proto\",\n"
    "  \"online\": true,\n"
    "  \"transport\": \"udp\",\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_zero\",\n"
    "      \"direction\": \"request\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"01\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"payload\", \"kind\": \"bytes\", \"role\": \"content\", \"length\": \"rest\"}\n"
    "        ]\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"states\": {\"initial\": \"init\", \"transitions\": [{\"from\": \"init\", \"to\": \"init\", \"message\": \"msg_zero\"}]},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 4, \"max_bytes\": 128}\n"
    "}";
  proto_engine *pe_bad = load_json_profile(zero_wire_accepting_profile, err, sizeof(err));
  CHECK(pe_bad == NULL);
  CHECK(strstr(err, "accepts zero-length wire message") != NULL);

  /* 2b. Message definition with zero-length example_hex */
  const char *empty_example_profile =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"empty_ex_proto\",\n"
    "  \"online\": true,\n"
    "  \"transport\": \"udp\",\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"msg_empty\",\n"
    "      \"direction\": \"request\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"val\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"content\"}\n"
    "        ]\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"states\": {\"initial\": \"init\", \"transitions\": []},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 4, \"max_bytes\": 128}\n"
    "}";
  proto_engine *pe_empty_ex = load_json_profile(empty_example_profile, err, sizeof(err));
  CHECK(pe_empty_ex == NULL);
  CHECK(strstr(err, "invalid example_hex") != NULL);

  /* ------------------------------------------------------------- */
  /* Part 3: Message with zero-length field along with non-zero fields */
  /* (A zero-length field is valid when total wire length > 0)     */
  /* ------------------------------------------------------------- */
  const char *zero_field_valid_profile =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"zero_field_proto\",\n"
    "  \"online\": true,\n"
    "  \"transport\": \"udp\",\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"req\",\n"
    "      \"direction\": \"request\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"42\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"magic\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"head\", \"min\": 1, \"max\": 255},\n"
    "          {\"id\": \"empty_bytes\", \"kind\": \"bytes\", \"role\": \"content\", \"length\": 0}\n"
    "        ]\n"
    "      }\n"
    "    }\n"
    "  ],\n"
    "  \"states\": {\"initial\": \"init\", \"transitions\": [{\"from\": \"init\", \"to\": \"init\", \"message\": \"req\"}]},\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 4, \"max_bytes\": 128}\n"
    "}";
  proto_engine *pe_valid = load_json_profile(zero_field_valid_profile, err, sizeof(err));
  CHECK(pe_valid != NULL);

  /* 3a. Verify that a 1-byte message with 0-byte field can be parsed and validated */
  uint8_t m2_valid[5] = {1, 0, 0, 0, 0x42};
  CHECK(proto_validate_sequence(pe_valid, NULL, 0, m2_valid, sizeof(m2_valid), NULL, 0, err, sizeof(err)) == 0);

  /* 3b. Verify that empty M2 sequence is rejected */
  CHECK(proto_validate_sequence(pe_valid, NULL, 0, NULL, 0, NULL, 0, err, sizeof(err)) < 0);
  CHECK(strstr(err, "M2 candidate record sequence cannot be empty") != NULL);

  /* 3c. Verify that proto_mutate rejects empty sequence */
  const uint8_t *mut_out = NULL;
  size_t mut_len = 0;
  CHECK(proto_mutate(pe_valid, NULL, 0, NULL, 0, 0, 1, dummy_rng, &mut_out, &mut_len, err, sizeof(err)) < 0);
  CHECK(strstr(err, "empty or oversized replay records") != NULL);

  /* 3d. Verify that proto_mutate on valid 1-byte message succeeds without producing zero-length record */
  CHECK(proto_mutate(pe_valid, m2_valid, sizeof(m2_valid), NULL, 0, 0, 1, dummy_rng, &mut_out, &mut_len, err, sizeof(err)) == 0);
  CHECK(mut_out != NULL && mut_len >= 5);
  size_t chk_count = 0;
  CHECK(proto_records_validate(mut_out, mut_len, &chk_count, err, sizeof(err)) == 0);
  CHECK(chk_count >= 1);

  proto_free(pe_valid);

  printf("PASS: test_zero_length_message passed (%u assertions)\n", checks);
  return 0;
}
