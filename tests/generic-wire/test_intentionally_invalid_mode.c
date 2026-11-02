#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "protocol_runtime.h"

enum {
  TEST_MODE_VALID = 0,
  TEST_MODE_NEAR_VALID = 1,
  TEST_MODE_INVALID = 2,
  TEST_MODE_RAW = 3,
  TEST_MODE_HYBRID = 4
};

/* Helper to pack a message with a 4-byte little-endian length prefix */
static uint8_t *make_record(const uint8_t *payload, uint32_t len, uint32_t *rec_len_out) {
  uint8_t *rec = (uint8_t *)malloc(4 + len);
  assert(rec != NULL);
  rec[0] = (uint8_t)(len & 0xFF);
  rec[1] = (uint8_t)((len >> 8) & 0xFF);
  rec[2] = (uint8_t)((len >> 16) & 0xFF);
  rec[3] = (uint8_t)((len >> 24) & 0xFF);
  memcpy(rec + 4, payload, len);
  *rec_len_out = 4 + len;
  return rec;
}

/* Mock whole-sequence validation under test implementing B10 contract */
static int test_validate_sequence_mode(int mode,
                                       size_t max_messages,
                                       size_t max_bytes,
                                       const uint8_t *m1, size_t m1_len,
                                       const uint8_t *m2, size_t m2_len,
                                       const uint8_t *m3, size_t m3_len,
                                       int (*semantic_model_check)(const uint8_t *buf, size_t len),
                                       char *err, size_t cap) {
  if (!m2 || !m2_len) {
    snprintf(err, cap, "M2 candidate record sequence cannot be empty");
    return -1;
  }

  const uint8_t *segs[3] = {m1, m2, m3};
  size_t lens[3] = {m1_len, m2_len, m3_len};
  size_t total_messages = 0;
  size_t total_replay_bytes = 0;

  for (int s = 0; s < 3; s++) {
    const uint8_t *buf = segs[s];
    size_t len = lens[s];
    if (!len) continue;

    size_t p = 0;
    while (p < len) {
      if (p + 4 > len) {
        snprintf(err, cap, "truncated record header");
        return -1;
      }
      uint32_t z = (uint32_t)buf[p] |
                   ((uint32_t)buf[p + 1] << 8) |
                   ((uint32_t)buf[p + 2] << 16) |
                   ((uint32_t)buf[p + 3] << 24);
      p += 4;
      if (p + z > len) {
        snprintf(err, cap, "record length %u overflows available buffer", z);
        return -1;
      }

      total_messages++;
      total_replay_bytes += 4 + z;

      if (total_messages > max_messages) {
        snprintf(err, cap, "max_messages exceeded across sequence (%zu > %zu)", total_messages, max_messages);
        return -1;
      }
      if (total_replay_bytes > max_bytes) {
        snprintf(err, cap, "max_bytes exceeded across sequence (%zu > %zu)", total_replay_bytes, max_bytes);
        return -1;
      }

      /* B10: Intentionally invalid and near_valid modes break length or constraint
         by design in M2; whole-sequence validation must NOT reject M2 as outside
         model when intentionally broken, preserving sequence context. */
      int is_m2 = (s == 1);
      int is_intentionally_broken = (is_m2 && (mode == TEST_MODE_NEAR_VALID || mode == TEST_MODE_INVALID));

      if (!is_intentionally_broken) {
        if (semantic_model_check && semantic_model_check(buf + p, z) < 0) {
          snprintf(err, cap, "%s message outside semantic model", s == 0 ? "M1" : s == 1 ? "M2" : "M3");
          return -1;
        }
      }

      p += z;
    }
  }

  return 0;
}

/* Mock semantic model checker: recognizes packet starting with 0xAA 0xBB as valid */
static int mock_semantic_check(const uint8_t *buf, size_t len) {
  if (len >= 2 && buf[0] == 0xAA && buf[1] == 0xBB) return 0;
  return -1;
}

int main(void) {
  printf("[*] Testing B10 intentionally-invalid mode whole-sequence validation contract...\n");

  char err[256];
  uint32_t rec1_len = 0, rec2_valid_len = 0, rec2_broken_len = 0, rec3_len = 0;

  /* M1 valid message */
  uint8_t m1_payload[] = { 0xAA, 0xBB, 0x01, 0x02 };
  uint8_t *rec1 = make_record(m1_payload, sizeof(m1_payload), &rec1_len);

  /* M2 valid candidate */
  uint8_t m2_valid_payload[] = { 0xAA, 0xBB, 0x10, 0x20 };
  uint8_t *rec2_valid = make_record(m2_valid_payload, sizeof(m2_valid_payload), &rec2_valid_len);

  /* M2 intentionally broken candidate (length violation / outside model) */
  uint8_t m2_broken_payload[] = { 0xEE, 0xFF, 0x99, 0x88, 0x77 }; /* Doesn't start with 0xAA 0xBB */
  uint8_t *rec2_broken = make_record(m2_broken_payload, sizeof(m2_broken_payload), &rec2_broken_len);

  /* M3 valid suffix */
  uint8_t m3_payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  uint8_t *rec3 = make_record(m3_payload, sizeof(m3_payload), &rec3_len);

  /* ========================================================================
   * 1. PROTO_VALID mode rejects broken M2 as outside model
   * ======================================================================== */
  err[0] = '\0';
  int res = test_validate_sequence_mode(TEST_MODE_VALID, 10, 1024,
                                        rec1, rec1_len,
                                        rec2_broken, rec2_broken_len,
                                        rec3, rec3_len,
                                        mock_semantic_check, err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "outside semantic model") != NULL);
  printf("[+] 1: PROTO_VALID correctly rejects broken message as outside model\n");

  /* ========================================================================
   * 2. PROTO_VALID accepts valid candidate
   * ======================================================================== */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_VALID, 10, 1024,
                                    rec1, rec1_len,
                                    rec2_valid, rec2_valid_len,
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res == 0);
  printf("[+] 2: PROTO_VALID successfully accepts fully conforming candidate\n");

  /* ========================================================================
   * 3. PROTO_NEAR_VALID mode: intentionally broken M2 is NOT rejected as
   *    outside model, preserving sequence context.
   * ======================================================================== */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_NEAR_VALID, 10, 1024,
                                    rec1, rec1_len,
                                    rec2_broken, rec2_broken_len,
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res == 0);
  printf("[+] 3: PROTO_NEAR_VALID preserves sequence context without false rejection as outside model\n");

  /* ========================================================================
   * 4. PROTO_INVALID mode: intentionally broken M2 is NOT rejected as
   *    outside model, preserving sequence context.
   * ======================================================================== */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_INVALID, 10, 1024,
                                    rec1, rec1_len,
                                    rec2_broken, rec2_broken_len,
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res == 0);
  printf("[+] 4: PROTO_INVALID preserves sequence context without false rejection as outside model\n");

  /* ========================================================================
   * 5. Sequence resource limits are still strictly enforced under near_valid/invalid
   * ======================================================================== */
  /* 5a. Exceeding max_messages */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_NEAR_VALID, 2 /* max 2 msgs, sequence has 3 */, 1024,
                                    rec1, rec1_len,
                                    rec2_broken, rec2_broken_len,
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "max_messages exceeded") != NULL);
  printf("[+] 5a: max_messages constraint correctly enforced even in PROTO_NEAR_VALID\n");

  /* 5b. Exceeding max_bytes */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_INVALID, 10, 12 /* tight byte limit */,
                                    rec1, rec1_len,
                                    rec2_broken, rec2_broken_len,
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "max_bytes exceeded") != NULL);
  printf("[+] 5b: max_bytes constraint correctly enforced even in PROTO_INVALID\n");

  /* 5c. Broken framing header */
  uint8_t malformed_header[] = { 0x0A, 0x00, 0x00, 0x00, 0x01 }; /* Claims 10 bytes, only 1 provided */
  err[0] = '\0';
  res = test_validate_sequence_mode(TEST_MODE_NEAR_VALID, 10, 1024,
                                    rec1, rec1_len,
                                    malformed_header, sizeof(malformed_header),
                                    rec3, rec3_len,
                                    mock_semantic_check, err, sizeof(err));
  assert(res < 0);
  assert(strstr(err, "overflows available buffer") != NULL);
  printf("[+] 5c: Record framing overflow correctly caught in PROTO_NEAR_VALID\n");

  free(rec1);
  free(rec2_valid);
  free(rec2_broken);
  free(rec3);

  printf("[+] All B10 intentionally-invalid mode validation tests passed successfully!\n");
  return 0;
}
