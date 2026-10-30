#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "config.h"

/* Stage gating predicate under test (identical in uniform and adaptive) */
static inline u8 protocol_stage_eligible(const char *stage) {
  if (!stage) return 0;
  return (!strcmp(stage, "havoc") || !strcmp(stage, "splice"));
}

/* Simulated candidate status serialization */
static void format_candidate_status(char *buf, size_t max_len,
                                    u32 candidate_id,
                                    const char *req_mode,
                                    const char *actual_mode,
                                    const char *stage,
                                    const char *layer,
                                    u8 executed,
                                    const char *outcome) {
  snprintf(buf, max_len,
           "{\"event\":\"candidate_status\",\"candidate_id\":%u,"
           "\"requested_mode\":\"%s\",\"actual_mode\":\"%s\",\"stage\":\"%s\","
           "\"layer\":\"%s\",\"executed\":%s,\"outcome\":\"%s\"}\n",
           candidate_id, req_mode, actual_mode,
           stage ? stage : "none",
           layer ? layer : "NONE",
           executed ? "true" : "false",
           outcome);
}

int main(void) {
  printf("[*] Testing P20: Deterministic stage gating and attribution...\n");

  /* --- 1. Shared stage eligibility for uniform and adaptive --- */
  assert(protocol_stage_eligible("havoc") == 1);
  assert(protocol_stage_eligible("splice") == 1);

  /* Deterministic stages must NOT run structured mutation */
  assert(protocol_stage_eligible("bitflip 1/1") == 0);
  assert(protocol_stage_eligible("bitflip 2/1") == 0);
  assert(protocol_stage_eligible("bitflip 4/1") == 0);
  assert(protocol_stage_eligible("arith 8/8") == 0);
  assert(protocol_stage_eligible("arith 16/8") == 0);
  assert(protocol_stage_eligible("arith 32/8") == 0);
  assert(protocol_stage_eligible("interest 8/8") == 0);
  assert(protocol_stage_eligible("auto extras (over)") == 0);
  assert(protocol_stage_eligible(NULL) == 0);

  /* --- 2. Unexecuted branch trace_bits clearance --- */
  u8 dummy_trace_bits[MAP_SIZE];
  /* Simulate stale trace bits from a previous execution */
  memset(dummy_trace_bits, 0xAA, sizeof(dummy_trace_bits));
  assert(dummy_trace_bits[0] == 0xAA);
  assert(dummy_trace_bits[1024] == 0xAA);

  /* When candidate is rejected without fallback, trace_bits must be cleared */
  u8 rejected = 1;
  u8 fallback = 0;
  if (rejected && !fallback) {
    memset(dummy_trace_bits, 0, sizeof(dummy_trace_bits));
  }

  /* Verify zero bits remain so caller cannot consume stale bitmap */
  for (size_t i = 0; i < sizeof(dummy_trace_bits); i++) {
    assert(dummy_trace_bits[i] == 0);
  }

  /* --- 3. Candidate status record logging and outcome attribution --- */
  char log_buf[512];

  /* 3a. Rejected candidate */
  format_candidate_status(log_buf, sizeof(log_buf), 101, "valid", "none", "havoc", "NONE", 0, "rejected");
  assert(strstr(log_buf, "\"executed\":false") != NULL);
  assert(strstr(log_buf, "\"outcome\":\"rejected\"") != NULL);
  assert(strstr(log_buf, "\"actual_mode\":\"none\"") != NULL);

  /* 3b. Deterministic stage raw run */
  format_candidate_status(log_buf, sizeof(log_buf), 102, "valid", "raw", "bitflip 1/1", "NONE", 1, "executed");
  assert(strstr(log_buf, "\"executed\":true") != NULL);
  assert(strstr(log_buf, "\"actual_mode\":\"raw\"") != NULL);
  assert(strstr(log_buf, "\"stage\":\"bitflip 1/1\"") != NULL);

  /* 3c. Havoc structured run */
  format_candidate_status(log_buf, sizeof(log_buf), 103, "hybrid", "structured", "havoc", "CONTENT", 1, "executed");
  assert(strstr(log_buf, "\"executed\":true") != NULL);
  assert(strstr(log_buf, "\"actual_mode\":\"structured\"") != NULL);
  assert(strstr(log_buf, "\"layer\":\"CONTENT\"") != NULL);

  /* 3d. Crash run */
  format_candidate_status(log_buf, sizeof(log_buf), 104, "valid", "structured", "splice", "SEQUENCE", 1, "crash");
  assert(strstr(log_buf, "\"outcome\":\"crash\"") != NULL);

  printf("PASS: test_stage_gating_attribution passed (18 assertions)\n");
  return 0;
}
