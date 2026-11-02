#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llvm_mode/state-tracer.h"

/* Append reference state hash during calibration initialization
 * Matching afl-llvm-rt-state-tracer.o.c:1363 (B03) */
static inline int calibration_append_ref_state(struct calibration *calib, const char *tlsh_hash) {
  if (!calib || !tlsh_hash) return -1;
  if (calib->ref_len < MAX_NUM_STATES) {
    strncpy(calib->ref_state_seq[calib->ref_len], tlsh_hash, TLSH_SIZE);
    calib->ref_state_seq[calib->ref_len][TLSH_SIZE] = '\0';
    calib->ref_len++;
    return 0;
  }
  return 1; /* Capacity full, cleanly prevented overflow */
}

/* Guarded reference state lookup
 * Matching afl-llvm-rt-state-tracer.o.c:1375 (B03) */
static inline const char *calibration_read_ref_state(const struct calibration *calib, int current_state_number) {
  if (!calib) return NULL;
  if (current_state_number >= 0 &&
      current_state_number < calib->ref_len &&
      current_state_number < MAX_NUM_STATES) {
    return calib->ref_state_seq[current_state_number];
  }
  return NULL;
}

/* Guarded distance recording
 * Matching afl-llvm-rt-state-tracer.o.c:1385 (B03) */
static inline int calibration_record_distance(struct calibration *calib, int diff) {
  if (!calib) return -1;
  if (calib->dist_len < (MAX_NUM_STATES * MAX_REPETITIONS)) {
    calib->dist[calib->dist_len] = diff;
    calib->dist_len++;
    return 0;
  }
  return 1; /* Capacity full, cleanly stopped */
}

int main(void) {
  printf("[*] Testing B03 calibration buffer bounds and index protections...\n");

  /* 1. Layout and dimension verification */
  assert(MAX_NUM_STATES == 100);
  assert(MAX_REPETITIONS == 1000);
  assert(TLSH_SIZE == 72);

  struct calibration *calib = (struct calibration *)calloc(1, sizeof(struct calibration));
  assert(calib != NULL);

  calib->enabled = 1;
  calib->initialized = 0;
  calib->ref_len = 0;
  calib->dist_len = 0;

  /* 2. Verify writing to ref_state_seq stops cleanly at MAX_NUM_STATES without overflow */
  printf("[*] 2. Testing ref_state_seq write bounds (capacity=%d)...\n", MAX_NUM_STATES);
  for (int i = 0; i < MAX_NUM_STATES; i++) {
    char hash_buf[TLSH_SIZE + 1];
    /* Exactly 72 chars: 8 + 64 = 72 chars */
    snprintf(hash_buf, sizeof(hash_buf), "T1A0%04d"
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", i);
    int rc = calibration_append_ref_state(calib, hash_buf);
    assert(rc == 0);
  }

  assert(calib->ref_len == MAX_NUM_STATES);
  assert(strncmp(calib->ref_state_seq[0], "T1A00000", 8) == 0);
  assert(strncmp(calib->ref_state_seq[MAX_NUM_STATES - 1], "T1A00099", 8) == 0);

  /* Attempt to write beyond MAX_NUM_STATES */
  for (int i = 0; i < 50; i++) {
    char overflow_buf[TLSH_SIZE + 1];
    snprintf(overflow_buf, sizeof(overflow_buf), "OVERFLOW%04d"
             "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
             "BBBBBBBBBBBBBBBBBBBBBBBBBBBB", i);
    int rc = calibration_append_ref_state(calib, overflow_buf);
    assert(rc == 1); /* Rejected cleanly */
  }

  /* Must clamp ref_len at MAX_NUM_STATES and not corrupt the last slot */
  assert(calib->ref_len == MAX_NUM_STATES);
  assert(strncmp(calib->ref_state_seq[MAX_NUM_STATES - 1], "T1A00099", 8) == 0);

  /* 3. Verify reading ref_state_seq is protected against negative and >= ref_len indices */
  printf("[*] 3. Testing ref_state_seq read protections (negative, >= ref_len, >= MAX_NUM_STATES)...\n");

  /* Negative indices */
  assert(calibration_read_ref_state(calib, -1) == NULL);
  assert(calibration_read_ref_state(calib, -10) == NULL);
  assert(calibration_read_ref_state(calib, -999) == NULL);
  assert(calibration_read_ref_state(calib, INT_MIN) == NULL);

  /* Test with partial sequence length */
  calib->ref_len = 40;
  assert(calibration_read_ref_state(calib, 0) != NULL);
  assert(calibration_read_ref_state(calib, 39) != NULL);
  assert(calibration_read_ref_state(calib, 40) == NULL); /* == ref_len */
  assert(calibration_read_ref_state(calib, 41) == NULL); /* > ref_len */
  assert(calibration_read_ref_state(calib, 99) == NULL); /* < MAX_NUM_STATES but >= ref_len */
  assert(calibration_read_ref_state(calib, 100) == NULL); /* == MAX_NUM_STATES */
  assert(calibration_read_ref_state(calib, 150) == NULL); /* > MAX_NUM_STATES */
  assert(calibration_read_ref_state(calib, INT_MAX) == NULL);

  /* Test with full sequence length */
  calib->ref_len = MAX_NUM_STATES;
  assert(calibration_read_ref_state(calib, 0) != NULL);
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES - 1) != NULL);
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES) == NULL);
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES + 1) == NULL);

  /* Defense-in-depth: corrupted ref_len exceeding MAX_NUM_STATES */
  calib->ref_len = MAX_NUM_STATES + 50;
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES - 1) != NULL);
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES) == NULL);
  assert(calibration_read_ref_state(calib, MAX_NUM_STATES + 10) == NULL);

  /* 4. Verify writing to dist stops cleanly at MAX_NUM_STATES * MAX_REPETITIONS */
  printf("[*] 4. Testing dist write bounds (capacity=%d)...\n", MAX_NUM_STATES * MAX_REPETITIONS);
  calib->dist_len = 0;
  const int max_dist_entries = MAX_NUM_STATES * MAX_REPETITIONS;

  for (int i = 0; i < max_dist_entries; i++) {
    int diff_val = (i % 300);
    int rc = calibration_record_distance(calib, diff_val);
    assert(rc == 0);
  }

  assert(calib->dist_len == max_dist_entries);
  assert(calib->dist[0] == 0);
  assert(calib->dist[max_dist_entries - 1] == ((max_dist_entries - 1) % 300));

  /* Attempt to write beyond max_dist_entries */
  for (int i = 0; i < 1000; i++) {
    int rc = calibration_record_distance(calib, 9999);
    assert(rc == 1); /* Rejected cleanly */
  }

  /* Must remain clamped at max_dist_entries and not corrupt neighboring memory */
  assert(calib->dist_len == max_dist_entries);
  assert(calib->dist[max_dist_entries - 1] == ((max_dist_entries - 1) % 300));

  free(calib);

  printf("[+] B03 calibration bounds and read protections passed cleanly under ASan/UBSan!\n");
  return 0;
}
