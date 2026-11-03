#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "execution_observation.h"

static void expect_serialized(const execution_observation_t *obs, int replay,
                              const u8 *expected, size_t size) {
  FILE *file = tmpfile();
  assert(file);
  size_t written = 0;
  assert(write_execution_wire(file, obs, replay, &written) == 0);
  assert(written == size);
  assert(fseek(file, 0, SEEK_SET) == 0);
  u8 result[64];
  assert(size < sizeof(result));
  assert(fread(result, 1, size, file) == size);
  assert(memcmp(result, expected, size) == 0);
  assert(fgetc(file) == EOF);
  assert(fclose(file) == 0);
}

int main(void) {
  u8 first[] = {0xa1, 0xa2, 0xa3};
  u8 partial[] = {0xb1, 0xb2};
  execution_wire_record_t records[] = {
    {first, sizeof(first), sizeof(first)},
    {partial, sizeof(partial), 5},
    {NULL, 0, 4}
  };
  execution_observation_t *orig = calloc(1, sizeof(*orig));
  execution_observation_t *rep = calloc(1, sizeof(*rep));
  assert(orig && rep);
  assert(copy_execution_wire(orig, records, 3, 4) == 0);
  assert(copy_execution_wire(rep, records, 3, 4) == 0);
  assert(orig->planned_messages == 4 && orig->wire_count == 3);
  assert(execution_submitted_records(orig) == 2);
  assert(orig->wire != rep->wire && orig->wire[0].data != first);
  assert(execution_wire_equal(orig, rep));
  memset(first, 0, sizeof(first));
  memset(partial, 0, sizeof(partial));
  assert(orig->wire[0].data[0] == 0xa1 && orig->wire[1].data[1] == 0xb2);
  assert(execution_wire_equal(orig, rep));

  const u8 flat[] = {0xa1, 0xa2, 0xa3, 0xb1, 0xb2};
  const u8 replay[] = {3, 0, 0, 0, 0xa1, 0xa2, 0xa3,
                       2, 0, 0, 0, 0xb1, 0xb2};
  expect_serialized(orig, 0, flat, sizeof(flat));
  expect_serialized(orig, 1, replay, sizeof(replay));
  /* The failed attempt is retained in metadata, never emitted as a zero record. */
  assert(orig->wire[2].size == 0 && orig->wire[2].planned_size == 4);
  rep->wire[0].data[0] ^= 1;
  assert(!execution_wire_equal(orig, rep));
  rep->wire[0].data[0] ^= 1;
  rep->wire[1].planned_size = 6;
  assert(!execution_wire_equal(orig, rep));
  rep->wire[1].planned_size = 5;
  rep->planned_messages = 3;
  assert(!execution_wire_equal(orig, rep));
  rep->planned_messages = 4;
  /* Existing owned buffers cannot be overwritten or silently leaked. */
  assert(copy_execution_wire(rep, records, 3, 4) < 0);
  free_execution_observation(rep);
  free_execution_observation(orig);

  execution_observation_t *invalid = calloc(1, sizeof(*invalid));
  assert(invalid);
  execution_wire_record_t oversized = {first, 3, 2};
  assert(copy_execution_wire(invalid, &oversized, 1, 1) < 0);
  assert(invalid->wire == NULL);
  execution_wire_record_t missing = {NULL, 1, 1};
  assert(copy_execution_wire(invalid, &missing, 1, 1) < 0);
  assert(copy_execution_wire(invalid, records, 3, 2) < 0);
  assert(copy_execution_wire(invalid, NULL, 1, 1) < 0);
  assert(!execution_wire_equal(invalid, invalid));
  assert(execution_submitted_records(invalid) == 0);
  free_execution_observation(invalid);
  puts("PASS: production submitted-wire ownership, identity and replay encoding");
  return 0;
}
