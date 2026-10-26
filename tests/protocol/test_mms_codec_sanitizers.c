/* Standalone sanitizer stress harness; pass the captured hexadecimal records. */
#include "protocol_codecs.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t state = 0x61850u;
static uint32_t next_random(void) {
  state ^= state << 13; state ^= state >> 17; state ^= state << 5;
  return state;
}
static unsigned from_hex(char c) {
  if (c >= '0' && c <= '9') return (unsigned)(c - '0');
  if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
  abort();
}

int main(int argc, char **argv) {
  uint8_t original[16][1024], wire[65535], value[4096];
  size_t original_sizes[16], n, at, length;
  char error[256];
  unsigned iteration;
  int i;
  assert(argc > 1 && argc <= 17);
  memset(value, 'x', sizeof(value));
  for (i = 1; i < argc; ++i) {
    size_t j, hex_length = strlen(argv[i]);
    assert(!(hex_length % 2) && hex_length / 2 < sizeof(original[0]));
    original_sizes[i - 1] = hex_length / 2;
    for (j = 0; j < hex_length / 2; ++j)
      original[i - 1][j] = (uint8_t)((from_hex(argv[i][j * 2]) << 4) | from_hex(argv[i][j * 2 + 1]));
    assert(pc_mms_validate(original[i - 1], original_sizes[i - 1], error, sizeof(error)) == 0);
  }
  for (iteration = 0; iteration < 50000; ++iteration) {
    unsigned source = next_random() % (unsigned)(argc - 1);
    n = original_sizes[source]; memcpy(wire, original[source], n);
    if (iteration % 3) {
      unsigned j, changes = 1 + next_random() % 8;
      for (j = 0; j < changes; ++j) wire[next_random() % n] = (uint8_t)next_random();
    } else if (iteration % 5) n = next_random() % n;
    (void)pc_mms_validate(wire, n, error, sizeof(error));
    (void)pc_mms_field(wire, n, "ber:mms.domain", PC_STRING, 0, &at, &length, error, sizeof(error));
    (void)pc_mms_field(wire, n, "ber:mms.invoke", PC_UINT32, 4, &at, &length, error, sizeof(error));
    (void)pc_mms_frame(wire, n, &length, error, sizeof(error));
    (void)pc_mms_same_kind(wire, n, original[source], original_sizes[source]);
    (void)pc_mms_repair(wire, n, error, sizeof(error));
    if (!pc_mms_validate(wire, n, error, sizeof(error))) {
      size_t replacement_size = next_random() % sizeof(value);
      int replaced = pc_mms_replace(wire, &n, sizeof(wire), "ber:mms.domain", PC_STRING,
                                    value, replacement_size, error, sizeof(error));
      if (!replaced) assert(!pc_mms_validate(wire, n, error, sizeof(error)));
    }
  }
  return 0;
}
