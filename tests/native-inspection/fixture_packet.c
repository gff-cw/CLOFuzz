/* Test support for a fixed fictional packet, not a protocol mutation engine. */
#include "fixture_packet.h"

#include <stdio.h>
#include <string.h>

const char fixture_packet_layout[] =
  "{\"kind\":\"struct\",\"id\":\"packet\",\"fields\":["
  "{\"kind\":\"uint\",\"id\":\"magic\",\"width\":1,\"byte_order\":\"big\",\"expected\":42},"
  "{\"kind\":\"uint\",\"id\":\"size\",\"width\":1,\"byte_order\":\"big\"},"
  "{\"kind\":\"bytes\",\"id\":\"body\",\"length\":{\"ref\":\"size\"},\"encoding\":\"hex\"}]}";

static int fixture_error(char *error, size_t capacity, const char *message) {
  if (error && capacity) snprintf(error, capacity, "%s", message);
  return -1;
}

int fixture_packet_mutate(const unsigned char *input, size_t input_length,
                          const fixture_packet_edit *edit,
                          unsigned char *output, size_t output_capacity,
                          size_t *output_length,
                          char *error, size_t error_capacity) {
  unsigned char staged[FIXTURE_PACKET_MAX_LENGTH];
  size_t body_length, result_length;
  int changed;

  if (output_length) *output_length = 0;
  if (error && error_capacity) error[0] = '\0';
  if (!input || !edit || !output || !output_length)
    return fixture_error(error, error_capacity, "missing fixture edit argument");
  if (input_length < FIXTURE_PACKET_HEADER_LENGTH ||
      input_length > FIXTURE_PACKET_MAX_LENGTH)
    return fixture_error(error, error_capacity, "fixture input length is outside its bounds");
  if (input[0] != 42)
    return fixture_error(error, error_capacity, "fixture magic must be 42");
  body_length = input_length - FIXTURE_PACKET_HEADER_LENGTH;
  if (body_length != input[1])
    return fixture_error(error, error_capacity, "fixture body length does not match its header");

  switch (edit->operation) {
    case FIXTURE_PACKET_SET_BYTE:
      if (edit->argument >= body_length)
        return fixture_error(error, error_capacity, "fixture body index is out of range");
      result_length = input_length;
      changed = input[FIXTURE_PACKET_HEADER_LENGTH + edit->argument] != edit->value;
      break;
    case FIXTURE_PACKET_RESIZE_BODY:
      if (edit->argument > FIXTURE_PACKET_MAX_BODY)
        return fixture_error(error, error_capacity, "fixture body exceeds 255 bytes");
      result_length = FIXTURE_PACKET_HEADER_LENGTH + edit->argument;
      changed = edit->argument != body_length;
      break;
    default:
      return fixture_error(error, error_capacity, "unknown fixture edit operation");
  }
  if (output_capacity < result_length)
    return fixture_error(error, error_capacity, "fixture output buffer is too small");

  /* All fallible validation precedes staging and the final output commit.
   * Staging also permits arbitrary overlap of the input and output buffers. */
  memcpy(staged, input, input_length);
  if (edit->operation == FIXTURE_PACKET_SET_BYTE) {
    staged[FIXTURE_PACKET_HEADER_LENGTH + edit->argument] = edit->value;
  } else {
    if (edit->argument > body_length)
      memset(staged + input_length, edit->value, edit->argument - body_length);
    staged[1] = (unsigned char)edit->argument;
  }
  memcpy(output, staged, result_length);
  *output_length = result_length;
  return changed ? 0 : 1;
}
