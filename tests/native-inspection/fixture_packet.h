/* Deterministic edits for one fictional native-inspection test fixture. */
#ifndef STATEAFL_TEST_FIXTURE_PACKET_H
#define STATEAFL_TEST_FIXTURE_PACKET_H

#include <stddef.h>

#define FIXTURE_PACKET_MAX_BODY 255u
#define FIXTURE_PACKET_HEADER_LENGTH 2u
#define FIXTURE_PACKET_MAX_LENGTH \
  (FIXTURE_PACKET_HEADER_LENGTH + FIXTURE_PACKET_MAX_BODY)

/* A native layout node, without the outer format/version/root wrapper.
 * Wire representation: magic byte 42, one body-length byte, then the body. */
extern const char fixture_packet_layout[];

enum fixture_packet_operation {
  FIXTURE_PACKET_SET_BYTE,
  FIXTURE_PACKET_RESIZE_BODY
};

typedef struct {
  enum fixture_packet_operation operation;
  /* SET_BYTE: existing body index. RESIZE_BODY: new body length, <=255. */
  size_t argument;
  /* SET_BYTE: replacement. RESIZE_BODY: fill byte for newly added bytes. */
  unsigned char value;
} fixture_packet_edit;

/* Only the fictional layout above is accepted; input must already be complete
 * and valid. All buffers are borrowed and must describe valid storage.
 * input, edit, output and output_length are required. error is optional.
 * input and output may overlap. edit, output_length and error storage must not
 * alias either data buffer or each other; the caller guarantees this.
 *
 * Entry resets a supplied *output_length to zero and a supplied error buffer
 * to an empty string when error_capacity>0. Failure returns -1 without writing
 * output bytes; an available error buffer receives a truncated diagnostic.
 * Return 0 when the resulting bytes differ from input, or 1 for a valid edit
 * with no change. Both successful results copy the complete result to output
 * and set *output_length. Caller-owned storage is never allocated or freed.
 * There is no protocol selection, I/O, target execution or feedback state. */
int fixture_packet_mutate(const unsigned char *input, size_t input_length,
                          const fixture_packet_edit *edit,
                          unsigned char *output, size_t output_capacity,
                          size_t *output_length,
                          char *error, size_t error_capacity);

#endif
