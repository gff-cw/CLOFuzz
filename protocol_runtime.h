/* ICP-IR v1: protocol semantic state is independent of StateAFL memory state. */
#ifndef STATEAFL_PROTOCOL_RUNTIME_H
#define STATEAFL_PROTOCOL_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct proto_engine proto_engine;
typedef uint32_t (*proto_random)(uint32_t limit);
enum proto_mode { PROTO_VALID, PROTO_NEAR_VALID, PROTO_INVALID, PROTO_RAW, PROTO_HYBRID };
enum proto_layer { PROTO_HEAD=1, PROTO_CONTENT=2, PROTO_SEQUENCE=4 };
/* All failures return -1 with a diagnostic, never an implicit raw fallback. */
proto_engine *proto_load(const char *protocol_ir, const char *state_ir, char *error, size_t cap);
/* Load one description-driven generic-wire package. No codec names are used. */
proto_engine *proto_load_generic(const char *description, char *error, size_t cap);
void proto_free(proto_engine *engine);
int proto_mode_parse(const char *name);
int proto_layers_parse(const char *name);
void proto_set_log(proto_engine *engine, FILE *stream);
const char *proto_transport(const proto_engine *engine);
/* Select the semantic context of the existing StateAFL M1 prefix. This only
 * simulates declared transitions; response values are bound from live I/O. */
int proto_set_prefix(proto_engine *engine, const uint8_t *records, size_t length,
                     char *error, size_t cap);
/* Input/output are LE32 length + datagram records, <= MAX_FILE. Output belongs
 * to engine until next mutation. afl_candidate is the original AFL engine's
 * wire-byte candidate (no record prefixes), used only by CONTENT. Scalar
 * CONTENT requires candidate bytes at the selected field's original wire
 * offset. Mutation uses a simulated session and preserves the live cache. */
int proto_mutate(proto_engine *engine, const uint8_t *records, size_t length,
                 const uint8_t *afl_candidate, size_t afl_length,
                 int mode, int layer, proto_random rng,
                 const uint8_t **result, size_t *result_length,
                 char *error, size_t error_cap);
int proto_records_validate(const uint8_t *records, size_t length, size_t *count,
                           char *error, size_t error_cap);
/* P09: Validate full logical candidate sequence (M1 + M2 + M3). */
int proto_validate_sequence(proto_engine *engine,
                            const uint8_t *m1, size_t m1_len,
                            const uint8_t *m2, size_t m2_len,
                            const uint8_t *m3, size_t m3_len,
                            char *error, size_t cap);
/* One cache per engine, cleared for EVERY connection/execution. */
void proto_session_begin(proto_engine *engine);
/* Bind a supported request atomically. Failure preserves both caller bytes
 * and session state; success commits bindings and records the pending request.
 * Callers may ignore rejection for deliberately malformed requests and send
 * their original bytes; valid sibling requests still establish bindings. */
int proto_before_send(proto_engine *engine, uint8_t *wire, size_t length,
                      char *error, size_t cap);
void proto_after_response(proto_engine *engine, const uint8_t *wire, size_t length);
void proto_write_stats(proto_engine *engine, const char *path);
/* Safe codec contract: validate complete datagram and locate a field; absent
 * optional field returns 0, invalid packet/locator -1, present field 1. */
int proto_bacnet_field(const uint8_t *wire, size_t length, const char *locator,
                       size_t *offset, size_t *width, char *error, size_t cap);
#endif
