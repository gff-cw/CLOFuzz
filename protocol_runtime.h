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
/* Validate all M1/M2/M3 resource limits and projected model transitions.
 * Legacy intentional wire violations require the exact candidate produced by
 * the most recent successful mutation; a private valid projection supplies
 * model identity and transitions without altering actual candidate bytes.
 * Generic-wire continues to accept valid mode only. */
int proto_validate_sequence(proto_engine *engine,
                            const uint8_t *m1, size_t m1_len,
                            const uint8_t *m2, size_t m2_len,
                            const uint8_t *m3, size_t m3_len,
                            char *error, size_t cap);
/* True only for an exact damaged record in the current legacy mutation whose
 * private valid projection can prepare in the current session. The temporary
 * preparation is cancelled; committed state and caller bytes are preserved. */
int proto_is_intentional_violation(proto_engine *engine,
                                   const uint8_t *wire, size_t length);
/* P13: Independent complete field constraint verification for message models. */
int proto_validate_message_fields(const proto_engine *engine, int message_index,
                                  const uint8_t *wire, size_t length,
                                  char *error, size_t cap);
/* One cache per engine, cleared for EVERY connection/execution. */
void proto_session_begin(proto_engine *engine);
/* Prepare on a private wire copy without changing committed session state.
 * At most one prepared send is allowed. The caller must commit only after the
 * complete wire message was submitted, or cancel on any partial/error result.
 * Both engines block new application requests while a response is pending;
 * IEC104 permits its declared S/TESTFR control traffic during interrogation.
 * No-response request edges do not create a host pending entry.
 * Response observation must happen after commit/cancel, never while prepared. */
int proto_prepare_send(proto_engine *engine, uint8_t *wire, size_t length,
                       char *error, size_t cap);
int proto_commit_send(proto_engine *engine, char *error, size_t cap);
void proto_cancel_send(proto_engine *engine);
/* Compatibility convenience for callers that already know submission succeeds:
 * prepare and immediately commit. Network execution must use the transaction
 * API above, so an attempted send cannot create committed pending/cache state. */
int proto_before_send(proto_engine *engine, uint8_t *wire, size_t length,
                      char *error, size_t cap);
void proto_after_response(proto_engine *engine, const uint8_t *wire, size_t length);
/* P16: Transport interface separates discrete UDP datagram events from TCP stream segments. */
void proto_after_dgram(proto_engine *engine, const uint8_t *wire, size_t length);
void proto_after_stream(proto_engine *engine, const uint8_t *wire, size_t length);
void proto_set_execution_purpose(proto_engine *engine, unsigned purpose);
void proto_set_mutating_mode(proto_engine *engine, int mode);
int proto_write_stats(proto_engine *engine, const char *path);
/* Safe codec contract: validate complete datagram and locate a field; absent
 * optional field returns 0, invalid packet/locator -1, present field 1. */
int proto_bacnet_field(const uint8_t *wire, size_t length, const char *locator,
                       size_t *offset, size_t *width, char *error, size_t cap);
#endif
