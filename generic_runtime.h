/* Description-driven online execution. No protocol-name dispatch. */
#ifndef STATEAFL_GENERIC_RUNTIME_H
#define STATEAFL_GENERIC_RUNTIME_H
#include "protocol_runtime.h"

typedef struct gr_engine gr_engine;
gr_engine *gr_load(const char *description, char *error, size_t cap);
void gr_free(gr_engine *engine);
const char *gr_transport(const gr_engine *engine);
void gr_set_log(gr_engine *engine, FILE *stream);
void gr_session_begin(gr_engine *engine);
int gr_set_prefix(gr_engine *engine, const uint8_t *records, size_t length,
                  char *error, size_t cap);
/* P09: Validate full logical candidate sequence (M1 + M2 + M3). */
int gr_validate_sequence(const gr_engine *engine,
                         const uint8_t *m1, size_t m1_len,
                         const uint8_t *m2, size_t m2_len,
                         const uint8_t *m3, size_t m3_len,
                         char *error, size_t cap);
int gr_mutate(gr_engine *engine, const uint8_t *records, size_t length,
              const uint8_t *candidate, size_t candidate_length, int mode, int layer,
              proto_random random, const uint8_t **result, size_t *result_length,
              char *error, size_t cap);
/* Structured calls accept PROTO_VALID. Hybrid/raw scheduling belongs to the
 * caller. Prefix and output together obey sequence limits. Live sessions
 * permit one outstanding request; rejection preserves bytes and bindings. */
int gr_before_send(gr_engine *engine, uint8_t *wire, size_t length,
                   char *error, size_t cap);
void gr_after_response(gr_engine *engine, const uint8_t *wire, size_t length);
void gr_write_stats(gr_engine *engine, const char *path);
#endif
