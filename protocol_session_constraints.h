/* Stateful, bounded cross-message checks for the existing legacy codecs.
 * The state is plain data: include it in the runtime's prepare/commit snapshot.
 * It does not implement encryption, Session services, Renew, or chunk assembly. */
#ifndef STATEAFL_PROTOCOL_SESSION_CONSTRAINTS_H
#define STATEAFL_PROTOCOL_SESSION_CONSTRAINTS_H

#include <stddef.h>
#include <stdint.h>

#define PSC_TIME_UNAVAILABLE UINT64_MAX

typedef struct {
  uint8_t pending, unit, function;
  uint16_t transaction, address, quantity, value;
} psc_modbus_session;

typedef struct {
  uint8_t hello, acknowledged, closed, pending;
  uint8_t client_sequence_seen, server_sequence_seen, clock_seen;
  uint32_t client_receive_buffer, client_send_buffer;
  uint32_t client_max_message, client_max_chunks;
  uint32_t server_receive_buffer, server_send_buffer;
  uint32_t server_max_message, server_max_chunks;
  uint32_t channel, token, client_sequence, server_sequence;
  uint32_t pending_request_id, pending_request_handle;
  uint64_t pending_sent_ms, token_expires_ms, last_now_ms;
} psc_opcua_session;

typedef struct {
  psc_modbus_session modbus;
  psc_opcua_session opcua;
} psc_session;

void psc_session_reset(psc_session *session);
/* Return PSC_TIME_UNAVAILABLE on clock failure. A zero timestamp is valid. */
uint64_t psc_monotonic_ms(void);
/* Return 0 on success, -1 on refusal. Refusal never changes *session.
 * before_send receives the final bound request. The caller must snapshot its
 * successful update until complete transport submission, and discard on cancel.
 * after_response runs only after the host's grammar/state/correlation checks;
 * the host must not cache or consume a refused response. Other codec names are
 * no-ops. now_ms is monotonic milliseconds, explicit for deterministic tests. */
int psc_before_send(psc_session *session, const char *codec,
                    const uint8_t *wire, size_t size, uint64_t now_ms,
                    char *error, size_t capacity);
int psc_after_response(psc_session *session, const char *codec,
                       const uint8_t *wire, size_t size, uint64_t now_ms,
                       char *error, size_t capacity);

#endif
