#ifndef STATEAFL_IEC104_SESSION_H
#define STATEAFL_IEC104_SESSION_H
#include <stddef.h>
#include <stdint.h>

/* Client-initiated, single-interrogation APCI session. This POD belongs in the
 * runtime's prepare/commit snapshot; it never performs transport I/O itself. */
typedef struct {
  uint16_t send_next, send_acked, receive_next, receive_acked;
  uint16_t k, w;
  uint32_t t0_ms, t1_ms, t2_ms, t3_ms;
  uint64_t connected_at, activity_at, first_unacked_at, receive_unacked_at;
  uint64_t start_at, stop_at, test_at;
  uint64_t sent_at[128];
  uint8_t active, start_pending, stop_pending, test_pending, started;
} ies_session;

void ies_reset(ies_session *session, uint64_t now_ms);
int ies_configure(ies_session *session, unsigned k, unsigned w,
                  uint32_t t0_ms, uint32_t t1_ms, uint32_t t2_ms,
                  uint32_t t3_ms, char *error, size_t capacity);
/* Bind actual N(S)/N(R), then atomically commit the tentative state and wire.
 * The host publishes this tentative state only after a complete socket send. */
int ies_before_send(ies_session *session, uint8_t *wire, size_t size,
                    uint64_t now_ms, char *error, size_t capacity);
/* Complete validated I/S/U frames only. Rejections leave the POD unchanged. */
int ies_after_response(ies_session *session, const uint8_t *wire, size_t size,
                       uint64_t now_ms, char *error, size_t capacity);
int ies_is_supervisory(const uint8_t *wire, size_t size);
int ies_is_control_request(const uint8_t *wire, size_t size);
#endif
