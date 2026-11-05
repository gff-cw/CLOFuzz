#include "protocol_iec104_session.h"
#include "protocol_codecs.h"
#include <stdio.h>
#include <string.h>

static int ies_error(char *error, size_t capacity, const char *message) {
  if (error && capacity) snprintf(error, capacity, "%s", message);
  return -1;
}
static unsigned distance(unsigned first, unsigned last) { return (last - first) & 32767u; }
static unsigned number(const uint8_t *bytes) { return ((unsigned)bytes[0] | (unsigned)bytes[1] << 8) >> 1; }
static void put_number(uint8_t *bytes, unsigned value) {
  value = (value & 32767u) << 1;
  bytes[0] = (uint8_t)value; bytes[1] = (uint8_t)(value >> 8);
}
static int expired(uint64_t now, uint64_t then, uint32_t interval) {
  return now < then || now - then >= interval;
}

void ies_reset(ies_session *session, uint64_t now_ms) {
  if (!session) return;
  memset(session, 0, sizeof(*session));
  session->k = 12; session->w = 8;
  session->t0_ms = 10000; session->t1_ms = 15000;
  session->t2_ms = 10000; session->t3_ms = 20000;
  session->connected_at = session->activity_at = now_ms;
}
int ies_configure(ies_session *session, unsigned k, unsigned w,
                  uint32_t t0_ms, uint32_t t1_ms, uint32_t t2_ms,
                  uint32_t t3_ms, char *error, size_t capacity) {
  if (!session || !k || k > 128 || !w || w > k || !t0_ms ||
      !t1_ms || !t2_ms || !t3_ms || t2_ms >= t1_ms)
    return ies_error(error, capacity, "invalid IEC104 window/timer configuration");
  session->k = (uint16_t)k; session->w = (uint16_t)w;
  session->t0_ms = t0_ms; session->t1_ms = t1_ms;
  session->t2_ms = t2_ms; session->t3_ms = t3_ms;
  return 0;
}
int ies_is_supervisory(const uint8_t *wire, size_t size) {
  return wire && size == 6 && wire[0] == 0x68 && wire[1] == 4 && wire[2] == 1;
}
int ies_is_control_request(const uint8_t *wire, size_t size) {
  return wire && size == 6 && wire[0] == 0x68 && wire[1] == 4 &&
         (wire[2] == 1 || wire[2] == 0x43);
}
static int time_valid(const ies_session *session, uint64_t now, char *error, size_t capacity) {
  if (now == UINT64_MAX || session->connected_at == UINT64_MAX)
    return ies_error(error, capacity, "IEC104 monotonic clock unavailable");
  if (now < session->activity_at)
    return ies_error(error, capacity, "IEC104 monotonic clock moved backwards");
  if ((session->start_pending && expired(now, session->start_at, session->t1_ms)) ||
      (session->stop_pending && expired(now, session->stop_at, session->t1_ms)) ||
      (session->test_pending && expired(now, session->test_at, session->t1_ms)) ||
      (session->send_next != session->send_acked && expired(now, session->first_unacked_at, session->t1_ms)))
    return ies_error(error, capacity, "IEC104 t1 confirmation/acknowledgement timeout; reconnect required");
  return 0;
}
static int acknowledge(ies_session *session, unsigned receive,
                        char *error, size_t capacity) {
  unsigned pending = distance(session->send_acked, session->send_next);
  unsigned advance = distance(session->send_acked, receive);
  if (advance > pending)
    return ies_error(error, capacity, "IEC104 N(R) is outside the outstanding send window");
  if (advance) {
    session->send_acked = (uint16_t)receive;
    if (session->send_acked != session->send_next)
      session->first_unacked_at = session->sent_at[session->send_acked % 128u];
  }
  return 0;
}
int ies_before_send(ies_session *session, uint8_t *wire, size_t size,
                    uint64_t now, char *error, size_t capacity) {
  if (!session || !wire || size > 255 || pc_iec104_validate(wire, size, error, capacity))
    return ies_error(error, capacity, "invalid IEC104 session send");
  ies_session next = *session;
  uint8_t bound[255]; memcpy(bound, wire, size);
  if (time_valid(&next, now, error, capacity)) return -1;
  int information = !(bound[2] & 1), supervisory = ies_is_supervisory(bound, size);
  if (next.active && !next.test_pending && expired(now, next.activity_at, next.t3_ms) && !supervisory && bound[2] != 0x43)
    return ies_error(error, capacity, "IEC104 idle t3 elapsed; send TESTFR act before further traffic");
  if (information) {
    if (!next.active || next.stop_pending)
      return ies_error(error, capacity, "IEC104 I-frame requires confirmed STARTDT");
    if (distance(next.send_acked, next.send_next) >= next.k)
      return ies_error(error, capacity, "IEC104 k send window is full");
    put_number(bound + 2, next.send_next);
    put_number(bound + 4, next.receive_next);
    if (next.send_next == next.send_acked) next.first_unacked_at = now;
    next.sent_at[next.send_next % 128u] = now;
    next.send_next = (uint16_t)((next.send_next + 1) & 32767u);
    next.receive_acked = next.receive_next;
  } else if (supervisory) {
    if (!next.active) return ies_error(error, capacity, "IEC104 S-frame requires active transfer");
    put_number(bound + 4, next.receive_next);
    next.receive_acked = next.receive_next;
  } else {
    switch (bound[2]) {
      case 0x07:
        if (next.active || next.start_pending || next.stop_pending ||
            (!next.started && expired(now, next.connected_at, next.t0_ms)))
          return ies_error(error, capacity, "IEC104 STARTDT invalid or t0 elapsed");
        next.start_pending = 1; next.start_at = now; break;
      case 0x13:
        if (!next.active || next.stop_pending || next.start_pending || next.send_next != next.send_acked)
          return ies_error(error, capacity, "IEC104 STOPDT requires active acknowledged transfer");
        next.stop_pending = 1; next.stop_at = now; break;
      case 0x43:
        if (next.test_pending) return ies_error(error, capacity, "IEC104 TESTFR confirmation already pending");
        next.test_pending = 1; next.test_at = now; break;
      default:
        return ies_error(error, capacity, "IEC104 client source cannot send an unsolicited U confirmation");
    }
    if (next.receive_next != next.receive_acked &&
        expired(now, next.receive_unacked_at, next.t2_ms))
      return ies_error(error, capacity, "IEC104 t2 elapsed; acknowledge received I-frames first");
  }
  next.activity_at = now;
  *session = next; memcpy(wire, bound, size);
  return 0;
}
int ies_after_response(ies_session *session, const uint8_t *wire, size_t size,
                       uint64_t now, char *error, size_t capacity) {
  if (!session || !wire || pc_iec104_validate(wire, size, error, capacity))
    return ies_error(error, capacity, "invalid IEC104 session response");
  ies_session next = *session;
  if (time_valid(&next, now, error, capacity)) return -1;
  if (!(wire[2] & 1)) {
    if (!next.active || number(wire + 2) != next.receive_next)
      return ies_error(error, capacity, "IEC104 I-frame inactive, duplicate or out of order");
    if (distance(next.receive_acked, next.receive_next) >= next.w ||
        (next.receive_next != next.receive_acked && expired(now, next.receive_unacked_at, next.t2_ms)))
      return ies_error(error, capacity, "IEC104 receive acknowledgement required by w/t2");
    if (acknowledge(&next, number(wire + 4), error, capacity)) return -1;
    if (next.receive_next == next.receive_acked) next.receive_unacked_at = now;
    next.receive_next = (uint16_t)((next.receive_next + 1) & 32767u);
  } else if (ies_is_supervisory(wire, size)) {
    if (!next.active || acknowledge(&next, number(wire + 4), error, capacity))
      return ies_error(error, capacity, "IEC104 invalid S-frame acknowledgement");
  } else {
    switch (wire[2]) {
      case 0x0b:
        if (!next.start_pending) return ies_error(error, capacity, "unsolicited IEC104 STARTDT con");
        next.start_pending = 0; next.active = 1; next.started = 1; break;
      case 0x23:
        if (!next.stop_pending) return ies_error(error, capacity, "unsolicited IEC104 STOPDT con");
        next.stop_pending = 0; next.active = 0; break;
      case 0x83:
        if (!next.test_pending) return ies_error(error, capacity, "unsolicited IEC104 TESTFR con");
        next.test_pending = 0; break;
      default:
        return ies_error(error, capacity, "server-initiated IEC104 U control is outside this client profile");
    }
  }
  next.activity_at = now; *session = next;
  return 0;
}
