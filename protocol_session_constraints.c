#define _POSIX_C_SOURCE 200809L
#include "protocol_session_constraints.h"
#include "protocol_codecs.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

enum { UA_WAIT_NONE, UA_WAIT_ACK, UA_WAIT_OPEN, UA_WAIT_SERVICE };

static int refused(char *error, size_t capacity, const char *message) {
  if (error && capacity) snprintf(error, capacity, "%s", message);
  return -1;
}

static uint16_t be16(const uint8_t *bytes) {
  return (uint16_t)((uint16_t)bytes[0] << 8 | bytes[1]);
}

static uint32_t le32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
         (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

void psc_session_reset(psc_session *session) {
  if (session) memset(session, 0, sizeof(*session));
}

uint64_t psc_monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 ||
      (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000)
    return PSC_TIME_UNAVAILABLE;
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int modbus_send(psc_modbus_session *session, const uint8_t *wire, size_t size,
                       char *error, size_t capacity) {
  unsigned function, quantity;
  if (pc_modbus_validate(wire, size, error, capacity)) return -1;
  if (session->pending) return refused(error, capacity, "Modbus request already pending");
  function = wire[7];
  if (function & 0x80 || size < 12)
    return refused(error, capacity, "Modbus send requires a request, not a response");
  if (function >= 1 && function <= 4) {
    quantity = be16(wire + 10);
    if (size != 12 || !quantity || quantity > (function <= 2 ? 2000u : 125u))
      return refused(error, capacity, "Modbus read request quantity/shape invalid");
  } else if (function == 15 || function == 16) {
    if (size <= 12)
      return refused(error, capacity, "Modbus multiwrite acknowledgment is not a request");
  }
  session->pending = 1;
  session->transaction = be16(wire);
  session->unit = wire[6];
  session->function = (uint8_t)function;
  session->address = be16(wire + 8);
  session->quantity = be16(wire + 10);
  session->value = be16(wire + 10);
  return 0;
}

static int modbus_response(psc_modbus_session *session, const uint8_t *wire, size_t size,
                           char *error, size_t capacity) {
  size_t expected;
  unsigned function;
  if (pc_modbus_validate(wire, size, error, capacity)) return -1;
  if (!session->pending) return refused(error, capacity, "Modbus response has no pending request");
  if (be16(wire) != session->transaction || wire[6] != session->unit)
    return refused(error, capacity, "Modbus response transaction/unit mismatch");
  function = wire[7];
  if (function == (session->function | 0x80u)) {
    session->pending = 0;
    return 0;
  }
  if (function != session->function)
    return refused(error, capacity, "Modbus response function differs from its request");
  if (function >= 1 && function <= 4) {
    expected = function <= 2 ? (session->quantity + 7u) / 8u : session->quantity * 2u;
    if (size != 9u + expected || wire[8] != expected)
      return refused(error, capacity, "Modbus read response does not match requested quantity");
    if (function <= 2 && (session->quantity & 7u) &&
        (wire[size - 1] >> (session->quantity & 7u)))
      return refused(error, capacity, "Modbus read response has nonzero unused coil bits");
  } else if (function == 5 || function == 6) {
    if (size != 12 || be16(wire + 8) != session->address ||
        be16(wire + 10) != session->value)
      return refused(error, capacity, "Modbus single-write response does not echo request");
  } else if (function == 15 || function == 16) {
    if (size != 12 || be16(wire + 8) != session->address ||
        be16(wire + 10) != session->quantity)
      return refused(error, capacity, "Modbus multiwrite response does not echo address/quantity");
  } else return refused(error, capacity, "Unsupported Modbus response function");
  session->pending = 0;
  return 0;
}

static int ua_number(const uint8_t *wire, size_t size, const char *name,
                     uint32_t *value, char *error, size_t capacity) {
  size_t offset, length;
  if (pc_opcua_field(wire, size, name, PC_UINT32, 4, &offset, &length,
                     error, capacity) != 1 || length != 4)
    return refused(error, capacity, "Missing OPC UA session scalar");
  *value = le32(wire + offset);
  return 0;
}

typedef struct {
  uint32_t service, channel, token, sequence, request_id, request_handle;
  size_t body_size;
} ua_secure_message;

static int ua_secure(const uint8_t *wire, size_t size, ua_secure_message *message,
                      char *error, size_t capacity) {
  size_t offset, length;
  memset(message, 0, sizeof(*message));
  if (pc_opcua_field(wire, size, "uabin:service_nodeid", PC_NODEID, 0,
                     &offset, &length, error, capacity) != 1)
    return refused(error, capacity, "Missing OPC UA service identity");
  message->body_size = size - offset;
  if (length == 2 && wire[offset] == 0) message->service = wire[offset + 1];
  else if (length == 4 && wire[offset] == 1)
    message->service = (uint32_t)wire[offset + 2] | (uint32_t)wire[offset + 3] << 8;
  else if (length == 7 && wire[offset] == 2) message->service = le32(wire + offset + 3);
  else return refused(error, capacity, "Unsupported OPC UA numeric service identity");
  if (ua_number(wire, size, "uabin:channel", &message->channel, error, capacity) ||
      ua_number(wire, size, "uabin:sequence", &message->sequence, error, capacity) ||
      ua_number(wire, size, "uabin:request_id", &message->request_id, error, capacity) ||
      ua_number(wire, size, "uabin:header.request_handle", &message->request_handle, error, capacity))
    return -1;
  if (memcmp(wire, "OPN", 3) &&
      ua_number(wire, size, "uabin:token", &message->token, error, capacity)) return -1;
  return 0;
}

static int ua_sequence(uint32_t sequence, uint32_t previous, int seen,
                       char *error, size_t capacity) {
  /* This bounded Issue-only profile reconnects at exhaustion. It does not
   * invent a renewal/rollover policy, nor permit replay on an old token. */
  if (seen && (previous == UINT32_MAX || sequence != previous + 1u))
    return refused(error, capacity, "OPC UA sequence is duplicated, skipped or exhausted");
  return 0;
}

static int ua_time(psc_opcua_session *session, uint64_t now,
                    char *error, size_t capacity) {
  if (now == PSC_TIME_UNAVAILABLE || (session->clock_seen && now < session->last_now_ms))
    return refused(error, capacity, "OPC UA monotonic clock is unavailable or moved backwards");
  session->last_now_ms = now;
  session->clock_seen = 1;
  return 0;
}

static int ua_limits(const psc_opcua_session *session, size_t size, size_t body_size,
                     int response, char *error, size_t capacity) {
  uint32_t buffer = response ? session->server_send_buffer : session->server_receive_buffer;
  uint32_t maximum = response ? session->client_max_message : session->server_max_message;
  if (buffer && size > buffer)
    return refused(error, capacity, "OPC UA final chunk exceeds negotiated buffer");
  if (maximum && body_size > maximum)
    return refused(error, capacity, "OPC UA message body exceeds peer MaxMessageSize");
  /* The codec admits exactly one final chunk. Every nonzero MaxChunkCount
   * admits that count; zero means unlimited. Continuations are refused there. */
  return 0;
}

static int ua_bound_token(const psc_opcua_session *session,
                          const ua_secure_message *message, uint64_t now,
                          char *error, size_t capacity) {
  if (!session->channel || !session->token || now >= session->token_expires_ms)
    return refused(error, capacity, "OPC UA channel/token is absent or expired");
  if (message->channel != session->channel || message->token != session->token)
    return refused(error, capacity, "OPC UA message uses a different channel/token");
  return 0;
}

static int ua_send(psc_opcua_session *session, const uint8_t *wire, size_t size,
                    uint64_t now, char *error, size_t capacity) {
  ua_secure_message message;
  uint32_t request_type;
  if (pc_opcua_validate(wire, size, error, capacity)) return -1;
  if (ua_time(session, now, error, capacity)) return -1;
  if (session->closed) return refused(error, capacity, "OPC UA transport/channel already closed");
  if (session->pending) return refused(error, capacity, "OPC UA request already pending");
  if (!memcmp(wire, "HEL", 3)) {
    if (session->hello) return refused(error, capacity, "OPC UA Hello already submitted on this connection");
    session->client_receive_buffer = le32(wire + 12);
    session->client_send_buffer = le32(wire + 16);
    session->client_max_message = le32(wire + 20);
    session->client_max_chunks = le32(wire + 24);
    session->hello = 1;
    session->pending = UA_WAIT_ACK;
    return 0;
  }
  if (memcmp(wire, "OPN", 3) && memcmp(wire, "MSG", 3) && memcmp(wire, "CLO", 3))
    return refused(error, capacity, "OPC UA send requires a client request");
  if (!session->acknowledged)
    return refused(error, capacity, "OPC UA secure request requires acknowledged Hello");
  if (ua_secure(wire, size, &message, error, capacity) ||
      ua_limits(session, size, message.body_size, 0, error, capacity) ||
      ua_sequence(message.sequence, session->client_sequence,
                    session->client_sequence_seen, error, capacity)) return -1;
  if (message.service == 446) {
    if (ua_number(wire, size, "uabin:open.request_type", &request_type, error, capacity)) return -1;
    if (request_type || session->channel || message.channel)
      return refused(error, capacity, "OPC UA bounded executor supports fresh Issue, not Renew");
    session->pending = UA_WAIT_OPEN;
  } else if (message.service == 428 || message.service == 452) {
    if (ua_bound_token(session, &message, now, error, capacity)) return -1;
    if (message.service == 428) session->pending = UA_WAIT_SERVICE;
    else {
      session->closed = 1;
      session->channel = session->token = 0;
      session->token_expires_ms = 0;
    }
  } else return refused(error, capacity, "OPC UA response service cannot be submitted as request");
  session->client_sequence = message.sequence;
  session->client_sequence_seen = 1;
  session->pending_request_id = message.request_id;
  session->pending_request_handle = message.request_handle;
  session->pending_sent_ms = now;
  return 0;
}

static int ua_response(psc_opcua_session *session, const uint8_t *wire, size_t size,
                        uint64_t now, char *error, size_t capacity) {
  ua_secure_message message;
  uint32_t receive, send, token, lifetime;
  if (pc_opcua_validate(wire, size, error, capacity)) return -1;
  if (ua_time(session, now, error, capacity)) return -1;
  if (session->hello && size > session->client_receive_buffer)
    return refused(error, capacity, "OPC UA response exceeds Hello receive buffer");
  if (session->acknowledged && size > session->server_send_buffer)
    return refused(error, capacity, "OPC UA final chunk exceeds negotiated buffer");
  if (!memcmp(wire, "RHE", 3)) {
    if (session->hello || session->closed)
      return refused(error, capacity, "OPC UA ReverseHello outside initial connection");
    return 0;
  }
  if (!memcmp(wire, "ERR", 3)) {
    session->closed = 1;
    session->pending = UA_WAIT_NONE;
    session->channel = session->token = 0;
    session->token_expires_ms = 0;
    return 0;
  }
  if (!memcmp(wire, "ACK", 3)) {
    if (!session->hello || session->pending != UA_WAIT_ACK)
      return refused(error, capacity, "OPC UA Acknowledge has no pending Hello");
    receive = le32(wire + 12); send = le32(wire + 16);
    if (receive > session->client_send_buffer || send > session->client_receive_buffer)
      return refused(error, capacity, "OPC UA Acknowledge buffers exceed corresponding Hello limits");
    session->server_receive_buffer = receive;
    session->server_send_buffer = send;
    session->server_max_message = le32(wire + 20);
    session->server_max_chunks = le32(wire + 24);
    session->acknowledged = 1;
    session->pending = UA_WAIT_NONE;
    return 0;
  }
  if (session->closed || !session->acknowledged || !session->pending)
    return refused(error, capacity, "OPC UA secure response has no pending request");
  if (memcmp(wire, "OPN", 3) && memcmp(wire, "MSG", 3))
    return refused(error, capacity, "OPC UA unsupported response message type");
  if (ua_secure(wire, size, &message, error, capacity) ||
      ua_limits(session, size, message.body_size, 1, error, capacity) ||
      ua_sequence(message.sequence, session->server_sequence,
                    session->server_sequence_seen, error, capacity)) return -1;
  if (message.request_id != session->pending_request_id ||
      message.request_handle != session->pending_request_handle)
    return refused(error, capacity, "OPC UA response request ID/handle mismatch");
  if (session->pending == UA_WAIT_OPEN && message.service == 449) {
    if (ua_number(wire, size, "uabin:token.token_id", &token, error, capacity) ||
        ua_number(wire, size, "uabin:token.lifetime", &lifetime, error, capacity)) return -1;
    if (!message.channel || !token || !lifetime ||
        session->pending_sent_ms > UINT64_MAX - lifetime ||
        now >= session->pending_sent_ms + lifetime)
      return refused(error, capacity, "OPC UA issued token is invalid or already expired");
    session->channel = message.channel;
    session->token = token;
    /* Local send time is an earlier bound on server token creation. This
     * avoids extending a token by response transit/processing latency. */
    session->token_expires_ms = session->pending_sent_ms + lifetime;
  } else if (session->pending == UA_WAIT_SERVICE &&
             (message.service == 431 || message.service == 397)) {
    if (ua_bound_token(session, &message, now, error, capacity)) return -1;
  } else return refused(error, capacity, "OPC UA response does not match pending service");
  session->server_sequence = message.sequence;
  session->server_sequence_seen = 1;
  session->pending = UA_WAIT_NONE;
  return 0;
}

int psc_before_send(psc_session *session, const char *codec, const uint8_t *wire,
                    size_t size, uint64_t now, char *error, size_t capacity) {
  psc_session next;
  int result;
  if (error && capacity) error[0] = 0;
  if (!session || !codec || (!wire && size)) return refused(error, capacity, "Invalid session-check arguments");
  if (strcmp(codec, "modbus") && strcmp(codec, "opcua")) return 0;
  next = *session;
  result = !strcmp(codec, "modbus") ? modbus_send(&next.modbus, wire, size, error, capacity) :
                                      ua_send(&next.opcua, wire, size, now, error, capacity);
  if (!result) *session = next;
  return result;
}

int psc_after_response(psc_session *session, const char *codec, const uint8_t *wire,
                       size_t size, uint64_t now, char *error, size_t capacity) {
  psc_session next;
  int result;
  if (error && capacity) error[0] = 0;
  if (!session || !codec || (!wire && size)) return refused(error, capacity, "Invalid session-check arguments");
  if (strcmp(codec, "modbus") && strcmp(codec, "opcua")) return 0;
  next = *session;
  result = !strcmp(codec, "modbus") ? modbus_response(&next.modbus, wire, size, error, capacity) :
                                      ua_response(&next.opcua, wire, size, now, error, capacity);
  if (!result) *session = next;
  return result;
}
