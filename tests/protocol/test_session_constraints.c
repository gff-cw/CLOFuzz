/* Actual cross-message checks using complete published wire vectors.
 * Run from the repository root. No target or network service is started. */
#include "protocol_session_constraints.h"
#include "protocol_codecs.h"
#include "native_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t bytes[16384]; size_t size; } packet;
static char error[512];
static unsigned assertions;

#define OK(call) do { int result_ = (call); assertions++; \
  if (result_) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, error); abort(); } \
} while (0)

static unsigned nibble(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  abort();
}

static packet fixture(const char *profile, const char *message) {
  char path[256]; nj_document *document = NULL; packet result;
  memset(&result, 0, sizeof(result));
  snprintf(path, sizeof(path), "protocols/%s/protocol_ir.json", profile);
  assert(nj_load_file(path, &document, error, sizeof(error)) == 0);
  const nj_value *messages = nj_get(document->root, "messages");
  for (size_t i = 0; i < messages->count; i++) {
    const nj_value *entry = messages->items[i];
    if (!nj_string_equal(nj_get(entry, "id"), message)) continue;
    const nj_value *hex = nj_get(entry, "example");
    assert(hex && !(hex->text_length & 1));
    result.size = hex->text_length / 2;
    assert(result.size && result.size <= sizeof(result.bytes));
    for (size_t j = 0; j < result.size; j++)
      result.bytes[j] = (uint8_t)(nibble(hex->text[2 * j]) * 16 + nibble(hex->text[2 * j + 1]));
    nj_free(document); return result;
  }
  fprintf(stderr, "Missing fixture %s/%s\n", profile, message); abort();
}

static void put32(uint8_t *wire, uint32_t value) {
  wire[0] = (uint8_t)value; wire[1] = (uint8_t)(value >> 8);
  wire[2] = (uint8_t)(value >> 16); wire[3] = (uint8_t)(value >> 24);
}

static void ua_set(packet *wire, const char *locator, uint32_t value) {
  size_t offset, length;
  assert(pc_opcua_field(wire->bytes, wire->size, locator, PC_UINT32, 4,
                        &offset, &length, error, sizeof(error)) == 1 && length == 4);
  put32(wire->bytes + offset, value);
}

static void refuse(psc_session *session, const char *codec, const packet *wire,
                    uint64_t now, int response, const char *reason) {
  psc_session before;
  memcpy(&before, session, sizeof(before));
  int result = response ? psc_after_response(session, codec, wire->bytes, wire->size, now, error, sizeof(error)) :
                          psc_before_send(session, codec, wire->bytes, wire->size, now, error, sizeof(error));
  assertions++;
  assert(result == -1 && strstr(error, reason));
  assert(!memcmp(&before, session, sizeof(before)));
}

static void negotiate(psc_session *session, uint64_t now) {
  packet hello = fixture("opcua_tcp", "hello"), ack = fixture("opcua_tcp", "ack");
  psc_session_reset(session);
  OK(psc_before_send(session, "opcua", hello.bytes, hello.size, now, error, sizeof(error)));
  OK(psc_after_response(session, "opcua", ack.bytes, ack.size, now, error, sizeof(error)));
}

static void open_channel(psc_session *session, uint64_t now) {
  packet request = fixture("opcua_tcp", "open_channel");
  packet response = fixture("opcua_tcp", "open_channel_response");
  OK(psc_before_send(session, "opcua", request.bytes, request.size, now, error, sizeof(error)));
  OK(psc_after_response(session, "opcua", response.bytes, response.size, now, error, sizeof(error)));
  assert(session->opcua.channel && session->opcua.token && session->opcua.token_expires_ms > now);
}

static void modbus_pairs(void) {
  static const char *pairs[][2] = {
    {"read_coils", "read_coils_response"}, {"read_discrete", "read_discrete_response"},
    {"read_holding", "read_response"}, {"read_input", "read_input_response"},
    {"write_coil", "write_coil_response"}, {"write_register", "write_register_response"},
    {"write_coils", "write_coils_response"}, {"write_coils_partial", "write_coils_partial_response"},
    {"write_registers", "write_registers_response"}
  };
  for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
    psc_session session; psc_session_reset(&session);
    packet request = fixture("modbus_tcp", pairs[i][0]);
    packet response = fixture("modbus_tcp", pairs[i][1]);
    OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
    refuse(&session, "modbus", &request, 0, 0, "already pending");
    OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));
    assert(!session.modbus.pending);
    refuse(&session, "modbus", &response, 0, 1, "no pending");
  }
}

static void modbus_quantity_padding_and_echo(void) {
  psc_session session; psc_session_reset(&session);
  packet request = fixture("modbus_tcp", "read_holding");
  packet response = fixture("modbus_tcp", "read_response");
  request.bytes[11] = 2;
  OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
  refuse(&session, "modbus", &response, 0, 1, "quantity");
  response.size = 13; response.bytes[5] = 7; response.bytes[8] = 4;
  response.bytes[11] = 0; response.bytes[12] = 2;
  OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));

  request = fixture("modbus_tcp", "read_coils"); request.bytes[11] = 9;
  response = fixture("modbus_tcp", "read_coils_response");
  response.size = 11; response.bytes[5] = 5; response.bytes[8] = 2;
  response.bytes[9] = 1; response.bytes[10] = 0x81;
  OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
  refuse(&session, "modbus", &response, 0, 1, "unused coil bits");
  response.bytes[10] = 1;
  OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));

  request = fixture("modbus_tcp", "write_register");
  response = fixture("modbus_tcp", "write_register_response");
  OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
  response.bytes[9] ^= 1;
  refuse(&session, "modbus", &response, 0, 1, "echo request");
  response.bytes[9] ^= 1;
  OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));
  request = fixture("modbus_tcp", "write_coils_partial");
  response = fixture("modbus_tcp", "write_coils_partial_response");
  OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
  response.bytes[11] = 8;
  refuse(&session, "modbus", &response, 0, 1, "address/quantity");
  response.bytes[11] = 9;
  OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));
  refuse(&session, "modbus", &response, 0, 0, "acknowledgment is not a request");
}

static void modbus_exception_identity(void) {
  psc_session session; psc_session_reset(&session);
  packet request = fixture("modbus_tcp", "read_holding");
  packet response = fixture("modbus_tcp", "exception");
  OK(psc_before_send(&session, "modbus", request.bytes, request.size, 0, error, sizeof(error)));
  response.bytes[7] = 0x81;
  refuse(&session, "modbus", &response, 0, 1, "function");
  response.bytes[7] = 0x83; response.bytes[0] ^= 1;
  refuse(&session, "modbus", &response, 0, 1, "transaction/unit");
  response.bytes[0] ^= 1;
  response.bytes[6] ^= 1;
  refuse(&session, "modbus", &response, 0, 1, "transaction/unit");
  response.bytes[6] ^= 1;
  OK(psc_after_response(&session, "modbus", response.bytes, response.size, 0, error, sizeof(error)));
}

static void ua_ack_and_zero_limits(void) {
  psc_session session; psc_session_reset(&session);
  packet hello = fixture("opcua_tcp", "hello"), ack = fixture("opcua_tcp", "ack");
  uint32_t client_send = (uint32_t)hello.bytes[16] | (uint32_t)hello.bytes[17] << 8 |
                         (uint32_t)hello.bytes[18] << 16 | (uint32_t)hello.bytes[19] << 24;
  OK(psc_before_send(&session, "opcua", hello.bytes, hello.size, 0, error, sizeof(error)));
  put32(ack.bytes + 12, client_send + 1);
  refuse(&session, "opcua", &ack, 1, 1, "corresponding Hello");
  ack = fixture("opcua_tcp", "ack");
  OK(psc_after_response(&session, "opcua", ack.bytes, ack.size, 1, error, sizeof(error)));
  refuse(&session, "opcua", &ack, 1, 1, "no pending Hello");

  psc_session_reset(&session);
  hello = fixture("opcua_tcp", "hello"); ack = fixture("opcua_tcp", "ack");
  put32(hello.bytes + 20, 0); put32(hello.bytes + 24, 0);
  put32(ack.bytes + 20, 0); put32(ack.bytes + 24, 0);
  OK(psc_before_send(&session, "opcua", hello.bytes, hello.size, 0, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", ack.bytes, ack.size, 0, error, sizeof(error)));
  open_channel(&session, 0);
  packet request = fixture("opcua_tcp", "message"), response = fixture("opcua_tcp", "message_response");
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, 1, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", response.bytes, response.size, 1, error, sizeof(error)));
}

static void ua_correlation_sequence_and_close(void) {
  psc_session session; negotiate(&session, 100); open_channel(&session, 101);
  packet request = fixture("opcua_tcp", "message"), response = fixture("opcua_tcp", "message_response");
  packet altered = request;
  ua_set(&altered, "uabin:channel", 2);
  refuse(&session, "opcua", &altered, 102, 0, "different channel/token");
  altered = request; ua_set(&altered, "uabin:sequence", 1);
  refuse(&session, "opcua", &altered, 102, 0, "sequence");
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, 102, error, sizeof(error)));
  altered = response; ua_set(&altered, "uabin:request_id", 99);
  refuse(&session, "opcua", &altered, 103, 1, "request ID/handle");
  altered = response; ua_set(&altered, "uabin:header.request_handle", 99);
  refuse(&session, "opcua", &altered, 103, 1, "request ID/handle");
  altered = response; ua_set(&altered, "uabin:sequence", 1);
  refuse(&session, "opcua", &altered, 103, 1, "sequence");
  OK(psc_after_response(&session, "opcua", response.bytes, response.size, 103, error, sizeof(error)));
  refuse(&session, "opcua", &request, 104, 0, "sequence");
  packet close = fixture("opcua_tcp", "close_channel");
  OK(psc_before_send(&session, "opcua", close.bytes, close.size, 104, error, sizeof(error)));
  assert(session.opcua.closed && !session.opcua.pending && !session.opcua.channel);
  refuse(&session, "opcua", &request, 104, 0, "already closed");
}

static void ua_expiry_fault_and_limits(void) {
  psc_session session; negotiate(&session, 0); open_channel(&session, 1);
  packet request = fixture("opcua_tcp", "message");
  uint64_t expiry = session.opcua.token_expires_ms;
  refuse(&session, "opcua", &request, expiry, 0, "expired");
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, expiry - 1, error, sizeof(error)));
  packet response = fixture("opcua_tcp", "service_fault");
  refuse(&session, "opcua", &response, expiry, 1, "expired");

  negotiate(&session, 10); open_channel(&session, 11);
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, 12, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", response.bytes, response.size, 13, error, sizeof(error)));
  assert(!session.opcua.pending);
  refuse(&session, "opcua", &request, 9, 0, "moved backwards");

  packet hello = fixture("opcua_tcp", "hello"), ack = fixture("opcua_tcp", "ack");
  psc_session_reset(&session); put32(ack.bytes + 20, 1);
  OK(psc_before_send(&session, "opcua", hello.bytes, hello.size, 0, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", ack.bytes, ack.size, 0, error, sizeof(error)));
  packet open = fixture("opcua_tcp", "open_channel");
  refuse(&session, "opcua", &open, 1, 0, "MaxMessageSize");

  negotiate(&session, 0); open_channel(&session, 1);
  packet transport_error; memset(&transport_error, 0, sizeof(transport_error));
  transport_error.size = 9016; memcpy(transport_error.bytes, "ERRF", 4);
  put32(transport_error.bytes + 4, (uint32_t)transport_error.size);
  put32(transport_error.bytes + 8, 0x80000000u); put32(transport_error.bytes + 12, 9000);
  memset(transport_error.bytes + 16, 'x', 9000);
  session.opcua.client_receive_buffer = 8192;
  refuse(&session, "opcua", &transport_error, 2, 1, "Hello receive buffer");
}

static void ua_failed_open_does_not_install_token(void) {
  psc_session session; negotiate(&session, 0);
  packet request = fixture("opcua_tcp", "open_channel"), response = fixture("opcua_tcp", "open_channel_response");
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, 1, error, sizeof(error)));
  packet altered = response; ua_set(&altered, "uabin:request_id", 77);
  refuse(&session, "opcua", &altered, 2, 1, "request ID/handle");
  assert(!session.opcua.channel && !session.opcua.token);
  altered = response; ua_set(&altered, "uabin:token.lifetime", 1);
  refuse(&session, "opcua", &altered, 2, 1, "already expired");
  assert(!session.opcua.channel && !session.opcua.token);
  OK(psc_after_response(&session, "opcua", response.bytes, response.size, 2, error, sizeof(error)));
}

static void ua_limits_boundaries_and_clock(void) {
  psc_session session;
  packet request = fixture("opcua_tcp", "message");
  packet response = fixture("opcua_tcp", "message_response");
  size_t offset, length;
  assert(pc_opcua_field(request.bytes, request.size, "uabin:service_nodeid", PC_NODEID,
                       0, &offset, &length, error, sizeof(error)) == 1);
  size_t request_body = request.size - offset;
  assert(pc_opcua_field(response.bytes, response.size, "uabin:service_nodeid", PC_NODEID,
                       0, &offset, &length, error, sizeof(error)) == 1);
  size_t response_body = response.size - offset;
  negotiate(&session, 0); open_channel(&session, 1);
  session.opcua.server_max_message = (uint32_t)request_body - 1;
  refuse(&session, "opcua", &request, 2, 0, "MaxMessageSize");
  session.opcua.server_max_message++;
  session.opcua.server_max_chunks = 1;
  OK(psc_before_send(&session, "opcua", request.bytes, request.size, 2, error, sizeof(error)));
  session.opcua.client_max_message = (uint32_t)response_body - 1;
  refuse(&session, "opcua", &response, 3, 1, "MaxMessageSize");
  session.opcua.client_max_message++;
  session.opcua.client_max_chunks = 1;
  packet altered = response; ua_set(&altered, "uabin:token", 99);
  refuse(&session, "opcua", &altered, 3, 1, "different channel/token");
  refuse(&session, "opcua", &response, PSC_TIME_UNAVAILABLE, 1, "clock is unavailable");
  OK(psc_after_response(&session, "opcua", response.bytes, response.size, 3, error, sizeof(error)));

  /* An ERR is a complete transport chunk too, even without a service body. */
  packet hello = fixture("opcua_tcp", "hello"), ack = fixture("opcua_tcp", "ack");
  put32(ack.bytes + 16, 8192);
  psc_session_reset(&session);
  OK(psc_before_send(&session, "opcua", hello.bytes, hello.size, 0, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", ack.bytes, ack.size, 0, error, sizeof(error)));
  packet transport_error; memset(&transport_error, 0, sizeof(transport_error));
  transport_error.size = 8193; memcpy(transport_error.bytes, "ERRF", 4);
  put32(transport_error.bytes + 4, (uint32_t)transport_error.size);
  put32(transport_error.bytes + 8, 0x80000000u);
  put32(transport_error.bytes + 12, (uint32_t)transport_error.size - 16);
  memset(transport_error.bytes + 16, 'x', transport_error.size - 16);
  refuse(&session, "opcua", &transport_error, 1, 1, "negotiated buffer");
  transport_error.size--;
  put32(transport_error.bytes + 4, (uint32_t)transport_error.size);
  put32(transport_error.bytes + 12, (uint32_t)transport_error.size - 16);
  OK(psc_after_response(&session, "opcua", transport_error.bytes, transport_error.size,
                         1, error, sizeof(error)));
  assert(session.opcua.closed);

  negotiate(&session, UINT64_MAX - 100);
  packet open = fixture("opcua_tcp", "open_channel");
  packet opened = fixture("opcua_tcp", "open_channel_response");
  OK(psc_before_send(&session, "opcua", open.bytes, open.size, UINT64_MAX - 99,
                     error, sizeof(error)));
  refuse(&session, "opcua", &opened, UINT64_MAX - 98, 1, "already expired");
}

static void ua_request_chunk_and_issue_profile(void) {
  psc_session session;
  packet hello = fixture("opcua_tcp", "hello"), ack = fixture("opcua_tcp", "ack");
  put32(ack.bytes + 12, 8192);
  psc_session_reset(&session);
  OK(psc_before_send(&session, "opcua", hello.bytes, hello.size, 0, error, sizeof(error)));
  OK(psc_after_response(&session, "opcua", ack.bytes, ack.size, 0, error, sizeof(error)));
  open_channel(&session, 1);
  packet request = fixture("opcua_tcp", "message");
  uint8_t endpoint[9000]; memset(endpoint, 'x', sizeof(endpoint));
  OK(pc_opcua_replace(request.bytes, &request.size, sizeof(request.bytes),
                       "uabin:endpoint", PC_STRING, endpoint, sizeof(endpoint),
                       error, sizeof(error)));
  assert(request.size > 8192);
  refuse(&session, "opcua", &request, 2, 0, "negotiated buffer");
  request = fixture("opcua_tcp", "message"); request.bytes[3] = 'C';
  refuse(&session, "opcua", &request, 2, 0, "only final");
  packet renew = fixture("opcua_tcp", "open_channel");
  ua_set(&renew, "uabin:open.request_type", 1);
  ua_set(&renew, "uabin:channel", session.opcua.channel);
  ua_set(&renew, "uabin:sequence", 2);
  refuse(&session, "opcua", &renew, 2, 0, "not Renew");
  request = fixture("opcua_tcp", "message");
  session.opcua.client_sequence = UINT32_MAX;
  refuse(&session, "opcua", &request, 2, 0, "exhausted");
}

int main(void) {
  assert(psc_monotonic_ms() != PSC_TIME_UNAVAILABLE);
  modbus_pairs(); modbus_quantity_padding_and_echo(); modbus_exception_identity();
  ua_ack_and_zero_limits(); ua_correlation_sequence_and_close();
  ua_expiry_fault_and_limits(); ua_failed_open_does_not_install_token();
  ua_limits_boundaries_and_clock();
  ua_request_chunk_and_issue_profile();
  printf("PASS: %u cross-message session checks, atomic refusals and full wire pairs\n", assertions);
  return 0;
}
