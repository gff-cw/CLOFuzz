/* Unit test for P16: UDP datagram boundary preservation across host, network, and runtime */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "alloc-inl.h"
#include "aflnet.h"
#include "protocol_runtime.h"
#include "generic_runtime.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

typedef struct {
  unsigned dgram_count;
  size_t lengths[16];
  uint8_t payloads[16][256];
  int is_dgram_flags[16];
} cb_trace_t;

static void trace_cb(const uint8_t *buf, size_t len, int is_dgram, int truncated, void *user) {
  cb_trace_t *trace = (cb_trace_t *)user;
  (void)truncated;
  if (trace->dgram_count < 16) {
    trace->lengths[trace->dgram_count] = len;
    trace->is_dgram_flags[trace->dgram_count] = is_dgram;
    if (len <= sizeof(trace->payloads[0]))
      memcpy(trace->payloads[trace->dgram_count], buf, len);
    trace->dgram_count++;
  }
}

static proto_engine *load_json_profile(const char *json_content, char *error, size_t cap) {
  char path[] = "/tmp/stateafl-udp-test-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) { snprintf(error, cap, "tempfile creation failed"); return NULL; }
  FILE *f = fdopen(fd, "wb");
  if (!f) { close(fd); remove(path); snprintf(error, cap, "tempfile open failed"); return NULL; }
  fputs(json_content, f);
  fclose(f);
  proto_engine *e = proto_load_generic(path, error, cap);
  remove(path);
  return e;
}

int main(void) {
  printf("[*] Testing P16: UDP datagram boundaries...\n");

  /* ------------------------------------------------------------------ */
  /* Part 1: net_recv_with_cb preserves discrete datagram boundaries    */
  /* ------------------------------------------------------------------ */
  int sock_a = socket(AF_INET, SOCK_DGRAM, 0);
  int sock_b = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(sock_a >= 0 && sock_b >= 0);

  struct sockaddr_in addr_a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  struct sockaddr_in addr_b = addr_a;
  CHECK(bind(sock_a, (struct sockaddr *)&addr_a, sizeof(addr_a)) == 0);
  CHECK(bind(sock_b, (struct sockaddr *)&addr_b, sizeof(addr_b)) == 0);

  socklen_t slen = sizeof(addr_a);
  CHECK(getsockname(sock_a, (struct sockaddr *)&addr_a, &slen) == 0);
  slen = sizeof(addr_b);
  CHECK(getsockname(sock_b, (struct sockaddr *)&addr_b, &slen) == 0);

  CHECK(connect(sock_a, (struct sockaddr *)&addr_b, sizeof(addr_b)) == 0);
  CHECK(connect(sock_b, (struct sockaddr *)&addr_a, sizeof(addr_a)) == 0);

  /* Send 2 distinct datagrams from sock_b to sock_a */
  const uint8_t dgram1[] = {0x11, 0x22, 0x33, 0x44};       /* 4 bytes */
  const uint8_t dgram2[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE}; /* 5 bytes */

  CHECK(send(sock_b, dgram1, sizeof(dgram1), 0) == (ssize_t)sizeof(dgram1));
  CHECK(send(sock_b, dgram2, sizeof(dgram2), 0) == (ssize_t)sizeof(dgram2));

  cb_trace_t trace;
  memset(&trace, 0, sizeof(trace));
  char *resp_buf = NULL;
  unsigned int resp_len = 0;
  struct timeval tv = {.tv_usec = 50000}; /* 50ms */

  int rv = net_recv_with_cb(sock_a, tv, 50, &resp_buf, &resp_len, trace_cb, &trace);
  CHECK(rv == 0);
  CHECK(resp_len == sizeof(dgram1) + sizeof(dgram2));
  CHECK(resp_buf != NULL);

  /* Verify callback received 2 discrete datagram events with exact lengths */
  CHECK(trace.dgram_count == 2);
  CHECK(trace.is_dgram_flags[0] == 1);
  CHECK(trace.lengths[0] == sizeof(dgram1));
  CHECK(memcmp(trace.payloads[0], dgram1, sizeof(dgram1)) == 0);

  CHECK(trace.is_dgram_flags[1] == 1);
  CHECK(trace.lengths[1] == sizeof(dgram2));
  CHECK(memcmp(trace.payloads[1], dgram2, sizeof(dgram2)) == 0);

  ck_free(resp_buf);
  close(sock_a);
  close(sock_b);

  /* ------------------------------------------------------------------ */
  /* Part 2: Generic UDP runtime processes discrete datagram responses   */
  /* ------------------------------------------------------------------ */
  const char *udp_profile =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"udp_proto\",\n"
    "  \"online\": true,\n"
    "  \"transport\": \"udp\",\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [\n"
    "    {\n"
    "      \"id\": \"req\",\n"
    "      \"direction\": \"request\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"0101\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"type\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"head\", \"expected\": 1},\n"
    "          {\"id\": \"id\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"content\"}\n"
    "        ]\n"
    "      }\n"
    "    },\n"
    "    {\n"
    "      \"id\": \"resp\",\n"
    "      \"direction\": \"response\",\n"
    "      \"weight\": 1,\n"
    "      \"example_hex\": \"8101\",\n"
    "      \"grammar\": {\n"
    "        \"kind\": \"struct\",\n"
    "        \"fields\": [\n"
    "          {\"id\": \"type\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"head\", \"expected\": 129},\n"
    "          {\"id\": \"id\", \"kind\": \"uint\", \"width\": 1, \"byte_order\": \"big\", \"role\": \"content\"}\n"
    "        ]\n"
    "      },\n"
    "      \"correlate\": [\n"
    "        {\"request\": \"req\", \"field\": \"id\", \"source\": \"id\"}\n"
    "      ]\n"
    "    }\n"
    "  ],\n"
    "  \"states\": {\n"
    "    \"initial\": \"init\",\n"
    "    \"transitions\": [\n"
    "      {\"from\": \"init\", \"to\": \"done\", \"message\": \"req\", \"response\": \"resp\"}\n"
    "    ]\n"
    "  },\n"
    "  \"limits\": {\"max_messages\": 4, \"max_repeat\": 4, \"max_bytes\": 128}\n"
    "}";

  char err[512] = {0};
  proto_engine *pe = load_json_profile(udp_profile, err, sizeof(err));
  CHECK(pe != NULL);

  /* Send request */
  uint8_t req_wire[] = {0x01, 0x42};
  CHECK(proto_before_send(pe, req_wire, sizeof(req_wire), err, sizeof(err)) == 0);

  /* Now simulate arrival of two separate UDP datagrams:
     First is an unrelated/dummy response: {0x81, 0x99} (mismatched correlation)
     Second is the matching response: {0x81, 0x42} (matches req id 0x42)
  */
  uint8_t resp_unrelated[] = {0x81, 0x99};
  uint8_t resp_matching[] = {0x81, 0x42};

  /* Deliver discrete datagrams via proto_after_dgram */
  proto_after_dgram(pe, resp_unrelated, sizeof(resp_unrelated));
  /* Not completed yet because id 0x99 != 0x42 */
  char stats_file[] = "/tmp/stateafl_udp_stats_XXXXXX";
  int sfd = mkstemp(stats_file);
  CHECK(sfd >= 0);
  close(sfd);

  proto_write_stats(pe, stats_file);
  FILE *sf = fopen(stats_file, "r");
  CHECK(sf != NULL);
  char sbuf[512] = {0};
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);
  CHECK(strstr(sbuf, "\"completed_responses\":0") != NULL);

  /* Now deliver the matching datagram */
  proto_after_dgram(pe, resp_matching, sizeof(resp_matching));

  proto_write_stats(pe, stats_file);
  sf = fopen(stats_file, "r");
  CHECK(sf != NULL);
  memset(sbuf, 0, sizeof(sbuf));
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);
  unlink(stats_file);

  CHECK(strstr(sbuf, "\"completed_responses\":1") != NULL);
  CHECK(strstr(sbuf, "\"correlated_responses\":1") != NULL);

  proto_free(pe);

  printf("PASS: test_udp_datagram_boundaries passed (%u assertions)\n", checks);
  return 0;
}
