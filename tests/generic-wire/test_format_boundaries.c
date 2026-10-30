#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "protocol_runtime.h"
#include "generic_runtime.h"

static void write_file(const char *path, const char *content) {
  FILE *f = fopen(path, "wb");
  assert(f != NULL);
  size_t len = strlen(content);
  assert(fwrite(content, 1, len, f) == len);
  fclose(f);
}

int main(void) {
  char err[512] = {0};
  char gw_path[] = "/tmp/test_gw_format_XXXXXX.json";
  char nl_path[] = "/tmp/test_nl_format_XXXXXX.json";
  char proto_path[] = "/tmp/test_proto_format_XXXXXX.json";
  char state_path[] = "/tmp/test_state_format_XXXXXX.json";

  int fd1 = mkstemps(gw_path, 5);
  int fd2 = mkstemps(nl_path, 5);
  int fd3 = mkstemps(proto_path, 5);
  int fd4 = mkstemps(state_path, 5);
  assert(fd1 >= 0 && fd2 >= 0 && fd3 >= 0 && fd4 >= 0);
  close(fd1); close(fd2); close(fd3); close(fd4);

  /* Generic-wire document */
  const char *gw_json =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"test_gw\",\n"
    "  \"transport\": \"udp\",\n"
    "  \"online\": false,\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [],\n"
    "  \"states\": [],\n"
    "  \"limits\": {\"max_messages\": 32, \"max_bytes\": 4096}\n"
    "}\n";
  write_file(gw_path, gw_json);

  /* Offline-layout document */
  const char *nl_json =
    "{\n"
    "  \"format\": \"stateafl.offline-layout\",\n"
    "  \"version\": 1,\n"
    "  \"description\": \"mock\"\n"
    "}\n";
  write_file(nl_path, nl_json);

  /* Protocol IR with format */
  const char *proto_json =
    "{\n"
    "  \"format\": \"stateafl.protocol-ir\",\n"
    "  \"ir_version\": 1,\n"
    "  \"codec\": \"mock\",\n"
    "  \"bundle_digest\": \"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\",\n"
    "  \"messages\": []\n"
    "}\n";
  write_file(proto_path, proto_json);

  /* State IR with format */
  const char *state_json =
    "{\n"
    "  \"format\": \"stateafl.state-ir\",\n"
    "  \"ir_version\": 1,\n"
    "  \"protocol_id\": \"mock\",\n"
    "  \"bundle_digest\": \"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\",\n"
    "  \"initial\": \"init\",\n"
    "  \"limits\": {\"max_messages\": 32, \"max_repeat\": 4, \"max_bytes\": 4096},\n"
    "  \"states\": [{\"id\": \"init\"}],\n"
    "  \"transitions\": []\n"
    "}\n";
  write_file(state_path, state_json);

  /* 1. Test proto_load rejecting generic_wire file */
  proto_engine *p1 = proto_load(gw_path, state_path, err, sizeof(err));
  assert(p1 == NULL);
  assert(strstr(err, "incompatible specification format: stateafl.generic-wire") != NULL);

  /* 2. Test proto_load rejecting offline_layout file */
  err[0] = 0;
  proto_engine *p2 = proto_load(nl_path, state_path, err, sizeof(err));
  assert(p2 == NULL);
  assert(strstr(err, "incompatible specification format: stateafl.offline-layout") != NULL);

  /* 3. Test gr_load rejecting offline_layout file */
  err[0] = 0;
  gr_engine *g1 = gr_load(nl_path, err, sizeof(err));
  assert(g1 == NULL);
  assert(strstr(err, "incompatible specification format: stateafl.offline-layout") != NULL);

  /* 4. Test gr_load rejecting protocol_ir file */
  err[0] = 0;
  gr_engine *g2 = gr_load(proto_path, err, sizeof(err));
  assert(g2 == NULL);
  assert(strstr(err, "incompatible specification format: stateafl.protocol-ir") != NULL);

  /* Clean up temporary files */
  unlink(gw_path);
  unlink(nl_path);
  unlink(proto_path);
  unlink(state_path);

  printf("test_format_boundaries: ALL 4 BOUNDARY CHECKS PASSED\n");
  return 0;
}
