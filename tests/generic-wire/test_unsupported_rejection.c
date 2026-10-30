#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "native_json.h"
#include "generic_wire.h"
#include "generic_runtime.h"

static void write_temp_file(char *template_path, const char *content) {
  int fd = mkstemps(template_path, 5);
  assert(fd >= 0);
  size_t len = strlen(content);
  assert(write(fd, content, len) == (ssize_t)len);
  close(fd);
}

int main(void) {
  char err[512] = {0};
  nj_document *doc = NULL;
  gw_schema *schema = NULL;

  /* 1. Test unsupported grammar kind (e.g. array) */
  const char *bad_kind_json = "{\"kind\": \"array\", \"fields\": []}";
  assert(nj_parse_buffer((const unsigned char *)bad_kind_json, strlen(bad_kind_json), &doc, err, sizeof(err)) == 0);
  schema = gw_compile(doc->root, err, sizeof(err));
  assert(schema == NULL);
  assert(strstr(err, "grammar must be struct") != NULL);
  nj_free(doc); doc = NULL;

  /* 2. Test unsupported field kind (e.g. float) */
  const char *bad_field_kind_json =
    "{\"kind\": \"struct\", \"fields\": [{\"id\": \"temp\", \"kind\": \"float\", \"role\": \"head\"}]}";
  assert(nj_parse_buffer((const unsigned char *)bad_field_kind_json, strlen(bad_field_kind_json), &doc, err, sizeof(err)) == 0);
  schema = gw_compile(doc->root, err, sizeof(err));
  assert(schema == NULL);
  assert(strstr(err, "invalid kind") != NULL);
  nj_free(doc); doc = NULL;

  /* 3. Test unsupported property (e.g. 'when' condition on field) */
  const char *bad_prop_json =
    "{\"kind\": \"struct\", \"fields\": [{\"id\": \"val\", \"kind\": \"uint\", \"role\": \"head\", \"width\": 2, \"byte_order\": \"big\", \"when\": \"x > 0\"}]}";
  assert(nj_parse_buffer((const unsigned char *)bad_prop_json, strlen(bad_prop_json), &doc, err, sizeof(err)) == 0);
  schema = gw_compile(doc->root, err, sizeof(err));
  assert(schema == NULL);
  assert(strstr(err, "unsupported JSON property") != NULL);
  nj_free(doc); doc = NULL;

  /* 4. Test rest length not on final field */
  const char *bad_rest_json =
    "{\"kind\": \"struct\", \"fields\": ["
    "  {\"id\": \"payload\", \"kind\": \"bytes\", \"role\": \"content\", \"length\": \"rest\"},"
    "  {\"id\": \"trailer\", \"kind\": \"uint\", \"role\": \"fixed\", \"width\": 1, \"byte_order\": \"big\", \"expected\": 0}"
    "]}";
  assert(nj_parse_buffer((const unsigned char *)bad_rest_json, strlen(bad_rest_json), &doc, err, sizeof(err)) == 0);
  schema = gw_compile(doc->root, err, sizeof(err));
  assert(schema == NULL);
  assert(strstr(err, "rest must be final") != NULL);
  nj_free(doc); doc = NULL;

  /* 5. Test length reference pointing to nonexistent field */
  const char *bad_ref_json =
    "{\"kind\": \"struct\", \"fields\": ["
    "  {\"id\": \"payload\", \"kind\": \"bytes\", \"role\": \"content\", \"length\": {\"ref\": \"len_hdr\"}}"
    "]}";
  assert(nj_parse_buffer((const unsigned char *)bad_ref_json, strlen(bad_ref_json), &doc, err, sizeof(err)) == 0);
  schema = gw_compile(doc->root, err, sizeof(err));
  assert(schema == NULL);
  assert(strstr(err, "length ref must name earlier uint") != NULL);
  nj_free(doc); doc = NULL;

  /* 6. Test gr_load rejecting unsupported transport */
  char bad_pkg_path[] = "/tmp/test_bad_pkg_XXXXXX.json";
  const char *bad_trans_json =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"unsupported_transport\",\n"
    "  \"transport\": \"sctp\",\n"
    "  \"online\": false,\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [],\n"
    "  \"states\": {\"initial\": \"init\", \"transitions\": []},\n"
    "  \"limits\": {\"max_messages\": 32, \"max_repeat\": 4, \"max_bytes\": 4096}\n"
    "}\n";
  write_temp_file(bad_pkg_path, bad_trans_json);
  err[0] = 0;
  gr_engine *ge = gr_load(bad_pkg_path, err, sizeof(err));
  assert(ge == NULL);
  unlink(bad_pkg_path);

  /* 7. Test gr_load rejecting online:false packages */
  char offline_pkg_path[] = "/tmp/test_offline_pkg_XXXXXX.json";
  const char *offline_json =
    "{\n"
    "  \"format\": \"stateafl.generic-wire\",\n"
    "  \"version\": 1,\n"
    "  \"protocol_id\": \"offline_proto\",\n"
    "  \"transport\": \"udp\",\n"
    "  \"online\": false,\n"
    "  \"framing\": {\"kind\": \"datagram\"},\n"
    "  \"messages\": [],\n"
    "  \"states\": {\"initial\": \"init\", \"transitions\": []},\n"
    "  \"limits\": {\"max_messages\": 32, \"max_repeat\": 4, \"max_bytes\": 4096}\n"
    "}\n";
  write_temp_file(offline_pkg_path, offline_json);
  err[0] = 0;
  ge = gr_load(offline_pkg_path, err, sizeof(err));
  assert(ge == NULL);
  assert(strstr(err, "description is offline-only") != NULL);
  unlink(offline_pkg_path);

  printf("test_unsupported_rejection: ALL 7 REJECTION CHECKS PASSED\n");
  return 0;
}
