/* Independent seventh-protocol test: no protocol-specific codec is linked. */
#include "generic_wire.h"
#include "native_json.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static uint32_t draw(uint32_t limit) { return limit ? 0 : 0; }
static uint32_t draw_last(uint32_t limit) { return limit ? limit - 1 : 0; }

static gw_schema *compile_fields(const char *fields, nj_document **doc,
                                 char *error, size_t cap) {
  char json[8192];
  int n = snprintf(json, sizeof(json), "{\"kind\":\"struct\",\"fields\":[%s]}", fields);
  if (n < 0 || (size_t)n >= sizeof(json) ||
      nj_parse_buffer((const unsigned char *)json, (size_t)n, doc, error, cap) < 0)
    return NULL;
  return gw_compile((*doc)->root, error, cap);
}

static int test_forward_resize(void) {
  static const char fields[] =
    "{\"id\":\"length\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":2,"
      "\"byte_order\":\"little\",\"derived\":{\"op\":\"size_of\",\"target\":\"payload\",\"add\":2}},"
    "{\"id\":\"payload\",\"kind\":\"bytes\",\"role\":\"content\","
      "\"length\":{\"ref\":\"length\",\"add\":-2},\"min\":0,\"max\":4},"
    "{\"id\":\"suffix\",\"kind\":\"uint\",\"role\":\"fixed\",\"width\":1,"
      "\"byte_order\":\"big\",\"expected\":165},"
    "{\"id\":\"marker\",\"kind\":\"uint\",\"role\":\"content\",\"width\":1,\"byte_order\":\"big\"}";
  static const unsigned char seed[] = {4, 0, 'x', 'y', 0xa5, 7};
  static const unsigned char grow[] = {0, 0, 'a', 'b', 'c', 'd', 0, 0};
  static const unsigned char shrink[] = {0, 0, 'z', 0, 0};
  static const unsigned char empty[] = {0, 0, 0, 0};
  static const unsigned char marker[] = {0, 0, 0, 0, 0, 9};
  static const unsigned char clipped[] = {0, 0, '1', '2', '3', '4', '5', 0, 0};
  unsigned char out[16], before[16];
  char error[256]; size_t n, at, z; uint64_t value;
  nj_document *doc = NULL; gw_packet *p = NULL, *other = NULL;
  gw_schema *s = compile_fields(fields, &doc, error, sizeof(error));
  CHECK(s != NULL);
  CHECK(gw_parse(s, seed, sizeof(seed), &p, error, sizeof(error)) == 0);
  CHECK(gw_set_u64(p, "length", 9, error, sizeof(error)) < 0);
  CHECK(gw_mutate(p, 2, grow, sizeof(grow), draw, error, sizeof(error)) == 0);
  CHECK(gw_get_u64(p, "length", &value) == 0 && value == 6);
  CHECK(gw_field_range(p, "marker", &at, &z) == 0 && at == 7 && z == 1);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 8 && out[0] == 6 && out[1] == 0 && !memcmp(out + 2, "abcd", 4));
  CHECK(out[6] == 0xa5 && out[7] == 7);
  /* The original scalar projection stays at byte 5 after the payload grows. */
  CHECK(gw_mutate(p, 2, marker, sizeof(marker), draw_last, error, sizeof(error)) == 0);
  CHECK(gw_get_u64(p, "marker", &value) == 0 && value == 9);
  CHECK(gw_mutate(p, 2, shrink, sizeof(shrink), draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 5 && out[0] == 3 && out[2] == 'z' && out[3] == 0xa5 && out[4] == 9);
  CHECK(gw_field_range(p, "suffix", &at, &z) == 0 && at == 3 && z == 1);
  CHECK(gw_mutate(p, 2, empty, sizeof(empty), draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 4 && out[0] == 2 && out[2] == 0xa5 && out[3] == 9);
  CHECK(gw_field_range(p, "payload", &at, &z) == 0 && at == 2 && z == 0);
  memcpy(before, out, n);
  CHECK(gw_mutate(p, 2, empty, 3, draw, error, sizeof(error)) < 0);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 4 && !memcmp(out, before, n));
  CHECK(gw_mutate(p, 2, clipped, sizeof(clipped), draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, SIZE_MAX, &n, error, sizeof(error)) == 0);
  CHECK(n == 8 && out[0] == 6 && !memcmp(out + 2, "1234", 4));
  CHECK(out[6] == 0xa5 && out[7] == 9);
  CHECK(gw_parse(s, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  memcpy(before, out, n);
  memset(out, 0x5a, sizeof(out));
  CHECK(gw_encode(p, out, n - 1, &n, error, sizeof(error)) < 0 && n == 0);
  for (size_t i = 0; i < sizeof(out); i++) CHECK(out[i] == 0x5a);
  CHECK(gw_get_u64(p, "length", &value) == 0 && value == 6);
  CHECK(gw_field_range(p, "marker", &at, &z) == 0 && at == 7 && z == 1);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 8 && !memcmp(out, before, n));
  out[0] = 1; /* ref + add is negative. */
  CHECK(gw_parse(s, out, n, &other, error, sizeof(error)) < 0 && other == NULL);
  out[0] = 7; /* Payload bound/truncation violation. */
  CHECK(gw_parse(s, out, n, &other, error, sizeof(error)) < 0 && other == NULL);
  gw_packet_free(p); gw_free(s); nj_free(doc);
  return 0;
}

static int test_message_and_positive_add(void) {
  static const char *const rules[] = {
    /* A byte count based on total message size, including a fixed suffix. */
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":1,\"byte_order\":\"big\","
      "\"derived\":{\"op\":\"size_of\",\"target\":\"$message\",\"add\":-3}},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"min\":1,\"max\":3,"
      "\"length\":{\"ref\":\"n\",\"add\":1}},"
    "{\"id\":\"end\",\"kind\":\"bytes\",\"role\":\"fixed\",\"length\":1,\"expected_hex\":\"ff\"}",
    /* The inverse adds must cancel, with the signed derived add applied once. */
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":1,\"byte_order\":\"big\","
      "\"derived\":{\"op\":\"size_of\",\"target\":\"data\",\"add\":-1}},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"min\":1,\"max\":3,"
      "\"length\":{\"ref\":\"n\",\"add\":1}},"
    "{\"id\":\"end\",\"kind\":\"bytes\",\"role\":\"fixed\",\"length\":1,\"expected_hex\":\"ff\"}"
  };
  static const unsigned char seed[] = {1, 'x', 'y', 0xff};
  static const unsigned char grow[] = {0, 'a', 'b', 'c', 0};
  static const unsigned char shrink[] = {0, 'z', 0};
  unsigned char out[16], before[16]; char error[256]; size_t n;
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
    nj_document *doc = NULL; gw_packet *p = NULL;
    gw_schema *s = compile_fields(rules[i], &doc, error, sizeof(error));
    CHECK(s != NULL);
    CHECK(gw_parse(s, seed, sizeof(seed), &p, error, sizeof(error)) == 0);
    CHECK(gw_mutate(p, 2, grow, sizeof(grow), draw, error, sizeof(error)) == 0);
    CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
    CHECK(n == 5 && out[0] == 2 && !memcmp(out + 1, "abc", 3) && out[4] == 0xff);
    CHECK(gw_mutate(p, 2, shrink, sizeof(shrink), draw, error, sizeof(error)) == 0);
    CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
    CHECK(n == 3 && out[0] == 0 && out[1] == 'z' && out[2] == 0xff);
    memcpy(before, out, n);
    CHECK(gw_mutate(p, 2, shrink, 2, draw, error, sizeof(error)) < 0);
    CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
    CHECK(n == 3 && !memcmp(out, before, n));
    gw_packet_free(p); gw_free(s); nj_free(doc);
  }
  return 0;
}

static int test_dependency_failures(void) {
  static const char fields[] =
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":1,\"byte_order\":\"big\","
      "\"max\":3,\"derived\":{\"op\":\"size_of\",\"target\":\"data\"}},"
    "{\"id\":\"mirror\",\"kind\":\"uint\",\"role\":\"head\",\"width\":1,\"byte_order\":\"big\"},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"max\":8,\"length\":{\"ref\":\"n\"}},"
    "{\"id\":\"copy\",\"kind\":\"bytes\",\"role\":\"fixed\",\"length\":{\"ref\":\"mirror\"},\"expected_hex\":\"ffee\"}";
  static const unsigned char seed[] = {2, 2, 'x', 'y', 0xff, 0xee};
  static const unsigned char grow[] = {0, 0, 'a', 'b', 'c', 'd', 0, 0};
  unsigned char out[16]; char error[256]; size_t n, at, z; uint64_t value;
  nj_document *doc = NULL; gw_packet *p = NULL;
  gw_schema *s = compile_fields(fields, &doc, error, sizeof(error));
  CHECK(s != NULL);
  CHECK(gw_parse(s, seed, sizeof(seed), &p, error, sizeof(error)) == 0);
  /* The leaf allows growth, but the derived uint's bound forbids it. */
  CHECK(gw_mutate(p, 2, grow, sizeof(grow), draw, error, sizeof(error)) < 0);
  CHECK(gw_get_u64(p, "n", &value) == 0 && value == 2);
  CHECK(gw_field_range(p, "copy", &at, &z) == 0 && at == 4 && z == 2);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == sizeof(seed) && !memcmp(out, seed, n));
  /* A writable length may be inconsistent until encode, which must be atomic. */
  CHECK(gw_set_u64(p, "mirror", 1, error, sizeof(error)) == 0);
  memset(out, 0x5a, sizeof(out)); n = 99;
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) < 0 && n == 0);
  for (size_t i = 0; i < sizeof(out); i++) CHECK(out[i] == 0x5a);
  CHECK(gw_get_u64(p, "mirror", &value) == 0 && value == 1);
  CHECK(gw_get_u64(p, "n", &value) == 0 && value == 2);
  CHECK(gw_mutate(p, 2, seed, sizeof(seed), draw, error, sizeof(error)) < 0);
  CHECK(gw_get_u64(p, "mirror", &value) == 0 && value == 1);
  CHECK(gw_set_u64(p, "mirror", 2, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == sizeof(seed) && !memcmp(out, seed, n));
  gw_packet_free(p); gw_free(s); nj_free(doc);
  return 0;
}

static int test_length_arithmetic(void) {
  static const char *const rules[] = {
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"head\",\"width\":8,\"byte_order\":\"big\"},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\","
      "\"length\":{\"ref\":\"n\",\"add\":-9223372036854775808}}",
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"head\",\"width\":8,\"byte_order\":\"big\"},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\","
      "\"length\":{\"ref\":\"n\",\"add\":9223372036854775807}}"
  };
  unsigned char wire[9] = {0x80, 0, 0, 0, 0, 0, 0, 0, 'a'}, out[16];
  char error[256]; size_t n;
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
    nj_document *doc = NULL; gw_packet *p = NULL;
    gw_schema *s = compile_fields(rules[i], &doc, error, sizeof(error));
    CHECK(s != NULL);
    if (i == 0) {
      CHECK(gw_parse(s, wire, 8, &p, error, sizeof(error)) == 0);
      CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
      CHECK(n == 8 && !memcmp(out, wire, n));
      gw_packet_free(p); p = NULL;
      wire[7] = 1;
      CHECK(gw_parse(s, wire, 9, &p, error, sizeof(error)) == 0);
      CHECK(gw_encode(p, out, sizeof(out), &n, error, sizeof(error)) == 0);
      CHECK(n == 9 && !memcmp(out, wire, n));
      gw_packet_free(p); p = NULL;
      memset(wire, 0, 8);
      CHECK(gw_parse(s, wire, 8, &p, error, sizeof(error)) < 0 && p == NULL);
    } else {
      memset(wire, 0xff, 8); /* Overflow must not wrap down to a small size. */
      CHECK(gw_parse(s, wire, 8, &p, error, sizeof(error)) < 0 && p == NULL);
      memset(wire, 0, 8);
      CHECK(gw_parse(s, wire, 8, &p, error, sizeof(error)) < 0 && p == NULL);
    }
    gw_free(s); nj_free(doc);
  }
  return 0;
}

static int test_wire_budget(void) {
  static const char fields[] =
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":4,\"byte_order\":\"big\","
      "\"derived\":{\"op\":\"size_of\",\"target\":\"data\"}},"
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":\"rest\"}";
  static const unsigned char seed[] = {0, 0, 0, 0};
  unsigned char *candidate = malloc(GW_MAX_WIRE + 1u), *out = malloc(GW_MAX_WIRE);
  char error[256]; size_t n; uint64_t value;
  nj_document *doc = NULL; gw_packet *p = NULL, *other = NULL;
  gw_schema *s = compile_fields(fields, &doc, error, sizeof(error));
  CHECK(s != NULL && candidate != NULL && out != NULL);
  memset(candidate, 0xab, GW_MAX_WIRE + 1u);
  CHECK(gw_parse(s, seed, sizeof(seed), &p, error, sizeof(error)) == 0);
  CHECK(gw_mutate(p, 2, candidate, GW_MAX_WIRE, draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, GW_MAX_WIRE, &n, error, sizeof(error)) == 0 && n == GW_MAX_WIRE);
  CHECK(gw_get_u64(p, "n", &value) == 0 && value == GW_MAX_WIRE - 4);
  CHECK(out[4] == 0xab && out[n - 1] == 0xab);
  CHECK(gw_parse(s, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  CHECK(gw_parse(s, candidate, GW_MAX_WIRE + 1u, &other, error, sizeof(error)) < 0 && other == NULL);
  CHECK(gw_mutate(p, 2, candidate, GW_MAX_WIRE + 1u, draw, error, sizeof(error)) < 0);
  CHECK(gw_mutate(p, 2, seed, sizeof(seed), draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, out, GW_MAX_WIRE, &n, error, sizeof(error)) == 0);
  CHECK(n == sizeof(seed) && !memcmp(out, seed, n));
  gw_packet_free(p); gw_free(s); nj_free(doc); free(candidate); free(out);

  doc = NULL; p = NULL;
  s = compile_fields("{\"id\":\"empty\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":0}",
                     &doc, error, sizeof(error));
  CHECK(s != NULL);
  CHECK(gw_parse(s, NULL, 0, &p, error, sizeof(error)) == 0);
  unsigned char byte = 0x5a;
  CHECK(gw_encode(p, &byte, 0, &n, error, sizeof(error)) == 0 && n == 0 && byte == 0x5a);
  CHECK(gw_mutate(p, 2, NULL, 0, draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(p, &byte, 0, &n, error, sizeof(error)) == 0 && n == 0);
  gw_packet_free(p); gw_free(s); nj_free(doc);
  return 0;
}

static int test_compile_rejections(void) {
  static const char *const fields[] = {
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":1,\"byte_order\":\"big\","
      "\"derived\":{\"op\":\"size_of\",\"target\":\"missing\"}}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":{\"ref\":\"n\"}},"
      "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"head\",\"width\":1,\"byte_order\":\"big\"}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":0},"
      "{\"id\":\"other\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":{\"ref\":\"data\"}}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":\"rest\"},"
      "{\"id\":\"other\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":0}",
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"head\",\"width\":1,\"byte_order\":\"big\"},"
      "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\","
      "\"length\":{\"ref\":\"n\",\"add\":9223372036854775808}}",
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"derived\",\"width\":1,\"byte_order\":\"big\","
      "\"derived\":{\"op\":\"size_of\",\"target\":\"n\",\"add\":-9223372036854775809}}",
    "{\"id\":\"n\",\"kind\":\"uint\",\"role\":\"head\",\"width\":9,\"byte_order\":\"big\"}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"fixed\",\"length\":0,\"expected_hex\":\"gg\"}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"fixed\",\"length\":0,\"expected_hex\":\"\"},"
      "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":0}",
    "{\"id\":\"data\",\"kind\":\"bytes\",\"role\":\"content\",\"length\":1,\"min\":2}"
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    nj_document *doc = NULL; char error[256] = {0};
    gw_schema *s = compile_fields(fields[i], &doc, error, sizeof(error));
    CHECK(s == NULL && error[0] != 0);
    nj_free(doc);
  }
  return 0;
}

static int valid_bytes(const unsigned char *wire, size_t n) {
  return n >= 7 && n <= 14 && wire[0] == 0xa7 && wire[3] == 1 &&
         ((unsigned)wire[1] << 8 | wire[2]) == n - 3 &&
         (((unsigned)wire[4] << 8 | wire[5]) >= 1);
}

int main(int argc, char **argv) {
  static const unsigned char seed[] = {0xa7,0,5,1,0,1,0x55,0x66};
  static const unsigned char bad_magic[] = {0xa6,0,5,1,0,1,0x55,0x66};
  static const unsigned char bad_length[] = {0xa7,0,4,1,0,1,0x55,0x66};
  static const unsigned char bad_opcode[] = {0xa7,0,5,2,0,1,0x55,0x66};
  static const unsigned char too_short[] = {0xa7,0,3,1,0,1};
  static const unsigned char too_long[] = {0xa7,0,12,1,0,1,1,2,3,4,5,6,7,8,9,10,11,12};
  unsigned char out[64], before[64], candidate[64];
  char error[256] = {0};
  size_t n = 0, before_n = 0, at = 0, width = 0;
  uint64_t serial = 0;
  nj_document *document = NULL;
  gw_schema *schema = NULL;
  gw_packet *packet = NULL, *other = NULL;
  const nj_value *messages, *grammar;
  CHECK(argc == 2);
  CHECK(test_forward_resize() == 0);
  CHECK(test_message_and_positive_add() == 0);
  CHECK(test_dependency_failures() == 0);
  CHECK(test_length_arithmetic() == 0);
  CHECK(test_wire_budget() == 0);
  CHECK(test_compile_rejections() == 0);
  CHECK(nj_load_file(argv[1], &document, error, sizeof(error)) == 0);
  CHECK(nj_string_equal(nj_get(document->root, "format"), "stateafl.generic-wire"));
  messages = nj_get(document->root, "messages");
  CHECK(messages && messages->type == NJ_ARRAY && messages->count == 1);
  grammar = nj_get(messages->items[0], "grammar");
  CHECK(grammar != NULL);
  schema = gw_compile(grammar, error, sizeof(error));
  CHECK(schema != NULL);

  CHECK(gw_parse(schema, seed, sizeof(seed), &packet, error, sizeof(error)) == 0);
  CHECK(packet != NULL);
  CHECK(gw_get_u64(packet, "serial", &serial) == 0 && serial == 1);
  CHECK(gw_field_range(packet, "serial", &at, &width) == 0 && at == 4 && width == 2);
  CHECK(gw_field_range(packet, "payload", &at, &width) == 0 && at == 6 && width == 2);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == sizeof(seed) && !memcmp(out, seed, n));
  CHECK(gw_set_u64(packet, "magic", 0xa6, error, sizeof(error)) < 0);
  CHECK(gw_set_u64(packet, "serial", 0, error, sizeof(error)) < 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == sizeof(seed) && !memcmp(out, seed, n));

  CHECK(gw_set_u64(packet, "serial", 3, error, sizeof(error)) == 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(valid_bytes(out, n) && out[4] == 0 && out[5] == 3);
  CHECK(gw_parse(schema, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  gw_packet_free(packet); packet = NULL;

  CHECK(gw_parse(schema, seed, sizeof(seed), &packet, error, sizeof(error)) == 0);
  memcpy(candidate, seed, sizeof(seed));
  memcpy(candidate + 6, "abcdef", 6);
  CHECK(gw_mutate(packet, 2, candidate, 12, draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == 12 && valid_bytes(out, n) && out[1] == 0 && out[2] == 9);
  CHECK(out[0] == 0xa7 && out[3] == 1 && out[4] == 0 && out[5] == 1);
  CHECK(!memcmp(out + 6, "abcdef", 6));
  CHECK(gw_parse(schema, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  gw_packet_free(packet); packet = NULL;

  CHECK(gw_parse(schema, seed, sizeof(seed), &packet, error, sizeof(error)) == 0);
  memset(out, 0x5a, sizeof(out));
  CHECK(gw_encode(packet, out, 1, &n, error, sizeof(error)) < 0);
  CHECK(out[0] == 0x5a && out[1] == 0x5a);
  gw_packet_free(packet); packet = NULL;

  CHECK(gw_parse(schema, seed, sizeof(seed), &packet, error, sizeof(error)) == 0);
  CHECK(gw_mutate(packet, 1, seed, sizeof(seed), draw_last, error, sizeof(error)) == 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(valid_bytes(out, n) && out[4] == 0 && out[5] == 2);
  CHECK(out[6] == seed[6] && out[7] == seed[7]);
  CHECK(gw_parse(schema, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  gw_packet_free(packet); packet = NULL;

  CHECK(gw_parse(schema, seed, sizeof(seed), &packet, error, sizeof(error)) == 0);
  memcpy(candidate, seed, sizeof(seed));
  candidate[6] = 0x33; candidate[7] = 0x44;
  CHECK(gw_mutate(packet, 2, candidate, sizeof(seed), draw, error, sizeof(error)) == 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(valid_bytes(out, n) && out[4] == 0 && out[5] == 1);
  CHECK(out[6] == 0x33 && out[7] == 0x44);
  CHECK(gw_parse(schema, out, n, &other, error, sizeof(error)) == 0);
  gw_packet_free(other); other = NULL;
  memcpy(before, out, n); before_n = n;
  CHECK(gw_mutate(packet, 2, NULL, 0, draw, error, sizeof(error)) < 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == before_n && !memcmp(out, before, n));
  CHECK(gw_mutate(packet, 4, candidate, sizeof(seed), draw, error, sizeof(error)) < 0);
  CHECK(gw_encode(packet, out, sizeof(out), &n, error, sizeof(error)) == 0);
  CHECK(n == before_n && !memcmp(out, before, n));
  gw_packet_free(packet); packet = NULL;

  const struct { const unsigned char *data; size_t length; } invalid[] = {
    {bad_magic, sizeof(bad_magic)}, {bad_length, sizeof(bad_length)},
    {bad_opcode, sizeof(bad_opcode)}, {too_short, sizeof(too_short)},
    {too_long, sizeof(too_long)}
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    CHECK(gw_parse(schema, invalid[i].data, invalid[i].length,
                   &other, error, sizeof(error)) < 0);
    CHECK(other == NULL);
  }
  gw_free(schema); nj_free(document);
  printf("PASS: seventh-protocol generic C parse, encode, HEAD, CONTENT and rejection (%u checks)\n", checks);
  return 0;
}
