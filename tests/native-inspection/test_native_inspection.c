#define _POSIX_C_SOURCE 200809L
/* Local-file API and fictional fixture tests; no target or socket is started. */
#include "native_inspect.h"
#include "native_json.h"
#include "fixture_packet.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t checks;
static unsigned case_number;
static char scratch[] = "/tmp/stateafl-native-inspection-XXXXXX";

static void failed(const char *expression, const char *file, int line) {
  fprintf(stderr, "%s:%d: check failed: %s\n", file, line, expression);
  exit(EXIT_FAILURE);
}
#define CHECK(expression) do { \
  checks++; \
  if (!(expression)) failed(#expression, __FILE__, __LINE__); \
} while (0)

static void cleanup(void) {
  char path[256];
  unsigned index;
  for (index = 1; index <= case_number; index++) {
    int n = snprintf(path, sizeof(path), "%s/case-%u", scratch, index);
    if (n > 0 && (size_t)n < sizeof(path)) (void)unlink(path);
  }
  (void)rmdir(scratch);
}

static void case_file(char path[256], const void *bytes, size_t length) {
  FILE *file;
  int n = snprintf(path, 256, "%s/case-%u", scratch, ++case_number);
  CHECK(n > 0 && n < 256);
  file = fopen(path, "wb");
  CHECK(file != NULL);
  CHECK(!length || fwrite(bytes, 1, length, file) == length);
  CHECK(fclose(file) == 0);
}

static char *join_text(const char *prefix, const char *body, const char *suffix) {
  size_t a = strlen(prefix), b = strlen(body), c = strlen(suffix);
  char *text;
  CHECK(a <= NJ_MAX_BYTES && b <= NJ_MAX_BYTES - a && c <= NJ_MAX_BYTES - a - b);
  text = malloc(a + b + c + 1);
  CHECK(text != NULL);
  memcpy(text, prefix, a);
  memcpy(text + a, body, b);
  memcpy(text + a + b, suffix, c + 1);
  return text;
}

static char *stream_text(FILE *stream, size_t *length) {
  long end;
  char *text;
  CHECK(fflush(stream) == 0);
  CHECK(fseek(stream, 0, SEEK_END) == 0);
  end = ftell(stream);
  CHECK(end >= 0 && (unsigned long)end <= NJ_MAX_BYTES);
  CHECK(fseek(stream, 0, SEEK_SET) == 0);
  text = malloc((size_t)end + 1);
  CHECK(text != NULL);
  CHECK(fread(text, 1, (size_t)end, stream) == (size_t)end);
  CHECK(!ferror(stream));
  text[end] = 0;
  if (length) *length = (size_t)end;
  return text;
}

static nj_document *parse(const char *text) {
  char error[256];
  nj_document *document = NULL;
  CHECK(nj_parse_buffer((const unsigned char *)text, strlen(text), &document,
                        error, sizeof(error)) == 0);
  CHECK(document != NULL && document->root != NULL);
  return document;
}

static nj_document *stream_document(FILE *stream) {
  char *text = stream_text(stream, NULL);
  nj_document *document = parse(text);
  free(text);
  return document;
}

static uint64_t unsigned_value(const nj_value *value) {
  uint64_t number = 0;
  char error[256];
  CHECK(nj_u64(value, &number, error, sizeof(error)) == 0);
  return number;
}

static void safe_diagnostic(const native_diagnostic *diagnostic) {
  CHECK(memchr(diagnostic->status, 0, sizeof(diagnostic->status)) != NULL);
  CHECK(memchr(diagnostic->message, 0, sizeof(diagnostic->message)) != NULL);
  CHECK(memchr(diagnostic->path, 0, sizeof(diagnostic->path)) != NULL);
}

static void empty_diagnostic(const native_diagnostic *diagnostic) {
  safe_diagnostic(diagnostic);
  CHECK(!diagnostic->status[0] && !diagnostic->message[0] &&
        !diagnostic->path[0] && diagnostic->offset == 0);
}

static void reject_json(const void *bytes, size_t length) {
  nj_document *document = NULL;
  char error[256] = "not cleared";
  CHECK(nj_parse_buffer(bytes, length, &document, error, sizeof(error)) == -1);
  CHECK(document == NULL && error[0]);
}

static void test_json_values(void) {
  nj_document *document = parse("{\"u\":18446744073709551615,\"i\":-9223372036854775808,"
                                "\"b\":true,\"n\":null,\"s\":\"A\\u0000B\"}");
  const nj_value *string = nj_get(document->root, "s");
  uint64_t u = 123;
  int64_t i = 123;
  int boolean = 7;
  char error[256], copy[16] = "old";
  CHECK(nj_u64(nj_get(document->root, "u"), &u, error, sizeof(error)) == 0);
  CHECK(u == UINT64_MAX);
  CHECK(nj_i64(nj_get(document->root, "i"), &i, error, sizeof(error)) == 0);
  CHECK(i == INT64_MIN);
  CHECK(nj_boolean(nj_get(document->root, "b"), &boolean, error, sizeof(error)) == 0);
  CHECK(boolean == 1 && nj_get(document->root, "n")->type == NJ_NULL);
  CHECK(nj_u64(nj_get(document->root, "b"), &u, error, sizeof(error)) == -1);
  CHECK(u == UINT64_MAX);
  CHECK(nj_i64(nj_get(document->root, "u"), &i, error, sizeof(error)) == -1);
  CHECK(i == INT64_MIN);
  CHECK(nj_u64(nj_get(document->root, "i"), &u, error, sizeof(error)) == -1);
  CHECK(string->text_length == 3 && memcmp(string->text, "A\0B", 3) == 0);
  CHECK(nj_string_copy(string, copy, sizeof(copy), error, sizeof(error)) == -1);
  CHECK(copy[0] == 0);
  nj_free(document);

  document = parse("{\"value\\u0000tail\":3}");
  CHECK(document->root->members[0].key_length == 10);
  CHECK(nj_get(document->root, "value") == NULL);
  {
    const char *const required[] = {"value"};
    CHECK(nj_keys(document->root, required, 1, NULL, 0, error, sizeof(error)) == -1);
  }
  nj_free(document);
  {
    unsigned char source[] = "\"owned copy\"";
    document = NULL;
    CHECK(nj_parse_buffer(source, sizeof(source) - 1, &document, error, sizeof(error)) == 0);
    memset(source, 'X', sizeof(source) - 1);
    CHECK(nj_string_equal(document->root, "owned copy"));
    CHECK(document->source[0] == '"');
    nj_free(document);
  }
  nj_free(NULL);
}

static void test_json_rejections(void) {
  static const char *const invalid[] = {
    "", "[1,]", "{\"a\":1,}", "01", "+1", "1.0", "1e2", "NaN", "truex", "null null",
    "18446744073709551616", "-9223372036854775809", "\"\\uD800\"", "\"\\uDC00\"",
    "\"\\x41\"", "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}"
  };
  size_t index;
  unsigned char invalid_utf8[] = {'"', 0xc0, 0xaf, '"'};
  unsigned char nul_tail[] = {'n', 'u', 'l', 'l', 0};
  for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++)
    reject_json(invalid[index], strlen(invalid[index]));
  reject_json(invalid_utf8, sizeof(invalid_utf8));
  reject_json(nul_tail, sizeof(nul_tail));
  reject_json(NULL, 1);
  {
    char error[256];
    CHECK(nj_parse_buffer((const unsigned char *)"null", 4, NULL, error, sizeof(error)) == -1);
  }
  {
    const size_t depth = NJ_MAX_DEPTH + 2;
    char *deep = malloc(depth * 2 + 2);
    CHECK(deep != NULL);
    memset(deep, '[', depth);
    deep[depth] = '0';
    memset(deep + depth + 1, ']', depth);
    reject_json(deep, depth * 2 + 1);
    free(deep);
  }
  {
    char *large = malloc(NJ_MAX_BYTES + 1);
    nj_document *document = NULL;
    char error[256];
    CHECK(large != NULL);
    memset(large, ' ', NJ_MAX_BYTES + 1);
    memcpy(large, "null", 4);
    CHECK(nj_parse_buffer((unsigned char *)large, NJ_MAX_BYTES, &document,
                          error, sizeof(error)) == 0);
    nj_free(document);
    reject_json(large, NJ_MAX_BYTES + 1);
    free(large);
  }
  {
    /* The root plus NJ_MAX_NODES scalar children exceeds the node budget. */
    size_t count = NJ_MAX_NODES, position = 0;
    char *many = malloc(count * 5 + 2);
    CHECK(many != NULL);
    many[position++] = '[';
    for (index = 0; index < count; index++) {
      if (index) many[position++] = ',';
      memcpy(many + position, "null", 4);
      position += 4;
    }
    many[position++] = ']';
    reject_json(many, position);
    free(many);
  }
}

static void test_json_output_and_files(void) {
  FILE *stream = tmpfile();
  char path[256], *text, error[256];
  unsigned char *data = NULL;
  size_t length = 99;
  nj_document *document;
  CHECK(stream != NULL);
  nj_write_string(stream, "A\0B", 3);
  text = stream_text(stream, NULL);
  CHECK(strcmp(text, "\"A\\u0000B\"") == 0);
  free(text);
  CHECK(fclose(stream) == 0);
  document = parse("\"\\uD83D\\uDE00\"");
  CHECK(document->root->text_length == 4);
  stream = tmpfile();
  CHECK(stream != NULL);
  CHECK(nj_write_value(stream, document, document->root) == 0);
  text = stream_text(stream, NULL);
  CHECK(strcmp(text, "\"\\uD83D\\uDE00\"") == 0);
  free(text);
  CHECK(fclose(stream) == 0);
  nj_free(document);
  case_file(path, "", 0);
  CHECK(nj_read_file(path, &data, &length, 0, error, sizeof(error)) == 0);
  CHECK(data != NULL && length == 0 && data[0] == 0);
  free(data);
  data = NULL;
  case_file(path, "x", 1);
  CHECK(nj_read_file(path, &data, &length, 0, error, sizeof(error)) == -1);
  CHECK(data == NULL && length == 0);
}

#if defined(__SIZEOF_INT128__)
static const nj_value *find_field(const nj_value *tree, const char *path) {
  const nj_value *children;
  size_t index;
  if (!tree || tree->type != NJ_OBJECT) return NULL;
  if (nj_string_equal(nj_get(tree, "path"), path)) return tree;
  children = nj_get(tree, "children");
  if (!children || children->type != NJ_ARRAY) return NULL;
  for (index = 0; index < children->count; index++) {
    const nj_value *found = find_field(children->items[index], path);
    if (found) return found;
  }
  return NULL;
}
#endif

static nj_document *layout_case(const char *node, const void *bytes, size_t length,
                                int expected, const char *status) {
  char layout_path[256], input_path[256];
  char *layout = join_text("{\"format\":\"stateafl.offline-layout\",\"version\":1,\"root\":", node, "}");
  native_diagnostic diagnostic;
  FILE *out = tmpfile();
  nj_document *report = NULL;
  CHECK(out != NULL);
  case_file(layout_path, layout, strlen(layout));
  case_file(input_path, bytes, length);
  free(layout);
  memset(&diagnostic, 0xa5, sizeof(diagnostic));
  CHECK(native_layout_inspect(layout_path, input_path, out, &diagnostic) == expected);
  safe_diagnostic(&diagnostic);
  if (expected == 0) {
    empty_diagnostic(&diagnostic);
    report = stream_document(out);
    CHECK(nj_string_equal(nj_get(report->root, "format"), "stateafl.native-decode"));
    CHECK(nj_string_equal(nj_get(report->root, "status"), "decoded"));
    CHECK(unsigned_value(nj_get(report->root, "consumed")) == length);
  } else {
    CHECK(ftell(out) == 0);
    CHECK(strcmp(diagnostic.status, status) == 0 && diagnostic.message[0]);
  }
  CHECK(fclose(out) == 0);
  return report;
}

static void test_layout(void) {
#if defined(__SIZEOF_INT128__)
  const unsigned char bytes[] = {42, 2, 'a', 'b'};
  const unsigned char little[] = {2, 1}, bad_enum[] = {3, 1};
  const char *enum_node = "{\"kind\":\"uint\",\"id\":\"value\",\"width\":2,\"byte_order\":\"little\",\"values\":[258]}";
  nj_document *report = layout_case(fixture_packet_layout, bytes, sizeof(bytes), 0, NULL);
  const nj_value *field = find_field(nj_get(report->root, "tree"), "packet.body");
  CHECK(field != NULL && nj_string_equal(nj_get(field, "value"), "6162"));
  CHECK(unsigned_value(nj_get(field, "start")) == 2 && unsigned_value(nj_get(field, "end")) == 4);
  CHECK(nj_string_equal(nj_get(field, "source_node_path"), "/root/fields/2"));
  nj_free(report);
  nj_free(layout_case(enum_node, little, sizeof(little), 0, NULL));
  nj_free(layout_case(enum_node, bad_enum, sizeof(bad_enum), 1, "invalid"));
  {
    const unsigned char bits[] = {0xa5, 0xb0};
    report = layout_case("{\"kind\":\"bits\",\"id\":\"flags\",\"width\":2,\"byte_order\":\"little\",\"fields\":["
                         "{\"id\":\"low\",\"lsb\":0,\"width\":4,\"expected\":5},"
                         "{\"id\":\"high\",\"lsb\":12,\"width\":4}]}", bits, sizeof(bits), 0, NULL);
    field = find_field(nj_get(report->root, "tree"), "flags.high");
    CHECK(field != NULL && unsigned_value(nj_get(field, "value")) == 11);
    CHECK(unsigned_value(nj_get(field, "start")) == 0 && unsigned_value(nj_get(field, "end")) == 2);
    nj_free(report);
  }
  nj_free(layout_case("{\"kind\":\"uint\",\"id\":\"x\",\"width\":3,\"byte_order\":\"big\"}", little, 2, 1, "truncated"));
  nj_free(layout_case("{\"kind\":\"bounded\",\"id\":\"box\",\"length\":2,\"body\":{\"kind\":\"uint\",\"id\":\"x\",\"width\":3,\"byte_order\":\"big\"}}", little, 2, 1, "invalid"));
  nj_free(layout_case("{\"kind\":\"uint\",\"id\":\"x\",\"width\":1,\"byte_order\":\"big\"}", little, 2, 1, "invalid"));
  {
    const unsigned char scoped[] = {99, 1, 'A', 2, 'B', 'C'};
    const char *node = "{\"kind\":\"struct\",\"id\":\"outer\",\"fields\":["
      "{\"kind\":\"uint\",\"id\":\"size\",\"width\":1,\"byte_order\":\"big\"},"
      "{\"kind\":\"repeat\",\"id\":\"rows\",\"count\":2,\"max_items\":2,\"item\":{\"kind\":\"struct\",\"id\":\"entry\",\"fields\":["
      "{\"kind\":\"uint\",\"id\":\"size\",\"width\":1,\"byte_order\":\"big\"},"
      "{\"kind\":\"bytes\",\"id\":\"body\",\"length\":{\"ref\":\"size\"},\"encoding\":\"hex\"}]}}]}";
    report = layout_case(node, scoped, sizeof(scoped), 0, NULL);
    field = find_field(nj_get(report->root, "tree"), "outer.rows[0].body");
    CHECK(field != NULL && nj_string_equal(nj_get(field, "value"), "41"));
    field = find_field(nj_get(report->root, "tree"), "outer.rows[1].body");
    CHECK(field != NULL && nj_string_equal(nj_get(field, "value"), "4243"));
    nj_free(report);
  }
  {
    const unsigned char transparent[] = {1, 2, 'x', 'y'};
    const char *node = "{\"kind\":\"struct\",\"id\":\"record\",\"fields\":["
      "{\"kind\":\"uint\",\"id\":\"tag\",\"width\":1,\"byte_order\":\"big\"},"
      "{\"kind\":\"bounded\",\"id\":\"payload\",\"length\":1,\"body\":{\"kind\":\"choice\",\"id\":\"selection\",\"selector\":{\"ref\":\"tag\"},\"cases\":{\"1\":{\"kind\":\"struct\",\"id\":\"entry\",\"fields\":["
      "{\"kind\":\"uint\",\"id\":\"size\",\"width\":1,\"byte_order\":\"big\"}]}}}},"
      "{\"kind\":\"bytes\",\"id\":\"tail\",\"length\":{\"ref\":\"payload.size\"},\"encoding\":\"hex\"}]}";
    report = layout_case(node, transparent, sizeof(transparent), 0, NULL);
    field = find_field(nj_get(report->root, "tree"), "record.tail");
    CHECK(field != NULL && nj_string_equal(nj_get(field, "value"), "7879"));
    nj_free(report);
  }
  nj_free(layout_case("{\"kind\":\"unknown\",\"id\":\"x\"}", "", 0, 2, "invalid_description"));
  nj_free(layout_case("{\"kind\":\"uint\",\"id\":\"x\",\"width\":1,\"byte_order\":\"big\",\"max\":3,\"expected\":4}", "", 0, 2, "invalid_description"));
  nj_free(layout_case("{\"kind\":\"bytes\",\"id\":\"x\",\"length\":0,\"encoding\":\"hex\",\"typo\":0}", "", 0, 2, "invalid_description"));
  nj_free(layout_case("{\"kind\":\"bytes\",\"id\":\"x\",\"length\":{\"ref\":\"missing\"},\"encoding\":\"hex\"}", "", 0, 1, "invalid"));
  nj_free(layout_case("{\"kind\":\"bytes\",\"id\":\"x\",\"length\":{\"op\":\"div\",\"args\":[1,0]},\"encoding\":\"hex\"}", "", 0, 1, "invalid"));
  nj_free(layout_case("{\"kind\":\"bytes\",\"id\":\"x\",\"length\":-1,\"encoding\":\"hex\"}", "", 0, 1, "invalid"));
  nj_free(layout_case("{\"kind\":\"repeat\",\"id\":\"rows\",\"count\":4096,\"max_items\":4096,\"item\":{\"kind\":\"repeat\",\"id\":\"cells\",\"count\":17,\"max_items\":17,\"item\":{\"kind\":\"bytes\",\"id\":\"x\",\"length\":0,\"encoding\":\"hex\"}}}", "", 0, 2, "resource_limit"));
#else
  nj_free(layout_case("{\"kind\":\"bytes\",\"id\":\"x\",\"length\":0,\"encoding\":\"hex\"}", "", 0, 2, "unsupported_platform"));
  fputs("Layout semantic cases skipped: compiler has no __int128 support.\n", stderr);
#endif
}

static void inspect_fixture(const unsigned char *bytes, size_t length) {
#if defined(__SIZEOF_INT128__)
  nj_free(layout_case(fixture_packet_layout, bytes, length, 0, NULL));
#else
  (void)bytes;
  (void)length;
#endif
}

static void reject_fixture(const unsigned char *input, size_t input_length,
                           const fixture_packet_edit *edit, size_t capacity) {
  unsigned char output[FIXTURE_PACKET_MAX_LENGTH], original[sizeof(output)];
  size_t length = 99;
  char error[96];
  memset(output, 0xa5, sizeof(output));
  memcpy(original, output, sizeof(output));
  memset(error, 0xa5, sizeof(error));
  CHECK(fixture_packet_mutate(input, input_length, edit, output, capacity,
                              &length, error, sizeof(error)) == -1);
  CHECK(length == 0 && error[0]);
  CHECK(memchr(error, 0, sizeof(error)) != NULL);
  CHECK(memcmp(output, original, sizeof(output)) == 0);
}

static void test_fixture_mutations(void) {
  const unsigned char input[] = {42, 2, 'a', 'b'}, empty[] = {42, 0};
  const unsigned char bad_magic[] = {41, 2, 'a', 'b'};
  const unsigned char bad_length[] = {42, 3, 'a', 'b'};
  const unsigned char trailing[] = {42, 1, 'a', 'b'};
  const unsigned char grown[] = {42, 3, 'a', 'b', 'x'};
  unsigned char output[FIXTURE_PACKET_MAX_LENGTH];
  unsigned char repeated[sizeof(output)], overlap[FIXTURE_PACKET_MAX_LENGTH + 2];
  unsigned char oversized[FIXTURE_PACKET_MAX_LENGTH + 1];
  fixture_packet_edit edit = {FIXTURE_PACKET_SET_BYTE, 1, 'z'};
  size_t length = 99, repeated_length = 99, index;
  char error[96] = "stale diagnostic", tiny = 'k';

  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 0);
  CHECK(!error[0] && length == 4 && output[0] == 42 && output[1] == 2);
  CHECK(output[2] == 'a' && output[3] == 'z' && input[3] == 'b');
  inspect_fixture(output, length);
  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, repeated, sizeof(repeated),
                              &repeated_length, NULL, 0) == 0);
  CHECK(repeated_length == length && !memcmp(output, repeated, length));

  edit.value = 'b';
  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, output, sizeof(input),
                              &length, error, sizeof(error)) == 1);
  CHECK(length == sizeof(input) && !memcmp(input, output, length));
  inspect_fixture(output, length);

  edit.operation = FIXTURE_PACKET_RESIZE_BODY;
  edit.argument = FIXTURE_PACKET_MAX_BODY;
  edit.value = 0x7e;
  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 0);
  CHECK(length == FIXTURE_PACKET_MAX_LENGTH && output[1] == FIXTURE_PACKET_MAX_BODY);
  CHECK(output[2] == 'a' && output[3] == 'b');
  for (index = sizeof(input); index < length; index++) CHECK(output[index] == 0x7e);
  inspect_fixture(output, length);
  CHECK(fixture_packet_mutate(output, length, &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 1);
  CHECK(length == FIXTURE_PACKET_MAX_LENGTH);

  edit.operation = FIXTURE_PACKET_SET_BYTE;
  edit.argument = FIXTURE_PACKET_MAX_BODY - 1;
  edit.value = 0;
  CHECK(fixture_packet_mutate(output, length, &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 0);
  CHECK(output[length - 1] == 0);
  inspect_fixture(output, length);

  edit.operation = FIXTURE_PACKET_RESIZE_BODY;
  edit.argument = 0;
  CHECK(fixture_packet_mutate(output, length, &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 0);
  CHECK(length == 2 && output[0] == 42 && output[1] == 0);
  inspect_fixture(output, length);
  CHECK(fixture_packet_mutate(empty, sizeof(empty), &edit, output, sizeof(output),
                              &length, error, sizeof(error)) == 1);
  CHECK(length == sizeof(empty) && !memcmp(output, empty, length));

  edit.argument = 3;
  edit.value = 'x';
  memcpy(overlap, input, sizeof(input));
  CHECK(fixture_packet_mutate(overlap, sizeof(input), &edit, overlap + 1,
                              sizeof(overlap) - 1, &length, error, sizeof(error)) == 0);
  CHECK(length == sizeof(grown) && !memcmp(overlap + 1, grown, length));
  inspect_fixture(overlap + 1, length);
  CHECK(fixture_packet_mutate(overlap + 1, length, &edit, overlap, sizeof(overlap),
                              &length, error, sizeof(error)) == 1);
  CHECK(length == sizeof(grown) && !memcmp(overlap, grown, length));

  reject_fixture(input, sizeof(input), &edit, 4);
  edit.argument = (size_t)-1;
  reject_fixture(input, sizeof(input), &edit, sizeof(output));
  edit.operation = FIXTURE_PACKET_SET_BYTE;
  edit.argument = 2;
  reject_fixture(input, sizeof(input), &edit, sizeof(output));
  edit.argument = 0;
  reject_fixture(empty, sizeof(empty), &edit, sizeof(output));
  reject_fixture(input, sizeof(input), &edit, sizeof(input) - 1);
  reject_fixture(input, 0, &edit, sizeof(output));
  reject_fixture(input, 1, &edit, sizeof(output));
  reject_fixture(bad_magic, sizeof(bad_magic), &edit, sizeof(output));
  reject_fixture(bad_length, sizeof(bad_length), &edit, sizeof(output));
  reject_fixture(trailing, sizeof(trailing), &edit, sizeof(output));
  memset(oversized, 0, sizeof(oversized));
  reject_fixture(oversized, sizeof(oversized), &edit, sizeof(output));
  reject_fixture(NULL, 0, &edit, sizeof(output));
  reject_fixture(input, sizeof(input), NULL, sizeof(output));
  edit.operation = (enum fixture_packet_operation)999;
  reject_fixture(input, sizeof(input), &edit, sizeof(output));

  memset(output, 0xa5, sizeof(output));
  memcpy(repeated, output, sizeof(output));
  edit.operation = FIXTURE_PACKET_SET_BYTE;
  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, output, sizeof(output),
                              NULL, error, sizeof(error)) == -1);
  CHECK(!memcmp(output, repeated, sizeof(output)));
  length = 99;
  CHECK(fixture_packet_mutate(input, sizeof(input), &edit, NULL, 0,
                              &length, error, sizeof(error)) == -1 && length == 0);
  CHECK(fixture_packet_mutate(NULL, 0, &edit, output, sizeof(output),
                              &length, &tiny, 0) == -1 && tiny == 'k');
  CHECK(fixture_packet_mutate(NULL, 0, &edit, output, sizeof(output),
                              &length, &tiny, 1) == -1 && tiny == 0);
}

/* These labels describe fictional producer records, not protocol traffic. */
#define DIGEST_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define PROTOCOL_OBSERVED \
  "\"protocol\":{\"status\":\"observed\",\"states\":[\"ready\"],\"source\":\"matched_response\",\"correlation\":\"confirmed\",\"complete\":true,\"evidence_ref\":\"local-record-1\"}"
#define PROTOCOL_PREDICTED \
  "\"protocol\":{\"status\":\"predicted\",\"states\":[\"ready\"],\"source\":\"prediction\",\"correlation\":\"missing\",\"complete\":true,\"evidence_ref\":\"model-prediction-1\"}"
#define PROTOCOL_AMBIGUOUS \
  "\"protocol\":{\"status\":\"ambiguous\",\"states\":[\"ready\",\"waiting\"],\"source\":\"local_observation\",\"correlation\":\"confirmed\",\"complete\":true,\"evidence_ref\":\"local-record-1\"}"
#define MEMORY_SNAPSHOT \
  "\"memory\":{\"namespace\":\"test-memory\",\"calibration_epoch\":0,\"library_revision\":\"test-v1\",\"state_id\":1,\"source\":\"local-record\",\"status\":\"snapshot_label\"}"
#define BOUNDARY_SYNC \
  "\"boundary\":{\"observation_id\":\"marker-1\",\"alignment\":\"shared_marker\",\"phase\":\"completed\",\"synchronization\":\"atomic_snapshot\",\"source\":\"local-record\"}"
#define OBSERVED_PAIR "," PROTOCOL_OBSERVED "," MEMORY_SNAPSHOT "," BOUNDARY_SYNC

static char *event_text(const char *session, uint64_t epoch, uint64_t index,
                         const char *kind, const char *model, const char *extra) {
  const char *format = "{\"run_id\":\"test-run\",\"session_id\":\"%s\","
    "\"session_epoch\":%" PRIu64 ",\"event_index\":%" PRIu64 ","
    "\"model_sha256\":\"%s\",\"kind\":\"%s\"%s}";
  int length = snprintf(NULL, 0, format, session, epoch, index, model, kind, extra);
  char *text;
  CHECK(length > 0 && (unsigned)length <= NJ_MAX_BYTES);
  text = malloc((size_t)length + 1);
  CHECK(text != NULL);
  CHECK(snprintf(text, (size_t)length + 1, format, session, epoch, index,
                 model, kind, extra) == length);
  return text;
}

static nj_document *observation_case(const char *const *events, size_t count, int expected) {
  const char *prefix = "{\"format\":\"stateafl.offline-observations\",\"version\":1,\"events\":[";
  size_t total = 0, position = 0, index;
  char path[256], *body, *input;
  native_diagnostic diagnostic;
  FILE *out = tmpfile();
  nj_document *report = NULL;
  CHECK(out != NULL);
  for (index = 0; index < count; index++) {
    size_t length = strlen(events[index]);
    CHECK(length < NJ_MAX_BYTES && total < NJ_MAX_BYTES - length);
    total += length + 1;
  }
  body = malloc(total + 1);
  CHECK(body != NULL);
  for (index = 0; index < count; index++) {
    size_t length = strlen(events[index]);
    if (index) body[position++] = ',';
    memcpy(body + position, events[index], length);
    position += length;
  }
  body[position] = 0;
  input = join_text(prefix, body, "]}");
  free(body);
  case_file(path, input, strlen(input));
  free(input);
  memset(&diagnostic, 0xa5, sizeof(diagnostic));
  CHECK(native_observation_inspect(path, out, &diagnostic) == expected);
  safe_diagnostic(&diagnostic);
  if (expected == 0) {
    empty_diagnostic(&diagnostic);
    report = stream_document(out);
    CHECK(nj_string_equal(nj_get(report->root, "format"), "stateafl.native-state-observations"));
    CHECK(unsigned_value(nj_get(report->root, "events")) == count);
    CHECK(nj_get(report->root, "relations_aggregated")->type == NJ_BOOL);
    CHECK(nj_get(report->root, "relations_aggregated")->boolean == 0);
  } else {
    CHECK(ftell(out) == 0);
    CHECK(strcmp(diagnostic.status, "invalid_observations") == 0 && diagnostic.message[0]);
  }
  CHECK(fclose(out) == 0);
  return report;
}

static const nj_value *session_at(const nj_document *report, size_t index) {
  const nj_value *sessions = nj_get(report->root, "sessions");
  CHECK(sessions != NULL && sessions->type == NJ_ARRAY && index < sessions->count);
  return sessions->items[index];
}

static void test_observation_history(void) {
  char *start = event_text("session-a", 0, 0, "session_start", DIGEST_A, "");
  char *observed = event_text("session-a", 0, 1, "observation", DIGEST_A, OBSERVED_PAIR);
  char *timeout = event_text("session-a", 0, 2, "timeout", DIGEST_A, "");
  char *partial = event_text("session-a", 0, 3, "partial", DIGEST_A, "");
  char *unmatched = event_text("session-a", 0, 4, "unmatched", DIGEST_A, "");
  const char *events[] = {start, observed, timeout, partial, unmatched};
  const nj_value *session, *history, *aligned;
  nj_document *report = observation_case(NULL, 0, 0);
  CHECK(unsigned_value(nj_get(report->root, "session_count")) == 0);
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 0);
  nj_free(report);
  report = observation_case(events, 2, 0);
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 1);
  aligned = nj_get(report->root, "aligned_observations");
  CHECK(aligned->type == NJ_ARRAY && aligned->count == 1);
  CHECK(nj_string_equal(nj_get(aligned->items[0], "certainty"), "observed"));
  CHECK(unsigned_value(nj_get(nj_get(aligned->items[0], "memory"), "state_id")) == 1);
  session = session_at(report, 0);
  CHECK(nj_string_equal(nj_get(session, "current_status"), "observed"));
  nj_free(report);
  report = observation_case(events, 5, 0);
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 1);
  session = session_at(report, 0);
  CHECK(nj_string_equal(nj_get(session, "current_status"), "unknown"));
  CHECK(nj_get(session, "current_candidates")->count == 0);
  history = nj_get(session, "last_confirmed");
  CHECK(nj_string_equal(nj_get(history, "state"), "ready"));
  CHECK(unsigned_value(nj_get(history, "event_index")) == 1);
  CHECK(unsigned_value(nj_get(nj_get(report->root, "skipped"), "timeout")) == 1);
  CHECK(unsigned_value(nj_get(nj_get(report->root, "skipped"), "partial")) == 1);
  CHECK(unsigned_value(nj_get(nj_get(report->root, "skipped"), "unmatched")) == 1);
  nj_free(report);
  free(start); free(observed); free(timeout); free(partial); free(unmatched);
}

static void test_observation_prediction_and_pairing(void) {
  static const char *const unpaired_extras[] = {
    "," PROTOCOL_OBSERVED,
    "," PROTOCOL_OBSERVED "," MEMORY_SNAPSHOT ",\"boundary\":{\"observation_id\":\"marker-1\",\"alignment\":\"shared_marker\",\"phase\":\"completed\",\"synchronization\":\"unknown\",\"source\":\"local-record\"}",
    "," PROTOCOL_OBSERVED "," MEMORY_SNAPSHOT ",\"boundary\":{\"observation_id\":\"marker-1\",\"alignment\":\"unaligned\",\"phase\":\"completed\",\"synchronization\":\"atomic_snapshot\",\"source\":\"local-record\"}",
    "," PROTOCOL_OBSERVED ",\"memory\":{\"namespace\":\"test-memory\",\"calibration_epoch\":0,\"library_revision\":\"test-v1\",\"state_id\":0,\"source\":\"local-record\",\"status\":\"snapshot_label\"}," BOUNDARY_SYNC,
    "," PROTOCOL_OBSERVED ",\"memory\":{\"namespace\":\"test-memory\",\"calibration_epoch\":0,\"library_revision\":\"test-v1\",\"state_id\":1,\"source\":\"local-record\",\"status\":\"synthetic\"}," BOUNDARY_SYNC
  };
  char *start = event_text("session-a", 0, 0, "session_start", DIGEST_A, "");
  char *event = event_text("session-a", 0, 1, "observation", DIGEST_A,
                          "," PROTOCOL_PREDICTED "," MEMORY_SNAPSHOT "," BOUNDARY_SYNC);
  const char *events[] = {start, event};
  nj_document *report = observation_case(events, 2, 0);
  const nj_value *session = session_at(report, 0), *prediction;
  size_t index;
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 0);
  CHECK(nj_get(session, "last_confirmed")->type == NJ_NULL);
  CHECK(nj_string_equal(nj_get(session, "current_status"), "unknown"));
  prediction = nj_get(session, "last_prediction");
  CHECK(nj_get(prediction, "states")->count == 1);
  CHECK(nj_string_equal(nj_get(prediction, "source"), "prediction"));
  nj_free(report);
  free(event);
  event = event_text("session-a", 0, 1, "observation", DIGEST_A,
                     "," PROTOCOL_AMBIGUOUS "," MEMORY_SNAPSHOT "," BOUNDARY_SYNC);
  events[1] = event;
  report = observation_case(events, 2, 0);
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 1);
  {
    const nj_value *aligned = nj_get(report->root, "aligned_observations");
    CHECK(aligned->count == 1);
    CHECK(nj_get(aligned->items[0], "protocol_states")->count == 2);
    CHECK(nj_string_equal(nj_get(aligned->items[0], "certainty"), "ambiguous"));
  }
  CHECK(nj_get(session_at(report, 0), "last_confirmed")->type == NJ_NULL);
  nj_free(report);
  free(event);
  for (index = 0; index < sizeof(unpaired_extras) / sizeof(unpaired_extras[0]); index++) {
    event = event_text("session-a", 0, 1, "observation", DIGEST_A, unpaired_extras[index]);
    events[1] = event;
    report = observation_case(events, 2, 0);
    CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 0);
    session = session_at(report, 0);
    CHECK(nj_string_equal(nj_get(session, "current_status"), "observed"));
    CHECK(nj_string_equal(nj_get(nj_get(session, "last_confirmed"), "state"), "ready"));
    nj_free(report);
    free(event);
  }
  free(start);
}

static void test_observation_identity(void) {
  char *start = event_text("session-a", 0, 0, "session_start", DIGEST_A, "");
  char *observed = event_text("session-a", 0, 1, "observation", DIGEST_A, OBSERVED_PAIR);
  char *reset = event_text("session-a", 1, 0, "reset", DIGEST_B, ",\"reset_evidence\":\"confirmed\"");
  char *second = event_text("session-a", 1, 1, "observation", DIGEST_B, OBSERVED_PAIR);
  char *other_start = event_text("session-b", 0, 0, "session_start", DIGEST_A, "");
  char *other = event_text("session-b", 0, 1, "observation", DIGEST_A, OBSERVED_PAIR);
  const char *events[] = {start, observed, reset, second, other_start, other};
  nj_document *report = observation_case(events, 3, 0);
  CHECK(unsigned_value(nj_get(report->root, "session_count")) == 2);
  CHECK(nj_string_equal(nj_get(nj_get(session_at(report, 0), "last_confirmed"), "state"), "ready"));
  CHECK(nj_get(session_at(report, 1), "last_confirmed")->type == NJ_NULL);
  CHECK(unsigned_value(nj_get(session_at(report, 1), "session_epoch")) == 1);
  CHECK(nj_string_equal(nj_get(session_at(report, 1), "model_sha256"), DIGEST_B));
  nj_free(report);
  /* Reuse of a marker is permitted only in a different session/epoch partition. */
  report = observation_case(events, 6, 0);
  CHECK(unsigned_value(nj_get(report->root, "session_count")) == 3);
  CHECK(unsigned_value(nj_get(report->root, "aligned_observation_count")) == 3);
  nj_free(report);
  free(start); free(observed); free(reset); free(second); free(other_start); free(other);
}

static void test_observation_rejections(void) {
  static const struct {
    const char *kind, *model, *extra;
    uint64_t epoch, index;
  } invalid[] = {
    {"session_start", DIGEST_A, "", 0, 1},
    {"reset", DIGEST_A, ",\"reset_evidence\":\"confirmed\"", 0, 1},
    {"reset", DIGEST_A, "", 1, 0},
    {"observation", DIGEST_A, ",\"reset_evidence\":\"confirmed\"", 0, 1},
    {"observation", DIGEST_B, "", 0, 1},
    {"observation", DIGEST_A, "", 0, 0},
    {"observation", DIGEST_A, ",\"protocol\":{\"status\":\"observed\",\"states\":[\"a\",\"b\"],\"source\":\"matched_response\",\"correlation\":\"confirmed\",\"complete\":true,\"evidence_ref\":\"record\"}", 0, 1},
    {"observation", DIGEST_A, ",\"protocol\":{\"status\":\"inconsistent\",\"states\":[],\"source\":\"matched_response\",\"correlation\":\"confirmed\",\"complete\":false,\"evidence_ref\":\"record\"}", 0, 1},
    {"observation", DIGEST_A, ",\"memory\":{\"namespace\":\"test\",\"calibration_epoch\":0,\"library_revision\":\"v1\",\"state_id\":4294967296,\"source\":\"record\",\"status\":\"snapshot_label\"}", 0, 1},
    {"observation", DIGEST_A, ",\"unknown_field\":0", 0, 1}
  };
  char *start = event_text("session-a", 0, 0, "session_start", DIGEST_A, "");
  char *observed = event_text("session-a", 0, 1, "observation", DIGEST_A, OBSERVED_PAIR);
  char *again = event_text("session-a", 0, 2, "observation", DIGEST_A, OBSERVED_PAIR);
  char *reset = event_text("session-a", 1, 0, "reset", DIGEST_A, ",\"reset_evidence\":\"confirmed\"");
  char *stale = event_text("session-a", 0, 3, "timeout", DIGEST_A, "");
  const char *events[] = {start, observed, again, stale};
  size_t index;
  nj_free(observation_case(events + 1, 1, 2)); /* Missing epoch start. */
  nj_free(observation_case(events, 3, 2)); /* Duplicate marker in one epoch. */
  events[2] = reset;
  nj_free(observation_case(events, 4, 2)); /* Returning to a stale epoch. */
  for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
    char *event = event_text("session-a", invalid[index].epoch, invalid[index].index,
                            invalid[index].kind, invalid[index].model, invalid[index].extra);
    events[1] = event;
    nj_free(observation_case(events, 2, 2));
    free(event);
  }
  {
    const char **too_many = malloc(10001 * sizeof(*too_many));
    CHECK(too_many != NULL);
    for (index = 0; index < 10001; index++) too_many[index] = "null";
    nj_free(observation_case(too_many, 10001, 2));
    free(too_many);
  }
  free(start); free(observed); free(again); free(reset); free(stale);
}

static void test_diagnostic_and_required_arguments(void) {
  struct {
    unsigned char before[16];
    native_diagnostic diagnostic;
    unsigned char after[16];
  } guard;
  char long_text[4096];
  FILE *out = tmpfile();
  size_t index;
  CHECK(out != NULL);
  memset(&guard, 0x6d, sizeof(guard));
  memset(long_text, 'x', sizeof(long_text) - 1);
  long_text[sizeof(long_text) - 1] = 0;
  native_inspect_error(&guard.diagnostic, long_text, long_text, 123,
                       "%s", long_text);
  safe_diagnostic(&guard.diagnostic);
  CHECK(guard.diagnostic.offset == 123);
  CHECK(strlen(guard.diagnostic.status) == sizeof(guard.diagnostic.status) - 1);
  CHECK(strlen(guard.diagnostic.path) == sizeof(guard.diagnostic.path) - 1);
  CHECK(strlen(guard.diagnostic.message) == sizeof(guard.diagnostic.message) - 1);
  for (index = 0; index < sizeof(guard.before); index++) {
    CHECK(guard.before[index] == 0x6d && guard.after[index] == 0x6d);
  }
  native_inspect_error(&guard.diagnostic, NULL, NULL, 0, NULL);
  safe_diagnostic(&guard.diagnostic);
  CHECK(guard.diagnostic.status[0] && guard.diagnostic.message[0] && !guard.diagnostic.path[0]);
  native_inspect_error(NULL, NULL, NULL, 0, NULL);

  memset(&guard.diagnostic, 0xa5, sizeof(guard.diagnostic));
  CHECK(native_layout_inspect(NULL, "unused", out, &guard.diagnostic) == 2);
  safe_diagnostic(&guard.diagnostic);
  CHECK(strcmp(guard.diagnostic.status, "input_error") == 0);
  CHECK(native_layout_inspect("unused", NULL, out, &guard.diagnostic) == 2);
  CHECK(strcmp(guard.diagnostic.status, "input_error") == 0);
  CHECK(native_layout_inspect("unused", "unused", NULL, &guard.diagnostic) == 2);
  CHECK(strcmp(guard.diagnostic.status, "input_error") == 0);
  CHECK(native_layout_inspect("unused", "unused", out, NULL) == 2);
  CHECK(native_observation_inspect(NULL, out, &guard.diagnostic) == 2);
  CHECK(strcmp(guard.diagnostic.status, "input_error") == 0);
  CHECK(native_observation_inspect("unused", NULL, &guard.diagnostic) == 2);
  CHECK(strcmp(guard.diagnostic.status, "input_error") == 0);
  CHECK(native_observation_inspect("unused", out, NULL) == 2);
  CHECK(ftell(out) == 0);
  /* Invalid arguments must not consume/close the caller's stream. */
  CHECK(fputs("still owned by caller", out) >= 0);
  CHECK(fclose(out) == 0);
}

static void dispatch_case(int argc, char **argv, int expected,
                           const char *error_status, int json_success) {
  FILE *out = tmpfile(), *errors = tmpfile();
  char *output, *diagnostics;
  CHECK(out != NULL && errors != NULL);
  CHECK(native_inspection_dispatch(argc, argv, out, errors) == expected);
  output = stream_text(out, NULL);
  diagnostics = stream_text(errors, NULL);
  if (expected == NATIVE_INSPECT_NOT_SELECTED) {
    CHECK(!output[0] && !diagnostics[0]);
  } else if (expected == NATIVE_INSPECT_OK) {
    CHECK(output[0] && !diagnostics[0]);
    if (json_success) {
      nj_document *report = parse(output);
      CHECK(nj_string_equal(nj_get(report->root, "format"), "stateafl.native-state-observations"));
      nj_free(report);
    } else {
      CHECK(strstr(output, "--inspect-layout") != NULL);
    }
  } else {
    nj_document *report;
    CHECK(!output[0] && diagnostics[0]);
    report = parse(diagnostics);
    CHECK(nj_string_equal(nj_get(report->root, "format"), "stateafl.native-inspection-error"));
    CHECK(nj_string_equal(nj_get(report->root, "status"), error_status));
    CHECK(nj_get(report->root, "error")->text_length > 0);
    nj_free(report);
  }
  free(output);
  free(diagnostics);
  /* Update streams need positioning between the preceding reads and writes. */
  CHECK(fseek(out, 0, SEEK_END) == 0);
  CHECK(fseek(errors, 0, SEEK_END) == 0);
  CHECK(fputs("caller still owns output", out) >= 0);
  CHECK(fputs("caller still owns errors", errors) >= 0);
  CHECK(fclose(out) == 0);
  CHECK(fclose(errors) == 0);
}

static void test_dispatcher(void) {
  char observations[256], layout[256], input[256], missing[256];
  const char *empty_observations = "{\"format\":\"stateafl.offline-observations\",\"version\":1,\"events\":[]}";
  const char *invalid_layout = "{\"format\":\"stateafl.offline-layout\",\"version\":1,\"root\":{\"kind\":\"uint\",\"id\":\"value\",\"width\":1,\"byte_order\":\"big\",\"expected\":42}}";
  char *program[] = {"afl-fuzz", NULL};
  char *ordinary[] = {"afl-fuzz", "-i", "seeds", NULL};
  char *help[] = {"afl-fuzz", "--inspect-help", NULL};
  char *help_extra[] = {"afl-fuzz", "--inspect-help", "-i", NULL};
  char *unknown[] = {"afl-fuzz", "--inspect-unknown", NULL};
  char *input_selector[] = {"afl-fuzz", "--inspect-input", "unused", NULL};
  char *layout_missing[] = {"afl-fuzz", "--inspect-layout", NULL};
  char *layout_wrong[] = {"afl-fuzz", "--inspect-layout", "unused", "-i", "unused", NULL};
  char *null_program[] = {NULL};
  char *null_argument[] = {"afl-fuzz", NULL};
  FILE *stream = tmpfile();
  int n;
  CHECK(stream != NULL);
  dispatch_case(1, program, -1, NULL, 0);
  dispatch_case(3, ordinary, -1, NULL, 0);
  dispatch_case(0, program, 2, "invalid_arguments", 0);
  dispatch_case(-1, program, 2, "invalid_arguments", 0);
  dispatch_case(1, NULL, 2, "invalid_arguments", 0);
  dispatch_case(1, null_program, 2, "invalid_arguments", 0);
  dispatch_case(2, null_argument, 2, "invalid_arguments", 0);
  CHECK(native_inspection_dispatch(1, program, NULL, stream) == 2);
  CHECK(native_inspection_dispatch(1, program, stream, NULL) == 2);
  CHECK(ftell(stream) == 0);
  CHECK(fclose(stream) == 0);
  dispatch_case(2, help, 0, NULL, 0);
  dispatch_case(3, help_extra, 2, "invalid_arguments", 0);
  dispatch_case(2, unknown, 2, "invalid_arguments", 0);
  dispatch_case(3, input_selector, 2, "invalid_arguments", 0);
  dispatch_case(2, layout_missing, 2, "invalid_arguments", 0);
  dispatch_case(5, layout_wrong, 2, "invalid_arguments", 0);
  case_file(observations, empty_observations, strlen(empty_observations));
  case_file(layout, invalid_layout, strlen(invalid_layout));
  case_file(input, "\015", 1);
  n = snprintf(missing, sizeof(missing), "%s/does-not-exist", scratch);
  CHECK(n > 0 && (size_t)n < sizeof(missing));
  {
    char *valid[] = {"afl-fuzz", "--inspect-observations", observations, NULL};
    char *bad_file[] = {"afl-fuzz", "--inspect-observations", missing, NULL};
    char *mixed[] = {"afl-fuzz", "--inspect-observations", observations, "-i", "seeds", NULL};
    char *extra_target[] = {"afl-fuzz", "--inspect-observations", observations, "--", "target", NULL};
    char *null_path[] = {"afl-fuzz", "--inspect-observations", NULL};
    char *content_invalid[] = {"afl-fuzz", "--inspect-layout", layout, "--inspect-input", input, NULL};
    dispatch_case(3, valid, 0, NULL, 1);
    dispatch_case(3, bad_file, 2, "input_error", 0);
    dispatch_case(5, mixed, 2, "invalid_arguments", 0);
    dispatch_case(5, extra_target, 2, "invalid_arguments", 0);
    dispatch_case(3, null_path, 2, "invalid_arguments", 0);
#if defined(__SIZEOF_INT128__)
    dispatch_case(5, content_invalid, 1, "invalid", 0);
#else
    dispatch_case(5, content_invalid, 2, "unsupported_platform", 0);
#endif
  }
}

int main(void) {
  CHECK(mkdtemp(scratch) != NULL);
  CHECK(atexit(cleanup) == 0);
  test_json_values();
  test_json_rejections();
  test_json_output_and_files();
  test_layout();
  test_fixture_mutations();
  test_observation_history();
  test_observation_prediction_and_pairing();
  test_observation_identity();
  test_observation_rejections();
  test_diagnostic_and_required_arguments();
  test_dispatcher();
  printf("Native local inspection and fixture checks passed: %zu\n", checks);
  return EXIT_SUCCESS;
}
