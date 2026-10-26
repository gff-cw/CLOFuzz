/* Strict, bounded JSON input for local inspection modules. */
#include "native_json.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  nj_document *document;
  size_t position;
  char *error;
  size_t error_capacity;
} nj_parser;

static int nj_error(char *error, size_t cap, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  if (error && cap) vsnprintf(error, cap, format, arguments);
  va_end(arguments);
  return -1;
}

static int parse_error(nj_parser *parser, const char *message) {
  return nj_error(parser->error, parser->error_capacity, "JSON byte %zu: %s",
                  parser->position, message);
}

static void free_value(nj_value *value) {
  size_t index;
  if (!value) return;
  if (value->items) {
    for (index = 0; index < value->count; index++) free_value(value->items[index]);
  }
  if (value->members) {
    for (index = 0; index < value->count; index++) {
      free(value->members[index].key);
      free_value(value->members[index].value);
    }
  }
  free(value->items);
  free(value->members);
  free(value->text);
  free(value);
}

void nj_free(nj_document *document) {
  if (!document) return;
  free_value(document->root);
  free(document->source);
  free(document);
}

static void whitespace(nj_parser *parser) {
  const unsigned char *source = parser->document->source;
  while (parser->position < parser->document->length) {
    unsigned char byte = source[parser->position];
    if (byte != ' ' && byte != '\t' && byte != '\r' && byte != '\n') break;
    parser->position++;
  }
}

static int charge_node(nj_parser *parser) {
  if (parser->document->nodes >= NJ_MAX_NODES) return parse_error(parser, "node budget exceeded");
  parser->document->nodes++;
  return 0;
}

/* Return one Unicode scalar and its byte width; overlong encodings are invalid. */
static int utf8_scalar(const unsigned char *source, size_t available,
                       uint32_t *scalar, size_t *width) {
  uint32_t code, minimum;
  size_t bytes, index;
  if (!source || !available) return -1;
  if (source[0] < 0x80) {
    *scalar = source[0];
    *width = 1;
    return 0;
  }
  if (source[0] >= 0xc2 && source[0] <= 0xdf) {
    bytes = 2; code = source[0] & 31u; minimum = 0x80;
  } else if (source[0] >= 0xe0 && source[0] <= 0xef) {
    bytes = 3; code = source[0] & 15u; minimum = 0x800;
  } else if (source[0] >= 0xf0 && source[0] <= 0xf4) {
    bytes = 4; code = source[0] & 7u; minimum = 0x10000;
  } else return -1;
  if (bytes > available) return -1;
  for (index = 1; index < bytes; index++) {
    if ((source[index] & 0xc0u) != 0x80u) return -1;
    code = (code << 6) | (source[index] & 63u);
  }
  if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return -1;
  *scalar = code;
  *width = bytes;
  return 0;
}

static int hex_digit(unsigned char byte) {
  if (byte >= '0' && byte <= '9') return byte - '0';
  if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
  if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
  return -1;
}

static int unicode_escape(const unsigned char *source, size_t end, size_t *position,
                          uint32_t *scalar) {
  uint32_t value = 0;
  size_t index;
  if (*position > end || end - *position < 4) return -1;
  for (index = 0; index < 4; index++) {
    int digit = hex_digit(source[*position + index]);
    if (digit < 0) return -1;
    value = (value << 4) | (unsigned)digit;
  }
  *position += 4;
  *scalar = value;
  return 0;
}

static size_t encode_scalar(uint32_t scalar, unsigned char *output) {
  if (scalar < 0x80) {
    output[0] = (unsigned char)scalar;
    return 1;
  }
  if (scalar < 0x800) {
    output[0] = 0xc0u | (scalar >> 6);
    output[1] = 0x80u | (scalar & 63u);
    return 2;
  }
  if (scalar < 0x10000) {
    output[0] = 0xe0u | (scalar >> 12);
    output[1] = 0x80u | ((scalar >> 6) & 63u);
    output[2] = 0x80u | (scalar & 63u);
    return 3;
  }
  output[0] = 0xf0u | (scalar >> 18);
  output[1] = 0x80u | ((scalar >> 12) & 63u);
  output[2] = 0x80u | ((scalar >> 6) & 63u);
  output[3] = 0x80u | (scalar & 63u);
  return 4;
}

/* Allocate only the raw string's length, not the remaining document length. */
static int parse_string(nj_parser *parser, char **text, size_t *length) {
  const unsigned char *source = parser->document->source;
  size_t start, end, input, output = 0;
  unsigned char *decoded;
  *text = NULL;
  *length = 0;
  if (parser->position >= parser->document->length || source[parser->position] != '"')
    return parse_error(parser, "expected a string");
  start = parser->position + 1;
  end = start;
  while (end < parser->document->length && source[end] != '"') {
    if (source[end] == '\\') {
      end++;
      if (end == parser->document->length) return parse_error(parser, "truncated string escape");
    }
    end++;
  }
  if (end == parser->document->length) return parse_error(parser, "unterminated string");
  decoded = malloc(end - start + 1);
  if (!decoded) return parse_error(parser, "out of memory decoding string");
  input = start;
  while (input < end) {
    unsigned char byte = source[input++];
    parser->position = input - 1;
    if (byte < 0x20) {
      free(decoded);
      return parse_error(parser, "unescaped control character");
    }
    if (byte == '\\') {
      uint32_t scalar, low;
      if (input >= end) goto bad_escape;
      byte = source[input++];
      switch (byte) {
        case '"': case '\\': case '/': decoded[output++] = byte; break;
        case 'b': decoded[output++] = '\b'; break;
        case 'f': decoded[output++] = '\f'; break;
        case 'n': decoded[output++] = '\n'; break;
        case 'r': decoded[output++] = '\r'; break;
        case 't': decoded[output++] = '\t'; break;
        case 'u':
          if (unicode_escape(source, end, &input, &scalar) < 0) goto bad_escape;
          if (scalar >= 0xd800 && scalar <= 0xdbff) {
            if (end - input < 2 || source[input] != '\\' || source[input + 1] != 'u') goto bad_escape;
            input += 2;
            if (unicode_escape(source, end, &input, &low) < 0 || low < 0xdc00 || low > 0xdfff)
              goto bad_escape;
            scalar = 0x10000u + ((scalar - 0xd800u) << 10) + low - 0xdc00u;
          } else if (scalar >= 0xdc00 && scalar <= 0xdfff) goto bad_escape;
          output += encode_scalar(scalar, decoded + output);
          break;
        default: goto bad_escape;
      }
    } else if (byte >= 0x80) {
      uint32_t scalar;
      size_t width;
      input--;
      if (utf8_scalar(source + input, end - input, &scalar, &width) < 0) {
        free(decoded);
        return parse_error(parser, "invalid UTF-8 string");
      }
      memcpy(decoded + output, source + input, width);
      input += width;
      output += width;
    } else decoded[output++] = byte;
  }
  decoded[output] = 0;
  *text = (char *)decoded;
  *length = output;
  parser->position = end + 1;
  return 0;
bad_escape:
  free(decoded);
  return parse_error(parser, "invalid escape or Unicode surrogate pair");
}

static int compare_members(const void *left, const void *right) {
  const nj_member *a = *(const nj_member *const *)left;
  const nj_member *b = *(const nj_member *const *)right;
  if (a->key_length < b->key_length) return -1;
  if (a->key_length > b->key_length) return 1;
  return memcmp(a->key, b->key, a->key_length);
}

static int unique_members(nj_parser *parser, const nj_value *object) {
  const nj_member **ordered;
  size_t index;
  if (object->count < 2) return 0;
  if (object->count > SIZE_MAX / sizeof(*ordered)) return parse_error(parser, "object size overflow");
  ordered = malloc(object->count * sizeof(*ordered));
  if (!ordered) return parse_error(parser, "out of memory checking object keys");
  for (index = 0; index < object->count; index++) ordered[index] = &object->members[index];
  qsort(ordered, object->count, sizeof(*ordered), compare_members);
  for (index = 1; index < object->count; index++) {
    if (compare_members(&ordered[index - 1], &ordered[index]) == 0) {
      free(ordered);
      return parse_error(parser, "duplicate decoded object key");
    }
  }
  free(ordered);
  return 0;
}

static nj_value *parse_value(nj_parser *parser, unsigned depth);

static int parse_container(nj_parser *parser, nj_value *value, unsigned depth) {
  const unsigned char *source = parser->document->source;
  size_t capacity = 0;
  int object = source[parser->position] == '{';
  unsigned char closing = object ? '}' : ']';
  value->type = object ? NJ_OBJECT : NJ_ARRAY;
  parser->position++;
  whitespace(parser);
  if (parser->position < parser->document->length && source[parser->position] == closing) {
    parser->position++;
    return 0;
  }
  for (;;) {
    char *key = NULL;
    size_t key_length = 0;
    nj_value *child;
    whitespace(parser);
    if (object) {
      if (charge_node(parser) < 0 || parse_string(parser, &key, &key_length) < 0) return -1;
      whitespace(parser);
      if (parser->position >= parser->document->length || source[parser->position] != ':') {
        free(key);
        return parse_error(parser, "expected object colon");
      }
      parser->position++;
    }
    child = parse_value(parser, depth + 1);
    if (!child) {
      free(key);
      return -1;
    }
    if (value->count == capacity) {
      size_t next = capacity ? capacity * 2 : 8;
      size_t item_size = object ? sizeof(*value->members) : sizeof(*value->items);
      void *grown;
      if (next > NJ_MAX_NODES) next = NJ_MAX_NODES;
      if (next <= capacity || next > SIZE_MAX / item_size) {
        free(key);
        free_value(child);
        return parse_error(parser, "container allocation overflow");
      }
      grown = realloc(object ? (void *)value->members : (void *)value->items, next * item_size);
      if (!grown) {
        free(key);
        free_value(child);
        return parse_error(parser, "out of memory growing container");
      }
      if (object) value->members = grown;
      else value->items = grown;
      capacity = next;
    }
    if (object) {
      value->members[value->count].key = key;
      value->members[value->count].key_length = key_length;
      value->members[value->count].value = child;
    } else value->items[value->count] = child;
    value->count++;
    whitespace(parser);
    if (parser->position >= parser->document->length) return parse_error(parser, "unterminated container");
    if (source[parser->position] == closing) {
      parser->position++;
      return object ? unique_members(parser, value) : 0;
    }
    if (source[parser->position] != ',') return parse_error(parser, "expected container comma or closing delimiter");
    parser->position++;
  }
}

static int parse_integer(nj_parser *parser, nj_value *value) {
  const unsigned char *source = parser->document->source;
  size_t length = parser->document->length;
  uint64_t magnitude = 0;
  int negative = 0;
  value->type = NJ_INTEGER;
  if (source[parser->position] == '-') {
    negative = 1;
    parser->position++;
  }
  if (parser->position >= length || source[parser->position] < '0' || source[parser->position] > '9')
    return parse_error(parser, "expected integer digits");
  if (source[parser->position] == '0' && parser->position + 1 < length &&
      source[parser->position + 1] >= '0' && source[parser->position + 1] <= '9')
    return parse_error(parser, "leading zero in integer");
  while (parser->position < length && source[parser->position] >= '0' && source[parser->position] <= '9') {
    unsigned digit = source[parser->position] - '0';
    if (magnitude > (UINT64_MAX - digit) / 10) return parse_error(parser, "integer exceeds uint64 range");
    magnitude = magnitude * 10 + digit;
    parser->position++;
  }
  if (parser->position < length && (source[parser->position] == '.' ||
      source[parser->position] == 'e' || source[parser->position] == 'E'))
    return parse_error(parser, "only integer JSON numbers are supported");
  if (negative && magnitude > (UINT64_C(1) << 63)) return parse_error(parser, "integer is below int64 minimum");
  value->number.negative = negative && magnitude != 0;
  value->number.magnitude = magnitude;
  return 0;
}

static nj_value *parse_value(nj_parser *parser, unsigned depth) {
  const unsigned char *source = parser->document->source;
  nj_value *value;
  unsigned char byte;
  whitespace(parser);
  if (depth > NJ_MAX_DEPTH) {
    parse_error(parser, "nesting depth exceeded");
    return NULL;
  }
  if (parser->position >= parser->document->length) {
    parse_error(parser, "missing value");
    return NULL;
  }
  if (charge_node(parser) < 0) return NULL;
  value = calloc(1, sizeof(*value));
  if (!value) {
    parse_error(parser, "out of memory allocating value");
    return NULL;
  }
  value->start = parser->position;
  byte = source[parser->position];
  if (byte == '{' || byte == '[') {
    if (parse_container(parser, value, depth) < 0) goto bad;
  } else if (byte == '"') {
    value->type = NJ_STRING;
    if (parse_string(parser, &value->text, &value->text_length) < 0) goto bad;
  } else if (byte == '-' || (byte >= '0' && byte <= '9')) {
    if (parse_integer(parser, value) < 0) goto bad;
  } else if (byte == 't' || byte == 'f' || byte == 'n') {
    const char *literal = byte == 't' ? "true" : byte == 'f' ? "false" : "null";
    size_t width = strlen(literal);
    if (width > parser->document->length - parser->position ||
        memcmp(source + parser->position, literal, width)) {
      parse_error(parser, "invalid literal");
      goto bad;
    }
    value->type = byte == 'n' ? NJ_NULL : NJ_BOOL;
    value->boolean = byte == 't';
    parser->position += width;
  } else {
    parse_error(parser, "unexpected value byte");
    goto bad;
  }
  value->end = parser->position;
  return value;
bad:
  free_value(value);
  return NULL;
}

int nj_parse_buffer(const unsigned char *data, size_t length, nj_document **out,
                    char *error, size_t cap) {
  nj_document *document;
  nj_parser parser;
  if (out) *out = NULL;
  if (error && cap) error[0] = 0;
  if (!out || (!data && length)) return nj_error(error, cap, "missing JSON input or output pointer");
  if (length > NJ_MAX_BYTES) return nj_error(error, cap, "JSON input exceeds 1 MiB");
  document = calloc(1, sizeof(*document));
  if (!document) return nj_error(error, cap, "out of memory allocating JSON document");
  document->source = malloc(length + 1);
  if (!document->source) {
    nj_free(document);
    return nj_error(error, cap, "out of memory copying JSON input");
  }
  if (length) memcpy(document->source, data, length);
  document->source[length] = 0;
  document->length = length;
  parser.document = document;
  parser.position = 0;
  parser.error = error;
  parser.error_capacity = cap;
  document->root = parse_value(&parser, 0);
  if (!document->root) {
    nj_free(document);
    return -1;
  }
  whitespace(&parser);
  if (parser.position != length) {
    parse_error(&parser, "trailing bytes after root value");
    nj_free(document);
    return -1;
  }
  *out = document;
  return 0;
}

int nj_read_file(const char *path, unsigned char **data, size_t *length,
                 size_t limit, char *error, size_t cap) {
  FILE *input;
  unsigned char *buffer;
  size_t used;
  int saved_errno;
  if (data) *data = NULL;
  if (length) *length = 0;
  if (error && cap) error[0] = 0;
  if (!path || !data || !length || limit > NJ_MAX_BYTES)
    return nj_error(error, cap, "invalid file input or byte limit");
  input = fopen(path, "rb");
  if (!input) return nj_error(error, cap, "cannot open input file: %s", strerror(errno));
  buffer = malloc(limit + 1);
  if (!buffer) {
    fclose(input);
    return nj_error(error, cap, "out of memory reading input");
  }
  used = fread(buffer, 1, limit + 1, input);
  if (ferror(input)) {
    saved_errno = errno;
    fclose(input);
    free(buffer);
    return nj_error(error, cap, "cannot read input file: %s", strerror(saved_errno));
  }
  if (fclose(input)) {
    saved_errno = errno;
    free(buffer);
    return nj_error(error, cap, "cannot close input file: %s", strerror(saved_errno));
  }
  if (used > limit) {
    free(buffer);
    return nj_error(error, cap, "input file exceeds byte limit");
  }
  buffer[used] = 0;
  *data = buffer;
  *length = used;
  return 0;
}

int nj_load_file(const char *path, nj_document **out, char *error, size_t cap) {
  unsigned char *data;
  size_t length;
  int result;
  if (out) *out = NULL;
  if (!out) return nj_error(error, cap, "missing JSON output pointer");
  if (nj_read_file(path, &data, &length, NJ_MAX_BYTES, error, cap) < 0) return -1;
  result = nj_parse_buffer(data, length, out, error, cap);
  free(data);
  return result;
}

const nj_value *nj_get(const nj_value *object, const char *key) {
  size_t index, length;
  if (!object || object->type != NJ_OBJECT || !key) return NULL;
  length = strlen(key);
  for (index = 0; index < object->count; index++) {
    if (object->members[index].key_length == length && !memcmp(object->members[index].key, key, length))
      return object->members[index].value;
  }
  return NULL;
}

static int named_key(const nj_member *member, const char *const *names, size_t count) {
  size_t index;
  for (index = 0; index < count; index++) {
    if (names[index] && strlen(names[index]) == member->key_length &&
        !memcmp(names[index], member->key, member->key_length)) return 1;
  }
  return 0;
}

int nj_keys(const nj_value *object, const char *const *required, size_t required_count,
             const char *const *optional, size_t optional_count, char *error, size_t cap) {
  size_t index;
  if (!object || object->type != NJ_OBJECT) return nj_error(error, cap, "expected JSON object");
  if ((required_count && !required) || (optional_count && !optional))
    return nj_error(error, cap, "invalid object key contract");
  for (index = 0; index < required_count; index++) {
    if (!required[index] || !nj_get(object, required[index]))
      return nj_error(error, cap, "missing required JSON property");
  }
  for (index = 0; index < object->count; index++) {
    if (!named_key(&object->members[index], required, required_count) &&
        !named_key(&object->members[index], optional, optional_count))
      return nj_error(error, cap, "unsupported JSON property");
  }
  return 0;
}

int nj_string_copy(const nj_value *value, char *out, size_t capacity, char *error, size_t cap) {
  if (out && capacity) out[0] = 0;
  if (!value || value->type != NJ_STRING || !out || !capacity)
    return nj_error(error, cap, "expected JSON string and output buffer");
  if (value->text_length >= capacity || memchr(value->text, 0, value->text_length))
    return nj_error(error, cap, "string contains NUL or exceeds destination capacity");
  memcpy(out, value->text, value->text_length);
  out[value->text_length] = 0;
  return 0;
}

int nj_string_equal(const nj_value *value, const char *text) {
  size_t length;
  if (!value || value->type != NJ_STRING || !text) return 0;
  length = strlen(text);
  return value->text_length == length && !memcmp(value->text, text, length);
}

int nj_u64(const nj_value *value, uint64_t *out, char *error, size_t cap) {
  if (!value || value->type != NJ_INTEGER || !out ||
      (value->number.negative && value->number.magnitude))
    return nj_error(error, cap, "expected unsigned integer");
  *out = value->number.magnitude;
  return 0;
}

int nj_i64(const nj_value *value, int64_t *out, char *error, size_t cap) {
  uint64_t magnitude;
  if (!value || value->type != NJ_INTEGER || !out) return nj_error(error, cap, "expected signed integer");
  magnitude = value->number.magnitude;
  if (value->number.negative) {
    if (magnitude > (UINT64_C(1) << 63)) return nj_error(error, cap, "signed integer underflow");
    *out = magnitude == (UINT64_C(1) << 63) ? INT64_MIN : -(int64_t)magnitude;
  } else {
    if (magnitude > INT64_MAX) return nj_error(error, cap, "signed integer overflow");
    *out = (int64_t)magnitude;
  }
  return 0;
}

int nj_boolean(const nj_value *value, int *out, char *error, size_t cap) {
  if (!value || value->type != NJ_BOOL || !out) return nj_error(error, cap, "expected JSON boolean");
  *out = value->boolean;
  return 0;
}

void nj_write_string(FILE *out, const char *text, size_t length) {
  size_t index;
  if (!out) return;
  if (!text) length = 0;
  fputc('"', out);
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)text[index];
    if (byte == '"' || byte == '\\') {
      fputc('\\', out);
      fputc(byte, out);
    } else if (byte < 0x20) fprintf(out, "\\u%04x", (unsigned)byte);
    else if (byte >= 0x80) {
      uint32_t scalar;
      size_t width;
      if (utf8_scalar((const unsigned char *)text + index, length - index, &scalar, &width) == 0) {
        fwrite(text + index, 1, width, out);
        index += width - 1;
      } else fprintf(out, "\\u%04x", (unsigned)byte);
    } else fputc(byte, out);
  }
  fputc('"', out);
}

int nj_write_value(FILE *out, const nj_document *document, const nj_value *value) {
  size_t width;
  if (!out || !document || !document->source || !value ||
      value->start >= value->end || value->end > document->length) return -1;
  width = value->end - value->start;
  if (fwrite(document->source + value->start, 1, width, out) != width || ferror(out)) return -1;
  return 0;
}
