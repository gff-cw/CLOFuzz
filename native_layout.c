/* Protocol-independent, passive decoding of existing local files.
 * No encoder, mutation callback, transport or target execution is present. */
#include "native_json.h"
#include "native_inspect.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__SIZEOF_INT128__)
int native_layout_inspect(const char *layout_path, const char *input_path,
                          FILE *out, native_diagnostic *diagnostic) {
  if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
  if (!layout_path || !input_path || !out || !diagnostic) {
    native_inspect_error(diagnostic, "input_error", "", 0, "missing inspection argument");
    return NATIVE_INSPECT_ERROR;
  }
  native_inspect_error(diagnostic, "unsupported_platform", "", 0,
                       "native layout inspection requires a compiler with 128-bit integers");
  return 2;
}
#else
typedef __int128 layout_int;
#define LI_MIN (-((layout_int)1 << 63))
#define LI_MAX ((layout_int)UINT64_MAX)
#define LAYOUT_MAX_NODES 4096u
#define LAYOUT_MAX_DEPTH 32u
#define LAYOUT_MAX_FIELDS 65536u
#define LAYOUT_MAX_REPEAT 4096u
#define LAYOUT_MAX_EXPR_STEPS 524288u
#define LAYOUT_MAX_PATH 8192u

enum layout_kind { L_STRUCT, L_UINT, L_INT, L_BYTES, L_BITS, L_CHOICE,
                   L_REPEAT, L_BOUNDED, L_ALIGN, L_BIT };
typedef struct layout_spec layout_spec;
struct layout_spec {
  enum layout_kind kind;
  char id[64];
  char *source;
  unsigned width, little, encoding, multiple, max_items, lsb, bit_width;
  int has_fill, has_expected;
  unsigned fill;
  layout_int minimum, maximum, expected;
  layout_int *values, *case_values;
  size_t value_count, child_count;
  layout_spec **children;
  layout_spec *body;
  const nj_value *expression, *expected_hex;
};

typedef struct layout_field layout_field;
struct layout_field {
  const layout_spec *spec;
  char *path;
  size_t start, end, child_count, child_capacity;
  layout_field **children;
  layout_int integer;
  char selected_case[48];
};
typedef struct layout_scope {
  layout_field *structure;
  struct layout_scope *outer;
} layout_scope;
typedef struct {
  native_diagnostic *diagnostic;
  unsigned char *data;
  size_t length, offset, specs, fields, expression_steps, bounded_depth;
  int exit_code;
} layout_context;

static int layout_error(layout_context *context, const char *status,
                        const char *path, const char *format, ...) {
  char message[512];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  context->exit_code = !strcmp(status, "invalid_description") ||
                       !strcmp(status, "input_error") ||
                       !strcmp(status, "resource_limit") ? 2 : 1;
  native_inspect_error(context->diagnostic, status, path ? path : "",
                       context->offset, "%s", message);
  return -1;
}

static char *layout_copy(layout_context *context, const char *text,
                         const char *path) {
  size_t length = strlen(text);
  char *copy = malloc(length + 1);
  if (!copy) {
    layout_error(context, "resource_limit", path, "out of memory");
    return NULL;
  }
  memcpy(copy, text, length + 1);
  return copy;
}

static char *layout_path(layout_context *context, const char *current,
                         const char *format, ...) {
  char text[LAYOUT_MAX_PATH];
  int length;
  va_list args;
  va_start(args, format);
  length = vsnprintf(text, sizeof(text), format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= sizeof(text)) {
    layout_error(context, "resource_limit", current, "field path exceeds 8191 bytes");
    return NULL;
  }
  return layout_copy(context, text, current);
}

static int layout_keys(layout_context *context, const nj_value *value,
                        const char *const *required, size_t required_count,
                        const char *const *optional, size_t optional_count,
                        const char *path) {
  char error[256];
  if (nj_keys(value, required, required_count, optional, optional_count,
               error, sizeof(error)) < 0)
    return layout_error(context, "invalid_description", path, "%s", error);
  return 0;
}

static int layout_number(const nj_value *value, layout_int *out) {
  if (!value || value->type != NJ_INTEGER) return -1;
  if (value->number.negative) {
    if (value->number.magnitude > UINT64_C(9223372036854775808)) return -1;
    *out = -(layout_int)value->number.magnitude;
  } else *out = (layout_int)value->number.magnitude;
  return 0;
}

static int layout_integer(layout_context *context, const nj_value *value,
                           layout_int low, layout_int high, layout_int *out,
                           const char *path) {
  if (layout_number(value, out) < 0 || *out < low || *out > high)
    return layout_error(context, "invalid_description", path,
                         "integer is absent, mistyped or outside its declared bounds");
  return 0;
}

static int layout_text(layout_context *context, const nj_value *value,
                        char *out, size_t cap, const char *path) {
  char error[256];
  if (nj_string_copy(value, out, cap, error, sizeof(error)) < 0)
    return layout_error(context, "invalid_description", path, "%s", error);
  return 0;
}

static int ascii_letter(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int valid_identifier(const char *text) {
  size_t length = strlen(text);
  if (!length || length > 63 || !ascii_letter((unsigned char)text[0])) return 0;
  for (size_t i = 1; i < length; i++) {
    unsigned char c = (unsigned char)text[i];
    if (!ascii_letter(c) && !(c >= '0' && c <= '9') && c != '_') return 0;
  }
  return 1;
}

static int valid_reference(const char *text) {
  char part[64];
  size_t length = 0, parts = 0;
  for (size_t i = 0;; i++) {
    if (!text[i] || text[i] == '.') {
      part[length] = 0;
      if (!valid_identifier(part) || ++parts > LAYOUT_MAX_DEPTH) return 0;
      length = 0;
      if (!text[i]) return 1;
    } else {
      if (length >= sizeof(part) - 1) return 0;
      part[length++] = text[i];
    }
  }
}

static int validate_expression(layout_context *context, const nj_value *value,
                                unsigned depth, const char *path) {
  static const char *const ref_keys[] = {"ref"};
  static const char *const op_keys[] = {"op", "args"};
  static const char *const operations[] = {
    "add", "sub", "mul", "div", "mod", "and", "or", "xor", "shl", "shr"
  };
  char reference[2048], operation[8];
  layout_int number;
  if (depth > LAYOUT_MAX_DEPTH)
    return layout_error(context, "invalid_description", path, "expression depth exceeds 32");
  if (layout_number(value, &number) == 0) return 0;
  if (!value || value->type != NJ_OBJECT)
    return layout_error(context, "invalid_description", path, "expected an integer expression object");
  if (nj_get(value, "ref")) {
    if (layout_keys(context, value, ref_keys, 1, NULL, 0, path) < 0 ||
        layout_text(context, nj_get(value, "ref"), reference, sizeof(reference), path) < 0) return -1;
    if (!valid_reference(reference))
      return layout_error(context, "invalid_description", path, "invalid lexical field reference");
    return 0;
  }
  if (layout_keys(context, value, op_keys, 2, NULL, 0, path) < 0 ||
      layout_text(context, nj_get(value, "op"), operation, sizeof(operation), path) < 0) return -1;
  int known = 0;
  for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); i++)
    if (!strcmp(operation, operations[i])) known = 1;
  const nj_value *arguments = nj_get(value, "args");
  if (!known || !arguments || arguments->type != NJ_ARRAY || arguments->count != 2)
    return layout_error(context, "invalid_description", path, "unknown operation or non-binary expression");
  return validate_expression(context, arguments->items[0], depth + 1, path) < 0 ||
         validate_expression(context, arguments->items[1], depth + 1, path) < 0 ? -1 : 0;
}

static void free_spec(layout_spec *spec) {
  if (!spec) return;
  for (size_t i = 0; i < spec->child_count; i++) free_spec(spec->children[i]);
  free_spec(spec->body);
  free(spec->children);
  free(spec->values);
  free(spec->case_values);
  free(spec->source);
  free(spec);
}

static layout_spec *new_spec(layout_context *context, const char *source) {
  if (++context->specs > LAYOUT_MAX_NODES) {
    layout_error(context, "invalid_description", source, "layout node budget exceeds 4096");
    return NULL;
  }
  layout_spec *spec = calloc(1, sizeof(*spec));
  if (!spec) {
    layout_error(context, "resource_limit", source, "out of memory");
    return NULL;
  }
  spec->source = layout_copy(context, source, source);
  if (!spec->source) { free(spec); return NULL; }
  return spec;
}

static int scalar_constraints(layout_context *context, layout_spec *spec,
                                const nj_value *object) {
  const char *path = spec->source;
  const nj_value *value;
  if ((value = nj_get(object, "min")) &&
      layout_integer(context, value, spec->minimum, spec->maximum, &spec->minimum, path) < 0) return -1;
  if ((value = nj_get(object, "max")) &&
      layout_integer(context, value, spec->minimum, spec->maximum, &spec->maximum, path) < 0) return -1;
  if ((value = nj_get(object, "expected"))) {
    if (layout_integer(context, value, spec->minimum, spec->maximum, &spec->expected, path) < 0) return -1;
    spec->has_expected = 1;
  }
  if ((value = nj_get(object, "values"))) {
    if (value->type != NJ_ARRAY || !value->count || value->count > 256)
      return layout_error(context, "invalid_description", path, "values requires 1..256 integers");
    spec->values = calloc(value->count, sizeof(*spec->values));
    if (!spec->values) return layout_error(context, "resource_limit", path, "out of memory");
    spec->value_count = value->count;
    int expected_present = !spec->has_expected;
    for (size_t i = 0; i < value->count; i++) {
      if (layout_integer(context, value->items[i], spec->minimum, spec->maximum, &spec->values[i], path) < 0) return -1;
      for (size_t j = 0; j < i; j++) if (spec->values[j] == spec->values[i])
        return layout_error(context, "invalid_description", path, "duplicate enumeration value");
      if (spec->has_expected && spec->values[i] == spec->expected) expected_present = 1;
    }
    if (!expected_present)
      return layout_error(context, "invalid_description", path, "expected value is absent from enumeration");
  }
  return 0;
}

static int hex_digit(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int case_number(const char *text, size_t length, layout_int *out) {
  uint64_t magnitude = 0;
  size_t i = 0;
  int negative = length && text[0] == '-';
  if (negative) i++;
  if (i == length || length - i > 20 || (text[i] == '0' && (negative || length - i != 1))) return -1;
  for (; i < length; i++) {
    if (text[i] < '0' || text[i] > '9') return -1;
    unsigned digit = (unsigned)(text[i] - '0');
    if (magnitude > (UINT64_MAX - digit) / 10) return -1;
    magnitude = magnitude * 10 + digit;
  }
  if (negative && magnitude > UINT64_C(9223372036854775808)) return -1;
  *out = negative ? -(layout_int)magnitude : (layout_int)magnitude;
  return 0;
}

static layout_spec *compile_spec(layout_context *context, const nj_value *object,
                                  unsigned depth, const char *source) {
  static const char *const names[] = {"struct", "uint", "int", "bytes", "bits", "choice", "repeat", "bounded", "align"};
  const char *required[8] = {"id", "kind"};
  const char *optional[8];
  size_t nr = 2, no = 0;
  char kind[16], byte_order[8], encoding[8];
  layout_int number;
  const nj_value *fields, *value;
  layout_spec *spec = NULL;
  if (depth > LAYOUT_MAX_DEPTH) {
    layout_error(context, "invalid_description", source, "layout depth exceeds 32");
    return NULL;
  }
  if (!object || object->type != NJ_OBJECT) {
    layout_error(context, "invalid_description", source, "layout node must be an object");
    return NULL;
  }
  spec = new_spec(context, source);
  if (!spec) return NULL;
  if (layout_text(context, nj_get(object, "id"), spec->id, sizeof(spec->id), source) < 0 ||
      layout_text(context, nj_get(object, "kind"), kind, sizeof(kind), source) < 0) goto bad;
  if (!valid_identifier(spec->id)) { layout_error(context, "invalid_description", source, "invalid node identifier"); goto bad; }
  int found = 0;
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    if (!strcmp(kind, names[i])) { spec->kind = (enum layout_kind)i; found = 1; break; }
  if (!found) { layout_error(context, "invalid_description", source, "unsupported node kind"); goto bad; }
  switch (spec->kind) {
    case L_UINT: case L_INT: case L_BITS:
      required[nr++] = "width"; required[nr++] = "byte_order";
      if (layout_integer(context, nj_get(object, "width"), 1, 8, &number, source) < 0 ||
          layout_text(context, nj_get(object, "byte_order"), byte_order, sizeof(byte_order), source) < 0) goto bad;
      spec->width = (unsigned)number;
      if (strcmp(byte_order, "big") && strcmp(byte_order, "little")) { layout_error(context, "invalid_description", source, "unknown byte order"); goto bad; }
      spec->little = !strcmp(byte_order, "little");
      if (spec->kind == L_BITS) required[nr++] = "fields";
      else {
        optional[no++] = "min"; optional[no++] = "max";
        optional[no++] = "expected"; optional[no++] = "values";
        spec->minimum = spec->kind == L_INT ? -((layout_int)1 << (spec->width * 8 - 1)) : 0;
        spec->maximum = spec->kind == L_INT ? ((layout_int)1 << (spec->width * 8 - 1)) - 1 : ((layout_int)1 << (spec->width * 8)) - 1;
        if (scalar_constraints(context, spec, object) < 0) goto bad;
      }
      break;
    case L_STRUCT: required[nr++] = "fields"; break;
    case L_BYTES:
      required[nr++] = "length"; optional[no++] = "encoding"; optional[no++] = "expected_hex";
      spec->expression = nj_get(object, "length");
      if (validate_expression(context, spec->expression, 0, source) < 0) goto bad;
      value = nj_get(object, "encoding");
      if (value) {
        if (layout_text(context, value, encoding, sizeof(encoding), source) < 0) goto bad;
        if (!strcmp(encoding, "ascii")) spec->encoding = 1;
        else if (!strcmp(encoding, "utf8")) spec->encoding = 2;
        else if (strcmp(encoding, "hex")) { layout_error(context, "invalid_description", source, "unsupported bytes encoding"); goto bad; }
      }
      spec->expected_hex = nj_get(object, "expected_hex");
      if (spec->expected_hex) {
        value = spec->expected_hex;
        if (value->type != NJ_STRING || value->text_length % 2 || value->text_length > NJ_MAX_BYTES * 2u) {
          layout_error(context, "invalid_description", source, "invalid expected_hex"); goto bad;
        }
        for (size_t i = 0; i < value->text_length; i++) if (hex_digit((unsigned char)value->text[i]) < 0) {
          layout_error(context, "invalid_description", source, "invalid expected_hex digit"); goto bad;
        }
      }
      break;
    case L_CHOICE: required[nr++] = "selector"; required[nr++] = "cases"; optional[no++] = "default"; break;
    case L_REPEAT:
      required[nr++] = "count"; required[nr++] = "max_items"; required[nr++] = "item";
      if (layout_integer(context, nj_get(object, "max_items"), 0, LAYOUT_MAX_REPEAT, &number, source) < 0) goto bad;
      spec->max_items = (unsigned)number;
      spec->expression = nj_get(object, "count");
      if (validate_expression(context, spec->expression, 0, source) < 0) goto bad;
      break;
    case L_BOUNDED:
      required[nr++] = "length"; required[nr++] = "body";
      spec->expression = nj_get(object, "length");
      if (validate_expression(context, spec->expression, 0, source) < 0) goto bad;
      break;
    case L_ALIGN:
      required[nr++] = "multiple"; optional[no++] = "fill";
      if (layout_integer(context, nj_get(object, "multiple"), 1, 256, &number, source) < 0) goto bad;
      spec->multiple = (unsigned)number;
      if ((value = nj_get(object, "fill"))) {
        if (layout_integer(context, value, 0, 255, &number, source) < 0) goto bad;
        spec->has_fill = 1; spec->fill = (unsigned)number;
      }
      break;
    case L_BIT: goto bad;
  }
  if (layout_keys(context, object, required, nr, optional, no, source) < 0) goto bad;
  if (spec->kind == L_STRUCT || spec->kind == L_BITS) {
    fields = nj_get(object, "fields");
    if (!fields || fields->type != NJ_ARRAY || !fields->count || fields->count > 256) {
      layout_error(context, "invalid_description", source, "fields requires 1..256 entries"); goto bad;
    }
    spec->children = calloc(fields->count, sizeof(*spec->children));
    if (!spec->children) { layout_error(context, "resource_limit", source, "out of memory"); goto bad; }
    uint64_t occupied = 0;
    for (size_t i = 0; i < fields->count; i++) {
      char *child_source = layout_path(context, source, "%s/fields/%zu", source, i);
      if (!child_source) goto bad;
      layout_spec *child;
      if (spec->kind == L_STRUCT) child = compile_spec(context, fields->items[i], depth + 1, child_source);
      else {
        static const char *const bit_required[] = {"id", "lsb", "width"};
        static const char *const bit_optional[] = {"expected"};
        const nj_value *bit = fields->items[i];
        child = new_spec(context, child_source);
        if (child) {
          child->kind = L_BIT; child->width = spec->width; child->little = spec->little;
          if (layout_keys(context, bit, bit_required, 3, bit_optional, 1, child_source) < 0 ||
              layout_text(context, nj_get(bit, "id"), child->id, sizeof(child->id), child_source) < 0 ||
              layout_integer(context, nj_get(bit, "lsb"), 0, spec->width * 8 - 1, &number, child_source) < 0) { free_spec(child); child = NULL; }
          if (child) {
            child->lsb = (unsigned)number;
            if (!valid_identifier(child->id)) { layout_error(context, "invalid_description", child_source, "invalid bit identifier"); free_spec(child); child = NULL; }
          }
          if (child && layout_integer(context, nj_get(bit, "width"), 1, spec->width * 8 - child->lsb, &number, child_source) < 0) { free_spec(child); child = NULL; }
          if (child) {
            child->bit_width = (unsigned)number;
            child->maximum = ((layout_int)1 << child->bit_width) - 1;
            uint64_t mask = (child->bit_width == 64 ? UINT64_MAX : (UINT64_C(1) << child->bit_width) - 1) << child->lsb;
            if (occupied & mask) { layout_error(context, "invalid_description", child_source, "overlapping bit fields"); free_spec(child); child = NULL; }
            else occupied |= mask;
          }
          if (child && (value = nj_get(bit, "expected"))) {
            if (layout_integer(context, value, 0, child->maximum, &child->expected, child_source) < 0) { free_spec(child); child = NULL; }
            else child->has_expected = 1;
          }
        }
      }
      free(child_source);
      if (!child) goto bad;
      spec->children[spec->child_count++] = child;
      for (size_t j = 0; j + 1 < spec->child_count; j++) if (!strcmp(spec->children[j]->id, child->id)) {
        layout_error(context, "invalid_description", source, "duplicate sibling field identifier"); goto bad;
      }
    }
  } else if (spec->kind == L_CHOICE) {
    spec->expression = nj_get(object, "selector");
    if (validate_expression(context, spec->expression, 0, source) < 0) goto bad;
    fields = nj_get(object, "cases");
    if (!fields || fields->type != NJ_OBJECT || !fields->count || fields->count > 256) {
      layout_error(context, "invalid_description", source, "choice requires 1..256 cases"); goto bad;
    }
    spec->children = calloc(fields->count, sizeof(*spec->children));
    spec->case_values = calloc(fields->count, sizeof(*spec->case_values));
    if (!spec->children || !spec->case_values) { layout_error(context, "resource_limit", source, "out of memory"); goto bad; }
    for (size_t i = 0; i < fields->count; i++) {
      const nj_member *member = &fields->members[i];
      if (case_number(member->key, member->key_length, &spec->case_values[i]) < 0) {
        layout_error(context, "invalid_description", source, "case key must be a canonical supported decimal integer"); goto bad;
      }
      char *child_source = layout_path(context, source, "%s/cases/%s", source, member->key);
      if (!child_source) goto bad;
      layout_spec *child = compile_spec(context, member->value, depth + 1, child_source);
      free(child_source);
      if (!child) goto bad;
      spec->children[spec->child_count++] = child;
    }
    if ((value = nj_get(object, "default"))) {
      char *child_source = layout_path(context, source, "%s/default", source);
      if (!child_source) goto bad;
      spec->body = compile_spec(context, value, depth + 1, child_source);
      free(child_source);
      if (!spec->body) goto bad;
    }
  } else if (spec->kind == L_REPEAT || spec->kind == L_BOUNDED) {
    const char *name = spec->kind == L_REPEAT ? "item" : "body";
    char *child_source = layout_path(context, source, "%s/%s", source, name);
    if (!child_source) goto bad;
    spec->body = compile_spec(context, nj_get(object, name), depth + 1, child_source);
    free(child_source);
    if (!spec->body) goto bad;
  }
  return spec;
bad:
  free_spec(spec);
  return NULL;
}

static void free_field(layout_field *field) {
  if (!field) return;
  for (size_t i = 0; i < field->child_count; i++) free_field(field->children[i]);
  free(field->children);
  free(field->path);
  free(field);
}

static layout_field *new_field(layout_context *context, const layout_spec *spec,
                                const char *path) {
  if (++context->fields > LAYOUT_MAX_FIELDS) {
    layout_error(context, "resource_limit", path, "decoded field budget exceeds 65536");
    return NULL;
  }
  layout_field *field = calloc(1, sizeof(*field));
  if (!field) { layout_error(context, "resource_limit", path, "out of memory"); return NULL; }
  field->spec = spec;
  field->start = context->offset;
  field->path = layout_copy(context, path, path);
  if (!field->path) { free(field); return NULL; }
  return field;
}

/* Ownership transfers only on success. */
static int append_field(layout_context *context, layout_field *parent,
                         layout_field *child) {
  if (parent->child_count == parent->child_capacity) {
    size_t capacity = parent->child_capacity ? parent->child_capacity * 2 : 4;
    if (capacity > LAYOUT_MAX_FIELDS) capacity = LAYOUT_MAX_FIELDS;
    if (capacity <= parent->child_count)
      return layout_error(context, "resource_limit", parent->path, "child field budget exceeded");
    layout_field **children = realloc(parent->children, capacity * sizeof(*children));
    if (!children) return layout_error(context, "resource_limit", parent->path, "out of memory");
    parent->children = children;
    parent->child_capacity = capacity;
  }
  parent->children[parent->child_count++] = child;
  return 0;
}

static layout_field *transparent_field(layout_field *field) {
  while (field && (field->spec->kind == L_CHOICE || field->spec->kind == L_BOUNDED))
    field = field->child_count == 1 ? field->children[0] : NULL;
  return field;
}

static layout_field *named_field(layout_field *field, const char *name) {
  field = transparent_field(field);
  if (!field || (field->spec->kind != L_STRUCT && field->spec->kind != L_BITS)) return NULL;
  for (size_t i = 0; i < field->child_count; i++)
    if (!strcmp(field->children[i]->spec->id, name)) return field->children[i];
  return NULL;
}

static int evaluate_reference(layout_context *context, const nj_value *value,
                                layout_scope *scope, const char *path,
                                layout_int *out) {
  char reference[2048], error[256];
  char *parts[LAYOUT_MAX_DEPTH];
  size_t count = 0;
  if (nj_string_copy(value, reference, sizeof(reference), error, sizeof(error)) < 0)
    return layout_error(context, "invalid", path, "invalid reference: %s", error);
  char *part = reference;
  for (;;) {
    if (count == LAYOUT_MAX_DEPTH)
      return layout_error(context, "invalid", path, "reference depth exceeded");
    parts[count++] = part;
    char *dot = strchr(part, '.');
    if (!dot) break;
    *dot = 0; part = dot + 1;
  }
  for (; scope; scope = scope->outer) {
    layout_field *field = named_field(scope->structure, parts[0]);
    if (!field) continue;
    for (size_t i = 1; i < count; i++) {
      field = named_field(field, parts[i]);
      if (!field) return layout_error(context, "invalid", path, "reference does not name a decoded integer");
    }
    field = transparent_field(field);
    if (!field || (field->spec->kind != L_UINT && field->spec->kind != L_INT && field->spec->kind != L_BIT))
      return layout_error(context, "invalid", path, "reference does not name a decoded integer");
    *out = field->integer;
    return 0;
  }
  return layout_error(context, "invalid", path, "unresolved or forward field reference");
}

static int evaluate_expression(layout_context *context, const nj_value *value,
                                 layout_scope *scope, const char *path,
                                 layout_int *out) {
  if (++context->expression_steps > LAYOUT_MAX_EXPR_STEPS)
    return layout_error(context, "resource_limit", path, "expression evaluation budget exceeded");
  if (layout_number(value, out) == 0) return 0;
  const nj_value *reference = nj_get(value, "ref");
  if (reference) return evaluate_reference(context, reference, scope, path, out);
  const nj_value *arguments = nj_get(value, "args");
  const nj_value *operation = nj_get(value, "op");
  layout_int a, b, result;
  if (!arguments || arguments->type != NJ_ARRAY || arguments->count != 2)
    return layout_error(context, "invalid", path, "invalid expression contract");
  if (evaluate_expression(context, arguments->items[0], scope, path, &a) < 0 ||
      evaluate_expression(context, arguments->items[1], scope, path, &b) < 0) return -1;
  if (nj_string_equal(operation, "add")) result = a + b;
  else if (nj_string_equal(operation, "sub")) result = a - b;
  else if (nj_string_equal(operation, "mul")) {
    layout_int aa = a < 0 ? -a : a, bb = b < 0 ? -b : b;
    layout_int limit = (a < 0) != (b < 0) ? -LI_MIN : LI_MAX;
    if (aa && bb > limit / aa)
      return layout_error(context, "invalid", path, "expression integer overflow");
    result = a * b;
  } else if (nj_string_equal(operation, "div") || nj_string_equal(operation, "mod")) {
    if (!b) return layout_error(context, "invalid", path, "division by zero");
    result = a % b;
    if (nj_string_equal(operation, "div")) {
      if (result) return layout_error(context, "invalid", path, "non-integral division");
      result = a / b;
    } else if (result && ((result < 0) != (b < 0))) result += b;
  } else {
    if (a < 0 || b < 0)
      return layout_error(context, "invalid", path, "bit operations require nonnegative integers");
    if (nj_string_equal(operation, "and")) result = (uint64_t)a & (uint64_t)b;
    else if (nj_string_equal(operation, "or")) result = (uint64_t)a | (uint64_t)b;
    else if (nj_string_equal(operation, "xor")) result = (uint64_t)a ^ (uint64_t)b;
    else {
      if (b > 63) return layout_error(context, "invalid", path, "shift outside 0..63");
      if (nj_string_equal(operation, "shl")) result = a << (unsigned)b;
      else if (nj_string_equal(operation, "shr")) result = a >> (unsigned)b;
      else return layout_error(context, "invalid", path, "unsupported expression operation");
    }
  }
  if (result < LI_MIN || result > LI_MAX)
    return layout_error(context, "invalid", path, "expression integer overflow");
  *out = result;
  return 0;
}

static int take_bytes(layout_context *context, layout_int amount, size_t end,
                       const char *path) {
  if (amount < 0 || amount > NJ_MAX_BYTES)
    return layout_error(context, "invalid", path, "length outside supported bounds");
  if (context->offset > end || (size_t)amount > end - context->offset)
    return layout_error(context, context->bounded_depth ? "invalid" : "truncated",
                         path, "field exceeds enclosing byte boundary");
  context->offset += (size_t)amount;
  return 0;
}

static uint64_t read_unsigned(const unsigned char *bytes, unsigned width,
                               unsigned little) {
  uint64_t value = 0;
  for (unsigned i = 0; i < width; i++)
    value = (value << 8) | bytes[little ? width - i - 1 : i];
  return value;
}

static int valid_utf8(const unsigned char *text, size_t length) {
  size_t at = 0;
  while (at < length) {
    unsigned c = text[at++], count, minimum;
    uint32_t codepoint;
    if (c < 128) continue;
    if (c >= 0xc2 && c <= 0xdf) { count = 1; minimum = 0x80; codepoint = c & 31; }
    else if (c >= 0xe0 && c <= 0xef) { count = 2; minimum = 0x800; codepoint = c & 15; }
    else if (c >= 0xf0 && c <= 0xf4) { count = 3; minimum = 0x10000; codepoint = c & 7; }
    else return 0;
    if (count > length - at) return 0;
    for (unsigned i = 0; i < count; i++) {
      unsigned continuation = text[at++];
      if ((continuation & 0xc0) != 0x80) return 0;
      codepoint = (codepoint << 6) | (continuation & 63);
    }
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0;
  }
  return 1;
}

static void number_text(layout_int value, char *out, size_t cap) {
  if (value < 0) snprintf(out, cap, "-%" PRIu64, (uint64_t)(-value));
  else snprintf(out, cap, "%" PRIu64, (uint64_t)value);
}

static layout_field *decode_spec(layout_context *context, const layout_spec *spec,
                                  layout_scope *scope, size_t end, size_t base,
                                  const char *path) {
  layout_field *field = new_field(context, spec, path);
  layout_field *child = NULL;
  layout_int value;
  char *child_path = NULL;
  if (!field) return NULL;
  switch (spec->kind) {
    case L_UINT: case L_INT: case L_BITS: {
      if (take_bytes(context, spec->width, end, path) < 0) goto bad;
      uint64_t raw = read_unsigned(context->data + field->start, spec->width, spec->little);
      if (spec->kind == L_BITS) {
        for (size_t i = 0; i < spec->child_count; i++) {
          const layout_spec *bit = spec->children[i];
          child_path = layout_path(context, path, "%s.%s", path, bit->id);
          if (!child_path) goto bad;
          child = new_field(context, bit, child_path);
          free(child_path); child_path = NULL;
          if (!child) goto bad;
          child->start = field->start; child->end = context->offset;
          uint64_t mask = bit->bit_width == 64 ? UINT64_MAX : (UINT64_C(1) << bit->bit_width) - 1;
          child->integer = (raw >> bit->lsb) & mask;
          if (bit->has_expected && child->integer != bit->expected) {
            layout_error(context, "invalid", child->path, "bit field differs from expected value"); goto bad;
          }
          if (append_field(context, field, child) < 0) goto bad;
          child = NULL;
        }
      } else {
        value = (layout_int)raw;
        if (spec->kind == L_INT && (raw & (UINT64_C(1) << (spec->width * 8 - 1))))
          value -= (layout_int)1 << (spec->width * 8);
        if (value < spec->minimum || value > spec->maximum) {
          layout_error(context, "invalid", path, "scalar outside declared range"); goto bad;
        }
        if (spec->has_expected && value != spec->expected) {
          layout_error(context, "invalid", path, "scalar differs from expected value"); goto bad;
        }
        if (spec->value_count) {
          int found = 0;
          for (size_t i = 0; i < spec->value_count; i++) if (value == spec->values[i]) found = 1;
          if (!found) { layout_error(context, "invalid", path, "scalar outside declared enumeration"); goto bad; }
        }
        field->integer = value;
      }
      break;
    }
    case L_BYTES: {
      if (evaluate_expression(context, spec->expression, scope, path, &value) < 0 ||
          take_bytes(context, value, end, path) < 0) goto bad;
      size_t length = context->offset - field->start;
      const unsigned char *bytes = context->data + field->start;
      if (spec->expected_hex) {
        const nj_value *expected = spec->expected_hex;
        if (length != expected->text_length / 2) { layout_error(context, "invalid", path, "bytes differ from expected value"); goto bad; }
        for (size_t i = 0; i < length; i++) {
          unsigned wanted = (unsigned)(hex_digit((unsigned char)expected->text[i * 2]) * 16 +
                                        hex_digit((unsigned char)expected->text[i * 2 + 1]));
          if (bytes[i] != wanted) { layout_error(context, "invalid", path, "bytes differ from expected value"); goto bad; }
        }
      }
      if (spec->encoding == 1) {
        for (size_t i = 0; i < length; i++) if (bytes[i] >= 128) { layout_error(context, "invalid", path, "invalid ASCII text"); goto bad; }
      } else if (spec->encoding == 2 && !valid_utf8(bytes, length)) {
        layout_error(context, "invalid", path, "invalid UTF-8 text"); goto bad;
      }
      break;
    }
    case L_STRUCT: {
      layout_scope local = {field, scope};
      for (size_t i = 0; i < spec->child_count; i++) {
        const layout_spec *part = spec->children[i];
        child_path = layout_path(context, path, "%s.%s", path, part->id);
        if (!child_path) goto bad;
        child = decode_spec(context, part, &local, end, field->start, child_path);
        free(child_path); child_path = NULL;
        if (!child || append_field(context, field, child) < 0) goto bad;
        child = NULL;
      }
      break;
    }
    case L_CHOICE: {
      if (evaluate_expression(context, spec->expression, scope, path, &value) < 0) goto bad;
      const layout_spec *selected = NULL;
      for (size_t i = 0; i < spec->child_count; i++)
        if (spec->case_values[i] == value) { selected = spec->children[i]; break; }
      char selector[32]; number_text(value, selector, sizeof(selector));
      if (selected) snprintf(field->selected_case, sizeof(field->selected_case), "%s", selector);
      else { selected = spec->body; snprintf(field->selected_case, sizeof(field->selected_case), "default:%s", selector); }
      if (!selected) { layout_error(context, "unsupported", path, "no declared case for discriminator %s", selector); goto bad; }
      child_path = layout_path(context, path, "%s.%s", path, selected->id);
      if (!child_path) goto bad;
      child = decode_spec(context, selected, scope, end, base, child_path);
      free(child_path); child_path = NULL;
      if (!child || append_field(context, field, child) < 0) goto bad;
      child = NULL;
      break;
    }
    case L_REPEAT:
      if (evaluate_expression(context, spec->expression, scope, path, &value) < 0) goto bad;
      if (value < 0 || value > spec->max_items) { layout_error(context, "invalid", path, "repeat count exceeds declared bound"); goto bad; }
      for (size_t i = 0; i < (size_t)value; i++) {
        child_path = layout_path(context, path, "%s[%zu]", path, i);
        if (!child_path) goto bad;
        child = decode_spec(context, spec->body, scope, end, base, child_path);
        free(child_path); child_path = NULL;
        if (!child || append_field(context, field, child) < 0) goto bad;
        child = NULL;
      }
      break;
    case L_BOUNDED: {
      if (evaluate_expression(context, spec->expression, scope, path, &value) < 0) goto bad;
      if (value < 0 || value > NJ_MAX_BYTES) { layout_error(context, "invalid", path, "bounded length outside supported range"); goto bad; }
      if (context->offset > end || (size_t)value > end - context->offset) {
        layout_error(context, context->bounded_depth ? "invalid" : "truncated", path, "bounded region exceeds enclosing bytes"); goto bad;
      }
      size_t boundary = context->offset + (size_t)value;
      child_path = layout_path(context, path, "%s.%s", path, spec->body->id);
      if (!child_path) goto bad;
      context->bounded_depth++;
      child = decode_spec(context, spec->body, scope, boundary, field->start, child_path);
      context->bounded_depth--;
      free(child_path); child_path = NULL;
      if (!child || append_field(context, field, child) < 0) goto bad;
      child = NULL;
      if (context->offset != boundary) { layout_error(context, "invalid", path, "bounded body did not consume its declared length"); goto bad; }
      break;
    }
    case L_ALIGN: {
      if (context->offset < base) { layout_error(context, "invalid", path, "invalid alignment base"); goto bad; }
      size_t remainder = (context->offset - base) % spec->multiple;
      size_t amount = remainder ? spec->multiple - remainder : 0;
      if (take_bytes(context, amount, end, path) < 0) goto bad;
      if (spec->has_fill) for (size_t i = field->start; i < context->offset; i++)
        if (context->data[i] != spec->fill) { layout_error(context, "invalid", path, "alignment differs from declared fill"); goto bad; }
      break;
    }
    case L_BIT:
      layout_error(context, "invalid_description", path, "bit leaf outside its carrier"); goto bad;
  }
  field->end = context->offset;
  return field;
bad:
  free(child_path);
  free_field(child);
  free_field(field);
  return NULL;
}

static void write_hex(FILE *out, const unsigned char *bytes, size_t length) {
  static const char alphabet[] = "0123456789abcdef";
  fputc('"', out);
  for (size_t i = 0; i < length; i++) {
    fputc(alphabet[bytes[i] >> 4], out);
    fputc(alphabet[bytes[i] & 15], out);
  }
  fputc('"', out);
}

static void write_field(FILE *out, const layout_context *context,
                         const layout_field *field) {
  static const char *const names[] = {"struct", "uint", "int", "bytes", "bits", "choice", "repeat", "bounded", "align", "bit"};
  const layout_spec *spec = field->spec;
  fputs("{\"path\":", out); nj_write_string(out, field->path, strlen(field->path));
  fputs(",\"kind\":", out); nj_write_string(out, names[spec->kind], strlen(names[spec->kind]));
  fprintf(out, ",\"start\":%zu,\"end\":%zu,\"value\":", field->start, field->end);
  if (spec->kind == L_UINT || spec->kind == L_INT || spec->kind == L_BIT) {
    char number[32]; number_text(field->integer, number, sizeof(number)); fputs(number, out);
  } else if (spec->kind == L_BYTES && spec->encoding)
    nj_write_string(out, (const char *)context->data + field->start, field->end - field->start);
  else if (spec->kind == L_BYTES || spec->kind == L_ALIGN)
    write_hex(out, context->data + field->start, field->end - field->start);
  else fputs("null", out);
  fputs(",\"children\":[", out);
  for (size_t i = 0; i < field->child_count; i++) {
    if (i) fputc(',', out);
    write_field(out, context, field->children[i]);
  }
  fputs("],\"bit_lsb\":", out);
  if (spec->kind == L_BIT) fprintf(out, "%u", spec->lsb); else fputs("null", out);
  fputs(",\"bit_width\":", out);
  if (spec->kind == L_BIT) fprintf(out, "%u", spec->bit_width); else fputs("null", out);
  fputs(",\"byte_order\":", out);
  if (spec->kind == L_UINT || spec->kind == L_INT || spec->kind == L_BITS || spec->kind == L_BIT)
    nj_write_string(out, spec->little ? "little" : "big", spec->little ? 6 : 3);
  else fputs("null", out);
  fputs(",\"encoding\":", out);
  if (spec->kind == L_BYTES) {
    const char *encoding = spec->encoding == 1 ? "ascii" : spec->encoding == 2 ? "utf8" : "hex";
    nj_write_string(out, encoding, strlen(encoding));
  } else fputs("null", out);
  fputs(",\"source_node_path\":", out); nj_write_string(out, spec->source, strlen(spec->source));
  fputs(",\"selected_case\":", out);
  if (spec->kind == L_CHOICE) nj_write_string(out, field->selected_case, strlen(field->selected_case));
  else fputs("null", out);
  fputc('}', out);
}

int native_layout_inspect(const char *layout_path, const char *input_path,
                          FILE *out, native_diagnostic *diagnostic) {
  static const char *const required[] = {"format", "version", "root"};
  static const char *const optional[] = {"description"};
  nj_document *document = NULL;
  layout_spec *spec = NULL;
  layout_field *field = NULL;
  layout_context context = {0};
  char error[512];
  layout_int version;
  int result = 2;
  if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
  context.diagnostic = diagnostic; context.exit_code = 2;
  if (!layout_path || !input_path || !out || !diagnostic) {
    if (diagnostic) native_inspect_error(diagnostic, "input_error", "", 0, "missing inspection argument");
    return 2;
  }
  if (nj_load_file(layout_path, &document, error, sizeof(error)) < 0) {
    native_inspect_error(diagnostic, "invalid_description", "", 0,
                         "native layouts require bounded JSON input: %s", error);
    goto done;
  }
  const nj_value *root = document->root;
  if (layout_keys(&context, root, required, 3, optional, 1, "/") < 0) goto done;
  if (!nj_string_equal(nj_get(root, "format"), "stateafl.offline-layout") ||
      layout_number(nj_get(root, "version"), &version) < 0 || version != 1) {
    layout_error(&context, "invalid_description", "/", "unsupported layout format or version"); goto done;
  }
  const nj_value *description = nj_get(root, "description");
  if (description && description->type != NJ_STRING) {
    layout_error(&context, "invalid_description", "/description", "description must be text"); goto done;
  }
  spec = compile_spec(&context, nj_get(root, "root"), 0, "/root");
  if (!spec) goto done;
  if (nj_read_file(input_path, &context.data, &context.length, NJ_MAX_BYTES, error, sizeof(error)) < 0) {
    layout_error(&context, "input_error", "", "%s", error); goto done;
  }
  field = decode_spec(&context, spec, NULL, context.length, 0, spec->id);
  if (!field) { result = context.exit_code; goto done; }
  if (context.offset != context.length) {
    layout_error(&context, "invalid", spec->id, "unconsumed trailing bytes");
    result = 1; goto done;
  }
  /* All interpretation and constraint checks finish before report emission. */
  fprintf(out, "{\"format\":\"stateafl.native-decode\",\"version\":1,\"status\":\"decoded\","
               "\"scope\":\"passive local-file structural inspection\","
               "\"digest_contract\":\"no Python-normalized SHA256 is supplied\","
               "\"input_length\":%zu,\"consumed\":%zu,\"decoded_fields\":%zu,\"tree\":",
          context.length, context.offset, context.fields);
  write_field(out, &context, field);
  fputs("}\n", out);
  if (ferror(out)) {
    native_inspect_error(diagnostic, "output_error", "", context.offset, "could not write inspection report");
    result = 2;
  } else result = 0;
done:
  free_field(field);
  free_spec(spec);
  free(context.data);
  nj_free(document);
  return result;
}
#endif
