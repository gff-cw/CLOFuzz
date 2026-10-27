/* Bounded JSON input for native, local-file inspection. No executable values. */
#ifndef STATEAFL_NATIVE_JSON_H
#define STATEAFL_NATIVE_JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define NJ_MAX_BYTES (1024u * 1024u)
#define NJ_MAX_NODES 65536u
#define NJ_MAX_DEPTH 96u

typedef enum { NJ_NULL, NJ_BOOL, NJ_INTEGER, NJ_STRING, NJ_ARRAY, NJ_OBJECT } nj_type;
typedef struct nj_value nj_value;
typedef struct { int negative; uint64_t magnitude; } nj_number;
typedef struct { char *key; size_t key_length; nj_value *value; } nj_member;

struct nj_value {
  nj_type type;
  size_t start, end;
  char *text;
  size_t text_length;
  nj_number number;
  int boolean;
  size_t count;
  nj_value **items;
  nj_member *members;
};

typedef struct {
  unsigned char *source;
  size_t length, nodes;
  nj_value *root;
} nj_document;

/* Helpers return 0 on success and -1 on failure, unless declared void or pointer.
 * parse/load produce a caller-owned document, released by nj_free(); parsing
 * owns a copy of the input bytes. Do not overwrite an unfreed document via out.
 * read_file produces a malloc buffer with a spare NUL byte, released by free().
 * On failure, parse/load set *out=NULL; read_file sets *data=NULL and *length=0.
 * The caller retains ownership of all argument buffers and error storage. */
int nj_read_file(const char *path, unsigned char **data, size_t *length,
                 size_t limit, char *error, size_t cap);
int nj_parse_buffer(const unsigned char *data, size_t length, nj_document **out,
                    char *error, size_t cap);
int nj_load_file(const char *path, nj_document **out, char *error, size_t cap);
void nj_free(nj_document *document);
const nj_value *nj_get(const nj_value *object, const char *key);
/* nj_get returns a borrowed node (or NULL); it and its strings/slices remain
 * valid only until the owning document is freed. Never free a node separately. */
int nj_keys(const nj_value *object, const char *const *required, size_t required_count,
             const char *const *optional, size_t optional_count, char *error, size_t cap);
/* Copy rejects embedded NUL; text_length remains available for binary-safe strings.
 * out must be separate from the source string. Failure clears a supplied out
 * buffer when capacity>0; numeric/boolean output values change only on success. */
int nj_string_copy(const nj_value *value, char *out, size_t capacity, char *error, size_t cap);
int nj_string_equal(const nj_value *value, const char *text);
int nj_u64(const nj_value *value, uint64_t *out, char *error, size_t cap);
int nj_i64(const nj_value *value, int64_t *out, char *error, size_t cap);
int nj_boolean(const nj_value *value, int *out, char *error, size_t cap);
void nj_write_string(FILE *out, const char *text, size_t length);
/* value must be borrowed from this document. Writers neither flush nor close
 * out; callers check ferror()/fflush(). JSON strings use explicit byte lengths. */
int nj_write_value(FILE *out, const nj_document *document, const nj_value *value);

#endif
