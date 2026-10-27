/* Native passive inspection entry points. They never execute a target. */
#ifndef STATEAFL_NATIVE_INSPECT_H
#define STATEAFL_NATIVE_INSPECT_H

#include <stddef.h>
#include <stdio.h>

typedef struct {
  char status[32];
  char message[512];
  char path[2048];
  size_t offset;
} native_diagnostic;

enum native_inspect_result {
  NATIVE_INSPECT_NOT_SELECTED = -1,
  NATIVE_INSPECT_OK = 0,
  NATIVE_INSPECT_INVALID = 1,
  NATIVE_INSPECT_ERROR = 2
};

/* diagnostic may be NULL for this formatting helper; NULL format is handled. */
void native_inspect_error(native_diagnostic *diagnostic, const char *status,
                         const char *path, size_t offset, const char *format, ...);

/* Paths, out and diagnostic are required and remain caller-owned. Each call
 * owns and frees its temporary input/parse trees, clears diagnostic on entry,
 * and leaves it empty on success. out is not closed; the caller owns flushing.
 * Validation completes before report output. Validation failure writes nothing.
 * Report I/O failure may leave a partial stream and fills diagnostic separately.
 * Return 0 for success, 1 for invalid observed content, 2 for input/description errors. */
int native_layout_inspect(const char *layout_path, const char *input_path,
                          FILE *out, native_diagnostic *diagnostic);
int native_observation_inspect(const char *input_path, FILE *out,
                               native_diagnostic *diagnostic);

/* Requires argc >= 1, argv[0] and all argc argument entries to be non-NULL,
 * plus non-NULL output/error streams; invalid API arguments return ERROR.
 * Returns NOT_SELECTED when argv[1] is not an inspection selector (or absent).
 * A selected inspection always finishes here, including on errors; it never
 * requests fallback into target execution. Streams and argv are borrowed.
 * Inspection selectors must be first and accept no fuzzer or target arguments. */
int native_inspection_dispatch(int argc, char **argv, FILE *out, FILE *errors);

#endif
