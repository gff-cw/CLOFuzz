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

void native_inspect_error(native_diagnostic *diagnostic, const char *status,
                         const char *path, size_t offset, const char *format, ...);

/* Validation completes before report output. Validation failure writes nothing.
 * Report I/O failure may leave a partial stream and fills diagnostic separately.
 * Return 0 for success, 1 for invalid observed content, 2 for input/description errors. */
int native_layout_inspect(const char *layout_path, const char *input_path,
                          FILE *out, native_diagnostic *diagnostic);
int native_observation_inspect(const char *input_path, FILE *out,
                               native_diagnostic *diagnostic);

/* Returns -1 when argv[1] is not an inspection selector; otherwise an exit code.
 * Inspection selectors must be first and accept no fuzzer or target arguments. */
int native_inspection_dispatch(int argc, char **argv, FILE *out, FILE *errors);

#endif
