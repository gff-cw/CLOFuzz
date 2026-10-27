/* Local-file inspection dispatch shared by afl-fuzz and afl-protocol-inspect. */
#include "native_inspect.h"
#include "native_json.h"

#include <stdarg.h>
#include <string.h>

void native_inspect_error(native_diagnostic *d, const char *status,
                         const char *path, size_t offset, const char *format, ...) {
  va_list arguments;
  if (!d) return;
  memset(d, 0, sizeof(*d));
  snprintf(d->status, sizeof(d->status), "%s", status ? status : "invalid");
  snprintf(d->path, sizeof(d->path), "%s", path ? path : "");
  d->offset = offset;
  va_start(arguments, format);
  vsnprintf(d->message, sizeof(d->message), format, arguments);
  va_end(arguments);
}

static void diagnostic_report(FILE *out, const native_diagnostic *d) {
  fputs("{\"format\":\"stateafl.native-inspection-error\",\"version\":1,\"status\":", out);
  nj_write_string(out, d->status, strlen(d->status));
  fputs(",\"error\":", out);
  nj_write_string(out, d->message, strlen(d->message));
  fputs(",\"path\":", out);
  nj_write_string(out, d->path, strlen(d->path));
  fprintf(out, ",\"offset\":%zu}\n", d->offset);
}

static int bad_arguments(FILE *out, const char *message) {
  native_diagnostic d;
  native_inspect_error(&d, "invalid_arguments", "", 0, "%s", message);
  diagnostic_report(out, &d);
  return 2;
}

int native_inspection_dispatch(int argc, char **argv, FILE *out, FILE *errors) {
  native_diagnostic d;
  int result;
  if (argc < 2) return -1;
  if (!strcmp(argv[1], "--inspect-help")) {
    if (argc != 2) return bad_arguments(errors, "--inspect-help accepts no other arguments");
    fputs("Native local-file inspection (no target is started):\n"
          "  --inspect-layout layout.json --inspect-input existing-message.bin\n"
          "  --inspect-observations existing-observations.json\n"
          "Inspection must be the first argument and cannot be mixed with fuzzer arguments.\n"
          "Input descriptions are JSON; YAML and existing ICP-IR codec files are not accepted.\n", out);
    return fflush(out) == EOF ? 2 : 0;
  }
  if (!strcmp(argv[1], "--inspect-layout")) {
    if (argc != 5 || strcmp(argv[3], "--inspect-input"))
      return bad_arguments(errors, "expected --inspect-layout layout.json --inspect-input existing-message.bin only");
    memset(&d, 0, sizeof(d));
    result = native_layout_inspect(argv[2], argv[4], out, &d);
  } else if (!strcmp(argv[1], "--inspect-observations")) {
    if (argc != 3)
      return bad_arguments(errors, "expected --inspect-observations existing-observations.json only");
    memset(&d, 0, sizeof(d));
    result = native_observation_inspect(argv[2], out, &d);
  } else if (!strncmp(argv[1], "--inspect-", 10)) {
    return bad_arguments(errors, "unknown inspection selector; use --inspect-help");
  } else {
    return -1;
  }
  /* An invalid module result must not fall through into normal fuzzing. */
  if (result < 0 || result > 2) {
    native_inspect_error(&d, "internal_error", "", 0, "invalid inspection return code");
    result = 2;
  }
  if (result != 0) {
    if (!d.status[0]) native_inspect_error(&d, "invalid", "", 0, "native inspection failed");
    diagnostic_report(errors, &d);
  }
  {
    int output_failed = fflush(out) == EOF;
    int errors_failed = fflush(errors) == EOF;
    if (output_failed || errors_failed) return 2;
  }
  return result;
}
