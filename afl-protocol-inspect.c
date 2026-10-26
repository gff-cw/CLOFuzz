/* Standalone entry to the same passive native inspection code as afl-fuzz. */
#include "native_inspect.h"

int main(int argc, char **argv) {
  int result = native_inspection_dispatch(argc, argv, stdout, stderr);
  if (result < 0) {
    fputs("Use --inspect-help for native local-file inspection.\n", stderr);
    return 2;
  }
  return result;
}
