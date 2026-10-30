#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "protocol_runtime.h"

int main(void) {
  char err[512] = {0};

  /* 1. Compile the minimal runnable example into a temporary output directory */
  int rc = system("python3 tools/proto_spec_compiler.py "
                  "--protocol protocols/templates/minimal_runnable_example/protocol_spec.yaml "
                  "--state protocols/templates/minimal_runnable_example/state_transition.yaml "
                  "--output /tmp/test_minimal_modbus_ir > /tmp/test_minimal_compile.log 2>&1");
  assert(rc == 0);

  /* 2. Verify that C proto_load cleanly loads the compiled minimal IR bundle */
  err[0] = 0;
  proto_engine *pe = proto_load("/tmp/test_minimal_modbus_ir/protocol_ir.json",
                                "/tmp/test_minimal_modbus_ir/state_ir.json",
                                err, sizeof(err));
  assert(pe != NULL);
  proto_free(pe);

  /* 3. Verify placeholder rejection: attempting to compile unexpanded template directly */
  rc = system("python3 tools/proto_spec_compiler.py "
              "--protocol protocols/templates/protocol_spec.template.yaml "
              "--state protocols/templates/state_transition.template.yaml "
              "--output /tmp/test_placeholder_out > /tmp/test_placeholder.log 2>&1");
  assert(rc != 0);
  FILE *f = fopen("/tmp/test_placeholder.log", "r");
  assert(f != NULL);
  char buf[1024] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  buf[n] = 0;
  fclose(f);
  assert(strstr(buf, "template placeholder skeleton") != NULL || strstr(buf, "must be replaced") != NULL);

  /* Clean up temporary artifacts */
  unlink("/tmp/test_minimal_compile.log");
  unlink("/tmp/test_placeholder.log");
  system("rm -rf /tmp/test_minimal_modbus_ir /tmp/test_placeholder_out");

  printf("test_template_misconfiguration_guard: ALL TEMPLATE GUARD CHECKS PASSED\n");
  return 0;
}
