#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "generic_runtime.h"

int main(void) {
  char err[512] = {0};

  /* The five offline packages must be strictly rejected by gr_load for online execution */
  const char *offline_profiles[] = {
    "protocols/bacnet_ip/generic_wire.json",
    "protocols/iec60870_5_104/generic_wire.json",
    "protocols/iec61850_mms_tcp/generic_wire.json",
    "protocols/ethernet_ip_cip_tcp/generic_wire.json",
    "protocols/opcua_tcp/generic_wire.json"
  };

  for (size_t i = 0; i < sizeof(offline_profiles)/sizeof(offline_profiles[0]); i++) {
    err[0] = 0;
    gr_engine *e = gr_load(offline_profiles[i], err, sizeof(err));
    assert(e == NULL);
    assert(strstr(err, "description is offline-only; required wire/session rules are not executable") != NULL);
  }

  /* Modbus TCP is the only currently scoped online profile */
  err[0] = 0;
  gr_engine *modbus = gr_load("protocols/modbus_tcp/generic_wire.json", err, sizeof(err));
  assert(modbus != NULL);
  gr_free(modbus);

  printf("test_protocol_capability_gaps: ALL 6 PROFILE CAPABILITY SCOPE CHECKS PASSED\n");
  return 0;
}
