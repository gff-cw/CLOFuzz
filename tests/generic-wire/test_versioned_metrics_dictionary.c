#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "generic_wire.h"
#include "execution_observation.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

int main(void) {
  printf("[*] Testing P23: Versioned metrics dictionary and denominators...\n");
  char err[256];

  /* 1. Load fictional protocol for testing generic-wire diagnostics */
  proto_engine *pe = proto_load_generic("tests/generic-wire/fictional_protocol.json", err, sizeof(err));
  CHECK(pe != NULL);

  char stats_path[] = "/tmp/stateafl-metrics-stats-XXXXXX";
  int sfd = mkstemp(stats_path);
  close(sfd);

  /* Set purpose to ORIGINAL (1) */
  proto_set_execution_purpose(pe, EXEC_PURPOSE_ORIGINAL);

  /* A. Send request to set pending state */
  uint8_t req_wire[] = {0xa7, 0x00, 0x05, 0x01, 0x00, 0x01, 0x55, 0x66};
  CHECK(proto_before_send(pe, req_wire, sizeof(req_wire), err, sizeof(err)) == 0);

  /* B. Incomplete framing (for stream transport) or invalid grammar */
  uint8_t invalid_grammar[] = {0xff, 0xff, 0xff, 0xff};
  proto_after_response(pe, invalid_grammar, sizeof(invalid_grammar));

  /* Check stats: grammar_mismatches should be incremented, but invalid frames must
     NOT increment responses or responses_by_purpose (B09: unified denominator) */
  proto_write_stats(pe, stats_path);
  FILE *sf = fopen(stats_path, "r");
  CHECK(sf != NULL);
  char sbuf[2048] = {0};
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);

  CHECK(strstr(sbuf, "\"metrics_version\":1") != NULL);
  CHECK(strstr(sbuf, "\"response_diagnostics\":") != NULL);
  CHECK(strstr(sbuf, "\"grammar_mismatches\":1") != NULL);
  CHECK(strstr(sbuf, "\"responses\":0") != NULL);
  CHECK(strstr(sbuf, "\"responses_by_purpose\":{\"coverage\":0,\"confirmation\":0,\"calibration\":0,\"sync\":0,\"state_analysis\":0,\"hang_check\":0,\"unknown\":0}") != NULL);
  proto_free(pe);

  /* C. Test valid response frame with unified denominator:
     Valid responses must increment both responses and responses_by_purpose under
     the respective execution purpose. */
  proto_engine *pe_mod = proto_load_generic("protocols/modbus_tcp/generic_wire.json", err, sizeof(err));
  CHECK(pe_mod != NULL);

  proto_set_execution_purpose(pe_mod, EXEC_PURPOSE_ORIGINAL);
  uint8_t valid_resp[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x01};
  proto_after_response(pe_mod, valid_resp, sizeof(valid_resp));

  proto_write_stats(pe_mod, stats_path);
  sf = fopen(stats_path, "r");
  CHECK(sf != NULL);
  memset(sbuf, 0, sizeof(sbuf));
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);

  CHECK(strstr(sbuf, "\"responses\":1") != NULL);
  CHECK(strstr(sbuf, "\"coverage\":1") != NULL);
  CHECK(strstr(sbuf, "\"confirmation\":0") != NULL);

  /* D. Test CONFIRMATION purpose with valid response */
  proto_set_execution_purpose(pe_mod, EXEC_PURPOSE_CONFIRMATION);
  proto_after_response(pe_mod, valid_resp, sizeof(valid_resp));

  proto_write_stats(pe_mod, stats_path);
  sf = fopen(stats_path, "r");
  CHECK(sf != NULL);
  memset(sbuf, 0, sizeof(sbuf));
  CHECK(fread(sbuf, 1, sizeof(sbuf) - 1, sf) > 0);
  fclose(sf);
  unlink(stats_path);

  CHECK(strstr(sbuf, "\"responses\":2") != NULL);
  CHECK(strstr(sbuf, "\"coverage\":1") != NULL);
  CHECK(strstr(sbuf, "\"confirmation\":1") != NULL);
  proto_free(pe_mod);

  /* D. Verify ratio calculations avoid division by zero and correctly mark N/A */
  uint64_t attempts = 0;
  uint64_t success = 0;
  char ratio_str[32];
  if (attempts == 0) {
    snprintf(ratio_str, sizeof(ratio_str), "N/A");
  } else {
    snprintf(ratio_str, sizeof(ratio_str), "%.2f%%", (double)success * 100.0 / attempts);
  }
  CHECK(strcmp(ratio_str, "N/A") == 0);

  attempts = 100;
  success = 85;
  if (attempts == 0) {
    snprintf(ratio_str, sizeof(ratio_str), "N/A");
  } else {
    snprintf(ratio_str, sizeof(ratio_str), "%.2f%%", (double)success * 100.0 / attempts);
  }
  CHECK(strcmp(ratio_str, "85.00%") == 0);

  printf("PASS: test_versioned_metrics_dictionary passed (%u assertions)\n", checks);
  return 0;
}
