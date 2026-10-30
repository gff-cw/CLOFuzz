#define _POSIX_C_SOURCE 200809L
#include "run_manifest.h"
#include "protocol_runtime.h"
#include "generic_runtime.h"
#include "native_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

int main(void) {
  printf("[*] Testing P26: Cold-start segment resumption, manifest validation, and atomic publication...\n");
  char err[256];

  char tmp_dir[] = "/tmp/stateafl-manifest-test-XXXXXX";
  CHECK(mkdtemp(tmp_dir) != NULL);

  char spec_path[512];
  snprintf(spec_path, sizeof(spec_path), "%s/spec.json", tmp_dir);
  FILE *sf = fopen(spec_path, "w");
  CHECK(sf != NULL);
  fputs("{\"protocol\":\"TEST_PROTO\",\"version\":1}\n", sf);
  fclose(sf);

  /* 1. Initial run: create segment 0 */
  run_manifest *m1 = NULL;
  int rc = manifest_init_or_resume(tmp_dir, "TEST_PROTO", spec_path, "hybrid", 12345, &m1, err, sizeof(err));
  CHECK(rc == 0);
  CHECK(m1 != NULL);
  CHECK(m1->manifest_version == MANIFEST_VERSION);
  CHECK(strcmp(m1->protocol, "TEST_PROTO") == 0);
  CHECK(m1->spec_hash != 0);
  CHECK(m1->current_segment_id == 0);
  CHECK(m1->num_segments == 1);
  CHECK(m1->segments[0].segment_id == 0);
  CHECK(m1->segments[0].parent_segment_id == -1);
  CHECK(strcmp(m1->segments[0].learning_state, "reset") == 0);
  CHECK(strcmp(m1->segments[0].reset_reason, "initial_start") == 0);
  CHECK(m1->segments[0].candidate_id_start == 0);

  /* Simulate saving 3 candidates in segment 0 */
  m1->segments[0].candidates_saved = 3;
  CHECK(manifest_save_atomic(m1, tmp_dir, err, sizeof(err)) == 0);
  manifest_free(m1);

  /* 2. Attribution check: Reject resume if protocol differs */
  run_manifest *m_bad = NULL;
  rc = manifest_init_or_resume(tmp_dir, "WRONG_PROTO", spec_path, "hybrid", 12345, &m_bad, err, sizeof(err));
  CHECK(rc == -1);
  CHECK(strstr(err, "Attribution conflict") != NULL);
  CHECK(m_bad == NULL);

  /* 3. Attribution check: Reject resume if spec content differs */
  char alt_spec[512];
  snprintf(alt_spec, sizeof(alt_spec), "%s/alt_spec.json", tmp_dir);
  FILE *asf = fopen(alt_spec, "w");
  CHECK(asf != NULL);
  fputs("{\"protocol\":\"TEST_PROTO\",\"version\":2,\"modified\":true}\n", asf);
  fclose(asf);

  rc = manifest_init_or_resume(tmp_dir, "TEST_PROTO", alt_spec, "hybrid", 12345, &m_bad, err, sizeof(err));
  CHECK(rc == -1);
  CHECK(strstr(err, "spec content hash mismatch") != NULL);
  CHECK(m_bad == NULL);

  /* 4. Candidate directory collision avoidance */
  char cand_dir[512];
  snprintf(cand_dir, sizeof(cand_dir), "%s/protocol-candidates", tmp_dir);
  CHECK(mkdir(cand_dir, 0700) == 0);
  char cand0[512], cand5[512];
  snprintf(cand0, sizeof(cand0), "%s/000000.replay", cand_dir);
  FILE *cf = fopen(cand0, "w"); CHECK(cf != NULL); fputs("data", cf); fclose(cf);
  snprintf(cand5, sizeof(cand5), "%s/000005.replay", cand_dir);
  cf = fopen(cand5, "w"); CHECK(cf != NULL); fputs("data", cf); fclose(cf);

  /* 5. Valid resume: Create cold-start segment 1 */
  run_manifest *m2 = NULL;
  rc = manifest_init_or_resume(tmp_dir, "TEST_PROTO", spec_path, "hybrid", 12345, &m2, err, sizeof(err));
  CHECK(rc == 0);
  CHECK(m2 != NULL);
  CHECK(m2->current_segment_id == 1);
  CHECK(m2->num_segments == 2);
  CHECK(m2->segments[1].segment_id == 1);
  CHECK(m2->segments[1].parent_segment_id == 0);
  CHECK(strcmp(m2->segments[1].learning_state, "reset") == 0);
  CHECK(strcmp(m2->segments[1].reset_reason, "cold_start_resumption") == 0);
  /* Should avoid collisions: candidate_id_start must be > 5 */
  CHECK(m2->segments[1].candidate_id_start >= 6);
  manifest_free(m2);

  /* 6. Test torn log repair */
  char log_path[512];
  snprintf(log_path, sizeof(log_path), "%s/protocol_mutations.jsonl", tmp_dir);
  FILE *lf = fopen(log_path, "w");
  CHECK(lf != NULL);
  fputs("{\"event\":\"mutation\",\"id\":1}\n", lf);
  fputs("{\"event\":\"mutation\",\"id\":2}\n", lf);
  fputs("{\"event\":\"mutation\",\"id\":3,torn_data...", lf); /* Truncated, no newline */
  fclose(lf);

  CHECK(manifest_repair_torn_log(log_path, err, sizeof(err)) == 0);

  /* Check that the repaired file only contains the first 2 complete lines */
  nj_document *doc = NULL;
  lf = fopen(log_path, "r");
  CHECK(lf != NULL);
  char line[256];
  int line_count = 0;
  while (fgets(line, sizeof(line), lf)) {
    line_count++;
    /* Verify line is valid JSON */
    CHECK(nj_parse_buffer((const unsigned char *)line, strlen(line), &doc, err, sizeof(err)) == 0);
    nj_free(doc); doc = NULL;
  }
  fclose(lf);
  CHECK(line_count == 2);

  /* 7. Test atomic stats write */
  char stats_path[512];
  snprintf(stats_path, sizeof(stats_path), "%s/protocol_stats.json", tmp_dir);
  proto_engine *pe = proto_load_generic("tests/generic-wire/fictional_protocol.json", err, sizeof(err));
  CHECK(pe != NULL);
  proto_write_stats(pe, stats_path);

  /* Verify stats file exists and is valid JSON */
  CHECK(nj_load_file(stats_path, &doc, err, sizeof(err)) == 0);
  const nj_value *v_ver = nj_get(doc->root, "metrics_version");
  CHECK(v_ver != NULL && v_ver->number.magnitude == 1);
  nj_free(doc);
  proto_free(pe);

  /* Cleanup test files */
  unlink(spec_path);
  unlink(alt_spec);
  unlink(cand0);
  unlink(cand5);
  rmdir(cand_dir);
  unlink(log_path);
  unlink(stats_path);
  char manifest_f[512];
  snprintf(manifest_f, sizeof(manifest_f), "%s/run_manifest.json", tmp_dir);
  unlink(manifest_f);
  rmdir(tmp_dir);

  printf("[+] P26 cold-start segment manifest tests passed (%u checks).\n", checks);
  return 0;
}
