#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "native_json.h"
#include "run_manifest.h"

static unsigned checks = 0;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

int main(void) {
  printf("[*] Testing B13 manifest attribution continuity, candidate 000000 preservation, and JSON escaping...\n");
  char err[512];

  /* Create base temporary test directory */
  char base_tmp[] = "/tmp/stateafl-b13-test-XXXXXX";
  CHECK(mkdtemp(base_tmp) != NULL);

  char spec_path[512];
  snprintf(spec_path, sizeof(spec_path), "%s/spec.json", base_tmp);
  FILE *sf = fopen(spec_path, "w");
  CHECK(sf != NULL);
  fputs("{\"protocol\":\"B13_PROTO\",\"version\":1}\n", sf);
  fclose(sf);

  /* ========================================================================
   * 1. Candidate 000000 preservation (scan_max_candidate_id)
   * ======================================================================== */
  {
    char t1_dir[512];
    snprintf(t1_dir, sizeof(t1_dir), "%s/t1", base_tmp);
    CHECK(mkdir(t1_dir, 0700) == 0);

    /* 1a. Non-existent candidate directory -> returns 0 */
    CHECK(scan_max_candidate_id(t1_dir) == 0);

    /* 1b. Empty candidate directory -> returns 0 */
    char cand_dir[512];
    snprintf(cand_dir, sizeof(cand_dir), "%s/protocol-candidates", t1_dir);
    CHECK(mkdir(cand_dir, 0700) == 0);
    CHECK(scan_max_candidate_id(t1_dir) == 0);

    /* 1c. Only 000000.json exists -> MUST return 1 (preserving candidate 000000) */
    char f0[512];
    snprintf(f0, sizeof(f0), "%s/000000.json", cand_dir);
    FILE *f = fopen(f0, "w"); CHECK(f != NULL); fputs("{}", f); fclose(f);
    uint32_t next_id = scan_max_candidate_id(t1_dir);
    CHECK(next_id == 1);

    /* 1d. Candidate 000000 and 000007 exist -> returns 8 */
    char f7[512];
    snprintf(f7, sizeof(f7), "%s/000007.raw", cand_dir);
    f = fopen(f7, "w"); CHECK(f != NULL); fputs("raw", f); fclose(f);
    CHECK(scan_max_candidate_id(t1_dir) == 8);

    /* 1e. Non-matching files (dotfiles, non-digits) ignored */
    char dotfile[512], txtfile[512];
    snprintf(dotfile, sizeof(dotfile), "%s/.ignore_me", cand_dir);
    f = fopen(dotfile, "w"); CHECK(f != NULL); fclose(f);
    snprintf(txtfile, sizeof(txtfile), "%s/readme.txt", cand_dir);
    f = fopen(txtfile, "w"); CHECK(f != NULL); fclose(f);
    CHECK(scan_max_candidate_id(t1_dir) == 8);

    printf("[+] 1: Candidate 000000 preservation verified (scan_max_candidate_id returns 1 for 000000.json)\n");
  }

  /* ========================================================================
   * 2. Fresh start candidate scanning
   * ======================================================================== */
  {
    char t2_dir[512];
    snprintf(t2_dir, sizeof(t2_dir), "%s/t2", base_tmp);
    CHECK(mkdir(t2_dir, 0700) == 0);

    /* Pre-populate candidates directory without manifest */
    char cand_dir[512];
    snprintf(cand_dir, sizeof(cand_dir), "%s/protocol-candidates", t2_dir);
    CHECK(mkdir(cand_dir, 0700) == 0);
    char f0[512], f3[512];
    snprintf(f0, sizeof(f0), "%s/000000.json", cand_dir);
    FILE *f = fopen(f0, "w"); CHECK(f != NULL); fputs("{}", f); fclose(f);
    snprintf(f3, sizeof(f3), "%s/000003.json", cand_dir);
    f = fopen(f3, "w"); CHECK(f != NULL); fputs("{}", f); fclose(f);

    /* Fresh start: manifest does not exist */
    run_manifest *m = NULL;
    int rc = manifest_init_or_resume(t2_dir, "B13_PROTO", spec_path, "valid", 42, &m, err, sizeof(err));
    CHECK(rc == 0);
    CHECK(m != NULL);
    CHECK(m->num_segments == 1);
    CHECK(m->current_segment_id == 0);
    /* seg0->candidate_id_start must be set to 4 (scanned from existing candidates), NOT 0! */
    CHECK(m->segments[0].candidate_id_start == 4);
    CHECK(m->segments[0].candidates_saved == 0);
    manifest_free(m);

    printf("[+] 2: Fresh start candidate scanning verified (seg0 candidate_id_start = 4)\n");
  }

  /* ========================================================================
   * 3. mutation_mode attribution validation
   * ======================================================================== */
  {
    char t3_dir[512];
    snprintf(t3_dir, sizeof(t3_dir), "%s/t3", base_tmp);
    CHECK(mkdir(t3_dir, 0700) == 0);

    /* Initialize manifest with mutation_mode = "valid" */
    run_manifest *m = NULL;
    int rc = manifest_init_or_resume(t3_dir, "B13_PROTO", spec_path, "valid", 100, &m, err, sizeof(err));
    CHECK(rc == 0);
    CHECK(m != NULL);
    CHECK(strcmp(m->mutation_mode, "valid") == 0);
    manifest_free(m);
    m = NULL;

    /* Resume attempt with conflicting mode "near_valid" MUST be rejected */
    rc = manifest_init_or_resume(t3_dir, "B13_PROTO", spec_path, "near_valid", 100, &m, err, sizeof(err));
    CHECK(rc == -1);
    CHECK(m == NULL);
    CHECK(strstr(err, "Attribution conflict") != NULL);
    CHECK(strstr(err, "mutation_mode") != NULL);

    /* Resume attempt with conflicting mode "invalid" MUST be rejected */
    rc = manifest_init_or_resume(t3_dir, "B13_PROTO", spec_path, "invalid", 100, &m, err, sizeof(err));
    CHECK(rc == -1);
    CHECK(m == NULL);
    CHECK(strstr(err, "Attribution conflict") != NULL);

    /* Resume attempt with matching mode "valid" MUST succeed */
    rc = manifest_init_or_resume(t3_dir, "B13_PROTO", spec_path, "valid", 100, &m, err, sizeof(err));
    CHECK(rc == 0);
    CHECK(m != NULL);
    CHECK(m->current_segment_id == 1);
    CHECK(m->num_segments == 2);
    CHECK(strcmp(m->mutation_mode, "valid") == 0);
    manifest_free(m);

    printf("[+] 3: mutation_mode attribution conflict rejection verified\n");
  }

  /* ========================================================================
   * 4. manifest_version validation
   * ======================================================================== */
  {
    char t4_dir[512];
    snprintf(t4_dir, sizeof(t4_dir), "%s/t4", base_tmp);
    CHECK(mkdir(t4_dir, 0700) == 0);

    /* Write a manifest with unsupported manifest_version = 999 */
    char man_path[512];
    snprintf(man_path, sizeof(man_path), "%s/run_manifest.json", t4_dir);
    FILE *f = fopen(man_path, "w");
    CHECK(f != NULL);
    fprintf(f,
      "{\n"
      "  \"manifest_version\": 999,\n"
      "  \"run_id\": \"run_bad_ver\",\n"
      "  \"protocol\": \"B13_PROTO\",\n"
      "  \"spec_path\": \"%s\",\n"
      "  \"spec_hash\": 12345,\n"
      "  \"random_seed\": 1,\n"
      "  \"mutation_mode\": \"valid\",\n"
      "  \"current_segment_id\": 0,\n"
      "  \"segments\": []\n"
      "}\n", spec_path);
    fclose(f);

    /* Resuming should detect version mismatch and reject */
    run_manifest *m = NULL;
    int rc = manifest_init_or_resume(t4_dir, "B13_PROTO", spec_path, "valid", 1, &m, err, sizeof(err));
    CHECK(rc == -1);
    CHECK(m == NULL);
    CHECK(strstr(err, "Attribution conflict") != NULL);
    CHECK(strstr(err, "manifest version mismatch") != NULL);

    printf("[+] 4: manifest_version mismatch validation verified (version 999 rejected)\n");
  }

  /* ========================================================================
   * 5. JSON string escaping
   * ======================================================================== */
  {
    char t5_dir[512];
    snprintf(t5_dir, sizeof(t5_dir), "%s/t5", base_tmp);
    CHECK(mkdir(t5_dir, 0700) == 0);

    /* 5a. Direct test of manifest_write_escaped_json_string */
    char buf[1024];
    FILE *memf = fmemopen(buf, sizeof(buf), "w");
    CHECK(memf != NULL);
    const char tricky_str[] = "Line 1\nLine 2\t\"quoted\" \\backslash\\ \r\b\f";
    manifest_write_escaped_json_string(memf, tricky_str);
    fclose(memf);

    /* Validate semantic round-trip; either short or Unicode JSON escapes work. */
    CHECK(buf[0] == '"');
    nj_document *escaped_doc = NULL;
    CHECK(nj_parse_buffer((const unsigned char *)buf, strlen(buf), &escaped_doc, err, sizeof(err)) == 0);
    CHECK(escaped_doc->root->type == NJ_STRING);
    CHECK(escaped_doc->root->text_length == strlen(tricky_str));
    CHECK(memcmp(escaped_doc->root->text, tricky_str, strlen(tricky_str)) == 0);
    nj_free(escaped_doc);

    /* 5b. End-to-end manifest serialization and parsing with special characters */
    run_manifest *m = calloc(1, sizeof(run_manifest));
    CHECK(m != NULL);
    m->manifest_version = MANIFEST_VERSION;
    snprintf(m->run_id, sizeof(m->run_id), "run_\"quote\"_\\test\\");
    snprintf(m->protocol, sizeof(m->protocol), "PROTO/\"escaped\"");
    snprintf(m->spec_path, sizeof(m->spec_path), "/tmp/dir with \"spaces\" & \\slashes/spec.json");
    m->spec_hash = 987654321ULL;
    m->random_seed = 777;
    snprintf(m->mutation_mode, sizeof(m->mutation_mode), "valid");
    manifest_config_init(&m->config);
    snprintf(m->config.protocol, sizeof(m->config.protocol), "%s", m->protocol);
    snprintf(m->config.spec_path, sizeof(m->config.spec_path), "%s", m->spec_path);
    snprintf(m->config.mutation_mode, sizeof(m->config.mutation_mode), "%s", m->mutation_mode);
    m->config.random_seed = m->random_seed;
    m->current_segment_id = 0;
    m->num_segments = 1;
    m->max_segments = 2;
    m->segments = calloc(m->max_segments, sizeof(run_segment_entry));
    CHECK(m->segments != NULL);
    m->segments[0].segment_id = 0;
    m->segments[0].parent_segment_id = -1;
    m->segments[0].start_time_ms = 1000000ULL;
    snprintf(m->segments[0].learning_state, sizeof(m->segments[0].learning_state), "reset");
    snprintf(m->segments[0].reset_reason, sizeof(m->segments[0].reset_reason), "reason with \"quotes\"\nand\ttabs");
    m->segments[0].candidate_id_start = 0;
    m->segments[0].candidates_saved = 10;
    m->segments[0].config = m->config;
    m->segments[0].spec_hash = m->spec_hash;

    CHECK(manifest_save_atomic(m, t5_dir, err, sizeof(err)) == 0);
    manifest_free(m);

    /* Parse saved file back with native_json parser */
    char saved_file[512];
    snprintf(saved_file, sizeof(saved_file), "%s/run_manifest.json", t5_dir);
    nj_document *doc = NULL;
    CHECK(nj_load_file(saved_file, &doc, err, sizeof(err)) == 0);
    CHECK(doc != NULL);
    CHECK(doc->root != NULL);

    /* Verify round-trip string integrity */
    const nj_value *v = nj_get(doc->root, "run_id");
    CHECK(v != NULL && v->text != NULL);
    CHECK(strcmp(v->text, "run_\"quote\"_\\test\\") == 0);

    v = nj_get(doc->root, "protocol");
    CHECK(v != NULL && v->text != NULL);
    CHECK(strcmp(v->text, "PROTO/\"escaped\"") == 0);

    v = nj_get(doc->root, "spec_path");
    CHECK(v != NULL && v->text != NULL);
    CHECK(strcmp(v->text, "/tmp/dir with \"spaces\" & \\slashes/spec.json") == 0);

    v = nj_get(doc->root, "mutation_mode");
    CHECK(v != NULL && v->text != NULL);
    CHECK(strcmp(v->text, "valid") == 0);

    const nj_value *segs = nj_get(doc->root, "segments");
    CHECK(segs != NULL && segs->type == NJ_ARRAY && segs->count == 1);
    const nj_value *s0 = segs->items[0];
    v = nj_get(s0, "reset_reason");
    CHECK(v != NULL && v->text != NULL);
    CHECK(strcmp(v->text, "reason with \"quotes\"\nand\ttabs") == 0);

    nj_free(doc);
    printf("[+] 5: JSON string escaping and unescaping round-trip verified\n");
  }

  printf("[+] All B13 manifest attribution continuity tests passed successfully! (%u checks)\n", checks);
  return 0;
}
