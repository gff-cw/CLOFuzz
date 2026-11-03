#define _POSIX_C_SOURCE 200809L
#include "run_manifest.h"
#include "native_json.h"
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Exercises production manifest APIs and their persisted JSON, not a duplicate
 * parser or serializer. It performs no target execution or network activity. */
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static void write_bytes(const char *path, const void *bytes, size_t n) {
  FILE *f = fopen(path, "wb");
  CHECK(f != NULL);
  CHECK(fwrite(bytes, 1, n, f) == n);
  CHECK(fclose(f) == 0);
}

static void write_text(const char *path, const char *text) {
  write_bytes(path, text, strlen(text));
}

static void write_replaced_node(const char *path, const nj_document *doc,
                                const nj_value *value, const char *replacement) {
  CHECK(value != NULL && value->start < value->end && value->end <= doc->length);
  FILE *f = fopen(path, "wb");
  CHECK(f != NULL);
  CHECK(fwrite(doc->source, 1, value->start, f) == value->start);
  CHECK(fputs(replacement, f) >= 0);
  size_t tail = doc->length - value->end;
  CHECK(fwrite(doc->source + value->end, 1, tail, f) == tail);
  CHECK(fclose(f) == 0);
}

static void expect_reject(const char *directory, const manifest_config *config) {
  run_manifest *out = (run_manifest *)1;
  char error[512] = "";
  CHECK(manifest_init_or_resume_config(directory, config, &out, error, sizeof(error)) < 0);
  CHECK(out == NULL);
  CHECK(error[0] != 0);
}

int main(void) {
  char directory[] = "/tmp/stateafl-config-contract-XXXXXX";
  CHECK(mkdtemp(directory) != NULL);
  char spec[512], state[512], manifest_path[512], candidates[512];
  snprintf(spec, sizeof(spec), "%s/protocol:literal.json", directory);
  snprintf(state, sizeof(state), "%s/state.json", directory);
  snprintf(manifest_path, sizeof(manifest_path), "%s/run_manifest.json", directory);
  snprintf(candidates, sizeof(candidates), "%s/protocol-candidates", directory);
  write_text(spec, "{\"test\":\"protocol\"}\n");
  write_text(state, "{\"test\":\"state\"}\n");

  manifest_config config;
  manifest_config_init(&config);
  strcpy(config.protocol, "protocol-ir");
  strcpy(config.spec_path, spec);
  strcpy(config.state_spec_path, state);
  strcpy(config.transport, "tcp");
  strcpy(config.endpoint, "fixture-only");
  strcpy(config.working_directory, directory);
  config.use_network = 1;
  config.configuration_complete = 1;
  config.state_aware = 1;
  config.fixed_seed = 1;
  config.random_seed = 17;
  config.ratio = 70;
  config.socket_timeout_us = 1000;
  config.poll_wait_ms = 1;
  config.state_poll_wait_ms = 50;
  char *argv[] = {(char *)"fictional-target", (char *)"a b", (char *)"a", (char *)"b", (char *)""};
  char error[512];
  CHECK(manifest_config_set_target_argv(&config, 5, argv, error, sizeof(error)) == 0);
  CHECK(strcmp(config.target_arguments, "4;3:a b1:a1:b0:") == 0);

  run_manifest *m = NULL;
  CHECK(manifest_init_or_resume_config(directory, &config, &m, error, sizeof(error)) == 0);
  CHECK(m != NULL && m->manifest_version == 2 && m->num_segments == 1);
  CHECK(m->spec_hash != 0 && m->state_spec_hash != 0);
  CHECK(m->segments[0].config.ratio == 70);
  CHECK(m->segments[0].effective_timeouts_known == 0);
  CHECK(manifest_set_effective_timeouts(m, 2500, 5000, error, sizeof(error)) == 0);
  CHECK(m->config.requested_exec_timeout_ms == 0 && m->config.exec_timeout_auto == 1);
  CHECK(manifest_save_atomic(m, directory, error, sizeof(error)) == 0);
  manifest_free(m);
  m = NULL;

  nj_document *saved = NULL;
  CHECK(nj_load_file(manifest_path, &saved, error, sizeof(error)) == 0);
  const nj_value *segments = nj_get(saved->root, "segments");
  CHECK(segments != NULL && segments->count == 1);
  CHECK(nj_get(segments->items[0], "effective_exec_timeout_ms")->number.magnitude == 2500);
  CHECK(nj_get(segments->items[0], "configuration") != NULL);

  /* Every tracked scalar setting affects resume, independent of the mode. */
  const size_t changed_fields[] = {
    offsetof(manifest_config, random_seed), offsetof(manifest_config, fixed_seed),
    offsetof(manifest_config, layers), offsetof(manifest_config, ratio),
    offsetof(manifest_config, fallback), offsetof(manifest_config, state_aware),
    offsetof(manifest_config, skip_deterministic), offsetof(manifest_config, state_selection),
    offsetof(manifest_config, local_port), offsetof(manifest_config, terminate_child),
    offsetof(manifest_config, false_negative_reduction), offsetof(manifest_config, use_network),
    offsetof(manifest_config, region_level_mutation), offsetof(manifest_config, dumb_mode),
    offsetof(manifest_config, no_forkserver), offsetof(manifest_config, qemu_mode),
    offsetof(manifest_config, crash_mode), offsetof(manifest_config, skip_arithmetic),
    offsetof(manifest_config, fast_calibration),
    offsetof(manifest_config, seed_selection), offsetof(manifest_config, requested_exec_timeout_ms),
    offsetof(manifest_config, requested_hang_timeout_ms), offsetof(manifest_config, exec_timeout_auto),
    offsetof(manifest_config, exec_timeout_policy), offsetof(manifest_config, candidate_capture_limit),
    offsetof(manifest_config, hang_timeout_auto), offsetof(manifest_config, socket_timeout_us),
    offsetof(manifest_config, poll_wait_ms), offsetof(manifest_config, state_poll_wait_ms),
    offsetof(manifest_config, send_delay_us), offsetof(manifest_config, server_wait_us),
    offsetof(manifest_config, max_request_bytes), offsetof(manifest_config, max_response_bytes)
  };
  for (size_t i = 0; i < sizeof(changed_fields) / sizeof(changed_fields[0]); i++) {
    manifest_config altered = config;
    uint32_t *field = (uint32_t *)((unsigned char *)&altered + changed_fields[i]);
    *field ^= 1;
    expect_reject(directory, &altered);
  }
  manifest_config altered = config;
  strcpy(altered.schedule, "adaptive"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.stage_policy, "different_policy"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.mutation_mode, "hybrid"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.endpoint, "other-fixture"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.vanilla_target, "other-coverage-target"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.vanilla_workdir, "other-coverage-directory"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.working_directory, "other-working-directory"); expect_reject(directory, &altered);
  altered = config; strcpy(altered.cleanup_script, "other-cleanup-hook"); expect_reject(directory, &altered);
  altered = config; altered.memory_limit_mb = 128; expect_reject(directory, &altered);
  altered = config;
  char *different_argv[] = {(char *)"fictional-target", (char *)"a", (char *)"b", (char *)"a b", (char *)""};
  CHECK(manifest_config_set_target_argv(&altered, 5, different_argv, error, sizeof(error)) == 0);
  expect_reject(directory, &altered);

  /* The second independent file is hashed; a literal colon is not split. */
  write_text(state, "{\"test\":\"changed-state\"}\n");
  expect_reject(directory, &config);
  write_text(state, "{\"test\":\"state\"}\n");
  uint64_t h = 123;
  CHECK(manifest_hash_file_checked(spec, &h, error, sizeof(error)) == 0 && h != 123);
  char missing[512];
  snprintf(missing, sizeof(missing), "%s/no-such-file", directory);
  h = 123;
  CHECK(manifest_hash_file_checked(missing, &h, error, sizeof(error)) < 0 && h == 123);

  /* Invalid/missing types cannot be papered over with requested defaults. */
  const char *bad_version[] = {"\"2\"", "true", "-2", "1", "null"};
  const nj_value *version = nj_get(saved->root, "manifest_version");
  for (size_t i = 0; i < sizeof(bad_version) / sizeof(bad_version[0]); i++) {
    write_replaced_node(manifest_path, saved, version, bad_version[i]);
    expect_reject(directory, &config);
  }
  write_replaced_node(manifest_path, saved, nj_get(saved->root, "configuration"), "{}");
  expect_reject(directory, &config);
  write_replaced_node(manifest_path, saved, nj_get(saved->root, "spec_hash"), "null");
  expect_reject(directory, &config);
  write_replaced_node(manifest_path, saved, nj_get(saved->root, "segments"), "[]");
  expect_reject(directory, &config);
  write_replaced_node(manifest_path, saved, nj_get(segments->items[0], "parent_segment_id"), "0");
  expect_reject(directory, &config);
  write_replaced_node(manifest_path, saved, nj_get(segments->items[0], "configuration"), "{}");
  expect_reject(directory, &config);
  write_bytes(manifest_path, saved->source, saved->length);

  /* A second segment preserves the original effective and requested settings. */
  CHECK(manifest_init_or_resume_config(directory, &config, &m, error, sizeof(error)) == 0);
  CHECK(m->num_segments == 2 && m->current_segment_id == 1);
  CHECK(m->segments[0].effective_timeouts_known == 1);
  CHECK(m->segments[0].effective_exec_timeout_ms == 2500);
  CHECK(m->segments[1].effective_timeouts_known == 0);
  CHECK(m->segments[1].config.requested_exec_timeout_ms == 0);
  CHECK(manifest_set_effective_timeouts(m, 3000, 6000, error, sizeof(error)) == 0);
  CHECK(manifest_save_atomic(m, directory, error, sizeof(error)) == 0);
  manifest_free(m); m = NULL;
  nj_free(saved);

  /* Corrupt candidate IDs are an error; they cannot wrap to candidate zero. */
  CHECK(mkdir(candidates, 0700) == 0);
  char candidate_path[1024];
  snprintf(candidate_path, sizeof(candidate_path), "%s/4294967295.replay", candidates);
  write_text(candidate_path, "x");
  uint32_t next = 123;
  CHECK(manifest_next_candidate_id(directory, &next, error, sizeof(error)) < 0);
  CHECK(next == 123);
  CHECK(scan_max_candidate_id(directory) == UINT32_MAX);
  expect_reject(directory, &config);
  CHECK(unlink(candidate_path) == 0);
  snprintf(candidate_path, sizeof(candidate_path), "%s/000000.json", candidates);
  write_text(candidate_path, "{}");
  CHECK(manifest_next_candidate_id(directory, &next, error, sizeof(error)) == 0 && next == 1);

  /* Requested output/path text must be bounded, never silently truncated. */
  altered = config;
  memset(altered.spec_path, 'x', sizeof(altered.spec_path));
  expect_reject(directory, &altered);
  altered = config;
  altered.layers = 0;
  expect_reject(directory, &altered);

  CHECK(unlink(candidate_path) == 0);
  CHECK(rmdir(candidates) == 0);
  CHECK(unlink(manifest_path) == 0);
  CHECK(unlink(spec) == 0);
  CHECK(unlink(state) == 0);
  CHECK(rmdir(directory) == 0);
  printf("PASS: manifest configuration contract (%u checks; target execution absent)\n", checks);
  return 0;
}
