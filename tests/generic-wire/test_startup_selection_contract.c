/* Production argument, path and selection helpers. No target is executed. */
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#include <assert.h>

static void put_fixture(const char *path, const char *text) {
  FILE *file = fopen(path, "wb"); assert(file);
  assert(fputs(text, file) >= 0 && fclose(file) == 0);
}

static void check_rejected_startup_preserves_output(void) {
  char directory[] = "/tmp/stateafl-startup-contract-XXXXXX";
  assert(mkdtemp(directory));
  char queue_path[512], seed_path[512], stats_path[512], manifest_path[512], resume_path[512];
  snprintf(queue_path, sizeof(queue_path), "%s/queue", directory);
  snprintf(seed_path, sizeof(seed_path), "%s/queue/id:000000", directory);
  snprintf(stats_path, sizeof(stats_path), "%s/fuzzer_stats", directory);
  snprintf(manifest_path, sizeof(manifest_path), "%s/%s", directory, MANIFEST_FILENAME);
  snprintf(resume_path, sizeof(resume_path), "%s/_resume", directory);
  assert(mkdir(queue_path, 0700) == 0);
  put_fixture(seed_path, "preserved seed");
  char state_path[512], replay_directory[512], replay_path[512];
  snprintf(state_path, sizeof(state_path), "%s/.state", queue_path);
  snprintf(replay_directory, sizeof(replay_directory), "%s/.state/replay", queue_path);
  snprintf(replay_path, sizeof(replay_path), "%s/.state/replay/id:000000", queue_path);
  assert(mkdir(state_path, 0700) == 0 && mkdir(replay_directory, 0700) == 0);
  out_dir = (u8 *)directory;
  region_t region = {.start_byte = 0, .end_byte = (int)strlen("preserved seed") - 1};
  struct queue_entry seed = {.fname = (u8 *)seed_path, .len = strlen("preserved seed"),
                             .regions = &region, .region_count = 1};
  persist_queue_replay(&seed);
  put_fixture(stats_path, "start_time     : 1\nlast_update    : 2\n");
  manifest_config config; manifest_config_init(&config);
  strcpy(config.protocol, "fixture");
  run_manifest *original = NULL; char error[512];
  assert(manifest_init_or_resume_config(directory, &config, &original, error, sizeof(error)) == 0);
  manifest_free(original);
  u64 before = manifest_hash_file(manifest_path);
  assert(before);
  for (int resume = 0; resume <= 1; resume++) {
    pid_t process = fork(); assert(process >= 0);
    if (!process) {
      out_dir = (u8 *)directory;
      manifest_configured = 1; manifest_ctx = NULL;
      requested_manifest_config = config; requested_manifest_config.ratio ^= 1;
      in_place_resume = resume;
      maybe_delete_out_dir();
      _exit(99); /* Configuration rejection must happen before cleanup. */
    }
    int status;
    assert(waitpid(process, &status, 0) == process);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    assert(access(seed_path, F_OK) == 0 && access(resume_path, F_OK) != 0);
    assert(manifest_hash_file(manifest_path) == before);
    char saved[32] = {0};
    FILE *file = fopen(seed_path, "rb"); assert(file);
    assert(fread(saved, 1, sizeof(saved), file) == strlen("preserved seed"));
    assert(!strcmp(saved, "preserved seed") && fclose(file) == 0);
  }
  assert(unlink(replay_path) == 0 && rmdir(replay_directory) == 0 && rmdir(state_path) == 0);
  assert(unlink(seed_path) == 0 && rmdir(queue_path) == 0);
  assert(unlink(stats_path) == 0 && unlink(manifest_path) == 0 && rmdir(directory) == 0);
}

int main(void) {
  check_rejected_startup_preserves_output();
  const char *invalid[] = {"", "0", "4", "257", "-1", "+1", " 1", "1x", "2 ", "9999999999999999999999999"};
  u8 mode = 99;
  for (u32 i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
    assert(parse_selection_mode(invalid[i], &mode) < 0 && mode == 99);
  }
  assert(parse_selection_mode("1", &mode) == 0 && mode == RANDOM_SELECTION);
  assert(parse_selection_mode("2", &mode) == 0 && mode == ROUND_ROBIN);
  assert(parse_selection_mode("3", &mode) == 0 && mode == FAVOR);

  assert(setenv("AFL_SKIP_BIN_CHECK", "1", 1) == 0);
  check_binary((u8 *)"/proc/self/exe");
  assert(target_path && target_path[0] == '/' && !strstr((char *)target_path, "/proc/self/exe"));
  ck_free(target_path); target_path = NULL;
  unsetenv("AFL_SKIP_BIN_CHECK");

  region_t region = {0};
  struct queue_entry pending = {.regions = &region, .region_count = 1};
  struct queue_entry ready = {.regions = &region, .region_count = 1, .calibration_ready = 1};
  struct queue_entry isolated = {.regions = &region, .region_count = 1, .calibration_quarantined = 1};
  void *seeds[11];
  seeds[0] = &ready;
  for (u32 i = 1; i < 11; i++) seeds[i] = &isolated;
  state_info_t state = {0}; state.seeds = seeds; state.seeds_count = 11;
  khms_states = kh_init(hms);
  int inserted;
  khint_t key = kh_put(hms, khms_states, 0, &inserted);
  kh_val(khms_states, key) = &state;
  u32 ids[] = {0}; state_ids = ids; state_ids_count = 1;
  char fuzzed[] = {0}; char *rows[] = {fuzzed}; was_fuzzed_map = rows;
  fixed_random_seed = 1; dumb_mode = 1; pending_favored = 1;
  for (u8 policy = RANDOM_SELECTION; policy <= FAVOR; policy++)
    assert(choose_seed(0, policy) == &ready);
  seeds[0] = &isolated;
  for (u8 policy = RANDOM_SELECTION; policy <= FAVOR; policy++)
    assert(choose_seed(0, policy) == NULL);
  assert(!choose_usable_state_seed());
  /* An initial pending entry has no trusted reachability membership. It still
     gets a calibration opportunity without manufacturing a state association. */
  queue = &pending; target_state_id = 42;
  assert(choose_usable_state_seed() == &pending && target_state_id == 0);
  assert(state.seeds_count == 11 && seeds[0] == &isolated);
  stop_soon = 1;
  assert(!choose_usable_state_seed() && !choose_seed(0, FAVOR));
  assert(!choose_seed(0, 0) && !choose_seed(0, 4));
  queue = NULL; state_ids = NULL; state_ids_count = 0; was_fuzzed_map = NULL;
  kh_destroy(hms, khms_states); khms_states = NULL;
  return 0;
}
