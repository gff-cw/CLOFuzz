/* Cold-start input restoration through production helpers; no target execution. */
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#include <assert.h>

static void write_bytes(const char *path, const void *data, size_t size) {
  FILE *file = fopen(path, "wb"); assert(file);
  assert(fwrite(data, 1, size, file) == size && fclose(file) == 0);
}

static void make_queue_layout(const char *directory) {
  const char *parts[] = {"queue", "queue/.state", "queue/.state/replay", "regions"};
  for (u32 i = 0; i < sizeof(parts) / sizeof(*parts); i++) {
    char path[1024]; snprintf(path, sizeof(path), "%s/%s", directory, parts[i]);
    assert(mkdir(path, 0700) == 0);
  }
}

static void remove_queue_layout(const char *directory, const char *name) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/queue/%s", directory, name); assert(unlink(path) == 0);
  snprintf(path, sizeof(path), "%s/queue/.state/replay", directory);
  assert(delete_queue_replay_files((u8 *)path) == 0);
  snprintf(path, sizeof(path), "%s/queue/.state", directory); assert(rmdir(path) == 0);
  snprintf(path, sizeof(path), "%s/queue", directory); assert(rmdir(path) == 0);
  snprintf(path, sizeof(path), "%s/regions", directory); assert(delete_files((u8 *)path, NULL) == 0);
  assert(rmdir(directory) == 0);
}

int main(void) {
  char source[] = "/tmp/stateafl-resume-source-XXXXXX";
  char destination[] = "/tmp/stateafl-resume-destination-XXXXXX";
  assert(mkdtemp(source) && mkdtemp(destination));
  make_queue_layout(source); make_queue_layout(destination);
  char raw_path[1024], replay_path[1024], temporary[1024], raw_directory[1024];
  snprintf(raw_directory, sizeof(raw_directory), "%s/queue", source);
  snprintf(raw_path, sizeof(raw_path), "%s/queue/id:000000", source);
  snprintf(replay_path, sizeof(replay_path), "%s/queue/.state/replay/id:000000", source);
  snprintf(temporary, sizeof(temporary), "%s/queue/.state/replay/.pending-0", source);
  const u8 raw[] = {5, 0, 0, 0, 0xa5}; /* Deliberately not LE32 replay framing. */
  region_t regions[2] = {{.start_byte = 0, .end_byte = 1}, {.start_byte = 2, .end_byte = 4}};
  struct queue_entry original = {.fname = (u8 *)raw_path, .len = sizeof(raw),
                                 .regions = regions, .region_count = 2};
  write_bytes(raw_path, raw, sizeof(raw)); out_dir = (u8 *)source;
  persist_queue_replay(&original);
  assert(saved_replay_matches_raw(raw_path, replay_path) == 0);
  u8 changed[sizeof(raw)]; memcpy(changed, raw, sizeof(raw)); changed[4] ^= 1;
  write_bytes(raw_path, changed, sizeof(changed));
  assert(saved_replay_matches_raw(raw_path, replay_path) < 0); /* Same length is insufficient. */
  write_bytes(raw_path, raw, sizeof(raw));
  const u8 truncated[] = {2, 0, 0};
  write_bytes(replay_path, truncated, sizeof(truncated));
  assert(saved_replay_matches_raw(raw_path, replay_path) < 0);
  persist_queue_replay(&original);
  validate_saved_queue_replays(raw_directory);
  write_bytes(temporary, truncated, sizeof(truncated)); /* Interrupted atomic publication. */

  out_dir = (u8 *)destination; in_dir = (u8 *)source;
  prepare_external_queue_input();
  assert(input_raw_queue && strstr((char *)in_dir, "/queue/.state/replay"));
  read_testcases();
  assert(queued_paths == 1 && queue && queue->region_count == 2);
  assert(queue->regions[0].end_byte == 1 && queue->regions[1].start_byte == 2);
  pivot_inputs();
  assert(queue->len == sizeof(raw) && queue->regions[1].end_byte == 4);
  char restored[1024]; snprintf(restored, sizeof(restored), "%s/queue/id:000000", destination);
  unsigned char *bytes = NULL; size_t size; char error[256];
  assert(nj_read_file(restored, &bytes, &size, MAX_FILE, error, sizeof(error)) == 0);
  assert(size == sizeof(raw) && !memcmp(bytes, raw, size)); free(bytes);
  snprintf(replay_path, sizeof(replay_path), "%s/queue/.state/replay/id:000000", destination);
  assert(saved_replay_matches_raw(restored, replay_path) == 0);
  destroy_queue(); queue = queue_top = NULL;
  for (u32 i = 0; i < fuzzed_map_states; i++) ck_free(was_fuzzed_map[i]);
  ck_free(was_fuzzed_map); was_fuzzed_map = NULL;
  ck_free(input_raw_queue); input_raw_queue = NULL;
  ck_free(in_dir); in_dir = NULL;
  remove_queue_layout(source, "id:000000"); /* Includes hidden interrupted temp cleanup. */
  remove_queue_layout(destination, "id:000000");
  return 0;
}
