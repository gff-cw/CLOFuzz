#ifndef STATEAFL_RUN_MANIFEST_H
#define STATEAFL_RUN_MANIFEST_H

#include <stdint.h>
#include <stddef.h>

#define MANIFEST_VERSION 1
#define MANIFEST_FILENAME "run_manifest.json"

typedef struct {
  uint32_t segment_id;
  int32_t  parent_segment_id;
  uint64_t start_time_ms;
  char     learning_state[32];   /* "reset" */
  char     reset_reason[128];    /* e.g. "initial_start", "cold_start_resumption" */
  uint32_t candidate_id_start;
  uint32_t candidates_saved;
} run_segment_entry;

typedef struct {
  uint32_t manifest_version;
  char     run_id[64];
  char     protocol[64];
  char     spec_path[256];
  uint64_t spec_hash;            /* FNV-1a hash of spec file content */
  uint32_t random_seed;
  char     mutation_mode[32];
  uint32_t current_segment_id;

  uint32_t num_segments;
  uint32_t max_segments;
  run_segment_entry *segments;
} run_manifest;

/* Calculate a 64-bit FNV-1a hash of a file's contents (returns 0 on error/empty) */
uint64_t manifest_hash_file(const char *path);

/* Create or resume a manifest in out_dir.
 * If manifest doesn't exist, initializes segment 0 and saves it.
 * If manifest exists, validates attribution (protocol, spec_hash, mode).
 * If mismatch, returns -1 with err message.
 * If match, creates a new cold-start segment, scans out_dir/protocol-candidates
 * to set candidate_id_start without collision, updates manifest atomically,
 * and returns 0. */
int manifest_init_or_resume(const char *out_dir,
                            const char *protocol,
                            const char *spec_path,
                            const char *mutation_mode,
                            uint32_t random_seed,
                            run_manifest **out_manifest,
                            char *err,
                            size_t err_cap);

/* Save manifest atomically to out_dir/run_manifest.json via temp file + rename */
int manifest_save_atomic(const run_manifest *manifest,
                         const char *out_dir,
                         char *err,
                         size_t err_cap);

/* Cleanly handle truncated tail in protocol_mutations.jsonl:
 * checks if file exists, if not ending in '\n', truncates to last '\n'.
 * Returns 0 on ok, -1 on error. */
int manifest_repair_torn_log(const char *log_path, char *err, size_t err_cap);

/* Free manifest structure */
void manifest_free(run_manifest *manifest);

#endif /* STATEAFL_RUN_MANIFEST_H */
