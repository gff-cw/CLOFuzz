#ifndef STATEAFL_RUN_MANIFEST_H
#define STATEAFL_RUN_MANIFEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define MANIFEST_VERSION 2u
#define MANIFEST_CONFIG_VERSION 1u
#define MANIFEST_FILENAME "run_manifest.json"
#define MANIFEST_MAX_SEGMENTS 128u
#define MANIFEST_PATH_CAP 1024u

/* Requested, immutable experiment configuration. File hashes observe disk
 * contents; they do not authenticate a process's actual executable image.
 * Paths are independent fields. No path-list delimiters are interpreted. */
typedef struct {
  char protocol[64];
  char spec_path[MANIFEST_PATH_CAP];
  char state_spec_path[MANIFEST_PATH_CAP];
  char mutation_mode[32];
  char schedule[16];
  char stage_policy[32];
  char transport[16];
  char endpoint[256];
  char target[MANIFEST_PATH_CAP];
  char target_arguments[MANIFEST_PATH_CAP];
  char vanilla_target[MANIFEST_PATH_CAP];
  char vanilla_workdir[MANIFEST_PATH_CAP];
  char working_directory[MANIFEST_PATH_CAP];
  char cleanup_script[MANIFEST_PATH_CAP];
  uint32_t configuration_complete;
  uint32_t random_seed;
  uint32_t fixed_seed;
  uint32_t layers;
  uint32_t ratio;
  uint32_t fallback;
  uint32_t state_aware;
  uint32_t skip_deterministic;
  uint32_t local_port;
  uint32_t terminate_child;
  uint32_t false_negative_reduction;
  uint32_t use_network;
  uint32_t region_level_mutation;
  uint32_t dumb_mode;
  uint32_t no_forkserver;
  uint32_t qemu_mode;
  uint32_t crash_mode;
  uint32_t skip_arithmetic;
  uint32_t fast_calibration;
  uint32_t state_selection;
  uint32_t seed_selection;
  uint32_t requested_exec_timeout_ms;
  uint32_t requested_hang_timeout_ms;
  uint32_t exec_timeout_auto;
  uint32_t exec_timeout_policy; /* Original -t policy, including trailing '+'. */
  uint32_t hang_timeout_auto;
  uint32_t candidate_capture_limit;
  uint32_t socket_timeout_us;
  uint32_t poll_wait_ms;
  uint32_t state_poll_wait_ms;
  uint32_t send_delay_us;
  uint32_t server_wait_us;
  uint32_t max_request_bytes;
  uint32_t max_response_bytes;
  uint64_t memory_limit_mb;
} manifest_config;

typedef struct {
  uint32_t segment_id;
  int32_t parent_segment_id;
  uint64_t start_time_ms;
  char learning_state[32];
  char reset_reason[128];
  uint32_t candidate_id_start;
  uint32_t candidates_saved;
  manifest_config config;
  uint64_t spec_hash;
  uint64_t state_spec_hash;
  uint32_t effective_timeouts_known;
  uint32_t effective_exec_timeout_ms;
  uint32_t effective_hang_timeout_ms;
} run_segment_entry;

typedef struct {
  uint32_t manifest_version;
  char run_id[64];
  /* Mirrored current fields retained for existing consumers. */
  char protocol[64];
  char spec_path[MANIFEST_PATH_CAP];
  uint64_t spec_hash;
  uint64_t state_spec_hash;
  uint32_t random_seed;
  char mutation_mode[32];
  uint32_t current_segment_id;
  manifest_config config;
  uint32_t num_segments;
  uint32_t max_segments;
  run_segment_entry *segments;
} run_manifest;

/* Defaults explicitly describe an incomplete compatibility configuration.
 * Production callers fill their settings and set configuration_complete=1. */
void manifest_config_init(manifest_config *config);
/* Record argv without shell interpretation or ambiguous whitespace joining. */
int manifest_config_set_target_argv(manifest_config *config, int argc,
                                    char *const argv[], char *error, size_t cap);
int manifest_hash_file_checked(const char *path, uint64_t *hash,
                               char *error, size_t cap);
/* Compatibility helper: one path, zero on error; attribution uses checked API. */
uint64_t manifest_hash_file(const char *path);
int manifest_next_candidate_id(const char *out_dir, uint32_t *next_id,
                                char *error, size_t cap);
/* Compatibility helper; production initialization uses the checked API. */
uint32_t scan_max_candidate_id(const char *out_dir);
void manifest_write_escaped_json_string(FILE *file, const char *text);

/* All requested settings and both description contents must match on resume.
 * Learning starts fresh in each segment. Version 1 is explicitly rejected. */
/* Prepare a validated next segment entirely in memory. This only reads disk;
 * the caller holds the output-directory lock and publishes with save_atomic
 * after preparing the directory layout. Rejection never changes old files. */
int manifest_prepare_config(const char *out_dir, const manifest_config *config,
                             run_manifest **out_manifest, char *error, size_t cap);
int manifest_init_or_resume_config(const char *out_dir,
                                   const manifest_config *config,
                                   run_manifest **out_manifest,
                                   char *error, size_t cap);
/* Legacy single-file wrapper. Never splits ':'; marks settings incomplete. */
int manifest_init_or_resume(const char *out_dir, const char *protocol,
                            const char *spec_path, const char *mutation_mode,
                            uint32_t random_seed, run_manifest **out_manifest,
                            char *error, size_t cap);
/* Post-calibration values belong to the latest segment. Caller then saves. */
int manifest_set_effective_timeouts(run_manifest *manifest,
                                     uint32_t exec_timeout_ms,
                                     uint32_t hang_timeout_ms,
                                     char *error, size_t cap);
int manifest_save_atomic(const run_manifest *manifest, const char *out_dir,
                         char *error, size_t cap);
int manifest_repair_torn_log(const char *log_path, char *error, size_t cap);
void manifest_free(run_manifest *manifest);

#endif /* STATEAFL_RUN_MANIFEST_H */
