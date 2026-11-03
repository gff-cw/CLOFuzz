#define _POSIX_C_SOURCE 200809L
#include "run_manifest.h"
#include "native_json.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

static int mf_error(char *err, size_t cap, const char *fmt, ...) {
  if (err && cap) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
  }
  return -1;
}

static int mf_utf8(const char *text, size_t size) {
  const unsigned char *s = (const unsigned char *)text;
  size_t i = 0;
  while (i < size) {
    uint32_t value, minimum;
    unsigned need;
    unsigned char c = s[i++];
    if (c < 0x80) continue;
    if (c >= 0xc2 && c <= 0xdf) { value = c & 31u; need = 1; minimum = 0x80; }
    else if (c >= 0xe0 && c <= 0xef) { value = c & 15u; need = 2; minimum = 0x800; }
    else if (c >= 0xf0 && c <= 0xf4) { value = c & 7u; need = 3; minimum = 0x10000; }
    else return 0;
    if (need > size - i) return 0;
    while (need--) {
      c = s[i++];
      if ((c & 0xc0u) != 0x80u) return 0;
      value = (value << 6) | (c & 63u);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
  }
  return 1;
}

static int mf_text_valid(const char *s, size_t limit, int required,
                         const char *name, char *err, size_t cap) {
  const char *end = memchr(s, 0, limit);
  if (!end) return mf_error(err, cap, "%s exceeds its bounded string capacity", name);
  size_t n = (size_t)(end - s);
  if ((required && !n) || !mf_utf8(s, n))
    return mf_error(err, cap, "%s must be %svalid UTF-8 text", name, required ? "nonempty " : "");
  return 0;
}

static int mf_copy(char *out, size_t capacity, const char *value,
                    const char *name, char *err, size_t cap) {
  if (!value) value = "";
  size_t n = strlen(value);
  if (n >= capacity) return mf_error(err, cap, "%s exceeds its bounded string capacity", name);
  memcpy(out, value, n + 1);
  return 0;
}

static char *mf_path(const char *directory, const char *leaf,
                     char *err, size_t cap) {
  if (!directory || !*directory || !leaf) {
    mf_error(err, cap, "Invalid output path");
    return NULL;
  }
  size_t a = strlen(directory), b = strlen(leaf);
  if (a > SIZE_MAX - b - 2) {
    mf_error(err, cap, "Output path length overflow");
    return NULL;
  }
  char *p = malloc(a + b + 2);
  if (!p) { mf_error(err, cap, "Out of memory forming output path"); return NULL; }
  memcpy(p, directory, a);
  p[a] = '/';
  memcpy(p + a + 1, leaf, b + 1);
  return p;
}

static uint64_t mf_time_ms(void) {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) return 0;
  return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

void manifest_config_init(manifest_config *c) {
  if (!c) return;
  memset(c, 0, sizeof(*c));
  memcpy(c->protocol, "unknown", sizeof("unknown"));
  memcpy(c->mutation_mode, "valid", sizeof("valid"));
  memcpy(c->schedule, "uniform", sizeof("uniform"));
  memcpy(c->stage_policy, "havoc_splice", sizeof("havoc_splice"));
  c->layers = 7;
  c->ratio = 100;
  c->exec_timeout_auto = 1;
  c->hang_timeout_auto = 1;
  c->max_request_bytes = NJ_MAX_BYTES;
  c->max_response_bytes = NJ_MAX_BYTES;
}

int manifest_config_set_target_argv(manifest_config *c, int argc,
                                    char *const argv[], char *err, size_t cap) {
  if (!c || argc < 1 || !argv || !argv[0] || !*argv[0])
    return mf_error(err, cap, "Target argv must include a nonempty executable name");
  manifest_config copy = *c;
  if (mf_copy(copy.target, sizeof(copy.target), argv[0], "target", err, cap) < 0) return -1;
  size_t at = 0;
  int z = snprintf(copy.target_arguments, sizeof(copy.target_arguments), "%d;", argc - 1);
  if (z < 0 || (size_t)z >= sizeof(copy.target_arguments))
    return mf_error(err, cap, "Target argument count cannot be represented");
  at = (size_t)z;
  for (int i = 1; i < argc; i++) {
    if (!argv[i]) return mf_error(err, cap, "NULL target argument");
    size_t n = strlen(argv[i]);
    if (!mf_utf8(argv[i], n)) return mf_error(err, cap, "Target arguments must be valid UTF-8");
    z = snprintf(copy.target_arguments + at, sizeof(copy.target_arguments) - at, "%zu:", n);
    if (z < 0 || (size_t)z >= sizeof(copy.target_arguments) - at)
      return mf_error(err, cap, "Target argument identity exceeds bounded capacity");
    at += (size_t)z;
    if (n >= sizeof(copy.target_arguments) - at)
      return mf_error(err, cap, "Target argument identity exceeds bounded capacity");
    memcpy(copy.target_arguments + at, argv[i], n);
    at += n;
    copy.target_arguments[at] = 0;
  }
  *c = copy;
  return 0;
}

int manifest_hash_file_checked(const char *path, uint64_t *out,
                               char *err, size_t cap) {
  if (!path || !*path || !out) return mf_error(err, cap, "Missing description path or hash output");
  int fd = open(path, O_RDONLY | O_NONBLOCK);
  if (fd < 0) return mf_error(err, cap, "Cannot open description '%s': %s", path, strerror(errno));
  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uint64_t)st.st_size > NJ_MAX_BYTES) {
    close(fd);
    return mf_error(err, cap, "Description '%s' must be a regular file of at most %u bytes", path, NJ_MAX_BYTES);
  }
  uint64_t h = FNV_OFFSET_BASIS;
  size_t total = 0;
  unsigned char bytes[4096];
  for (;;) {
    ssize_t n = read(fd, bytes, sizeof(bytes));
    if (n < 0) {
      if (errno == EINTR) continue;
      int e = errno;
      close(fd);
      return mf_error(err, cap, "Cannot read description '%s': %s", path, strerror(e));
    }
    if (!n) break;
    if ((size_t)n > NJ_MAX_BYTES - total) {
      close(fd);
      return mf_error(err, cap, "Description '%s' changed beyond the input budget", path);
    }
    total += (size_t)n;
    for (ssize_t i = 0; i < n; i++) { h ^= bytes[i]; h *= FNV_PRIME; }
  }
  if (close(fd) < 0) return mf_error(err, cap, "Cannot close description '%s': %s", path, strerror(errno));
  *out = h;
  return 0;
}

uint64_t manifest_hash_file(const char *path) {
  uint64_t h = 0;
  if (manifest_hash_file_checked(path, &h, NULL, 0) < 0) return 0;
  return h;
}

int manifest_next_candidate_id(const char *out_dir, uint32_t *next,
                                char *err, size_t cap) {
  if (!next) return mf_error(err, cap, "Missing next candidate output");
  char *path = mf_path(out_dir, "protocol-candidates", err, cap);
  if (!path) return -1;
  DIR *dir = opendir(path);
  if (!dir) {
    int e = errno;
    free(path);
    if (e == ENOENT) { *next = 0; return 0; }
    return mf_error(err, cap, "Cannot read candidate directory: %s", strerror(e));
  }
  free(path);
  uint32_t maximum = 0;
  int found = 0, result = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(dir)) != NULL) {
    const char *name = entry->d_name;
    if (*name < '0' || *name > '9') continue;
    errno = 0;
    char *end;
    unsigned long long n = strtoull(name, &end, 10);
    int range_error = errno == ERANGE;
    if (strcmp(end, ".json") && strcmp(end, ".replay") && strcmp(end, ".raw") && *end != '_') {
      errno = 0;
      continue;
    }
    if (range_error || n >= UINT32_MAX) {
      result = mf_error(err, cap, "Candidate ID range exhausted by '%s'", name);
      break;
    }
    if (!found || (uint32_t)n > maximum) maximum = (uint32_t)n;
    found = 1;
    errno = 0;
  }
  int read_error = errno;
  if (result == 0 && !entry && read_error)
    result = mf_error(err, cap, "Cannot enumerate candidate directory: %s", strerror(read_error));
  if (closedir(dir) < 0 && result == 0)
    result = mf_error(err, cap, "Cannot close candidate directory: %s", strerror(errno));
  if (result < 0) return -1;
  *next = found ? maximum + 1 : 0;
  return 0;
}

uint32_t scan_max_candidate_id(const char *out_dir) {
  uint32_t next = 0;
  if (manifest_next_candidate_id(out_dir, &next, NULL, 0) < 0) return UINT32_MAX;
  return next;
}

void manifest_write_escaped_json_string(FILE *file, const char *text) {
  if (file) nj_write_string(file, text ? text : "", text ? strlen(text) : 0);
}

/* One field table drives strict schema checking, serialization and comparison. */
enum mf_kind { MF_TEXT, MF_U32, MF_U64 };
typedef struct {
  const char *key;
  size_t offset, width;
  enum mf_kind kind;
  uint64_t max;
} mf_field;
#define MF_STRING(x) {#x, offsetof(manifest_config, x), sizeof(((manifest_config *)0)->x), MF_TEXT, 0}
#define MF_NUMBER(x, upper) {#x, offsetof(manifest_config, x), sizeof(((manifest_config *)0)->x), MF_U32, upper}
static const mf_field mf_config_fields[] = {
  MF_STRING(protocol), MF_STRING(spec_path), MF_STRING(state_spec_path),
  MF_STRING(mutation_mode), MF_STRING(schedule), MF_STRING(stage_policy),
  MF_STRING(transport), MF_STRING(endpoint), MF_STRING(target), MF_STRING(target_arguments),
  MF_STRING(vanilla_target), MF_STRING(vanilla_workdir), MF_STRING(working_directory), MF_STRING(cleanup_script),
  MF_NUMBER(configuration_complete, 1), MF_NUMBER(random_seed, UINT32_MAX),
  MF_NUMBER(fixed_seed, 1), MF_NUMBER(layers, 7), MF_NUMBER(ratio, 100),
  MF_NUMBER(fallback, 1), MF_NUMBER(state_aware, 1), MF_NUMBER(skip_deterministic, 1),
  MF_NUMBER(local_port, 65535), MF_NUMBER(terminate_child, 1), MF_NUMBER(false_negative_reduction, 1),
  MF_NUMBER(use_network, 1), MF_NUMBER(region_level_mutation, 1), MF_NUMBER(dumb_mode, 2),
  MF_NUMBER(no_forkserver, 1), MF_NUMBER(qemu_mode, 1), MF_NUMBER(crash_mode, 1),
  MF_NUMBER(skip_arithmetic, 1), MF_NUMBER(fast_calibration, 1),
  MF_NUMBER(state_selection, UINT32_MAX), MF_NUMBER(seed_selection, UINT32_MAX),
  MF_NUMBER(requested_exec_timeout_ms, UINT32_MAX), MF_NUMBER(requested_hang_timeout_ms, UINT32_MAX),
  MF_NUMBER(exec_timeout_auto, 1), MF_NUMBER(exec_timeout_policy, 3),
  MF_NUMBER(hang_timeout_auto, 1), MF_NUMBER(candidate_capture_limit, UINT32_MAX),
  MF_NUMBER(socket_timeout_us, 600000000), MF_NUMBER(poll_wait_ms, 600000),
  MF_NUMBER(state_poll_wait_ms, 600000), MF_NUMBER(send_delay_us, UINT32_MAX),
  MF_NUMBER(server_wait_us, UINT32_MAX), MF_NUMBER(max_request_bytes, UINT32_MAX),
  MF_NUMBER(max_response_bytes, UINT32_MAX),
  {"memory_limit_mb", offsetof(manifest_config, memory_limit_mb), sizeof(uint64_t), MF_U64, UINT64_MAX}
};
#define MF_CONFIG_COUNT (sizeof(mf_config_fields) / sizeof(mf_config_fields[0]))

static uint64_t mf_number(const manifest_config *c, const mf_field *f) {
  const unsigned char *p = (const unsigned char *)c + f->offset;
  return f->kind == MF_U32 ? *(const uint32_t *)p : *(const uint64_t *)p;
}

static int mf_config_valid(const manifest_config *c, char *err, size_t cap) {
  if (!c) return mf_error(err, cap, "Missing configuration");
  for (size_t i = 0; i < MF_CONFIG_COUNT; i++) {
    const mf_field *f = &mf_config_fields[i];
    if (f->kind == MF_TEXT) {
      if (mf_text_valid((const char *)c + f->offset, f->width, 0, f->key, err, cap) < 0) return -1;
    } else if (mf_number(c, f) > f->max) return mf_error(err, cap, "Configuration '%s' exceeds its range", f->key);
  }
  if (!c->protocol[0] || !c->stage_policy[0] || !c->layers ||
      !c->max_request_bytes || !c->max_response_bytes)
    return mf_error(err, cap, "Configuration requires protocol, stage policy, layers and nonzero budgets");
  if (strcmp(c->schedule, "uniform") && strcmp(c->schedule, "adaptive"))
    return mf_error(err, cap, "Unknown schedule in configuration");
  if (strcmp(c->mutation_mode, "valid") && strcmp(c->mutation_mode, "hybrid") &&
      strcmp(c->mutation_mode, "near_valid") && strcmp(c->mutation_mode, "invalid") && strcmp(c->mutation_mode, "raw"))
    return mf_error(err, cap, "Unknown mutation_mode in configuration");
  if ((!c->exec_timeout_auto && !c->requested_exec_timeout_ms) ||
      (!c->hang_timeout_auto && !c->requested_hang_timeout_ms))
    return mf_error(err, cap, "Explicit requested timeouts must be nonzero");
  if (c->configuration_complete) {
    if (!c->spec_path[0] || !c->target[0] || !c->target_arguments[0] || !c->endpoint[0] || !c->working_directory[0] ||
        (strcmp(c->transport, "tcp") && strcmp(c->transport, "udp")))
      return mf_error(err, cap, "Complete configuration requires descriptions, target argv, transport and endpoint");
    if (!strcmp(c->protocol, "protocol-ir") && !c->state_spec_path[0])
      return mf_error(err, cap, "protocol-ir configuration requires an independent state_spec_path");
    if (!strcmp(c->protocol, "generic-wire") && c->state_spec_path[0])
      return mf_error(err, cap, "generic-wire configuration must not contain a legacy state_spec_path");
  }
  return 0;
}

static int mf_config_equal(const manifest_config *a, const manifest_config *b,
                             char *err, size_t cap) {
  for (size_t i = 0; i < MF_CONFIG_COUNT; i++) {
    const mf_field *f = &mf_config_fields[i];
    int differs = f->kind == MF_TEXT
        ? strcmp((const char *)a + f->offset, (const char *)b + f->offset) != 0
        : mf_number(a, f) != mf_number(b, f);
    if (differs) return mf_error(err, cap, "Attribution conflict: configuration '%s' changed", f->key);
  }
  return 0;
}

static int mf_read_u64(const nj_value *object, const char *key, uint64_t max,
                        uint64_t *out, char *err, size_t cap) {
  uint64_t n;
  if (nj_u64(nj_get(object, key), &n, err, cap) < 0 || n > max)
    return mf_error(err, cap, "Manifest field '%s' must be an unsigned integer within range", key);
  *out = n;
  return 0;
}

static int mf_read_u32(const nj_value *object, const char *key, uint32_t max,
                        uint32_t *out, char *err, size_t cap) {
  uint64_t n;
  if (mf_read_u64(object, key, max, &n, err, cap) < 0) return -1;
  *out = (uint32_t)n;
  return 0;
}

static int mf_config_read(const nj_value *value, manifest_config *c,
                           char *err, size_t cap) {
  const char *keys[MF_CONFIG_COUNT + 1];
  keys[0] = "config_version";
  for (size_t i = 0; i < MF_CONFIG_COUNT; i++) keys[i + 1] = mf_config_fields[i].key;
  if (nj_keys(value, keys, MF_CONFIG_COUNT + 1, NULL, 0, err, cap) < 0) return -1;
  uint32_t version;
  if (mf_read_u32(value, "config_version", UINT32_MAX, &version, err, cap) < 0 || version != MANIFEST_CONFIG_VERSION)
    return mf_error(err, cap, "Unsupported manifest configuration version");
  memset(c, 0, sizeof(*c));
  for (size_t i = 0; i < MF_CONFIG_COUNT; i++) {
    const mf_field *f = &mf_config_fields[i];
    unsigned char *dest = (unsigned char *)c + f->offset;
    if (f->kind == MF_TEXT) {
      if (nj_string_copy(nj_get(value, f->key), (char *)dest, f->width, err, cap) < 0) return -1;
    } else {
      uint64_t n;
      if (mf_read_u64(value, f->key, f->max, &n, err, cap) < 0) return -1;
      if (f->kind == MF_U32) *(uint32_t *)dest = (uint32_t)n;
      else *(uint64_t *)dest = n;
    }
  }
  return mf_config_valid(c, err, cap);
}

static int mf_config_write(FILE *f, const manifest_config *c) {
  if (fprintf(f, "{\"config_version\":%u", MANIFEST_CONFIG_VERSION) < 0) return -1;
  for (size_t i = 0; i < MF_CONFIG_COUNT; i++) {
    const mf_field *field = &mf_config_fields[i];
    if (fprintf(f, ",\"%s\":", field->key) < 0) return -1;
    if (field->kind == MF_TEXT) manifest_write_escaped_json_string(f, (const char *)c + field->offset);
    else if (fprintf(f, "%" PRIu64, mf_number(c, field)) < 0) return -1;
  }
  return fputc('}', f) == EOF ? -1 : 0;
}

static void mf_mirror(run_manifest *m) {
  memcpy(m->protocol, m->config.protocol, sizeof(m->protocol));
  memcpy(m->spec_path, m->config.spec_path, sizeof(m->spec_path));
  memcpy(m->mutation_mode, m->config.mutation_mode, sizeof(m->mutation_mode));
  m->random_seed = m->config.random_seed;
}

static int mf_valid(const run_manifest *m, char *err, size_t cap) {
  if (!m || m->manifest_version != MANIFEST_VERSION || !m->segments ||
      !m->num_segments || m->num_segments > MANIFEST_MAX_SEGMENTS || m->num_segments > m->max_segments)
    return mf_error(err, cap, "Invalid manifest version or segment count");
  if (mf_text_valid(m->run_id, sizeof(m->run_id), 1, "run_id", err, cap) < 0 ||
      mf_config_valid(&m->config, err, cap) < 0) return -1;
  if (mf_text_valid(m->protocol, sizeof(m->protocol), 1, "protocol", err, cap) < 0 ||
      mf_text_valid(m->spec_path, sizeof(m->spec_path), 0, "spec_path", err, cap) < 0 ||
      mf_text_valid(m->mutation_mode, sizeof(m->mutation_mode), 1, "mutation_mode", err, cap) < 0) return -1;
  if (strcmp(m->protocol, m->config.protocol) || strcmp(m->spec_path, m->config.spec_path) ||
      strcmp(m->mutation_mode, m->config.mutation_mode) || m->random_seed != m->config.random_seed)
    return mf_error(err, cap, "Manifest mirrored configuration fields disagree");
  uint32_t previous_end = 0;
  for (uint32_t i = 0; i < m->num_segments; i++) {
    const run_segment_entry *s = &m->segments[i];
    if (s->segment_id != i || s->parent_segment_id != (i ? (int32_t)i - 1 : -1) || !s->start_time_ms ||
        s->candidates_saved > UINT32_MAX - s->candidate_id_start ||
        (i && s->candidate_id_start < previous_end))
      return mf_error(err, cap, "Invalid segment identity, lineage or candidate range");
    previous_end = s->candidate_id_start + s->candidates_saved;
    if (mf_text_valid(s->learning_state, sizeof(s->learning_state), 1, "learning_state", err, cap) < 0 ||
        mf_text_valid(s->reset_reason, sizeof(s->reset_reason), 1, "reset_reason", err, cap) < 0) return -1;
    if (strcmp(s->learning_state, "reset")) return mf_error(err, cap, "Unknown segment learning state");
    if (mf_config_valid(&s->config, err, cap) < 0 ||
        mf_config_equal(&m->config, &s->config, err, cap) < 0) return -1;
    if (s->spec_hash != m->spec_hash || s->state_spec_hash != m->state_spec_hash)
      return mf_error(err, cap, "Segment description identities disagree");
    if (s->effective_timeouts_known > 1 ||
        (s->effective_timeouts_known && !s->effective_exec_timeout_ms) ||
        (!s->effective_timeouts_known && (s->effective_exec_timeout_ms || s->effective_hang_timeout_ms)))
      return mf_error(err, cap, "Invalid effective timeout state");
  }
  if (m->current_segment_id != m->segments[m->num_segments - 1].segment_id)
    return mf_error(err, cap, "Manifest current segment does not identify the final segment");
  return 0;
}

int manifest_save_atomic(const run_manifest *m, const char *out_dir,
                         char *err, size_t cap) {
  if (mf_valid(m, err, cap) < 0) return -1;
  char *final = mf_path(out_dir, MANIFEST_FILENAME, err, cap);
  char *temp = mf_path(out_dir, ".run_manifest.json.tmp.XXXXXX", err, cap);
  if (!final || !temp) { free(final); free(temp); return -1; }
  int fd = mkstemp(temp);
  if (fd < 0) {
    int e = errno;
    free(final); free(temp);
    return mf_error(err, cap, "Cannot create temporary manifest: %s", strerror(e));
  }
  FILE *f = fdopen(fd, "w");
  if (!f) {
    int e = errno;
    close(fd); unlink(temp); free(final); free(temp);
    return mf_error(err, cap, "Cannot open temporary manifest stream: %s", strerror(e));
  }
  int ok = fprintf(f, "{\n\"manifest_version\":%u,\n\"run_id\":", m->manifest_version) >= 0;
  manifest_write_escaped_json_string(f, m->run_id);
  if (fprintf(f, ",\n\"protocol\":") < 0) ok = 0;
  manifest_write_escaped_json_string(f, m->protocol);
  if (fprintf(f, ",\n\"spec_path\":") < 0) ok = 0;
  manifest_write_escaped_json_string(f, m->spec_path);
  if (fprintf(f, ",\n\"spec_hash\":%" PRIu64 ",\n\"state_spec_hash\":%" PRIu64 ",\n\"random_seed\":%u,\n\"mutation_mode\":",
              m->spec_hash, m->state_spec_hash, m->random_seed) < 0) ok = 0;
  manifest_write_escaped_json_string(f, m->mutation_mode);
  if (fprintf(f, ",\n\"current_segment_id\":%u,\n\"configuration\":", m->current_segment_id) < 0 ||
      mf_config_write(f, &m->config) < 0 || fputs(",\n\"segments\":[\n", f) == EOF) ok = 0;
  for (uint32_t i = 0; i < m->num_segments && ok; i++) {
    const run_segment_entry *s = &m->segments[i];
    if (fprintf(f, "%s{\"segment_id\":%u,\"parent_segment_id\":%d,\"start_time_ms\":%" PRIu64 ",\"learning_state\":",
                i ? ",\n" : "", s->segment_id, s->parent_segment_id, s->start_time_ms) < 0) ok = 0;
    manifest_write_escaped_json_string(f, s->learning_state);
    if (fputs(",\"reset_reason\":", f) == EOF) ok = 0;
    manifest_write_escaped_json_string(f, s->reset_reason);
    if (fprintf(f, ",\"candidate_id_start\":%u,\"candidates_saved\":%u,\"spec_hash\":%" PRIu64 ",\"state_spec_hash\":%" PRIu64
                   ",\"effective_timeouts_known\":%u,\"effective_exec_timeout_ms\":%u,\"effective_hang_timeout_ms\":%u,\"configuration\":",
                s->candidate_id_start, s->candidates_saved, s->spec_hash, s->state_spec_hash,
                s->effective_timeouts_known, s->effective_exec_timeout_ms, s->effective_hang_timeout_ms) < 0 ||
        mf_config_write(f, &s->config) < 0 || fputc('}', f) == EOF) ok = 0;
  }
  if (fputs("\n]}\n", f) == EOF) ok = 0;
  long size = ftell(f);
  if (size < 0 || (uint64_t)size > NJ_MAX_BYTES || ferror(f)) ok = 0;
  if (fflush(f) != 0) ok = 0;
  if (ok && fsync(fd) != 0) ok = 0;
  if (fclose(f) != 0) ok = 0;
  if (!ok) {
    unlink(temp); free(final); free(temp);
    return mf_error(err, cap, "Cannot completely write manifest within its input budget");
  }
  if (rename(temp, final) < 0) {
    int e = errno;
    unlink(temp); free(final); free(temp);
    return mf_error(err, cap, "Cannot publish manifest: %s", strerror(e));
  }
  free(final); free(temp);
  return 0;
}

static int mf_read_manifest(const nj_value *root, run_manifest *m, char *err, size_t cap) {
  static const char *keys[] = {"manifest_version", "run_id", "protocol", "spec_path", "spec_hash", "state_spec_hash",
                              "random_seed", "mutation_mode", "current_segment_id", "configuration", "segments"};
  /* Diagnose missing historical configuration rather than guessing its values. */
  uint32_t version;
  if (mf_read_u32(root, "manifest_version", UINT32_MAX, &version, err, cap) < 0 || version != MANIFEST_VERSION)
    return mf_error(err, cap, "Attribution conflict: manifest version mismatch; version 2 configuration snapshots are required");
  if (nj_keys(root, keys, sizeof(keys) / sizeof(keys[0]), NULL, 0, err, cap) < 0) return -1;
  m->manifest_version = version;
  if (nj_string_copy(nj_get(root, "run_id"), m->run_id, sizeof(m->run_id), err, cap) < 0 ||
      nj_string_copy(nj_get(root, "protocol"), m->protocol, sizeof(m->protocol), err, cap) < 0 ||
      nj_string_copy(nj_get(root, "spec_path"), m->spec_path, sizeof(m->spec_path), err, cap) < 0 ||
      nj_string_copy(nj_get(root, "mutation_mode"), m->mutation_mode, sizeof(m->mutation_mode), err, cap) < 0 ||
      mf_read_u64(root, "spec_hash", UINT64_MAX, &m->spec_hash, err, cap) < 0 ||
      mf_read_u64(root, "state_spec_hash", UINT64_MAX, &m->state_spec_hash, err, cap) < 0 ||
      mf_read_u32(root, "random_seed", UINT32_MAX, &m->random_seed, err, cap) < 0 ||
      mf_read_u32(root, "current_segment_id", INT32_MAX, &m->current_segment_id, err, cap) < 0 ||
      mf_config_read(nj_get(root, "configuration"), &m->config, err, cap) < 0) return -1;
  const nj_value *segments = nj_get(root, "segments");
  if (!segments || segments->type != NJ_ARRAY || !segments->count || segments->count > MANIFEST_MAX_SEGMENTS)
    return mf_error(err, cap, "Manifest must contain a bounded nonempty segment array");
  m->segments = calloc(segments->count, sizeof(*m->segments));
  if (!m->segments) return mf_error(err, cap, "Out of memory reading manifest segments");
  m->num_segments = m->max_segments = (uint32_t)segments->count;
  static const char *segment_keys[] = {"segment_id", "parent_segment_id", "start_time_ms", "learning_state", "reset_reason",
      "candidate_id_start", "candidates_saved", "spec_hash", "state_spec_hash", "effective_timeouts_known",
      "effective_exec_timeout_ms", "effective_hang_timeout_ms", "configuration"};
  for (uint32_t i = 0; i < m->num_segments; i++) {
    const nj_value *v = segments->items[i];
    run_segment_entry *s = &m->segments[i];
    int64_t parent;
    if (nj_keys(v, segment_keys, sizeof(segment_keys) / sizeof(segment_keys[0]), NULL, 0, err, cap) < 0 ||
        mf_read_u32(v, "segment_id", INT32_MAX, &s->segment_id, err, cap) < 0 ||
        nj_i64(nj_get(v, "parent_segment_id"), &parent, err, cap) < 0) return -1;
    if (parent < -1 || parent > INT32_MAX) return mf_error(err, cap, "Invalid parent segment ID");
    s->parent_segment_id = (int32_t)parent;
    if (mf_read_u64(v, "start_time_ms", UINT64_MAX, &s->start_time_ms, err, cap) < 0 ||
        nj_string_copy(nj_get(v, "learning_state"), s->learning_state, sizeof(s->learning_state), err, cap) < 0 ||
        nj_string_copy(nj_get(v, "reset_reason"), s->reset_reason, sizeof(s->reset_reason), err, cap) < 0 ||
        mf_read_u32(v, "candidate_id_start", UINT32_MAX, &s->candidate_id_start, err, cap) < 0 ||
        mf_read_u32(v, "candidates_saved", UINT32_MAX, &s->candidates_saved, err, cap) < 0 ||
        mf_read_u64(v, "spec_hash", UINT64_MAX, &s->spec_hash, err, cap) < 0 ||
        mf_read_u64(v, "state_spec_hash", UINT64_MAX, &s->state_spec_hash, err, cap) < 0 ||
        mf_read_u32(v, "effective_timeouts_known", 1, &s->effective_timeouts_known, err, cap) < 0 ||
        mf_read_u32(v, "effective_exec_timeout_ms", UINT32_MAX, &s->effective_exec_timeout_ms, err, cap) < 0 ||
        mf_read_u32(v, "effective_hang_timeout_ms", UINT32_MAX, &s->effective_hang_timeout_ms, err, cap) < 0 ||
        mf_config_read(nj_get(v, "configuration"), &s->config, err, cap) < 0) return -1;
  }
  return mf_valid(m, err, cap);
}

int manifest_init_or_resume_config(const char *out_dir, const manifest_config *config,
                                   run_manifest **out, char *err, size_t cap) {
  if (!out) return mf_error(err, cap, "Missing manifest output");
  *out = NULL;
  if (mf_config_valid(config, err, cap) < 0) return -1;
  uint64_t spec_hash = 0, state_hash = 0;
  if ((config->spec_path[0] && manifest_hash_file_checked(config->spec_path, &spec_hash, err, cap) < 0) ||
      (config->state_spec_path[0] && manifest_hash_file_checked(config->state_spec_path, &state_hash, err, cap) < 0)) return -1;
  char *path = mf_path(out_dir, MANIFEST_FILENAME, err, cap);
  if (!path) return -1;
  struct stat st;
  int exists = stat(path, &st) == 0;
  if (!exists && errno != ENOENT) {
    int e = errno;
    free(path);
    return mf_error(err, cap, "Cannot inspect manifest: %s", strerror(e));
  }
  run_manifest *m = calloc(1, sizeof(*m));
  if (!m) { free(path); return mf_error(err, cap, "Out of memory allocating manifest"); }
  int result = -1;
  if (exists) {
    nj_document *doc = NULL;
    if (!S_ISREG(st.st_mode)) { mf_error(err, cap, "Manifest must be a regular file"); goto done; }
    if (nj_load_file(path, &doc, err, cap) < 0) goto done;
    int parsed = mf_read_manifest(doc->root, m, err, cap);
    nj_free(doc);
    if (parsed < 0) goto done;
    if (m->spec_hash != spec_hash || m->state_spec_hash != state_hash) {
      mf_error(err, cap, "Attribution conflict: spec content hash mismatch");
      goto done;
    }
    if (mf_config_equal(&m->config, config, err, cap) < 0) goto done;
    if (m->num_segments >= MANIFEST_MAX_SEGMENTS) {
      mf_error(err, cap, "Manifest segment capacity exhausted; start a new output directory");
      goto done;
    }
  } else {
    m->manifest_version = MANIFEST_VERSION;
    m->config = *config;
    m->spec_hash = spec_hash;
    m->state_spec_hash = state_hash;
    mf_mirror(m);
    if (snprintf(m->run_id, sizeof(m->run_id), "run_%016" PRIx64 "_%ld", mf_time_ms(), (long)getpid()) >= (int)sizeof(m->run_id)) {
      mf_error(err, cap, "Run identity overflow");
      goto done;
    }
  }
  uint32_t next;
  if (manifest_next_candidate_id(out_dir, &next, err, cap) < 0) goto done;
  if (m->num_segments) {
    const run_segment_entry *previous = &m->segments[m->num_segments - 1];
    uint32_t end = previous->candidate_id_start + previous->candidates_saved;
    if (end > next) next = end;
  }
  if (next == UINT32_MAX) { mf_error(err, cap, "Candidate ID capacity exhausted"); goto done; }
  uint32_t count = m->num_segments + 1;
  run_segment_entry *grown = realloc(m->segments, (size_t)count * sizeof(*grown));
  if (!grown) { mf_error(err, cap, "Out of memory adding manifest segment"); goto done; }
  m->segments = grown;
  m->max_segments = count;
  run_segment_entry *segment = &m->segments[m->num_segments];
  memset(segment, 0, sizeof(*segment));
  segment->segment_id = m->num_segments;
  segment->parent_segment_id = m->num_segments ? (int32_t)m->num_segments - 1 : -1;
  segment->start_time_ms = mf_time_ms();
  memcpy(segment->learning_state, "reset", sizeof("reset"));
  const char *reason = m->num_segments ? "cold_start_resumption" : "initial_start";
  memcpy(segment->reset_reason, reason, strlen(reason) + 1);
  segment->candidate_id_start = next;
  segment->config = *config;
  segment->spec_hash = spec_hash;
  segment->state_spec_hash = state_hash;
  m->num_segments = count;
  m->current_segment_id = segment->segment_id;
  if (manifest_save_atomic(m, out_dir, err, cap) < 0) goto done;
  *out = m;
  m = NULL;
  result = 0;
 done:
  free(path);
  manifest_free(m);
  return result;
}

int manifest_init_or_resume(const char *out_dir, const char *protocol,
                            const char *spec_path, const char *mode, uint32_t seed,
                            run_manifest **out, char *err, size_t cap) {
  if (out) *out = NULL;
  manifest_config c;
  manifest_config_init(&c);
  if (mf_copy(c.protocol, sizeof(c.protocol), protocol ? protocol : "unknown", "protocol", err, cap) < 0 ||
      mf_copy(c.spec_path, sizeof(c.spec_path), spec_path, "spec_path", err, cap) < 0 ||
      mf_copy(c.mutation_mode, sizeof(c.mutation_mode), mode ? mode : "valid", "mutation_mode", err, cap) < 0) return -1;
  c.random_seed = seed;
  c.fixed_seed = 1;
  return manifest_init_or_resume_config(out_dir, &c, out, err, cap);
}

int manifest_set_effective_timeouts(run_manifest *m, uint32_t exec_ms,
                                     uint32_t hang_ms, char *err, size_t cap) {
  if (mf_valid(m, err, cap) < 0) return -1;
  if (!exec_ms) return mf_error(err, cap, "Effective execution timeout must be nonzero");
  run_segment_entry *s = &m->segments[m->num_segments - 1];
  s->effective_timeouts_known = 1;
  s->effective_exec_timeout_ms = exec_ms;
  s->effective_hang_timeout_ms = hang_ms;
  return 0;
}

int manifest_repair_torn_log(const char *path, char *err, size_t cap) {
  if (!path || !*path) return mf_error(err, cap, "Missing mutation log path");
  FILE *f = fopen(path, "r+b");
  if (!f) {
    if (errno == ENOENT) return 0;
    return mf_error(err, cap, "Cannot open mutation log: %s", strerror(errno));
  }
  struct stat st;
  int result = -1;
  if (fstat(fileno(f), &st) < 0 || !S_ISREG(st.st_mode) || fseeko(f, 0, SEEK_END) < 0) {
    mf_error(err, cap, "Cannot inspect mutation log");
    goto done;
  }
  off_t size = ftello(f);
  if (size < 0) { mf_error(err, cap, "Cannot determine mutation log size"); goto done; }
  if (!size) { result = 0; goto done; }
  char chunk[4096];
  off_t end = size, keep = 0;
  int found = 0;
  while (end > 0 && !found) {
    size_t amount = end > (off_t)sizeof(chunk) ? sizeof(chunk) : (size_t)end;
    off_t start = end - (off_t)amount;
    if (fseeko(f, start, SEEK_SET) < 0 || fread(chunk, 1, amount, f) != amount) {
      mf_error(err, cap, "Cannot read mutation log tail");
      goto done;
    }
    for (size_t i = amount; i > 0; i--) if (chunk[i - 1] == '\n') {
      keep = start + (off_t)i;
      found = 1;
      break;
    }
    end = start;
  }
  if (keep != size && ftruncate(fileno(f), keep) < 0) {
    mf_error(err, cap, "Cannot truncate incomplete mutation log tail: %s", strerror(errno));
    goto done;
  }
  result = 0;
 done:
  if (fclose(f) != 0 && result == 0) result = mf_error(err, cap, "Cannot close mutation log");
  return result;
}

void manifest_free(run_manifest *m) {
  if (!m) return;
  free(m->segments);
  free(m);
}
