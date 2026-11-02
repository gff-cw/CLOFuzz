#define _POSIX_C_SOURCE 200809L
#include "run_manifest.h"
#include "native_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>

#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME        0x100000001b3ULL

uint64_t manifest_hash_file(const char *path) {
  if (!path || !*path) return 0;
  const char *colon = strchr(path, ':');
  if (colon) {
    char p1[512], p2[512];
    size_t l1 = (size_t)(colon - path);
    if (l1 >= sizeof(p1)) l1 = sizeof(p1) - 1;
    memcpy(p1, path, l1); p1[l1] = 0;
    snprintf(p2, sizeof(p2), "%s", colon + 1);
    uint64_t h1 = manifest_hash_file(p1);
    uint64_t h2 = manifest_hash_file(p2);
    return (h1 ^ h2) * FNV_PRIME;
  }
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  uint64_t hash = FNV_OFFSET_BASIS;
  unsigned char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    for (size_t i = 0; i < n; i++) {
      hash ^= buf[i];
      hash *= FNV_PRIME;
    }
  }
  fclose(f);
  return hash;
}

static uint64_t get_time_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
}

void manifest_write_escaped_json_string(FILE *f, const char *s) {
  fputc('"', f);
  if (s) {
    for (const char *p = s; *p; p++) {
      if (*p == '"') fputs("\\\"", f);
      else if (*p == '\\') fputs("\\\\", f);
      else if (*p == '\b') fputs("\\b", f);
      else if (*p == '\f') fputs("\\f", f);
      else if (*p == '\n') fputs("\\n", f);
      else if (*p == '\r') fputs("\\r", f);
      else if (*p == '\t') fputs("\\t", f);
      else if ((unsigned char)*p < 0x20) fprintf(f, "\\u%04x", (unsigned char)*p);
      else fputc(*p, f);
    }
  }
  fputc('"', f);
}

uint32_t scan_max_candidate_id(const char *out_dir) {
  char cand_dir[512];
  snprintf(cand_dir, sizeof(cand_dir), "%s/protocol-candidates", out_dir);
  DIR *d = opendir(cand_dir);
  if (!d) return 0;

  int found_any = 0;
  uint32_t max_id = 0;
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.') continue;
    char *end = NULL;
    unsigned long val = strtoul(de->d_name, &end, 10);
    if (end && end != de->d_name && (*end == '.' || *end == '_')) {
      if (!found_any || (uint32_t)val > max_id) {
        max_id = (uint32_t)val;
      }
      found_any = 1;
    }
  }
  closedir(d);
  return found_any ? (max_id + 1) : 0;
}

int manifest_repair_torn_log(const char *log_path, char *err, size_t err_cap) {
  if (!log_path || !*log_path) return 0;
  FILE *f = fopen(log_path, "r+b");
  if (!f) {
    if (errno == ENOENT) return 0; /* No log yet */
    if (err && err_cap) snprintf(err, err_cap, "Failed to open log '%s': %s", log_path, strerror(errno));
    return -1;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  long sz = ftell(f);
  if (sz <= 0) {
    fclose(f);
    return 0;
  }

  /* Check last byte */
  if (fseek(f, sz - 1, SEEK_SET) != 0) {
    fclose(f);
    return 0;
  }
  int last_ch = fgetc(f);
  if (last_ch == '\n') {
    fclose(f);
    return 0; /* Log ends cleanly with newline */
  }

  /* File does not end in '\n', find previous '\n' */
  long last_newline = -1;
  long pos = sz - 1;
  while (pos >= 0) {
    if (fseek(f, pos, SEEK_SET) != 0) break;
    int c = fgetc(f);
    if (c == '\n') {
      last_newline = pos;
      break;
    }
    pos--;
  }

  int fd = fileno(f);
  if (last_newline >= 0) {
    if (ftruncate(fd, last_newline + 1) != 0) {
      if (err && err_cap) snprintf(err, err_cap, "ftruncate failed on '%s': %s", log_path, strerror(errno));
      fclose(f);
      return -1;
    }
  } else {
    /* No newline found at all in the file - truncate to 0 */
    if (ftruncate(fd, 0) != 0) {
      if (err && err_cap) snprintf(err, err_cap, "ftruncate to 0 failed on '%s': %s", log_path, strerror(errno));
      fclose(f);
      return -1;
    }
  }

  fclose(f);
  return 0;
}

int manifest_save_atomic(const run_manifest *m,
                         const char *out_dir,
                         char *err,
                         size_t err_cap) {
  if (!m || !out_dir) {
    if (err && err_cap) snprintf(err, err_cap, "Invalid arguments to manifest_save_atomic");
    return -1;
  }

  char tmp_path[512], final_path[512];
  snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%d", out_dir, MANIFEST_FILENAME, (int)getpid());
  snprintf(final_path, sizeof(final_path), "%s/%s", out_dir, MANIFEST_FILENAME);

  FILE *f = fopen(tmp_path, "w");
  if (!f) {
    if (err && err_cap) snprintf(err, err_cap, "Failed to create temp manifest '%s': %s", tmp_path, strerror(errno));
    return -1;
  }

  fprintf(f, "{\n"
             "  \"manifest_version\": %u,\n"
             "  \"run_id\": ",
          m->manifest_version);
  manifest_write_escaped_json_string(f, m->run_id);
  fprintf(f, ",\n  \"protocol\": ");
  manifest_write_escaped_json_string(f, m->protocol);
  fprintf(f, ",\n  \"spec_path\": ");
  manifest_write_escaped_json_string(f, m->spec_path);
  fprintf(f, ",\n  \"spec_hash\": %" PRIu64 ",\n"
             "  \"random_seed\": %u,\n"
             "  \"mutation_mode\": ",
          m->spec_hash,
          m->random_seed);
  manifest_write_escaped_json_string(f, m->mutation_mode);
  fprintf(f, ",\n  \"current_segment_id\": %u,\n"
             "  \"segments\": [\n",
          m->current_segment_id);

  for (uint32_t i = 0; i < m->num_segments; i++) {
    const run_segment_entry *s = &m->segments[i];
    fprintf(f, "    {\n"
               "      \"segment_id\": %u,\n"
               "      \"parent_segment_id\": %d,\n"
               "      \"start_time_ms\": %" PRIu64 ",\n"
               "      \"learning_state\": ",
            s->segment_id,
            s->parent_segment_id,
            s->start_time_ms);
    manifest_write_escaped_json_string(f, s->learning_state);
    fprintf(f, ",\n      \"reset_reason\": ");
    manifest_write_escaped_json_string(f, s->reset_reason);
    fprintf(f, ",\n      \"candidate_id_start\": %u,\n"
               "      \"candidates_saved\": %u\n"
               "    }%s\n",
            s->candidate_id_start,
            s->candidates_saved,
            (i + 1 < m->num_segments) ? "," : "");
  }

  fprintf(f, "  ]\n}\n");

  if (fflush(f) != 0 || fclose(f) != 0) {
    if (err && err_cap) snprintf(err, err_cap, "Failed to flush/close temp manifest '%s'", tmp_path);
    unlink(tmp_path);
    return -1;
  }

  if (rename(tmp_path, final_path) != 0) {
    if (err && err_cap) snprintf(err, err_cap, "Failed to atomically rename manifest '%s' -> '%s': %s",
                                 tmp_path, final_path, strerror(errno));
    unlink(tmp_path);
    return -1;
  }

  return 0;
}

int manifest_init_or_resume(const char *out_dir,
                            const char *protocol,
                            const char *spec_path,
                            const char *mutation_mode,
                            uint32_t random_seed,
                            run_manifest **out_manifest,
                            char *err,
                            size_t err_cap) {
  if (!out_dir || !out_manifest) {
    if (err && err_cap) snprintf(err, err_cap, "Invalid arguments to manifest_init_or_resume");
    return -1;
  }

  *out_manifest = NULL;
  char manifest_path[512];
  snprintf(manifest_path, sizeof(manifest_path), "%s/%s", out_dir, MANIFEST_FILENAME);

  uint64_t current_spec_hash = manifest_hash_file(spec_path);
  const char *use_proto = protocol ? protocol : "unknown";
  const char *use_mode = mutation_mode ? mutation_mode : "default";

  run_manifest *m = calloc(1, sizeof(run_manifest));
  if (!m) {
    if (err && err_cap) snprintf(err, err_cap, "Out of memory allocating run_manifest");
    return -1;
  }

  m->max_segments = 16;
  m->segments = calloc(m->max_segments, sizeof(run_segment_entry));
  if (!m->segments) {
    free(m);
    if (err && err_cap) snprintf(err, err_cap, "Out of memory allocating run_manifest segments");
    return -1;
  }

  nj_document *doc = NULL;
  if (access(manifest_path, F_OK) == 0) {
    /* Manifest exists - validate attribution! */
    char parse_err[256];
    if (nj_load_file(manifest_path, &doc, parse_err, sizeof(parse_err)) < 0) {
      if (err && err_cap) snprintf(err, err_cap, "Failed to load existing run manifest '%s': %s", manifest_path, parse_err);
      manifest_free(m);
      return -1;
    }

    const nj_value *v_ver = nj_get(doc->root, "manifest_version");
    if (!v_ver || v_ver->number.magnitude != MANIFEST_VERSION) {
      if (err && err_cap) snprintf(err, err_cap,
        "Attribution conflict: manifest version mismatch (found=%" PRIu64 ", expected=%u)",
        v_ver ? v_ver->number.magnitude : 0, MANIFEST_VERSION);
      nj_free(doc);
      manifest_free(m);
      return -1;
    }

    const nj_value *v_proto = nj_get(doc->root, "protocol");
    if (v_proto && v_proto->text && strcmp(use_proto, "unknown") != 0 && strcmp(v_proto->text, "unknown") != 0) {
      if (strcmp(v_proto->text, use_proto) != 0) {
        if (err && err_cap) snprintf(err, err_cap,
          "Attribution conflict: existing manifest in '%s' belongs to protocol '%s', but current is '%s'",
          out_dir, v_proto->text, use_proto);
        nj_free(doc);
        manifest_free(m);
        return -1;
      }
    }

    const nj_value *v_mode = nj_get(doc->root, "mutation_mode");
    if (v_mode && v_mode->text && strcmp(use_mode, "default") != 0 && strcmp(v_mode->text, "default") != 0) {
      if (strcmp(v_mode->text, use_mode) != 0) {
        if (err && err_cap) snprintf(err, err_cap,
          "Attribution conflict: existing manifest in '%s' was run with mutation_mode '%s', but current is '%s'",
          out_dir, v_mode->text, use_mode);
        nj_free(doc);
        manifest_free(m);
        return -1;
      }
    }

    const nj_value *v_hash = nj_get(doc->root, "spec_hash");
    if (v_hash && current_spec_hash != 0 && v_hash->number.magnitude != 0) {
      if (v_hash->number.magnitude != current_spec_hash) {
        if (err && err_cap) snprintf(err, err_cap,
          "Attribution conflict: spec content hash mismatch (existing=%" PRIu64 ", current=%" PRIu64 ")",
          v_hash->number.magnitude, current_spec_hash);
        nj_free(doc);
        manifest_free(m);
        return -1;
      }
    }

    /* Attribution verified! Parse existing manifest fields */
    const nj_value *v_run_id = nj_get(doc->root, "run_id");
    if (v_run_id && v_run_id->text) snprintf(m->run_id, sizeof(m->run_id), "%s", v_run_id->text);
    else snprintf(m->run_id, sizeof(m->run_id), "run_%016" PRIx64, get_time_ms());

    m->manifest_version = MANIFEST_VERSION;
    snprintf(m->protocol, sizeof(m->protocol), "%s", use_proto);
    if (spec_path) snprintf(m->spec_path, sizeof(m->spec_path), "%s", spec_path);
    m->spec_hash = current_spec_hash;
    m->random_seed = random_seed;
    snprintf(m->mutation_mode, sizeof(m->mutation_mode), "%s", use_mode);

    /* Read existing segments */
    const nj_value *v_segs = nj_get(doc->root, "segments");
    uint32_t prev_seg_id = 0;
    if (v_segs && v_segs->type == NJ_ARRAY) {
      for (size_t i = 0; i < v_segs->count; i++) {
        if (m->num_segments >= m->max_segments) {
          m->max_segments *= 2;
          m->segments = realloc(m->segments, m->max_segments * sizeof(run_segment_entry));
        }
        const nj_value *item = v_segs->items[i];
        run_segment_entry *s = &m->segments[m->num_segments++];
        memset(s, 0, sizeof(*s));

        const nj_value *v = nj_get(item, "segment_id");
        if (v) s->segment_id = (uint32_t)v->number.magnitude;
        v = nj_get(item, "parent_segment_id");
        if (v) s->parent_segment_id = v->number.negative ? -(int32_t)v->number.magnitude : (int32_t)v->number.magnitude;
        v = nj_get(item, "start_time_ms");
        if (v) s->start_time_ms = v->number.magnitude;
        v = nj_get(item, "learning_state");
        if (v && v->text) snprintf(s->learning_state, sizeof(s->learning_state), "%s", v->text);
        v = nj_get(item, "reset_reason");
        if (v && v->text) snprintf(s->reset_reason, sizeof(s->reset_reason), "%s", v->text);
        v = nj_get(item, "candidate_id_start");
        if (v) s->candidate_id_start = (uint32_t)v->number.magnitude;
        v = nj_get(item, "candidates_saved");
        if (v) s->candidates_saved = (uint32_t)v->number.magnitude;

        if (s->segment_id >= prev_seg_id) prev_seg_id = s->segment_id;
      }
    }
    nj_free(doc);

    /* Determine next segment ID and non-colliding candidate start ID */
    uint32_t next_seg_id = m->num_segments > 0 ? (prev_seg_id + 1) : 1;
    uint32_t cand_start = scan_max_candidate_id(out_dir);
    if (m->num_segments > 0) {
      uint32_t last_end = m->segments[m->num_segments - 1].candidate_id_start +
                          m->segments[m->num_segments - 1].candidates_saved;
      if (last_end > cand_start) cand_start = last_end;
    }

    if (m->num_segments >= m->max_segments) {
      m->max_segments *= 2;
      m->segments = realloc(m->segments, m->max_segments * sizeof(run_segment_entry));
    }
    run_segment_entry *new_seg = &m->segments[m->num_segments++];
    memset(new_seg, 0, sizeof(*new_seg));
    new_seg->segment_id = next_seg_id;
    new_seg->parent_segment_id = (int32_t)prev_seg_id;
    new_seg->start_time_ms = get_time_ms();
    snprintf(new_seg->learning_state, sizeof(new_seg->learning_state), "reset");
    snprintf(new_seg->reset_reason, sizeof(new_seg->reset_reason), "cold_start_resumption");
    new_seg->candidate_id_start = cand_start;
    new_seg->candidates_saved = 0;

    m->current_segment_id = next_seg_id;
  } else {
    /* Brand new run */
    m->manifest_version = MANIFEST_VERSION;
    snprintf(m->run_id, sizeof(m->run_id), "run_%016" PRIx64, get_time_ms());
    snprintf(m->protocol, sizeof(m->protocol), "%s", use_proto);
    if (spec_path) snprintf(m->spec_path, sizeof(m->spec_path), "%s", spec_path);
    m->spec_hash = current_spec_hash;
    m->random_seed = random_seed;
    snprintf(m->mutation_mode, sizeof(m->mutation_mode), "%s", use_mode);
    m->current_segment_id = 0;

    run_segment_entry *seg0 = &m->segments[0];
    memset(seg0, 0, sizeof(*seg0));
    seg0->segment_id = 0;
    seg0->parent_segment_id = -1;
    seg0->start_time_ms = get_time_ms();
    snprintf(seg0->learning_state, sizeof(seg0->learning_state), "reset");
    snprintf(seg0->reset_reason, sizeof(seg0->reset_reason), "initial_start");
    seg0->candidate_id_start = scan_max_candidate_id(out_dir);
    seg0->candidates_saved = 0;
    m->num_segments = 1;
  }

  /* Atomically save manifest to disk */
  if (manifest_save_atomic(m, out_dir, err, err_cap) < 0) {
    manifest_free(m);
    return -1;
  }

  *out_manifest = m;
  return 0;
}

void manifest_free(run_manifest *m) {
  if (!m) return;
  if (m->segments) free(m->segments);
  free(m);
}
