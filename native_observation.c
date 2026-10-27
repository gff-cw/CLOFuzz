/* Passive, bounded validation of producer-declared dual-state observations.
 * No protocol transitions, target execution, generation or scheduling occurs. */
#include "native_inspect.h"
#include "native_json.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBS_MAX_EVENTS 10000u
#define OBS_MAX_CANDIDATES 64u
#define OBS_MAX_TEXT 256u

typedef struct {
  const nj_value *run, *session, *model;
  uint64_t epoch, last_index;
  int has_index;
  const char *current_status;
  const nj_value *current_candidates;
  const nj_value *last_confirmed_event, *last_prediction_event;
} obs_session;

typedef struct {
  const nj_value *run, *session;
  uint64_t last_epoch;
} obs_stream;

typedef struct { size_t session_index; const nj_value *id; } obs_marker;

typedef enum {
  OBS_ALIGNED = 0,
  OBS_TIMEOUT,
  OBS_PARTIAL,
  OBS_UNMATCHED,
  OBS_NO_PROTOCOL,
  OBS_PREDICTED,
  OBS_UNKNOWN,
  OBS_UNOBSERVED,
  OBS_INCONSISTENT,
  OBS_INCOMPLETE,
  OBS_MISSING_PAIR,
  OBS_NON_SNAPSHOT,
  OBS_UNALIGNED,
  OBS_REASON_COUNT
} obs_reason;

static const char *const reason_names[OBS_REASON_COUNT] = {
  "aligned", "timeout", "partial", "unmatched", "no_protocol_observation",
  "predicted", "unknown", "unobserved", "inconsistent",
  "incomplete_or_uncorrelated", "missing_memory_or_shared_boundary",
  "non_snapshot_memory", "unaligned_pending_or_unsynchronized"
};

typedef struct { const nj_value *event; size_t session_index; obs_reason reason; } obs_result;

typedef struct {
  nj_document *document;
  native_diagnostic *diagnostic;
  obs_session *sessions;
  obs_stream *streams;
  obs_marker *markers;
  obs_result *results;
  size_t *session_slots, *stream_slots, *marker_slots;
  size_t session_count, stream_count, marker_count, capacity;
  size_t reason_counts[OBS_REASON_COUNT];
} obs_context;

static int obs_fail(obs_context *context, const nj_value *value, const char *path,
                    const char *format, ...) {
  char message[512];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(message, sizeof(message), format, arguments);
  va_end(arguments);
  native_inspect_error(context->diagnostic, "invalid_observations", path,
                       value ? value->start : 0, "%s", message);
  return -1;
}

static int obs_keys(obs_context *context, const nj_value *value, const char *path,
                    const char *const *required, size_t required_count,
                    const char *const *optional, size_t optional_count) {
  char error[512];
  if (nj_keys(value, required, required_count, optional, optional_count,
               error, sizeof(error)) < 0)
    return obs_fail(context, value, path, "%s", error);
  return 0;
}

/* The JSON layer validates UTF-8. Count code points, not encoded bytes, and
 * reject the control characters excluded by the Python observation contract. */
static int obs_text(obs_context *context, const nj_value *value, const char *path) {
  size_t characters = 0, index;
  if (!value || value->type != NJ_STRING || !value->text_length)
    return obs_fail(context, value, path, "expected nonempty text");
  for (index = 0; index < value->text_length; index++) {
    unsigned char byte = (unsigned char)value->text[index];
    if (byte < 32)
      return obs_fail(context, value, path, "text contains a forbidden control character");
    if ((byte & 0xc0u) != 0x80u) characters++;
  }
  if (characters > OBS_MAX_TEXT)
    return obs_fail(context, value, path, "text exceeds 256 characters");
  return 0;
}

static int obs_equal(const nj_value *left, const nj_value *right) {
  return left && right && left->type == NJ_STRING && right->type == NJ_STRING &&
         left->text_length == right->text_length &&
         !memcmp(left->text, right->text, left->text_length);
}

static int obs_number(obs_context *context, const nj_value *value, uint64_t maximum,
                      const char *path, uint64_t *number) {
  char error[256];
  if (nj_u64(value, number, error, sizeof(error)) < 0)
    return obs_fail(context, value, path, "%s", error);
  if (*number > maximum)
    return obs_fail(context, value, path, "integer exceeds the permitted range");
  return 0;
}

static int obs_digest(obs_context *context, const nj_value *value, const char *path) {
  size_t index;
  if (!value || value->type != NJ_STRING || value->text_length != 64)
    return obs_fail(context, value, path, "expected a lowercase SHA256 digest");
  for (index = 0; index < value->text_length; index++) {
    unsigned char byte = (unsigned char)value->text[index];
    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')))
      return obs_fail(context, value, path, "expected a lowercase SHA256 digest");
  }
  return 0;
}

static int obs_enum(obs_context *context, const nj_value *value, const char *path,
                    const char *const *options, size_t count) {
  size_t index;
  for (index = 0; index < count; index++)
    if (nj_string_equal(value, options[index])) return 0;
  return obs_fail(context, value, path, "unsupported enum value");
}

static const nj_value *obs_optional(const nj_value *object, const char *name) {
  const nj_value *value = nj_get(object, name);
  return value && value->type != NJ_NULL ? value : NULL;
}

static uint64_t obs_hash_bytes(uint64_t hash, const unsigned char *bytes, size_t length) {
  size_t index;
  for (index = 0; index < length; index++) {
    hash ^= bytes[index];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static uint64_t obs_hash_text(uint64_t hash, const nj_value *text) {
  /* Include a length boundary so concatenated tuple members remain distinct. */
  unsigned char length[8];
  size_t index;
  for (index = 0; index < sizeof(length); index++)
    length[index] = (unsigned char)((uint64_t)text->text_length >> (index * 8));
  hash = obs_hash_bytes(hash, length, sizeof(length));
  return obs_hash_bytes(hash, (const unsigned char *)text->text, text->text_length);
}

static uint64_t obs_hash_number(uint64_t hash, uint64_t number) {
  unsigned char encoded[8];
  size_t index;
  for (index = 0; index < sizeof(encoded); index++)
    encoded[index] = (unsigned char)(number >> (index * 8));
  return obs_hash_bytes(hash, encoded, sizeof(encoded));
}

static int obs_stream_slot(obs_context *context, const nj_value *run,
                           const nj_value *session, size_t *slot, int *found) {
  uint64_t hash = obs_hash_text(UINT64_C(14695981039346656037), run);
  size_t attempts, position;
  hash = obs_hash_text(hash, session);
  position = (size_t)hash & (context->capacity - 1);
  for (attempts = 0; attempts < context->capacity; attempts++) {
    size_t entry = context->stream_slots[position];
    if (!entry) { *slot = position; *found = 0; return 0; }
    if (obs_equal(context->streams[entry - 1].run, run) &&
        obs_equal(context->streams[entry - 1].session, session)) {
      *slot = position; *found = 1; return 0;
    }
    position = (position + 1) & (context->capacity - 1);
  }
  return obs_fail(context, session, "/events", "stream table budget exceeded");
}

static int obs_session_slot(obs_context *context, const nj_value *run,
                            const nj_value *session, uint64_t epoch,
                            size_t *slot, int *found) {
  uint64_t hash = obs_hash_text(UINT64_C(14695981039346656037), run);
  size_t attempts, position;
  hash = obs_hash_number(obs_hash_text(hash, session), epoch);
  position = (size_t)hash & (context->capacity - 1);
  for (attempts = 0; attempts < context->capacity; attempts++) {
    size_t entry = context->session_slots[position];
    if (!entry) { *slot = position; *found = 0; return 0; }
    if (context->sessions[entry - 1].epoch == epoch &&
        obs_equal(context->sessions[entry - 1].run, run) &&
        obs_equal(context->sessions[entry - 1].session, session)) {
      *slot = position; *found = 1; return 0;
    }
    position = (position + 1) & (context->capacity - 1);
  }
  return obs_fail(context, session, "/events", "session table budget exceeded");
}

static int obs_add_marker(obs_context *context, size_t session_index,
                          const nj_value *id, const char *path) {
  uint64_t hash = obs_hash_number(UINT64_C(14695981039346656037), session_index);
  size_t attempts, position;
  hash = obs_hash_text(hash, id);
  position = (size_t)hash & (context->capacity - 1);
  for (attempts = 0; attempts < context->capacity; attempts++) {
    size_t entry = context->marker_slots[position];
    if (!entry) {
      obs_marker *marker = &context->markers[context->marker_count];
      marker->session_index = session_index;
      marker->id = id;
      context->marker_slots[position] = ++context->marker_count;
      return 0;
    }
    if (context->markers[entry - 1].session_index == session_index &&
        obs_equal(context->markers[entry - 1].id, id))
      return obs_fail(context, id, path, "observation_id reused within a session epoch");
    position = (position + 1) & (context->capacity - 1);
  }
  return obs_fail(context, id, path, "marker table budget exceeded");
}

static int obs_protocol(obs_context *context, const nj_value *protocol, const char *path) {
  static const char *const required[] = {"status", "states", "source", "correlation", "complete"};
  static const char *const optional[] = {"evidence_ref"};
  static const char *const statuses[] = {"observed", "ambiguous", "predicted", "unknown", "unobserved", "inconsistent"};
  static const char *const sources[] = {"matched_response", "local_observation", "prediction", "none"};
  static const char *const correlations[] = {"confirmed", "ambiguous", "missing"};
  const nj_value *status, *states, *source, *correlation, *evidence;
  size_t index, previous;
  int complete;
  char error[256];
  if (obs_keys(context, protocol, path, required, 5, optional, 1) < 0) return -1;
  status = nj_get(protocol, "status"); states = nj_get(protocol, "states");
  source = nj_get(protocol, "source"); correlation = nj_get(protocol, "correlation");
  evidence = nj_get(protocol, "evidence_ref");
  if (obs_enum(context, status, path, statuses, 6) < 0 ||
      obs_enum(context, source, path, sources, 4) < 0 ||
      obs_enum(context, correlation, path, correlations, 3) < 0) return -1;
  if (!states || states->type != NJ_ARRAY || states->count > OBS_MAX_CANDIDATES)
    return obs_fail(context, states, path, "states must contain at most 64 names");
  for (index = 0; index < states->count; index++) {
    if (obs_text(context, states->items[index], path) < 0) return -1;
    for (previous = 0; previous < index; previous++)
      if (obs_equal(states->items[index], states->items[previous]))
        return obs_fail(context, states->items[index], path, "duplicate protocol state");
  }
  if (nj_boolean(nj_get(protocol, "complete"), &complete, error, sizeof(error)) < 0)
    return obs_fail(context, nj_get(protocol, "complete"), path, "%s", error);
  if (nj_string_equal(status, "observed")) {
    if (states->count != 1) return obs_fail(context, states, path, "observed requires one state");
  } else if (nj_string_equal(status, "ambiguous")) {
    if (states->count < 2) return obs_fail(context, states, path, "ambiguous requires at least two candidates");
  } else if (nj_string_equal(status, "predicted")) {
    if (!states->count || !nj_string_equal(source, "prediction"))
      return obs_fail(context, protocol, path, "predicted requires candidates and prediction provenance");
  } else if (nj_string_equal(status, "inconsistent")) {
    if (states->count || !complete || !nj_string_equal(correlation, "confirmed") ||
        !(nj_string_equal(source, "matched_response") || nj_string_equal(source, "local_observation")))
      return obs_fail(context, protocol, path, "inconsistent requires empty candidates and complete correlated observation evidence");
  } else if (states->count || !nj_string_equal(source, "none")) {
    return obs_fail(context, protocol, path, "unknown/unobserved cannot assert candidates or observation provenance");
  }
  if ((nj_string_equal(status, "observed") || nj_string_equal(status, "ambiguous")) &&
      !(nj_string_equal(source, "matched_response") || nj_string_equal(source, "local_observation")))
    return obs_fail(context, source, path, "observed states require actual observation provenance");
  if (!nj_string_equal(status, "unknown") && !nj_string_equal(status, "unobserved")) {
    if (obs_text(context, evidence, path) < 0) return -1;
  } else if (evidence && obs_text(context, evidence, path) < 0) return -1;
  return 0;
}

static int obs_memory(obs_context *context, const nj_value *memory, const char *path) {
  static const char *const required[] = {"namespace", "calibration_epoch", "library_revision", "state_id", "source", "status"};
  static const char *const statuses[] = {"snapshot_label", "synthetic"};
  uint64_t number;
  if (obs_keys(context, memory, path, required, 6, NULL, 0) < 0) return -1;
  if (obs_text(context, nj_get(memory, "namespace"), path) < 0 ||
      obs_text(context, nj_get(memory, "library_revision"), path) < 0 ||
      obs_text(context, nj_get(memory, "source"), path) < 0 ||
      obs_enum(context, nj_get(memory, "status"), path, statuses, 2) < 0 ||
      obs_number(context, nj_get(memory, "calibration_epoch"), INT64_MAX, path, &number) < 0 ||
      obs_number(context, nj_get(memory, "state_id"), UINT32_MAX, path, &number) < 0) return -1;
  return 0;
}

static int obs_boundary(obs_context *context, const nj_value *boundary,
                        size_t session_index, const char *path) {
  static const char *const required[] = {"observation_id", "alignment", "phase", "synchronization", "source"};
  static const char *const alignments[] = {"shared_marker", "unaligned"};
  static const char *const phases[] = {"completed", "quiescent", "pending"};
  static const char *const synchronization[] = {"quiescent", "atomic_snapshot", "unknown"};
  const nj_value *id;
  if (obs_keys(context, boundary, path, required, 5, NULL, 0) < 0) return -1;
  id = nj_get(boundary, "observation_id");
  if (obs_text(context, id, path) < 0 || obs_text(context, nj_get(boundary, "source"), path) < 0 ||
      obs_enum(context, nj_get(boundary, "alignment"), path, alignments, 2) < 0 ||
      obs_enum(context, nj_get(boundary, "phase"), path, phases, 3) < 0 ||
      obs_enum(context, nj_get(boundary, "synchronization"), path, synchronization, 3) < 0) return -1;
  return obs_add_marker(context, session_index, id, path);
}

static obs_reason obs_classify(obs_session *session, const nj_value *event,
                               const nj_value *protocol, const nj_value *memory,
                               const nj_value *boundary) {
  const nj_value *kind = nj_get(event, "kind"), *status;
  session->current_status = "unknown";
  session->current_candidates = NULL;
  if (nj_string_equal(kind, "timeout")) return OBS_TIMEOUT;
  if (nj_string_equal(kind, "partial")) return OBS_PARTIAL;
  if (nj_string_equal(kind, "unmatched")) return OBS_UNMATCHED;
  if (!protocol) return OBS_NO_PROTOCOL;
  status = nj_get(protocol, "status");
  if (nj_string_equal(status, "predicted")) {
    session->last_prediction_event = event;
    return OBS_PREDICTED;
  }
  if (nj_string_equal(status, "unknown")) return OBS_UNKNOWN;
  if (nj_string_equal(status, "unobserved")) {
    session->current_status = "unobserved"; return OBS_UNOBSERVED;
  }
  if (nj_string_equal(status, "inconsistent")) {
    session->current_status = "inconsistent"; return OBS_INCONSISTENT;
  }
  if (!nj_get(protocol, "complete")->boolean ||
      !nj_string_equal(nj_get(protocol, "correlation"), "confirmed")) return OBS_INCOMPLETE;
  session->current_status = nj_string_equal(status, "observed") ? "observed" : "ambiguous";
  session->current_candidates = nj_get(protocol, "states");
  if (nj_string_equal(status, "observed")) session->last_confirmed_event = event;
  if (!memory || !boundary) return OBS_MISSING_PAIR;
  if (!nj_string_equal(nj_get(memory, "status"), "snapshot_label") ||
      !nj_get(memory, "state_id")->number.magnitude) return OBS_NON_SNAPSHOT;
  if (!nj_string_equal(nj_get(boundary, "alignment"), "shared_marker") ||
      !(nj_string_equal(nj_get(boundary, "phase"), "completed") ||
        nj_string_equal(nj_get(boundary, "phase"), "quiescent")) ||
      nj_string_equal(nj_get(boundary, "synchronization"), "unknown")) return OBS_UNALIGNED;
  return OBS_ALIGNED;
}

static int obs_event(obs_context *context, const nj_value *event, size_t event_number) {
  static const char *const required[] = {"run_id", "session_id", "session_epoch", "event_index", "model_sha256", "kind"};
  static const char *const optional[] = {"protocol", "memory", "boundary", "reset_evidence"};
  static const char *const kinds[] = {"session_start", "reset", "observation", "timeout", "partial", "unmatched"};
  const nj_value *run, *session_id, *model, *kind, *protocol, *memory, *boundary;
  uint64_t epoch, index;
  size_t stream_slot, session_slot, session_index;
  int stream_found, session_found, starts;
  obs_session *session;
  obs_stream *stream;
  char path[80];
  snprintf(path, sizeof(path), "/events/%zu", event_number);
  if (obs_keys(context, event, path, required, 6, optional, 4) < 0) return -1;
  run = nj_get(event, "run_id"); session_id = nj_get(event, "session_id");
  model = nj_get(event, "model_sha256"); kind = nj_get(event, "kind");
  if (obs_text(context, run, path) < 0 || obs_text(context, session_id, path) < 0 ||
      obs_digest(context, model, path) < 0 || obs_enum(context, kind, path, kinds, 6) < 0 ||
      obs_number(context, nj_get(event, "session_epoch"), INT64_MAX, path, &epoch) < 0 ||
      obs_number(context, nj_get(event, "event_index"), INT64_MAX, path, &index) < 0) return -1;
  if (obs_stream_slot(context, run, session_id, &stream_slot, &stream_found) < 0 ||
      obs_session_slot(context, run, session_id, epoch, &session_slot, &session_found) < 0) return -1;
  stream = stream_found ? &context->streams[context->stream_slots[stream_slot] - 1] : NULL;
  if (stream && epoch < stream->last_epoch)
    return obs_fail(context, event, path, "stale session epoch or out-of-order stream");
  starts = nj_string_equal(kind, "session_start") || nj_string_equal(kind, "reset");
  if (!session_found) {
    if (!starts) return obs_fail(context, event, path, "new session epoch requires an explicit start/reset marker");
    session_index = context->session_count++;
    context->session_slots[session_slot] = session_index + 1;
    session = &context->sessions[session_index];
    session->run = run; session->session = session_id; session->epoch = epoch;
    session->model = model; session->current_status = "unknown";
  } else {
    if (starts) return obs_fail(context, event, path, "start/reset must create a fresh session epoch");
    session_index = context->session_slots[session_slot] - 1;
    session = &context->sessions[session_index];
  }
  if (!obs_equal(session->model, model))
    return obs_fail(context, model, path, "model changed inside a session epoch");
  if (session->has_index && index <= session->last_index)
    return obs_fail(context, event, path, "event_index must increase strictly within a session epoch");
  session->last_index = index; session->has_index = 1;
  if (!stream_found) {
    stream = &context->streams[context->stream_count++];
    stream->run = run; stream->session = session_id;
    context->stream_slots[stream_slot] = context->stream_count;
  }
  stream->last_epoch = epoch;
  if (nj_string_equal(kind, "reset")) {
    if (!nj_string_equal(nj_get(event, "reset_evidence"), "confirmed"))
      return obs_fail(context, event, path, "reset requires explicitly confirmed reset evidence");
  } else if (nj_get(event, "reset_evidence")) {
    return obs_fail(context, event, path, "reset_evidence is only valid on reset events");
  }
  protocol = obs_optional(event, "protocol"); memory = obs_optional(event, "memory");
  boundary = obs_optional(event, "boundary");
  if ((protocol && obs_protocol(context, protocol, path) < 0) ||
      (memory && obs_memory(context, memory, path) < 0) ||
      (boundary && obs_boundary(context, boundary, session_index, path) < 0)) return -1;
  context->results[event_number].event = event;
  context->results[event_number].session_index = session_index;
  context->results[event_number].reason = obs_classify(session, event, protocol, memory, boundary);
  context->reason_counts[context->results[event_number].reason]++;
  return 0;
}

static void obs_value(FILE *out, const nj_document *document, const nj_value *value) {
  if (value) (void)nj_write_value(out, document, value);
  else fputs("null", out);
}

static void obs_member(FILE *out, const nj_document *document, const char *key,
                       const nj_value *value, int comma) {
  if (comma) fputc(',', out);
  nj_write_string(out, key, strlen(key)); fputc(':', out);
  obs_value(out, document, value);
}

static void obs_historical(FILE *out, const nj_document *document,
                           const nj_value *event, int prediction) {
  const nj_value *protocol;
  if (!event) { fputs("null", out); return; }
  protocol = nj_get(event, "protocol");
  fputc('{', out);
  if (prediction) obs_member(out, document, "states", nj_get(protocol, "states"), 0);
  else obs_member(out, document, "state", nj_get(protocol, "states")->items[0], 0);
  obs_member(out, document, "event_index", nj_get(event, "event_index"), 1);
  obs_member(out, document, "source", nj_get(protocol, "source"), 1);
  obs_member(out, document, "evidence_ref", nj_get(protocol, "evidence_ref"), 1);
  fputc('}', out);
}

static void obs_report(FILE *out, obs_context *context, size_t event_count) {
  size_t index;
  int comma;
  const nj_document *document = context->document;
  fputs("{\"format\":\"stateafl.native-state-observations\",\"version\":1,", out);
  fprintf(out, "\"events\":%zu,\"session_count\":%zu,\"aligned_observation_count\":%zu,",
          event_count, context->session_count, context->reason_counts[OBS_ALIGNED]);
  fputs("\"relations_aggregated\":false,\"aligned_observations\":[", out);
  comma = 0;
  for (index = 0; index < event_count; index++) {
    const nj_value *event = context->results[index].event, *protocol;
    if (context->results[index].reason != OBS_ALIGNED) continue;
    if (comma) fputc(',', out);
    comma = 1; protocol = nj_get(event, "protocol"); fputc('{', out);
    obs_member(out, document, "run_id", nj_get(event, "run_id"), 0);
    obs_member(out, document, "session_id", nj_get(event, "session_id"), 1);
    obs_member(out, document, "session_epoch", nj_get(event, "session_epoch"), 1);
    obs_member(out, document, "event_index", nj_get(event, "event_index"), 1);
    obs_member(out, document, "model_sha256", nj_get(event, "model_sha256"), 1);
    obs_member(out, document, "protocol_states", nj_get(protocol, "states"), 1);
    obs_member(out, document, "certainty", nj_get(protocol, "status"), 1);
    obs_member(out, document, "protocol_evidence_ref", nj_get(protocol, "evidence_ref"), 1);
    /* These provenance objects together with run/session/model form the full partition. */
    obs_member(out, document, "memory", nj_get(event, "memory"), 1);
    obs_member(out, document, "boundary", nj_get(event, "boundary"), 1);
    obs_member(out, document, "source_event", event, 1);
    fputc('}', out);
  }
  fputs("],\"sessions\":[", out);
  for (index = 0; index < context->session_count; index++) {
    obs_session *session = &context->sessions[index];
    if (index) fputc(',', out);
    fputc('{', out);
    obs_member(out, document, "run_id", session->run, 0);
    obs_member(out, document, "session_id", session->session, 1);
    fprintf(out, ",\"session_epoch\":%" PRIu64 ",\"last_event_index\":%" PRIu64,
            session->epoch, session->last_index);
    obs_member(out, document, "model_sha256", session->model, 1);
    fputs(",\"current_status\":", out);
    nj_write_string(out, session->current_status, strlen(session->current_status));
    fputs(",\"current_candidates\":", out);
    if (session->current_candidates) obs_value(out, document, session->current_candidates);
    else fputs("[]", out);
    fputs(",\"last_confirmed\":", out);
    obs_historical(out, document, session->last_confirmed_event, 0);
    fputs(",\"last_prediction\":", out);
    obs_historical(out, document, session->last_prediction_event, 1);
    fputc('}', out);
  }
  fputs("],\"skipped\":{", out);
  comma = 0;
  for (index = 1; index < OBS_REASON_COUNT; index++) {
    if (!context->reason_counts[index]) continue;
    if (comma) fputc(',', out);
    comma = 1;
    nj_write_string(out, reason_names[index], strlen(reason_names[index]));
    fprintf(out, ":%zu", context->reason_counts[index]);
  }
  fputs("},\"unpaired_observations\":[", out);
  comma = 0;
  for (index = 0; index < event_count; index++) {
    obs_result *result = &context->results[index];
    if (result->reason == OBS_ALIGNED) continue;
    if (comma) fputc(',', out);
    comma = 1;
    fputs("{\"reason\":", out);
    nj_write_string(out, reason_names[result->reason], strlen(reason_names[result->reason]));
    obs_member(out, document, "event", result->event, 1);
    fputc('}', out);
  }
  fputs("],\"limits\":["
        "\"Markers, identities, synchronization and provenance are producer declarations, not independently verified facts.\","
        "\"Each aligned row is one declared observation; rows are not aggregated probabilities or inferred transitions.\","
        "\"Ambiguous candidate sets remain grouped and are not separate confirmed state pairs.\","
        "\"No protocol or memory state IDs, TLSH data, target execution or scheduling are modified.\","
        "\"Legacy arrays do not establish shared observation boundaries.\"]}\n", out);
}

int native_observation_inspect(const char *input_path, FILE *out,
                               native_diagnostic *diagnostic) {
  static const char *const root_keys[] = {"format", "version", "events"};
  obs_context context;
  const nj_value *events;
  uint64_t version;
  size_t count, index, allocation_count;
  char error[512];
  int result = 2;
  memset(&context, 0, sizeof(context));
  if (diagnostic) memset(diagnostic, 0, sizeof(*diagnostic));
  context.diagnostic = diagnostic;
  if (!input_path || !out || !diagnostic) {
    native_inspect_error(diagnostic, "input_error", "", 0, "input path, output stream and diagnostic are required");
    return 2;
  }
  if (nj_load_file(input_path, &context.document, error, sizeof(error)) < 0) {
    native_inspect_error(diagnostic, "input_error", "", 0, "%s", error);
    return 2;
  }
  if (obs_keys(&context, context.document->root, "", root_keys, 3, NULL, 0) < 0) goto done;
  if (!nj_string_equal(nj_get(context.document->root, "format"), "stateafl.offline-observations")) {
    obs_fail(&context, context.document->root, "/format", "unsupported observation format"); goto done;
  }
  if (obs_number(&context, nj_get(context.document->root, "version"), INT64_MAX,
                  "/version", &version) < 0) goto done;
  if (version != 1) { obs_fail(&context, context.document->root, "/version", "unsupported observation version"); goto done; }
  events = nj_get(context.document->root, "events");
  if (!events || events->type != NJ_ARRAY || events->count > OBS_MAX_EVENTS) {
    obs_fail(&context, events, "/events", "events must contain at most 10000 entries"); goto done;
  }
  count = events->count;
  allocation_count = count ? count : 1;
  context.capacity = 2;
  while (context.capacity < allocation_count * 2) context.capacity <<= 1;
  context.sessions = calloc(allocation_count, sizeof(*context.sessions));
  context.streams = calloc(allocation_count, sizeof(*context.streams));
  context.markers = calloc(allocation_count, sizeof(*context.markers));
  context.results = calloc(allocation_count, sizeof(*context.results));
  context.session_slots = calloc(context.capacity, sizeof(*context.session_slots));
  context.stream_slots = calloc(context.capacity, sizeof(*context.stream_slots));
  context.marker_slots = calloc(context.capacity, sizeof(*context.marker_slots));
  if (!context.sessions || !context.streams || !context.markers || !context.results ||
      !context.session_slots || !context.stream_slots || !context.marker_slots) {
    native_inspect_error(diagnostic, "resource_limit", "/events", 0, "cannot allocate bounded observation tables");
    goto done;
  }
  for (index = 0; index < count; index++)
    if (obs_event(&context, events->items[index], index) < 0) goto done;
  /* No externally visible report is emitted before all events pass validation. */
  obs_report(out, &context, count);
  if (ferror(out)) {
    native_inspect_error(diagnostic, "report_io_error", "", 0, "failed to write the observation report");
    goto done;
  }
  result = 0;
done:
  free(context.sessions); free(context.streams); free(context.markers); free(context.results);
  free(context.session_slots); free(context.stream_slots); free(context.marker_slots);
  nj_free(context.document);
  return result;
}
