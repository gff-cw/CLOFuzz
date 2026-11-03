/*
   execution_observation.h - Immutable Execution Observation and Verification
   --------------------------------------------------------------------------

   Defines execution observation records and verification comparisons to ensure
   that original coverage executions and confirmation replay executions maintain
   strictly isolated observation lifecycles (P05).
*/

#ifndef _HAVE_EXECUTION_OBSERVATION_H
#define _HAVE_EXECUTION_OBSERVATION_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "types.h"
#include "llvm_mode/state-tracer.h"

/* Execution purposes */
#define EXEC_PURPOSE_UNKNOWN        0
#define EXEC_PURPOSE_ORIGINAL       1
#define EXEC_PURPOSE_CONFIRMATION   2
#define EXEC_PURPOSE_CALIBRATION    3
#define EXEC_PURPOSE_SYNC           4
#define EXEC_PURPOSE_STATE_ANALYSIS 5
#define EXEC_PURPOSE_HANG_CHECK     6
#define EXEC_PURPOSE_COUNT          7

static inline const char *exec_purpose_to_str(u8 purpose) {
  switch (purpose) {
    case EXEC_PURPOSE_ORIGINAL:       return "coverage";
    case EXEC_PURPOSE_CONFIRMATION:   return "confirmation";
    case EXEC_PURPOSE_CALIBRATION:    return "calibration";
    case EXEC_PURPOSE_SYNC:           return "sync";
    case EXEC_PURPOSE_STATE_ANALYSIS: return "state_analysis";
    case EXEC_PURPOSE_HANG_CHECK:     return "hang_check";
    default:                          return "unknown";
  }
}

/* State observation providers */
#define STATE_OBS_PROVIDER_NONE   0
#define STATE_OBS_PROVIDER_TRACER 1
#define STATE_OBS_PROVIDER_CODES  2

/* Submitted bytes are owned by an execution, never by the reusable seed. */
typedef struct {
  u8 *data;
  u32 size;
  u32 planned_size;
} execution_wire_record_t;

typedef struct {
  u32 exec_id;                  /* Execution identifier */
  u8  exec_purpose;             /* EXEC_PURPOSE_* */
  u32 messages_sent;            /* Number of messages attempted */
  u32 complete_messages;        /* Number of messages fully submitted */
  u32 total_bytes_sent;         /* Total wire bytes actually submitted */
  u32 partial_bytes_tail;       /* Submitted bytes of incomplete final message */
  u8  is_transmission_complete; /* Entire planned input, not merely attempted records. */
  u32 planned_messages;
  u32 wire_count;
  execution_wire_record_t *wire;
  u8 has_wire_observation;

  /* Network response observation */
  char *response_buf;           /* Copy of network responses */
  int   response_buf_size;      /* Total size of response_buf */
  u32  *response_bytes;         /* Per-message accumulated response bytes */
  u32   response_bytes_count;   /* Count of entries in response_bytes */
  u8    is_response_complete;   /* 1 if response was completely observed within budget, 0 if truncated/exceeded/error */
  u8    response_budget_exceeded; /* 1 if cumulative response budget was exceeded */

  /* State observation */
  u8   has_state_observation;   /* 1 if state trace was captured, 0 otherwise */
  u8   provider;                /* STATE_OBS_PROVIDER_* */
  u8   is_truncated;            /* 1 if trace exceeded capacity or marked truncated */
  u32  status;                  /* Terminal status from tracer */
  u32  state_count;             /* Number of states in sequence */
  unsigned int *state_sequence; /* State sequence array */
  u32  unique_state_count;      /* Count of unique states in sequence */
  /* A provider-supplied, explicit message ordinal -> stored snapshot map. */
  u32 boundary_count;
  u32 boundary_state_index[MAX_NUM_STATES];
  u8 has_verified_boundaries;
} execution_observation_t;

static inline void free_execution_wire(execution_wire_record_t *wire, u32 count) {
  if (!wire) return;
  for (u32 i = 0; i < count; i++) free(wire[i].data);
  free(wire);
}

static inline int copy_execution_wire(execution_observation_t *obs,
                                     const execution_wire_record_t *wire,
                                     u32 count, u32 planned) {
  if (!obs || obs->wire || (count && !wire) || count > planned) return -1;
  obs->planned_messages = planned;
  if (!count) return 0;
  obs->wire = calloc(count, sizeof(*obs->wire));
  if (!obs->wire) return -1;
  for (u32 i = 0; i < count; i++) {
    obs->wire[i].size = wire[i].size;
    obs->wire[i].planned_size = wire[i].planned_size;
    if (wire[i].size > wire[i].planned_size || (wire[i].size && !wire[i].data)) goto fail;
    if (wire[i].size) {
      obs->wire[i].data = malloc(wire[i].size);
      if (!obs->wire[i].data) goto fail;
      memcpy(obs->wire[i].data, wire[i].data, wire[i].size);
    }
  }
  obs->wire_count = count;
  obs->has_wire_observation = 1;
  return 0;
fail:
  free_execution_wire(obs->wire, count);
  obs->wire = NULL;
  return -1;
}

/* Exact submitted-byte identity is the default. No implicit masking of tokens. */
static inline int execution_wire_equal(const execution_observation_t *a,
                                      const execution_observation_t *b) {
  if (!a || !b || !a->has_wire_observation || !b->has_wire_observation ||
      !a->wire || !b->wire || !a->wire_count ||
      a->wire_count > a->planned_messages || b->wire_count > b->planned_messages ||
      a->planned_messages != b->planned_messages || a->wire_count != b->wire_count)
    return 0;
  for (u32 i = 0; i < a->wire_count; i++) {
    if (a->wire[i].size > a->wire[i].planned_size ||
        b->wire[i].size > b->wire[i].planned_size ||
        (a->wire[i].size && (!a->wire[i].data || !b->wire[i].data)) ||
        a->wire[i].size != b->wire[i].size ||
        a->wire[i].planned_size != b->wire[i].planned_size ||
        (a->wire[i].size && memcmp(a->wire[i].data, b->wire[i].data, a->wire[i].size)))
      return 0;
  }
  return 1;
}

/* Zero-submission attempts are diagnostic events, never zero-length messages. */
static inline u32 execution_submitted_records(const execution_observation_t *obs) {
  u32 count = 0;
  if (obs && obs->wire) for (u32 i = 0; i < obs->wire_count; i++)
    if (obs->wire[i].size) count++;
  return count;
}

static inline int write_execution_wire(FILE *stream, const execution_observation_t *obs,
                                       int replay, size_t *written) {
  size_t total = 0;
  if (!stream || !obs || !obs->has_wire_observation || !obs->wire ||
      !obs->wire_count || obs->wire_count > obs->planned_messages) return -1;
  for (u32 i = 0; i < obs->wire_count; i++) {
    u32 n = obs->wire[i].size;
    if (!n) continue;
    size_t overhead = replay ? 4 : 0;
    if (!obs->wire[i].data || n > obs->wire[i].planned_size ||
        total > SIZE_MAX - overhead || n > SIZE_MAX - overhead - total) return -1;
    if (replay) {
      u8 prefix[4];
      for (unsigned j = 0; j < 4; j++) prefix[j] = (u8)(n >> (8 * j));
      if (fwrite(prefix, 1, 4, stream) != 4) return -1;
      total += 4;
    }
    if (fwrite(obs->wire[i].data, 1, n, stream) != n) return -1;
    total += n;
  }
  if (written) *written = total;
  return ferror(stream) ? -1 : 0;
}

/* Free all memory associated with an execution_observation_t */
static inline void free_execution_observation(execution_observation_t *obs) {
  if (!obs) return;
  if (obs->response_buf) {
    free(obs->response_buf);
    obs->response_buf = NULL;
  }
  if (obs->response_bytes) {
    free(obs->response_bytes);
    obs->response_bytes = NULL;
  }
  if (obs->state_sequence) {
    free(obs->state_sequence);
    obs->state_sequence = NULL;
  }
  free_execution_wire(obs->wire, obs->wire_count);
  free(obs);
}

/* Compare original and confirmation replay observations.
   Returns 1 if identical/repeatable, 0 if mismatched with reason written to buffer. */
static inline int compare_execution_observations(const execution_observation_t *orig,
                                                 const execution_observation_t *rep,
                                                 char *reason, size_t reason_sz) {
  if (!orig || !rep) {
    if (reason && reason_sz > 0) snprintf(reason, reason_sz, "NULL observation");
    return 0;
  }

  if (!orig->is_transmission_complete || !rep->is_transmission_complete ||
      !orig->is_response_complete || !rep->is_response_complete) {
    if (reason && reason_sz) snprintf(reason, reason_sz, "incomplete execution");
    return 0;
  }
  if (!execution_wire_equal(orig, rep)) {
    if (reason && reason_sz) snprintf(reason, reason_sz, "submitted input identity differs or is unavailable");
    return 0;
  }
  if (orig->boundary_count > MAX_NUM_STATES || rep->boundary_count > MAX_NUM_STATES ||
      orig->has_verified_boundaries != rep->has_verified_boundaries ||
      orig->boundary_count != rep->boundary_count ||
      (orig->has_verified_boundaries &&
       memcmp(orig->boundary_state_index, rep->boundary_state_index,
              orig->boundary_count * sizeof(orig->boundary_state_index[0])))) {
    if (reason && reason_sz) snprintf(reason, reason_sz, "message boundary evidence differs");
    return 0;
  }

  /* Transmission completeness check */
  if (orig->messages_sent != rep->messages_sent) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "transmission count mismatch: orig %u vs rep %u",
               orig->messages_sent, rep->messages_sent);
    return 0;
  }

  if (orig->complete_messages != rep->complete_messages) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "complete messages mismatch: orig %u vs rep %u",
               orig->complete_messages, rep->complete_messages);
    return 0;
  }

  /* Transmission completeness and volume check */
  if (orig->is_transmission_complete != rep->is_transmission_complete) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "transmission completeness flag mismatch: orig %u vs rep %u",
               orig->is_transmission_complete, rep->is_transmission_complete);
    return 0;
  }

  if (orig->total_bytes_sent != rep->total_bytes_sent) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "total bytes sent mismatch: orig %u vs rep %u",
               orig->total_bytes_sent, rep->total_bytes_sent);
    return 0;
  }

  /* P17: Response completeness and budget check */
  if (orig->is_response_complete != rep->is_response_complete) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "response completeness mismatch: orig %u vs rep %u",
               orig->is_response_complete, rep->is_response_complete);
    return 0;
  }

  if (orig->response_budget_exceeded || rep->response_budget_exceeded) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "response budget exceeded: orig %u vs rep %u",
               orig->response_budget_exceeded, rep->response_budget_exceeded);
    return 0;
  }

  /* Truncation check */
  if (orig->is_truncated || rep->is_truncated) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "state trace truncated (orig: %u, rep: %u)",
               orig->is_truncated, rep->is_truncated);
    return 0;
  }

  /* State observation presence */
  if (orig->has_state_observation != rep->has_state_observation) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "state observation presence mismatch (orig: %u, rep: %u)",
               orig->has_state_observation, rep->has_state_observation);
    return 0;
  }

  /* P27: If state observation is absent or unavailable, confirmation cannot confirm memory state */
  if (!orig->has_state_observation || !rep->has_state_observation ||
      orig->status == STATE_TRACER_STATUS_UNAVAILABLE ||
      rep->status == STATE_TRACER_STATUS_UNAVAILABLE) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "state observation unavailable; cannot confirm memory state");
    return 0;
  }

  if (orig->provider == STATE_OBS_PROVIDER_NONE || orig->provider != rep->provider ||
      orig->status != STATE_TRACER_STATUS_COMPLETE || rep->status != STATE_TRACER_STATUS_COMPLETE ||
      !orig->state_count || !rep->state_count || !orig->state_sequence || !rep->state_sequence) {
    if (reason && reason_sz) snprintf(reason, reason_sz, "invalid state observation provider, status or sequence");
    return 0;
  }

  /* State sequence length check */
  if (orig->state_count != rep->state_count) {
    if (reason && reason_sz > 0)
      snprintf(reason, reason_sz, "variable state sequence length (orig %u vs rep %u)",
               orig->state_count, rep->state_count);
    return 0;
  }

  /* State sequence element check */
  if (orig->state_sequence && rep->state_sequence) {
    for (u32 i = 0; i < orig->state_count; i++) {
      if (orig->state_sequence[i] != rep->state_sequence[i]) {
        if (reason && reason_sz > 0)
          snprintf(reason, reason_sz, "state trajectory mismatch at step %u (orig %u vs rep %u)",
                   i, orig->state_sequence[i], rep->state_sequence[i]);
        return 0;
      }
    }
  }

  if (reason && reason_sz > 0) snprintf(reason, reason_sz, "repeatable match");
  return 1;
}

#endif /* _HAVE_EXECUTION_OBSERVATION_H */
