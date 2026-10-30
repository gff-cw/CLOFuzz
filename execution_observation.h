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
#define EXEC_PURPOSE_UNKNOWN      0
#define EXEC_PURPOSE_ORIGINAL     1
#define EXEC_PURPOSE_CONFIRMATION 2
#define EXEC_PURPOSE_CALIBRATION  3
#define EXEC_PURPOSE_SYNC         4

static inline const char *exec_purpose_to_str(u8 purpose) {
  switch (purpose) {
    case EXEC_PURPOSE_ORIGINAL:     return "coverage";
    case EXEC_PURPOSE_CONFIRMATION: return "confirmation";
    case EXEC_PURPOSE_CALIBRATION:  return "calibration";
    case EXEC_PURPOSE_SYNC:         return "sync";
    default:                        return "unknown";
  }
}

/* State observation providers */
#define STATE_OBS_PROVIDER_NONE   0
#define STATE_OBS_PROVIDER_TRACER 1
#define STATE_OBS_PROVIDER_CODES  2

typedef struct {
  u32 exec_id;                  /* Execution identifier */
  u8  exec_purpose;             /* EXEC_PURPOSE_* */
  u32 messages_sent;            /* Number of messages attempted */
  u32 complete_messages;        /* Number of messages fully submitted */
  u32 total_bytes_sent;         /* Total wire bytes actually submitted */
  u32 partial_bytes_tail;       /* Submitted bytes of incomplete final message */
  u8  is_transmission_complete; /* 1 if all attempted messages were fully sent */

  /* Network response observation */
  char *response_buf;           /* Copy of network responses */
  int   response_buf_size;      /* Total size of response_buf */
  u32  *response_bytes;         /* Per-message accumulated response bytes */
  u32   response_bytes_count;   /* Count of entries in response_bytes */

  /* State observation */
  u8   has_state_observation;   /* 1 if state trace was captured, 0 otherwise */
  u8   provider;                /* STATE_OBS_PROVIDER_* */
  u8   is_truncated;            /* 1 if trace exceeded capacity or marked truncated */
  u32  status;                  /* Terminal status from tracer */
  u32  state_count;             /* Number of states in sequence */
  unsigned int *state_sequence; /* State sequence array */
  u32  unique_state_count;      /* Count of unique states in sequence */
} execution_observation_t;

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
