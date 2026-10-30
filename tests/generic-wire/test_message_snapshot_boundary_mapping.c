#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "execution_observation.h"

/* Minimal mock structures matching aflnet.h and afl-fuzz.c */
typedef struct {
  int start_byte;
  int end_byte;
  char modifiable;
  unsigned int *state_sequence;
  unsigned int state_count;
} mock_region_t;

struct mock_queue_entry {
  mock_region_t *regions;
  u32 region_count;
};

/* Mock memory allocation wrappers matching ck_alloc / ck_free */
#define mock_alloc(sz) calloc(1, (sz))
#define mock_free(ptr) free(ptr)

/* Function pointer mock for ASCII response codes mode */
static unsigned int *(*mock_extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;

static unsigned int mock_code_seq_2[] = { 220, 250 };
static unsigned int mock_code_seq_3[] = { 220, 250, 331 };

static unsigned int *mock_response_extractor(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) {
  (void)buf;
  if (buf_size <= 10) {
    *state_count_ref = 2;
    unsigned int *ret = (unsigned int *)malloc(2 * sizeof(unsigned int));
    memcpy(ret, mock_code_seq_2, 2 * sizeof(unsigned int));
    return ret;
  } else {
    *state_count_ref = 3;
    unsigned int *ret = (unsigned int *)malloc(3 * sizeof(unsigned int));
    memcpy(ret, mock_code_seq_3, 3 * sizeof(unsigned int));
    return ret;
  }
}

/* Implementation of update_region_annotations under test (P02 verified contract) */
static void test_update_region_annotations(struct mock_queue_entry *q, const execution_observation_t *obs) {
  u32 i = 0;

  if (!q) return;

  if (!obs) {
    for (i = 0; i < q->region_count; i++) {
      if (q->regions[i].state_sequence) {
        mock_free(q->regions[i].state_sequence);
        q->regions[i].state_sequence = NULL;
      }
      q->regions[i].state_count = 0;
    }
    return;
  }

  for (i = 0; i < q->region_count; i++) {
    if (q->regions[i].state_sequence) {
      mock_free(q->regions[i].state_sequence);
      q->regions[i].state_sequence = NULL;
    }
    q->regions[i].state_count = 0;

    /* P02 Boundary Evidence Verification */
    if (i >= obs->messages_sent || !obs->response_bytes || i >= obs->response_bytes_count) {
      continue;
    }

    if (i == 0) {
      if (obs->response_bytes[0] == 0) continue;
    } else {
      if (obs->response_bytes[i] <= obs->response_bytes[i - 1]) continue;
    }

    if (obs->provider == STATE_OBS_PROVIDER_TRACER) {
      /* In StateAFL tracer mode, snapshot boundary for region i requires obs->state_count >= i + 2 */
      if (!obs->has_state_observation || !obs->state_sequence ||
          (obs->status != STATE_TRACER_STATUS_COMPLETE && obs->status != STATE_TRACER_STATUS_TRUNCATED) ||
          obs->state_count < i + 2) {
        continue;
      }

      u32 regional_state_count = i + 2;
      unsigned int *state_sequence = (unsigned int *)mock_alloc(regional_state_count * sizeof(unsigned int));
      memcpy(state_sequence, obs->state_sequence, regional_state_count * sizeof(unsigned int));
      q->regions[i].state_sequence = state_sequence;
      q->regions[i].state_count = regional_state_count;

    } else {
      /* In AFLNet ASCII response code mode */
      unsigned int parsed_count = 0;
      unsigned int *state_sequence = NULL;

      if (mock_extract_response_codes && obs->response_buf) {
        state_sequence = (*mock_extract_response_codes)((unsigned char *)obs->response_buf,
                                                        obs->response_bytes[i],
                                                        &parsed_count);
      }

      if (state_sequence && parsed_count > 0) {
        q->regions[i].state_sequence = state_sequence;
        q->regions[i].state_count = parsed_count;
      } else {
        if (state_sequence) mock_free(state_sequence);
        q->regions[i].state_sequence = NULL;
        q->regions[i].state_count = 0;
      }
    }
  }
}

int main(void) {
  printf("[*] Testing P02 message and state snapshot boundary mapping contract...\n");

  /* Setup a mock queue entry with 3 regions */
  struct mock_queue_entry q;
  q.region_count = 3;
  q.regions = (mock_region_t *)calloc(3, sizeof(mock_region_t));
  assert(q.regions != NULL);

  /* Pre-populate regions with dummy old allocations */
  for (u32 i = 0; i < 3; i++) {
    q.regions[i].state_sequence = (unsigned int *)malloc(sizeof(unsigned int));
    q.regions[i].state_sequence[0] = 999;
    q.regions[i].state_count = 1;
  }

  /* 1. NULL observation must free and clear all regions */
  test_update_region_annotations(&q, NULL);
  for (u32 i = 0; i < 3; i++) {
    assert(q.regions[i].state_sequence == NULL);
    assert(q.regions[i].state_count == 0);
  }

  /* 2. StateAFL tracer mode: 3 regions, 2 sent, valid responses for msg 0 and 1 */
  execution_observation_t *obs = (execution_observation_t *)calloc(1, sizeof(execution_observation_t));
  assert(obs != NULL);
  obs->messages_sent = 2; /* Only 2 of 3 sent */
  obs->complete_messages = 2;
  obs->provider = STATE_OBS_PROVIDER_TRACER;
  obs->has_state_observation = 1;
  obs->status = STATE_TRACER_STATUS_COMPLETE;
  obs->response_bytes_count = 2;
  obs->response_bytes = (u32 *)malloc(2 * sizeof(u32));
  obs->response_bytes[0] = 10;
  obs->response_bytes[1] = 25; /* Positive delta: 25 - 10 = 15 */

  /* Tracer sequence: seq[0] = State 0 (initial), seq[1] = 0xAA, seq[2] = 0xBB */
  obs->state_count = 3;
  obs->state_sequence = (unsigned int *)malloc(3 * sizeof(unsigned int));
  obs->state_sequence[0] = 0;
  obs->state_sequence[1] = 0xAA;
  obs->state_sequence[2] = 0xBB;

  test_update_region_annotations(&q, obs);

  /* Region 0:
     - Boundary evidence verified
     - regional_state_count == 2
     - state_sequence = [0, 0xAA]
     - Reached state (last element) == 0xAA */
  assert(q.regions[0].state_count == 2);
  assert(q.regions[0].state_sequence != NULL);
  assert(q.regions[0].state_sequence[0] == 0);
  assert(q.regions[0].state_sequence[1] == 0xAA);
  assert(q.regions[0].state_sequence[q.regions[0].state_count - 1] == 0xAA);

  /* Region 1:
     - Boundary evidence verified
     - regional_state_count == 3
     - state_sequence = [0, 0xAA, 0xBB]
     - Reached state (last element) == 0xBB */
  assert(q.regions[1].state_count == 3);
  assert(q.regions[1].state_sequence != NULL);
  assert(q.regions[1].state_sequence[0] == 0);
  assert(q.regions[1].state_sequence[1] == 0xAA);
  assert(q.regions[1].state_sequence[2] == 0xBB);
  assert(q.regions[1].state_sequence[q.regions[1].state_count - 1] == 0xBB);

  /* Region 2:
     - Not sent (i >= messages_sent)
     - Marked unknown: state_count == 0, state_sequence == NULL */
  assert(q.regions[2].state_count == 0);
  assert(q.regions[2].state_sequence == NULL);

  /* 3. Test missing response boundary: msg 1 receives 0 delta bytes */
  obs->response_bytes[1] = 10; /* delta = 10 - 10 = 0 */
  test_update_region_annotations(&q, obs);

  assert(q.regions[0].state_count == 2); /* Msg 0 still valid */
  assert(q.regions[1].state_count == 0); /* Msg 1 boundary rejected */
  assert(q.regions[1].state_sequence == NULL);
  assert(q.regions[2].state_count == 0);

  /* 4. Test insufficient tracer snapshots: obs->state_count < i + 2 */
  obs->response_bytes[1] = 25; /* restore positive delta */
  obs->state_count = 2;        /* Only seq[0], seq[1] available, region 1 needs 3 */
  test_update_region_annotations(&q, obs);

  assert(q.regions[0].state_count == 2); /* Region 0 has 2 states available */
  assert(q.regions[1].state_count == 0); /* Region 1 requires 3 states, unavailable */
  assert(q.regions[1].state_sequence == NULL);

  /* 5. Test tracer status UNAVAILABLE */
  obs->state_count = 3;
  obs->status = STATE_TRACER_STATUS_UNAVAILABLE;
  test_update_region_annotations(&q, obs);
  assert(q.regions[0].state_count == 0);
  assert(q.regions[0].state_sequence == NULL);
  assert(q.regions[1].state_count == 0);
  assert(q.regions[1].state_sequence == NULL);

  /* 6. Test AFLNet ASCII response codes mode */
  obs->provider = STATE_OBS_PROVIDER_CODES;
  obs->status = STATE_TRACER_STATUS_COMPLETE;
  obs->response_buf = (char *)malloc(30);
  obs->response_buf_size = 30;
  mock_extract_response_codes = mock_response_extractor;

  test_update_region_annotations(&q, obs);

  /* Region 0: parsed 2 codes [220, 250] */
  assert(q.regions[0].state_count == 2);
  assert(q.regions[0].state_sequence != NULL);
  assert(q.regions[0].state_sequence[0] == 220);
  assert(q.regions[0].state_sequence[1] == 250);

  /* Region 1: parsed 3 codes [220, 250, 331] */
  assert(q.regions[1].state_count == 3);
  assert(q.regions[1].state_sequence != NULL);
  assert(q.regions[1].state_sequence[0] == 220);
  assert(q.regions[1].state_sequence[1] == 250);
  assert(q.regions[1].state_sequence[2] == 331);

  /* Cleanup */
  test_update_region_annotations(&q, NULL);
  free(q.regions);
  free_execution_observation(obs);

  printf("[+] All P02 message-to-state boundary mapping tests passed successfully!\n");
  return 0;
}
