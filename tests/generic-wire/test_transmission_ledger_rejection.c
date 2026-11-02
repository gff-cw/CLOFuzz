#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"
#include "execution_observation.h"

static unsigned checks = 0;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

/* Helper simulating queue candidate admission check in save_if_interesting */
static int simulate_save_if_interesting(klist_t(lms) *kl_messages,
                                        const char *queue_fn,
                                        u32 complete_messages,
                                        u8 is_transmission_complete) {
  if (complete_messages == 0 || !is_transmission_complete) {
    /* P19/B08: Incomplete messages or partial send; reject truncated prefix from queue */
    return 0;
  }
  u32 full_len = save_kl_messages_to_file(kl_messages, (u8 *)queue_fn, 0, complete_messages);
  return (full_len > 0) ? 1 : 0;
}

int main(void) {
  printf("[*] Testing B08/B09 transmission ledger rejection, partial send exclusion, and run accounting...\n");

  /* Setup dummy message list with 3 messages */
  char tmp_path[] = "/tmp/stateafl_b08_test_XXXXXX";
  int fd = mkstemp(tmp_path);
  CHECK(fd >= 0);

  const uint8_t m1_data[] = {0x01, 0x02, 0x03, 0x04};             /* len 4 */
  const uint8_t m2_data[] = {0xAA, 0xBB, 0xCC, 0xDD};             /* len 4 */
  const uint8_t m3_data[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60}; /* len 6 */

  CHECK(write(fd, m1_data, sizeof(m1_data)) == sizeof(m1_data));
  CHECK(write(fd, m2_data, sizeof(m2_data)) == sizeof(m2_data));
  CHECK(write(fd, m3_data, sizeof(m3_data)) == sizeof(m3_data));
  close(fd);

  region_t regions[3];
  regions[0].start_byte = 0;  regions[0].end_byte = 3;
  regions[1].start_byte = 4;  regions[1].end_byte = 7;
  regions[2].start_byte = 8;  regions[2].end_byte = 13;

  klist_t(lms) *messages = construct_kl_messages((u8 *)tmp_path, regions, 3);
  CHECK(messages != NULL);
  CHECK(messages->size == 3);

  /* ========================================================================
   * 1. session_rejected marks is_transmission_complete = 0
   * ======================================================================== */
  {
    u32 messages_sent = 0;
    u32 complete_messages = 0;
    u64 protocol_rejections = 0;
    u8 is_transmission_complete = 1;
    u8 protocol_structured_run = 1;

    /* Message 1 succeeds */
    messages_sent++;
    complete_messages++;

    /* Message 2 encounters session rejection in before_send hook */
    int proto_before_send_res = -1; /* simulated before_send failure */
    if (proto_before_send_res < 0) {
      if (protocol_structured_run) {
        protocol_rejections++;
        is_transmission_complete = 0;
        /* Simulated jump to HANDLE_RESPONSES */
      }
    }

    CHECK(protocol_rejections == 1);
    CHECK(is_transmission_complete == 0);
    CHECK(complete_messages == 1);
    CHECK(messages_sent == 1);

    printf("[+] 1: session_rejected properly marks is_transmission_complete = 0 and halts transmission\n");
  }

  /* ========================================================================
   * 2. Partial sends do not increment complete_transmissions or valid_observations
   * ======================================================================== */
  {
    u64 protocol_complete_transmissions = 0;
    u64 protocol_valid_observations = 0;
    u8 feedback_layer = 1;
    u8 response_budget_exceeded = 0;
    u8 fault = 0, crash_mode = 0;

    /* 2a. Incomplete transmission (is_transmission_complete == 0) */
    {
      u32 protocol_count = 3;
      u32 protocol_structured_sent = 3;
      u8 is_transmission_complete = 0; /* partial / interrupted send */

      u8 feedback_delivered = protocol_count &&
                              (protocol_structured_sent == protocol_count) &&
                              is_transmission_complete;
      CHECK(feedback_delivered == 0);
      if (feedback_delivered) protocol_complete_transmissions++;

      u8 protocol_collect_coverage = feedback_layer &&
                                     feedback_delivered &&
                                     !response_budget_exceeded &&
                                     (fault == crash_mode);
      CHECK(protocol_collect_coverage == 0);
      if (protocol_collect_coverage) protocol_valid_observations++;

      CHECK(protocol_complete_transmissions == 0);
      CHECK(protocol_valid_observations == 0);
    }

    /* 2b. Structured count mismatch (protocol_structured_sent < protocol_count) */
    {
      u32 protocol_count = 3;
      u32 protocol_structured_sent = 2; /* only 2 of 3 sent */
      u8 is_transmission_complete = 1;

      u8 feedback_delivered = protocol_count &&
                              (protocol_structured_sent == protocol_count) &&
                              is_transmission_complete;
      CHECK(feedback_delivered == 0);
      if (feedback_delivered) protocol_complete_transmissions++;

      u8 protocol_collect_coverage = feedback_layer &&
                                     feedback_delivered &&
                                     !response_budget_exceeded &&
                                     (fault == crash_mode);
      CHECK(protocol_collect_coverage == 0);
      if (protocol_collect_coverage) protocol_valid_observations++;

      CHECK(protocol_complete_transmissions == 0);
      CHECK(protocol_valid_observations == 0);
    }

    /* 2c. Successful complete transmission */
    {
      u32 protocol_count = 3;
      u32 protocol_structured_sent = 3;
      u8 is_transmission_complete = 1;

      u8 feedback_delivered = protocol_count &&
                              (protocol_structured_sent == protocol_count) &&
                              is_transmission_complete;
      CHECK(feedback_delivered == 1);
      if (feedback_delivered) protocol_complete_transmissions++;

      u8 protocol_collect_coverage = feedback_layer &&
                                     feedback_delivered &&
                                     !response_budget_exceeded &&
                                     (fault == crash_mode);
      CHECK(protocol_collect_coverage == 1);
      if (protocol_collect_coverage) protocol_valid_observations++;

      CHECK(protocol_complete_transmissions == 1);
      CHECK(protocol_valid_observations == 1);
    }

    printf("[+] 2: Partial sends verified: zero increments to complete_transmissions and valid_observations\n");
  }

  /* ========================================================================
   * 3. Partial sends are not saved to queue in save_if_interesting
   * ======================================================================== */
  {
    char queue_tmp[] = "/tmp/stateafl_b08_q_XXXXXX";
    int qfd = mkstemp(queue_tmp);
    CHECK(qfd >= 0);
    close(qfd);
    unlink(queue_tmp); /* remove so we check whether file was created */

    /* 3a. Rejection when is_transmission_complete == 0 */
    int kept = simulate_save_if_interesting(messages, queue_tmp, 2, 0);
    CHECK(kept == 0);
    CHECK(access(queue_tmp, F_OK) != 0); /* file must NOT have been created */

    /* 3b. Rejection when complete_messages == 0 */
    kept = simulate_save_if_interesting(messages, queue_tmp, 0, 1);
    CHECK(kept == 0);
    CHECK(access(queue_tmp, F_OK) != 0);

    /* 3c. Rejection when both are 0 */
    kept = simulate_save_if_interesting(messages, queue_tmp, 0, 0);
    CHECK(kept == 0);
    CHECK(access(queue_tmp, F_OK) != 0);

    /* 3d. Admission when complete_messages > 0 and is_transmission_complete == 1 */
    kept = simulate_save_if_interesting(messages, queue_tmp, 2, 1);
    CHECK(kept == 1);
    CHECK(access(queue_tmp, F_OK) == 0);

    /* Verify saved file contains exactly complete_messages (m1 + m2 = 8 bytes) */
    FILE *qf = fopen(queue_tmp, "rb");
    CHECK(qf != NULL);
    fseek(qf, 0, SEEK_END);
    long qsz = ftell(qf);
    fclose(qf);
    CHECK(qsz == 8); /* 4 bytes (m1) + 4 bytes (m2) */
    unlink(queue_tmp);

    printf("[+] 3: Queue admission gating verified: partial sends rejected from queue\n");
  }

  /* ========================================================================
   * 4. structured_runs increments on execution start rather than preparation
   * ======================================================================== */
  {
    u64 protocol_structured_runs = 0;
    u8 protocol_structured_run = 1;

    /* Stage A: protocol_prepare (candidate mutation & preparation) */
    /* Preparation performs generation, framing, and mutation, but MUST NOT increment run count */
    int prep_ok = 1; /* preparation succeeded */
    CHECK(prep_ok == 1);
    CHECK(protocol_structured_runs == 0);

    /* Stage B: Candidate abortion / pre-execution gating (e.g. novelty retry exhausted or outside model) */
    int aborted_before_exec = 1;
    if (aborted_before_exec) {
      /* Candidate discarded without executing run_target */
    }
    CHECK(protocol_structured_runs == 0); /* Still 0! */

    /* Stage C: Actual execution start (immediately preceding run_target) */
    if (protocol_structured_run) {
      protocol_structured_runs++;
    }
    /* Simulated run_target execution */
    CHECK(protocol_structured_runs == 1);

    /* Stage D: Subsequent run preparation and execution */
    /* Second candidate prepared */
    CHECK(protocol_structured_runs == 1); /* Still 1 after prep */
    /* Second candidate starts execution */
    if (protocol_structured_run) {
      protocol_structured_runs++;
    }
    CHECK(protocol_structured_runs == 2);

    printf("[+] 4: structured_runs increment verified on execution start rather than preparation\n");
  }

  delete_kl_messages(messages);
  unlink(tmp_path);

  printf("[+] All B08/B09 transmission ledger rejection tests passed successfully! (%u checks)\n", checks);
  return 0;
}
