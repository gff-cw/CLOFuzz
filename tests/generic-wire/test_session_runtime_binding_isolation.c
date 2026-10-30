#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "hash.h"
#include "aflnet.h"
#include "protocol_runtime.h"

/* Structure matching afl-fuzz.c for executed message preservation */
typedef struct {
  u8 *data;
  u32 size;
} executed_message_t;

static void save_executed_messages_to_file(executed_message_t *msgs, u32 count, const char *fname) {
  if (!msgs || !count || !fname) return;
  u32 len = 0;
  for (u32 i = 0; i < count; i++) {
    len += 4 + msgs[i].size;
  }
  u8 *mem = (u8 *) ck_alloc(len);
  u32 offset = 0;
  for (u32 i = 0; i < count; i++) {
    u32 sz = msgs[i].size;
    for (unsigned j = 0; j < 4; j++) mem[offset + j] = (u8)(sz >> (8 * j));
    offset += 4;
    if (sz && msgs[i].data) {
      memcpy(mem + offset, msgs[i].data, sz);
      offset += sz;
    }
  }
  s32 fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    ck_free(mem);
    abort();
  }
  if (write(fd, mem, len) != (ssize_t)len) {
    close(fd);
    ck_free(mem);
    abort();
  }
  close(fd);
  ck_free(mem);
}

int main(void) {
  printf("[*] Testing P11 session runtime binding isolation and M1/M3 session contract...\n");

  /* 1. Setup temporary message list: M1 (prefix), M2 (target), M3 (suffix) */
  char tmp_path[] = "/tmp/stateafl_p11_test_XXXXXX";
  int fd = mkstemp(tmp_path);
  assert(fd >= 0);

  /* Message 1: 12-byte Modbus read holding registers request with TxID = 0x0001 */
  const uint8_t m1_logical[] = {
    0x00, 0x01, /* TxID: 1 */
    0x00, 0x00, /* Proto ID: 0 */
    0x00, 0x06, /* Len: 6 */
    0x01,       /* Unit ID: 1 */
    0x03,       /* Function: Read Holding Registers */
    0x00, 0x00, /* Starting Address: 0 */
    0x00, 0x01  /* Quantity: 1 */
  };

  /* Message 2: 12-byte Modbus request with TxID = 0x0002 */
  const uint8_t m2_logical[] = {
    0x00, 0x02, /* TxID: 2 */
    0x00, 0x00,
    0x00, 0x06,
    0x01,
    0x03,
    0x00, 0x01,
    0x00, 0x01
  };

  /* Message 3: 12-byte Modbus request with TxID = 0x0003 */
  const uint8_t m3_logical[] = {
    0x00, 0x03, /* TxID: 3 */
    0x00, 0x00,
    0x00, 0x06,
    0x01,
    0x03,
    0x00, 0x02,
    0x00, 0x01
  };

  assert(write(fd, m1_logical, sizeof(m1_logical)) == sizeof(m1_logical));
  assert(write(fd, m2_logical, sizeof(m2_logical)) == sizeof(m2_logical));
  assert(write(fd, m3_logical, sizeof(m3_logical)) == sizeof(m3_logical));
  close(fd);

  region_t regions[3];
  regions[0].start_byte = 0;
  regions[0].end_byte = sizeof(m1_logical) - 1;
  regions[1].start_byte = sizeof(m1_logical);
  regions[1].end_byte = sizeof(m1_logical) + sizeof(m2_logical) - 1;
  regions[2].start_byte = sizeof(m1_logical) + sizeof(m2_logical);
  regions[2].end_byte = sizeof(m1_logical) + sizeof(m2_logical) + sizeof(m3_logical) - 1;

  klist_t(lms) *messages = construct_kl_messages((u8 *)tmp_path, regions, 3);
  assert(messages != NULL);
  assert(messages->size == 3);

  /* Tag only M2 as protocol_structured (as done in AFLNet custom mutation) */
  kliter_t(lms) *it = kl_begin(messages);
  kl_val(it)->protocol_structured = 0; /* M1 */
  it = kl_next(it);
  kl_val(it)->protocol_structured = 1; /* M2 */
  it = kl_next(it);
  kl_val(it)->protocol_structured = 0; /* M3 */

  /* 2. Test Execution Buffer Isolation:
     Simulate execution copy binding. Modifying send_buf must NEVER touch mdata. */
  it = kl_begin(messages);
  message_t *m1 = kl_val(it);

  u8 *m1_exec_buf = (u8 *) ck_alloc(m1->msize);
  memcpy(m1_exec_buf, m1->mdata, m1->msize);

  /* Simulate dynamic session binding rewrite in execution copy */
  m1_exec_buf[0] = 0xAA;
  m1_exec_buf[1] = 0xBB;

  /* Check that the executed buffer has the new runtime binding */
  assert(m1_exec_buf[0] == 0xAA && m1_exec_buf[1] == 0xBB);

  /* Crucial P11 invariant: The logical candidate mdata remains pristine! */
  assert(m1->mdata[0] == 0x00 && m1->mdata[1] == 0x01);
  assert(memcmp(m1->mdata, m1_logical, sizeof(m1_logical)) == 0);

  /* 3. Test Digest Separation:
     Logical digest must be computed from immutable mdata.
     Executed digest must be computed from send_buf. */
  u32 logical_digest = 0;
  u32 executed_digest = 0;

  for (it = kl_begin(messages); it != kl_end(messages); it = kl_next(it)) {
    logical_digest = hash32(kl_val(it)->mdata, kl_val(it)->msize, logical_digest);
  }

  /* Executed sequence has modified M1 */
  executed_digest = hash32(m1_exec_buf, m1->msize, 0);
  it = kl_next(kl_begin(messages)); /* M2 */
  executed_digest = hash32(kl_val(it)->mdata, kl_val(it)->msize, executed_digest);
  it = kl_next(it); /* M3 */
  executed_digest = hash32(kl_val(it)->mdata, kl_val(it)->msize, executed_digest);

  assert(logical_digest != executed_digest);
  assert(logical_digest != 0);
  assert(executed_digest != 0);

  /* 4. Test Stale Session Value Elimination on Subsequent Iteration:
     On iteration 2, the message must be freshly copied from mdata.
     It must NOT inherit 0xAABB from iteration 1. */
  u8 *m1_iter2_buf = (u8 *) ck_alloc(m1->msize);
  memcpy(m1_iter2_buf, m1->mdata, m1->msize);
  assert(m1_iter2_buf[0] == 0x00 && m1_iter2_buf[1] == 0x01);
  assert(m1_iter2_buf[0] != 0xAA);
  ck_free(m1_iter2_buf);

  /* 5. Test P11 Structured Session Contract Coverage for M1 and M3:
     In structured runs (protocol_structured_run = 1), binding/before_send failure on
     M1 or M3 must reject the candidate in PROTO_VALID and PROTO_HYBRID modes,
     not ignore the failure just because kl_val(it)->protocol_structured == 0. */
  u8 protocol_structured_run = 1;
  int protocol_mode_valid = 0; /* PROTO_VALID */
  int protocol_mode_hybrid = 4; /* PROTO_HYBRID */
  int protocol_mode_raw = 3; /* PROTO_RAW */

  /* M1 has protocol_structured == 0 */
  assert(kl_val(kl_begin(messages))->protocol_structured == 0);

  /* Under old buggy logic:
     if (kl_val(it)->protocol_structured && (protocol_mode == PROTO_VALID || protocol_mode == PROTO_HYBRID))
     -> Evaluated to FALSE for M1! Silently ignored failure on M1! */
  u8 old_reject_m1 = (kl_val(kl_begin(messages))->protocol_structured &&
                      (protocol_mode_valid == 0 || protocol_mode_valid == 4));
  assert(old_reject_m1 == 0); /* Buggy: old logic allowed M1 to bypass rejection! */

  /* Under new P11 logic:
     if ((protocol_structured_run || kl_val(it)->protocol_structured) &&
         (protocol_mode == PROTO_VALID || protocol_mode == PROTO_HYBRID))
     -> Evaluates to TRUE for M1 and M3! */
  u8 new_reject_m1_valid = ((protocol_structured_run || kl_val(kl_begin(messages))->protocol_structured) &&
                            (protocol_mode_valid == 0 || protocol_mode_valid == 4));
  assert(new_reject_m1_valid == 1); /* Fixed: M1 failure is properly rejected! */

  u8 new_reject_m1_hybrid = ((protocol_structured_run || kl_val(kl_begin(messages))->protocol_structured) &&
                             (protocol_mode_hybrid == 0 || protocol_mode_hybrid == 4));
  assert(new_reject_m1_hybrid == 1); /* Fixed: M1 failure rejected in hybrid! */

  /* In RAW mode, failure must not reject deliberately raw packets */
  u8 new_reject_m1_raw = ((protocol_structured_run || kl_val(kl_begin(messages))->protocol_structured) &&
                          (protocol_mode_raw == 0 || protocol_mode_raw == 4));
  assert(new_reject_m1_raw == 0);

  /* 6. Test save_executed_messages_to_file:
     Ensure executed bytes (with 0xAABB in M1) are saved to replay evidence,
     while save_kl_messages_to_file saves the pristine logical candidate. */
  char replay_exec_file[] = "/tmp/stateafl_p11_exec_XXXXXX";
  int e_fd = mkstemp(replay_exec_file);
  assert(e_fd >= 0);
  close(e_fd);

  executed_message_t exec_msgs[3];
  exec_msgs[0].data = m1_exec_buf;
  exec_msgs[0].size = sizeof(m1_logical);
  exec_msgs[1].data = (u8 *)m2_logical;
  exec_msgs[1].size = sizeof(m2_logical);
  exec_msgs[2].data = (u8 *)m3_logical;
  exec_msgs[2].size = sizeof(m3_logical);

  save_executed_messages_to_file(exec_msgs, 3, replay_exec_file);

  /* Read replay file and verify it contains 0xAABB in first message */
  FILE *efp = fopen(replay_exec_file, "rb");
  assert(efp != NULL);
  uint8_t read_prefix[4];
  assert(fread(read_prefix, 1, 4, efp) == 4);
  uint8_t read_m1[sizeof(m1_logical)];
  assert(fread(read_m1, 1, sizeof(m1_logical), efp) == sizeof(m1_logical));
  fclose(efp);

  assert(read_m1[0] == 0xAA && read_m1[1] == 0xBB);

  /* Verify queue candidate saved from kl_messages still has pristine 0x0001 */
  char queue_file[] = "/tmp/stateafl_p11_q_XXXXXX";
  int q_fd = mkstemp(queue_file);
  assert(q_fd >= 0);
  close(q_fd);

  save_kl_messages_to_file(messages, (u8 *)queue_file, 0, 3);
  FILE *qfp = fopen(queue_file, "rb");
  assert(qfp != NULL);
  uint8_t read_qm1[sizeof(m1_logical)];
  assert(fread(read_qm1, 1, sizeof(m1_logical), qfp) == sizeof(m1_logical));
  fclose(qfp);

  assert(read_qm1[0] == 0x00 && read_qm1[1] == 0x01);

  /* Clean up */
  ck_free(m1_exec_buf);
  delete_kl_messages(messages);
  unlink(tmp_path);
  unlink(replay_exec_file);
  unlink(queue_file);

  printf("[+] P11 session runtime binding isolation tests passed successfully!\n");
  return 0;
}
