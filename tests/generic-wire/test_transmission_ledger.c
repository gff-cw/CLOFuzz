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

int main(void) {
  printf("[*] Testing P19 transmission ledger and complete_messages serialization...\n");

  /* 1. Setup temporary message list with 3 messages */
  char tmp_path[] = "/tmp/stateafl_p19_test_XXXXXX";
  int fd = mkstemp(tmp_path);
  assert(fd >= 0);

  const uint8_t m1_data[] = {0x11, 0x22, 0x33, 0x44};             /* len 4 */
  const uint8_t m2_data[] = {0xAA, 0xBB, 0xCC};                   /* len 3 */
  const uint8_t m3_data[] = {0x55, 0x66, 0x77, 0x88, 0x99, 0x00}; /* len 6 (incomplete tail) */

  assert(write(fd, m1_data, sizeof(m1_data)) == sizeof(m1_data));
  assert(write(fd, m2_data, sizeof(m2_data)) == sizeof(m2_data));
  assert(write(fd, m3_data, sizeof(m3_data)) == sizeof(m3_data));
  close(fd);

  region_t regions[3];
  regions[0].start_byte = 0;
  regions[0].end_byte = 3;
  regions[1].start_byte = 4;
  regions[1].end_byte = 6;
  regions[2].start_byte = 7;
  regions[2].end_byte = 12;

  klist_t(lms) *messages = construct_kl_messages((u8 *)tmp_path, regions, 3);
  assert(messages != NULL);
  assert(messages->size == 3);

  /* 2. Simulate transmission:
        m1 sent completely (4 bytes)
        m2 sent completely (3 bytes)
        m3 attempted, but only 2 of 6 bytes sent before socket error
  */
  u32 messages_sent = 0;
  u32 complete_messages = 0;
  u32 total_bytes_sent = 0;
  u32 partial_bytes_tail = 0;
  u8  is_transmission_complete = 1;

  kliter_t(lms) *it = kl_begin(messages);
  /* m1 */
  messages_sent++;
  complete_messages++;
  total_bytes_sent += kl_val(it)->msize;

  /* m2 */
  it = kl_next(it);
  messages_sent++;
  complete_messages++;
  total_bytes_sent += kl_val(it)->msize;

  /* m3 (partial error: 2 bytes committed of 6) */
  it = kl_next(it);
  messages_sent++;
  int n_simulated = 2;
  if (n_simulated != (int)kl_val(it)->msize) {
    if (n_simulated > 0) {
      total_bytes_sent += n_simulated;
      partial_bytes_tail = n_simulated;
    }
    is_transmission_complete = 0;
  }

  assert(messages_sent == 3);
  assert(complete_messages == 2);
  assert(total_bytes_sent == 9); /* 4 + 3 + 2 */
  assert(partial_bytes_tail == 2);
  assert(is_transmission_complete == 0);

  /* 3. Verify saving queue file with complete_messages:
        Must only contain m1 and m2 (4 + 3 = 7 bytes), not the uncompleted m3! */
  char queue_file[] = "/tmp/stateafl_p19_q_XXXXXX";
  int q_fd = mkstemp(queue_file);
  assert(q_fd >= 0);
  close(q_fd);

  u32 full_len = save_kl_messages_to_file(messages, (u8 *)queue_file, 0, complete_messages);
  assert(full_len == 7); /* 4 + 3 */

  FILE *q_fp = fopen(queue_file, "rb");
  assert(q_fp != NULL);
  fseek(q_fp, 0, SEEK_END);
  long actual_q_len = ftell(q_fp);
  fclose(q_fp);
  assert(actual_q_len == 7);

  /* 4. Verify replayable queue file with complete_messages:
        Must contain LE32 prefixes only for m1 and m2 (4+4 + 4+3 = 15 bytes) */
  char replay_file[] = "/tmp/stateafl_p19_rep_XXXXXX";
  int rep_fd = mkstemp(replay_file);
  assert(rep_fd >= 0);
  close(rep_fd);

  u32 rep_len = save_kl_messages_to_file(messages, (u8 *)replay_file, 1, complete_messages);
  assert(rep_len == 15); /* (4+4) + (4+3) */

  /* 5. Verify convert_kl_messages_to_regions with complete_messages:
        Must generate exactly 2 regions matching the 7 byte queue file */
  u32 reg_count = 0;
  region_t *conv_regions = convert_kl_messages_to_regions(messages, &reg_count, complete_messages);
  assert(reg_count == 2);
  assert(conv_regions != NULL);
  assert(conv_regions[0].start_byte == 0);
  assert(conv_regions[0].end_byte == 3);
  assert(conv_regions[1].start_byte == 4);
  assert(conv_regions[1].end_byte == 6);
  ck_free(conv_regions);

  /* 6. Verify zero complete messages rejection:
        If complete_messages == 0, saving should produce 0 bytes */
  char zero_file[] = "/tmp/stateafl_p19_zero_XXXXXX";
  int z_fd = mkstemp(zero_file);
  assert(z_fd >= 0);
  close(z_fd);

  u32 zero_len = save_kl_messages_to_file(messages, (u8 *)zero_file, 0, 0);
  assert(zero_len == 0);

  delete_kl_messages(messages);
  unlink(tmp_path);
  unlink(queue_file);
  unlink(replay_file);
  unlink(zero_file);

  printf("[+] P19 transmission ledger tests passed successfully!\n");
  return 0;
}
