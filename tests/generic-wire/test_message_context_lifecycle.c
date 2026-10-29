#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"

int main(void) {
  printf("[*] Testing P08 message context lifecycle and ownership...\n");

  /* 1. NULL safety */
  delete_kl_messages(NULL);
  assert(get_last_message(NULL) == NULL);

  /* 2. Create temporary file with known message content */
  char tmp_path[] = "/tmp/stateafl_p08_test_XXXXXX";
  int fd = mkstemp(tmp_path);
  assert(fd >= 0);

  const uint8_t msg1[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t msg2[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  assert(write(fd, msg1, sizeof(msg1)) == sizeof(msg1));
  assert(write(fd, msg2, sizeof(msg2)) == sizeof(msg2));
  close(fd);

  /* 3. Setup regions corresponding to msg1 and msg2 */
  region_t regions[2];
  regions[0].start_byte = 0;
  regions[0].end_byte = 3;
  regions[1].start_byte = 4;
  regions[1].end_byte = 8;

  /* 4. Construct independent message list */
  klist_t(lms) *messages = construct_kl_messages((u8 *)tmp_path, regions, 2);
  assert(messages != NULL);
  assert(messages->size == 2);

  kliter_t(lms) *it = kl_begin(messages);
  assert(it != kl_end(messages));
  message_t *m1 = kl_val(it);
  assert(m1->msize == 4);
  assert(memcmp(m1->mdata, msg1, 4) == 0);

  it = kl_next(it);
  assert(it != kl_end(messages));
  message_t *m2 = kl_val(it);
  assert(m2->msize == 5);
  assert(memcmp(m2->mdata, msg2, 5) == 0);

  kliter_t(lms) *last = get_last_message(messages);
  assert(last != NULL);
  assert(kl_val(last) == m2);

  /* 5. Save message list to file and verify round-trip byte identity */
  char out_path[] = "/tmp/stateafl_p08_out_XXXXXX";
  int out_fd = mkstemp(out_path);
  assert(out_fd >= 0);
  close(out_fd);

  u32 saved_len = save_kl_messages_to_file(messages, (u8 *)out_path, 0, 2);
  assert(saved_len == sizeof(msg1) + sizeof(msg2));

  FILE *f = fopen(out_path, "rb");
  assert(f != NULL);
  uint8_t readback[9];
  assert(fread(readback, 1, 9, f) == 9);
  fclose(f);

  assert(memcmp(readback, msg1, 4) == 0);
  assert(memcmp(readback + 4, msg2, 5) == 0);

  /* 6. Clean up message list and ensure pointer nullification */
  delete_kl_messages(messages);
  messages = NULL;

  /* Double delete on NULL is safe */
  delete_kl_messages(messages);

  unlink(tmp_path);
  unlink(out_path);

  printf("[+] P08 tests passed successfully!\n");
  return 0;
}
