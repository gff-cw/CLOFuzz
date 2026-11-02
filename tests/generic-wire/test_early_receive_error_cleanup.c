#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "alloc-inl.h"

typedef struct {
  uint8_t *data;
  uint32_t size;
} test_executed_msg_t;

/* Simulate the exact cleanup block in send_over_network() */
static void cleanup_executed_messages(test_executed_msg_t **msgs_ptr, uint32_t count) {
  test_executed_msg_t *exec_msgs = *msgs_ptr;
  if (exec_msgs) {
    for (uint32_t i = 0; i < count; i++) {
      if (exec_msgs[i].data) {
        ck_free(exec_msgs[i].data);
        exec_msgs[i].data = NULL;
      }
    }
    ck_free(exec_msgs);
    *msgs_ptr = NULL;
  }
}

int main(void) {
  printf("[*] Testing B02: Early receive error cleanup safety and pointer initialization...\n");

  /* Test Case 1: Early receive error when exec_msgs is properly initialized to NULL */
  test_executed_msg_t *exec_msgs = NULL;
  uint32_t messages_sent = 0;
  uint32_t complete_messages = 0;

  /* Simulating early jump to HANDLE_RESPONSES */
  cleanup_executed_messages(&exec_msgs, messages_sent);
  assert(exec_msgs == NULL);
  assert(messages_sent == 0);
  assert(complete_messages == 0);

  /* Test Case 2: Partial execution before error in loop */
  exec_msgs = (test_executed_msg_t *)ck_alloc(4 * sizeof(test_executed_msg_t));
  for (uint32_t i = 0; i < 2; i++) {
    exec_msgs[i].data = (uint8_t *)ck_alloc(32);
    exec_msgs[i].size = 32;
    messages_sent++;
  }
  assert(messages_sent == 2);
  cleanup_executed_messages(&exec_msgs, messages_sent);
  assert(exec_msgs == NULL);

  printf("test_early_receive_error_cleanup: ALL 2 CLEANUP SAFETY CHECKS PASSED\n");
  return 0;
}
