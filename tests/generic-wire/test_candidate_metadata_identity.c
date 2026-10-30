#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "execution_observation.h"

static void serialize_candidate_metadata(char *buf, size_t max_len,
                                         u32 candidate_id,
                                         u32 exec_id,
                                         u64 execution_counter,
                                         u8 purpose,
                                         const char *forkserver,
                                         u8 structured,
                                         u32 target_state,
                                         u32 parent_seed_id,
                                         const char *layer,
                                         const char *stage,
                                         u32 complete_messages,
                                         u32 messages_sent,
                                         u32 total_bytes_sent,
                                         u32 partial_bytes_tail,
                                         u8 is_transmission_complete,
                                         u32 logical_digest,
                                         u32 executed_digest) {
  snprintf(buf, max_len,
           "{\"format_version\":2,"
           "\"candidate_id\":%u,"
           "\"exec_id\":%u,"
           "\"execution_counter\":%llu,"
           "\"purpose\":\"%s\","
           "\"forkserver\":\"%s\","
           "\"structured\":%s,"
           "\"target_state\":%u,"
           "\"parent_seed_id\":%u,"
           "\"layer\":\"%s\","
           "\"stage\":\"%s\","
           "\"sent_messages\":%u,"
           "\"attempted_messages\":%u,"
           "\"total_bytes_sent\":%u,"
           "\"partial_bytes_tail\":%u,"
           "\"is_transmission_complete\":%s,"
           "\"logical_digest\":\"0x%08x\","
           "\"executed_digest\":\"0x%08x\","
           "\"execution_identity_verified\":false}\n",
           candidate_id,
           exec_id,
           (unsigned long long)execution_counter,
           exec_purpose_to_str(purpose),
           forkserver,
           structured ? "true" : "false",
           target_state,
           parent_seed_id,
           layer,
           stage,
           complete_messages,
           messages_sent,
           total_bytes_sent,
           partial_bytes_tail,
           is_transmission_complete ? "true" : "false",
           logical_digest,
           executed_digest);
}

int main(void) {
  printf("[*] Testing P24 candidate execution identity linking and metadata provenance...\n");

  /* 1. Purpose mapping check */
  assert(strcmp(exec_purpose_to_str(EXEC_PURPOSE_ORIGINAL), "coverage") == 0);
  assert(strcmp(exec_purpose_to_str(EXEC_PURPOSE_CONFIRMATION), "confirmation") == 0);
  assert(strcmp(exec_purpose_to_str(EXEC_PURPOSE_CALIBRATION), "calibration") == 0);
  assert(strcmp(exec_purpose_to_str(EXEC_PURPOSE_SYNC), "sync") == 0);
  assert(strcmp(exec_purpose_to_str(EXEC_PURPOSE_UNKNOWN), "unknown") == 0);

  /* 2. Original coverage candidate metadata */
  char orig_json[1024];
  serialize_candidate_metadata(orig_json, sizeof(orig_json),
                               42,          /* candidate_id */
                               1001,        /* exec_id */
                               5500,        /* execution_counter */
                               EXEC_PURPOSE_ORIGINAL,
                               "coverage",
                               1,           /* structured */
                               7,           /* target_state */
                               12,          /* parent_seed_id */
                               "CONTENT",
                               "havoc",
                               3,           /* complete_messages */
                               3,           /* messages_sent */
                               128,         /* total_bytes_sent */
                               0,           /* partial_bytes_tail */
                               1,           /* is_transmission_complete */
                               0x12345678,  /* logical_digest */
                               0x12345678); /* executed_digest */

  assert(strstr(orig_json, "\"format_version\":2") != NULL);
  assert(strstr(orig_json, "\"candidate_id\":42") != NULL);
  assert(strstr(orig_json, "\"exec_id\":1001") != NULL);
  assert(strstr(orig_json, "\"purpose\":\"coverage\"") != NULL);
  assert(strstr(orig_json, "\"forkserver\":\"coverage\"") != NULL);
  assert(strstr(orig_json, "\"structured\":true") != NULL);
  assert(strstr(orig_json, "\"target_state\":7") != NULL);
  assert(strstr(orig_json, "\"parent_seed_id\":12") != NULL);
  assert(strstr(orig_json, "\"layer\":\"CONTENT\"") != NULL);
  assert(strstr(orig_json, "\"stage\":\"havoc\"") != NULL);
  assert(strstr(orig_json, "\"sent_messages\":3") != NULL);
  assert(strstr(orig_json, "\"attempted_messages\":3") != NULL);
  assert(strstr(orig_json, "\"total_bytes_sent\":128") != NULL);
  assert(strstr(orig_json, "\"is_transmission_complete\":true") != NULL);
  assert(strstr(orig_json, "\"logical_digest\":\"0x12345678\"") != NULL);
  assert(strstr(orig_json, "\"executed_digest\":\"0x12345678\"") != NULL);
  assert(strstr(orig_json, "\"execution_identity_verified\":false") != NULL);

  /* 3. Replay confirmation execution links to same candidate_id but distinct exec_id and purpose */
  char replay_json[1024];
  serialize_candidate_metadata(replay_json, sizeof(replay_json),
                               42,          /* same logical candidate_id */
                               1002,        /* distinct execution exec_id */
                               5501,        /* execution_counter */
                               EXEC_PURPOSE_CONFIRMATION,
                               "state",
                               1,           /* structured */
                               7,           /* target_state */
                               12,          /* parent_seed_id */
                               "CONTENT",
                               "havoc",
                               3,           /* complete_messages */
                               3,           /* messages_sent */
                               128,         /* total_bytes_sent */
                               0,           /* partial_bytes_tail */
                               1,           /* is_transmission_complete */
                               0x12345678,  /* logical_digest */
                               0xabcdef01); /* executed_digest (bound copy) */

  assert(strstr(replay_json, "\"candidate_id\":42") != NULL);
  assert(strstr(replay_json, "\"exec_id\":1002") != NULL);
  assert(strstr(replay_json, "\"purpose\":\"confirmation\"") != NULL);
  assert(strstr(replay_json, "\"forkserver\":\"state\"") != NULL);
  assert(strstr(replay_json, "\"logical_digest\":\"0x12345678\"") != NULL);
  assert(strstr(replay_json, "\"executed_digest\":\"0xabcdef01\"") != NULL);

  /* 4. Partial transmission candidate metadata */
  char partial_json[1024];
  serialize_candidate_metadata(partial_json, sizeof(partial_json),
                               43,          /* candidate_id */
                               1003,        /* exec_id */
                               5502,        /* execution_counter */
                               EXEC_PURPOSE_ORIGINAL,
                               "coverage",
                               1,           /* structured */
                               7,           /* target_state */
                               12,          /* parent_seed_id */
                               "HEAD",
                               "havoc",
                               2,           /* complete_messages */
                               3,           /* messages_sent */
                               95,          /* total_bytes_sent */
                               15,          /* partial_bytes_tail */
                               0,           /* is_transmission_complete == 0 */
                               0x98765432,  /* logical_digest */
                               0x55555555); /* executed_digest */

  assert(strstr(partial_json, "\"sent_messages\":2") != NULL);
  assert(strstr(partial_json, "\"attempted_messages\":3") != NULL);
  assert(strstr(partial_json, "\"total_bytes_sent\":95") != NULL);
  assert(strstr(partial_json, "\"partial_bytes_tail\":15") != NULL);
  assert(strstr(partial_json, "\"is_transmission_complete\":false") != NULL);

  printf("[+] P24 candidate metadata execution identity tests passed successfully!\n");
  return 0;
}
