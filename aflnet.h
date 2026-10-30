#ifndef __AFLNET_H
#define __AFLNET_H 1

#include <sys/time.h>
#include <sys/types.h>
#include "types.h"
#include "klist.h"
#include "khash.h"
#include <arpa/inet.h>
#include <poll.h>

typedef struct {
  int start_byte;                 /* The start byte, negative if unknown. */
  int end_byte;                   /* The last byte, negative if unknown. */
  char modifiable;                /* The modifiable flag. */
  unsigned int *state_sequence;   /* The annotation keeping the state feedback. */
  unsigned int state_count;       /* Number of states stored in state_sequence. */
} region_t;

typedef struct {
  char *mdata; /* Buffer keeping the message data */
  int msize;   /* Message size */
  unsigned char protocol_structured; /* Current M2 candidate; zero for legacy */
} message_t;

typedef struct {
  u32 id;                     /* state id */
  u8 is_covered;              /* has this state been covered */
  u32 paths;                  /* total number of paths exercising this state */
  u32 paths_discovered;       /* total number of new paths that have been discovered when this state is targeted/selected */
  u32 selected_times;         /* total number of times this state has been targeted/selected */
  u32 fuzzs;                  /* Total number of fuzzs (i.e., inputs generated) */
  u32 score;                  /* current score of the state */
  u32 selected_seed_index;    /* the recently selected seed index */
  void **seeds;               /* keeps all seeds reaching this state -- can be casted to struct queue_entry* */
  u32 seeds_count;            /* total number of seeds, it must be equal the size of the seeds array */
} state_info_t;

enum {
  /* 00 */ PRO_TCP,
  /* 01 */ PRO_UDP
};

enum {
  /* 00 */ INVALID_SELECTION,
  /* 01 */ RANDOM_SELECTION,
  /* 02 */ ROUND_ROBIN,
  /* 03 */ FAVOR
};

// Initialize klist linked list data structure
#define message_t_freer(x)
KLIST_INIT(lms, message_t *, message_t_freer)

KHASH_SET_INIT_INT(hs32)

// Initialize a hash table with int key and value is of type state_info_t
KHASH_INIT(hms, khint32_t, state_info_t *, 1, kh_int_hash_func, kh_int_hash_equal)

// Functions for extracting requests and responses

/*To add support for a new application protocol, please add corresponding function declartion and implementation
And update the code to handle -P option in the main function in afl-fuzz.c accordingly */

unsigned int* extract_response_codes_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_tls(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dns(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_sip(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_http(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
unsigned int* extract_response_codes_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);
extern unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref);

region_t* extract_requests_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_tls(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dns(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_sip(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_http(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
region_t* extract_requests_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);
extern region_t* (*extract_requests)(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref);

// Network communication functions

// Two wrappers for sending and receiving data over socket
typedef void (*net_recv_cb_t)(const uint8_t *buf, size_t len, int is_dgram, int truncated, void *user);

#define NET_RECV_OK              0
#define NET_RECV_ERROR           1
#define NET_RECV_BUDGET_EXCEEDED 2
#define NET_RECV_TIMED_OUT       3

#define DEFAULT_MAX_RESPONSE_BUDGET (1 * 1024 * 1024)

void net_set_response_budget(unsigned int budget);
unsigned int net_get_response_budget(void);

/* P18: Time normalization and I/O status accounting */
typedef enum {
  NET_IO_STATUS_NONE = 0,
  NET_IO_STATUS_OK,
  NET_IO_STATUS_EOF,
  NET_IO_STATUS_TIMEOUT,
  NET_IO_STATUS_SYSCALL_ERR,
  NET_IO_STATUS_BUDGET_EXCEEDED
} net_io_status_t;

net_io_status_t net_get_last_io_status(void);
const char *net_io_status_to_str(net_io_status_t status);

static inline struct timeval normalize_timeval(struct timeval tv) {
  struct timeval norm;
  norm.tv_sec = tv.tv_sec + (tv.tv_usec / 1000000);
  norm.tv_usec = tv.tv_usec % 1000000;
  return norm;
}

static inline struct timeval usecs_to_timeval(uint64_t usecs) {
  struct timeval tv;
  tv.tv_sec = (time_t)(usecs / 1000000ULL);
  tv.tv_usec = (suseconds_t)(usecs % 1000000ULL);
  return tv;
}

static inline uint64_t timeval_to_usecs(struct timeval tv) {
  struct timeval norm = normalize_timeval(tv);
  return (uint64_t)norm.tv_sec * 1000000ULL + (uint64_t)norm.tv_usec;
}

static inline int timeval_to_poll_ms(struct timeval tv) {
  struct timeval norm = normalize_timeval(tv);
  int ms = (int)(norm.tv_sec * 1000 + (norm.tv_usec + 999) / 1000);
  return ms;
}

int net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len);
int net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len);
int net_recv_with_cb(int sockfd, struct timeval timeout, int poll_w,
                     char **response_buf, unsigned int *len,
                     net_recv_cb_t cb, void *user);

// kl_messages manipulating functions

/* Read consecutive messages using the ordered region lengths, without seeking
 * to start_byte. fname is required; regions is required when region_count>0.
 * Each region requires 0 <= start_byte <= end_byte and length <= MAX_ALLOC.
 * Filename and regions are borrowed and must remain stable during the call.
 * Exact reads and a successful close are required; invalid input or I/O errors
 * use the existing fatal-error contract. Remaining file bytes are ignored.
 * On success, the caller owns the returned list and uses delete_kl_messages. */
klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count);

/* Free all items and delete kl_messages */
void delete_kl_messages(klist_t(lms) *kl_messages);

/* Get the last message in the linked list. As kl_messages->tail points to an empty item, we cannot use it to get the last message */
kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages);

/* Save at most max_count messages as raw bytes or LE32 length-prefixed records.
 * The list, messages and fname are borrowed and must remain stable during the
 * call. Validate only the selected prefix, including positive message lengths,
 * non-NULL payloads and a total no greater than MAX_ALLOC, before opening the
 * destination. Empty lists or max_count == 0 produce an empty file and return 0.
 * Returns serialized byte count; invalid metadata or I/O errors are fatal.
 * A write/close failure may leave a partial file; this is not atomic replacement. */
u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count);

/* Convert back a linked list of messages to regions to maintain the message sequence structure as much as possible */
region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count);

// Utility functions

/* Save regions' information to file for debugging purpose */
void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname);

/* Split a string using a delimiter */
int str_split(char* a_str, const char* a_delim, char **result, int a_count);

/* Remove unwanted characters from the right */
void str_rtrim(char* a_str);

/* Parse user provided server information to get IP address, transport protocol (TCP/UDP) and port number */
int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port);

/* Convert state sequence to string */
u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount);

/* Print the hexdump of a segment of a buffer preceded by a messsage */
void hexdump(unsigned char *msg, unsigned char * buf, int start, int end);

/* Reads a number of bytes from buf from offset into an unsigned int and returns it. May overflow*/
u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes);

#endif /* __AFLNET_H */
