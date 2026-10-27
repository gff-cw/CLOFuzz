#define _POSIX_C_SOURCE 200809L
/* Local message-file regression source. No sockets, targets or mutations. */
#include "alloc-inl.h"
#include "aflnet.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks;
static pid_t owner;
static char scratch[] = "/tmp/stateafl-message-files-XXXXXX";
static char seed_path[256], output_path[256], missing_path[256];
/* Keep caller-owned test lists reachable while a fatal child exits. */
static klist_t(lms) *volatile failure_list;
static message_t *volatile detached_message;
static char *volatile detached_payload;

static void cleanup(void) {
  if (getpid() != owner) return;
  if (seed_path[0]) (void)unlink(seed_path);
  if (output_path[0]) (void)unlink(output_path);
  (void)rmdir(scratch);
}

static void failed(const char *expression, int line) {
  fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, line, expression);
  exit(EXIT_FAILURE);
}

#define CHECK(expression) do { \
  checks++; \
  if (!(expression)) failed(#expression, __LINE__); \
} while (0)

static void path_name(char *output, size_t capacity, const char *name) {
  int length = snprintf(output, capacity, "%s/%s", scratch, name);
  CHECK(length > 0 && (size_t)length < capacity);
}

static void write_file(const char *path, const void *data, size_t length) {
  FILE *stream = fopen(path, "wb");
  CHECK(stream != NULL);
  CHECK(!length || fwrite(data, 1, length, stream) == length);
  CHECK(fclose(stream) == 0);
}

static void file_equals(const char *path, const void *expected, size_t length) {
  unsigned char actual[128];
  FILE *stream = fopen(path, "rb");
  CHECK(stream != NULL && length <= sizeof(actual));
  CHECK(!length || fread(actual, 1, length, stream) == length);
  CHECK(!length || memcmp(actual, expected, length) == 0);
  CHECK(fgetc(stream) == EOF && !ferror(stream));
  CHECK(fclose(stream) == 0);
}

static message_t *append_message(klist_t(lms) *list, const void *data, size_t length) {
  message_t *message;
  CHECK(list != NULL && length > 0 && length <= INT_MAX);
  message = ck_alloc(sizeof(*message));
  message->mdata = ck_alloc((u32)length);
  message->msize = (int)length;
  memcpy(message->mdata, data, length);
  *kl_pushp(lms, list) = message;
  return message;
}

typedef void (*fatal_action)(void *context);

/* Signals, unexpected return, and sanitizer exits are not controlled errors. */
static void expect_fatal(fatal_action action, void *context) {
  FILE *diagnostics = tmpfile();
  char text[16384];
  size_t length;
  pid_t child, waited;
  int status;
  CHECK(diagnostics != NULL);
  CHECK(fflush(NULL) == 0);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    if (dup2(fileno(diagnostics), STDERR_FILENO) < 0) _exit(3);
    action(context);
    _exit(0);
  }
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  CHECK(waited == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
  CHECK(fseek(diagnostics, 0, SEEK_SET) == 0);
  length = fread(text, 1, sizeof(text) - 1, diagnostics);
  CHECK(!ferror(diagnostics) && length < sizeof(text) - 1);
  text[length] = 0;
  CHECK(strstr(text, "PROGRAM ABORT") || strstr(text, "SYSTEM ERROR"));
  CHECK(!strstr(text, "AddressSanitizer") && !strstr(text, "LeakSanitizer") &&
        !strstr(text, "UndefinedBehaviorSanitizer") && !strstr(text, "runtime error:"));
  CHECK(fclose(diagnostics) == 0);
}

typedef struct {
  u8 *path;
  region_t *regions;
  u32 count;
} construct_request;

static void construct_action(void *context) {
  construct_request *request = context;
  klist_t(lms) *list = construct_kl_messages(request->path, request->regions, request->count);
  delete_kl_messages(list);
}

typedef struct {
  klist_t(lms) *list;
  u8 *path;
  u8 replay;
  u32 maximum;
} save_request;

static void save_action(void *context) {
  save_request *request = context;
  (void)save_kl_messages_to_file(request->list, request->path,
                                request->replay, request->maximum);
}

static void test_construct_and_save(void) {
  static const unsigned char source[] = {'a', 0, 'b', 'C', 'D', 'x'};
  static const unsigned char replay[] = {3, 0, 0, 0, 'a', 0, 'b',
                                         2, 0, 0, 0, 'C', 'D'};
  region_t regions[] = {{.start_byte = 0, .end_byte = 2},
                        {.start_byte = 3, .end_byte = 4}};
  klist_t(lms) *list;
  kliter_t(lms) *first, *second;
  char *first_data, *second_data;
  write_file(seed_path, source, sizeof(source));
  list = construct_kl_messages((u8 *)seed_path, regions, 2);
  CHECK(list != NULL && list->size == 2);
  first = kl_begin(list);
  second = kl_next(first);
  CHECK(second != kl_end(list) && kl_next(second) == kl_end(list));
  CHECK(kl_val(first)->msize == 3 && kl_val(second)->msize == 2);
  CHECK(!memcmp(kl_val(first)->mdata, source, 3));
  CHECK(!memcmp(kl_val(second)->mdata, source + 3, 2));
  CHECK(!kl_val(first)->protocol_structured && !kl_val(second)->protocol_structured);
  CHECK(regions[0].start_byte == 0 && regions[0].end_byte == 2 &&
        regions[1].start_byte == 3 && regions[1].end_byte == 4);
  first_data = kl_val(first)->mdata;
  second_data = kl_val(second)->mdata;
  kl_val(first)->protocol_structured = 1;

  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 1, 2) == sizeof(replay));
  file_equals(output_path, replay, sizeof(replay));
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 0, UINT_MAX) == 5);
  file_equals(output_path, source, 5);
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 1, 1) == 7);
  file_equals(output_path, replay, 7);
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 0, 1) == 3);
  file_equals(output_path, source, 3);
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 1, 0) == 0);
  file_equals(output_path, "", 0);
  CHECK(list->size == 2 && kl_begin(list) == first && kl_next(first) == second);
  CHECK(kl_val(first)->mdata == first_data && kl_val(second)->mdata == second_data);
  CHECK(kl_val(first)->msize == 3 && kl_val(second)->msize == 2);
  CHECK(kl_val(first)->protocol_structured == 1);
  CHECK(!memcmp(first_data, source, 3) && !memcmp(second_data, source + 3, 2));
  file_equals(seed_path, source, sizeof(source));
  delete_kl_messages(list);
}

static void test_empty_and_limited_lists(void) {
  klist_t(lms) *empty, *list = kl_init(lms);
  static const unsigned char replay[] = {1, 0, 0, 0, 'q'};
  CHECK(list != NULL);
  write_file(seed_path, "unused", 6);
  empty = construct_kl_messages((u8 *)seed_path, NULL, 0);
  CHECK(empty != NULL && empty->size == 0 && kl_begin(empty) == kl_end(empty));
  CHECK(save_kl_messages_to_file(empty, (u8 *)output_path, 1, UINT_MAX) == 0);
  file_equals(output_path, "", 0);
  CHECK(save_kl_messages_to_file(empty, (u8 *)output_path, 0, UINT_MAX) == 0);
  file_equals(output_path, "", 0);
  delete_kl_messages(empty);

  append_message(list, "q", 1);
  *kl_pushp(lms, list) = NULL;
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 1, 1) == sizeof(replay));
  file_equals(output_path, replay, sizeof(replay));
  CHECK(list->size == 2 && kl_val(kl_next(kl_begin(list))) == NULL);
  delete_kl_messages(list);

  list = kl_init(lms);
  CHECK(list != NULL);
  *kl_pushp(lms, list) = NULL;
  CHECK(save_kl_messages_to_file(list, (u8 *)output_path, 1, 0) == 0);
  file_equals(output_path, "", 0);
  delete_kl_messages(list);
}

static void test_sequential_region_lengths(void) {
  region_t regions[] = {{.start_byte = 5, .end_byte = 6},
                        {.start_byte = 20, .end_byte = 20}};
  klist_t(lms) *list;
  write_file(seed_path, "abcd", 4);
  list = construct_kl_messages((u8 *)seed_path, regions, 2);
  CHECK(list->size == 2);
  CHECK(kl_val(kl_begin(list))->msize == 2);
  CHECK(!memcmp(kl_val(kl_begin(list))->mdata, "ab", 2));
  CHECK(kl_val(kl_next(kl_begin(list)))->msize == 1);
  CHECK(kl_val(kl_next(kl_begin(list)))->mdata[0] == 'c');
  delete_kl_messages(list);
}

static void test_construct_rejections(void) {
  region_t region = {.start_byte = 0, .end_byte = 0};
  construct_request request = {(u8 *)seed_path, &region, 1};
  write_file(seed_path, "abc", 3);
  request.path = NULL;
  expect_fatal(construct_action, &request);
  request.path = (u8 *)missing_path;
  expect_fatal(construct_action, &request);
  request.path = (u8 *)seed_path;
  request.regions = NULL;
  expect_fatal(construct_action, &request);
  request.regions = &region;
  region.start_byte = -1;
  expect_fatal(construct_action, &request);
  region.start_byte = 0;
  region.end_byte = -1;
  expect_fatal(construct_action, &request);
  region.start_byte = 2;
  region.end_byte = 1;
  expect_fatal(construct_action, &request);
  region.start_byte = 0;
  region.end_byte = MAX_ALLOC;
  expect_fatal(construct_action, &request);
  region.end_byte = 3; /* Source has only three bytes. */
  expect_fatal(construct_action, &request);
  {
    region_t regions[] = {{.start_byte = 0, .end_byte = 1},
                          {.start_byte = 2, .end_byte = 3}};
    request.regions = regions;
    request.count = 2;
    expect_fatal(construct_action, &request);
  }
  request.path = (u8 *)scratch; /* Directory open/read must fail in a controlled way. */
  request.regions = &region;
  request.count = 1;
  region.end_byte = 0;
  expect_fatal(construct_action, &request);
  file_equals(seed_path, "abc", 3);
}

static void reject_save(save_request *request) {
  static const char sentinel[] = "existing output must survive invalid metadata";
  write_file(output_path, sentinel, sizeof(sentinel) - 1);
  failure_list = request->list;
  expect_fatal(save_action, request);
  failure_list = NULL;
  file_equals(output_path, sentinel, sizeof(sentinel) - 1);
}

static void test_save_rejections(void) {
  klist_t(lms) *list = kl_init(lms);
  message_t *message = append_message(list, "x", 1);
  char *payload = message->mdata;
  save_request request = {list, (u8 *)output_path, 1, 1};
  request.list = NULL;
  reject_save(&request);
  request.list = list;
  request.path = (u8 *)scratch; /* A directory cannot be opened as an output file. */
  reject_save(&request);
  request.path = NULL;
  reject_save(&request);
  request.path = (u8 *)output_path;
  detached_message = message;
  kl_val(kl_begin(list)) = NULL;
  reject_save(&request);
  kl_val(kl_begin(list)) = message;
  detached_message = NULL;
  detached_payload = payload;
  message->mdata = NULL;
  reject_save(&request);
  message->mdata = payload;
  detached_payload = NULL;
  message->msize = 0;
  reject_save(&request);
  message->msize = -1;
  reject_save(&request);
  message->msize = MAX_ALLOC;
  reject_save(&request); /* Header plus body exceeds the allocator bound. */
  message->msize = 1;
  CHECK(message->mdata == payload && payload[0] == 'x');
  delete_kl_messages(list);

  list = kl_init(lms);
  append_message(list, "a", 1)->msize = MAX_ALLOC / 2 + 1;
  append_message(list, "b", 1)->msize = MAX_ALLOC / 2 + 1;
  request.list = list;
  request.replay = 0;
  request.maximum = 2;
  /* Invalid lengths are rejected in preflight, before payload access or a large allocation. */
  reject_save(&request);
  kl_val(kl_begin(list))->msize = MAX_ALLOC / 2 - 2;
  kl_val(kl_next(kl_begin(list)))->msize = MAX_ALLOC / 2 - 2;
  request.replay = 1;
  reject_save(&request); /* Both LE32 headers count toward the total. */
  delete_kl_messages(list);
}

int main(void) {
  owner = getpid();
  CHECK(atexit(cleanup) == 0);
  CHECK(mkdtemp(scratch) != NULL);
  path_name(seed_path, sizeof(seed_path), "seed");
  path_name(output_path, sizeof(output_path), "output");
  path_name(missing_path, sizeof(missing_path), "missing");
  test_construct_and_save();
  test_empty_and_limited_lists();
  test_sequential_region_lengths();
  test_construct_rejections();
  test_save_rejections();
  printf("Local message-file checks passed: %u\n", checks);
  return EXIT_SUCCESS;
}
