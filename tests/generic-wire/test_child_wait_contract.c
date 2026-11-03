/* Compile-only in the current review. Future execution uses scripted syscalls
   against the production helpers; it never starts or signals a real target. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int scripted_clock_gettime(clockid_t, struct timespec *);
static int scripted_poll(struct pollfd *, nfds_t, int);
static ssize_t scripted_read(int, void *, size_t);
static ssize_t scripted_write(int, const void *, size_t);
static pid_t scripted_waitpid(pid_t, int *, int);
static int scripted_kill(pid_t, int);
static int scripted_nanosleep(const struct timespec *, struct timespec *);
#define clock_gettime scripted_clock_gettime
#define poll scripted_poll
#define read scripted_read
#define write scripted_write
#define waitpid scripted_waitpid
#define kill scripted_kill
#define nanosleep scripted_nanosleep
#define main stateafl_program_main
#include "../../afl-fuzz.c"
#undef main
#undef clock_gettime
#undef poll
#undef read
#undef write
#undef waitpid
#undef kill
#undef nanosleep

typedef struct {
  int result;
  int error;
  int status;
} syscall_step;

static uint64_t fake_now;
static syscall_step wait_steps[8], io_steps[8], poll_steps[8];
static unsigned wait_count, wait_index, io_count, io_index, poll_count, poll_index;
static unsigned kill_count, sleep_count;
static pid_t last_killed;
static int last_signal;
static unsigned char io_bytes[4], written_bytes[4];
static size_t io_offset, written_offset;
static int poll_silent;

static void reset_script(void) {
  fake_now = 100;
  memset(wait_steps, 0, sizeof(wait_steps));
  memset(io_steps, 0, sizeof(io_steps));
  memset(poll_steps, 0, sizeof(poll_steps));
  wait_count = wait_index = io_count = io_index = poll_count = poll_index = 0;
  kill_count = sleep_count = 0;
  io_offset = written_offset = 0;
  last_killed = 0;
  last_signal = poll_silent = 0;
  stop_soon = child_timed_out = 0;
  child_pid = 4321;
  errno = 0;
}

static int scripted_clock_gettime(clockid_t clock, struct timespec *now) {
  assert(clock == CLOCK_MONOTONIC && now);
  now->tv_sec = fake_now / 1000;
  now->tv_nsec = (fake_now % 1000) * 1000000;
  return 0;
}

static int scripted_poll(struct pollfd *fds, nfds_t count, int timeout) {
  assert(count == 1 && fds && timeout > 0 && timeout <= 20);
  if (poll_index < poll_count) {
    syscall_step step = poll_steps[poll_index++];
    if (step.result < 0) { errno = step.error; return -1; }
    if (!step.result) { fake_now += timeout; return 0; }
  } else if (poll_silent) {
    fake_now += timeout;
    return 0;
  }
  fds->revents = fds->events;
  return 1;
}

static ssize_t scripted_read(int fd, void *buf, size_t len) {
  assert(fd == 91 && io_index < io_count);
  syscall_step step = io_steps[io_index++];
  if (step.result < 0) { errno = step.error; return -1; }
  assert((size_t)step.result <= len && io_offset + step.result <= sizeof(io_bytes));
  memcpy(buf, io_bytes + io_offset, step.result);
  io_offset += step.result;
  return step.result;
}

static ssize_t scripted_write(int fd, const void *buf, size_t len) {
  assert(fd == 92 && io_index < io_count);
  syscall_step step = io_steps[io_index++];
  if (step.result < 0) { errno = step.error; return -1; }
  assert((size_t)step.result <= len && written_offset + step.result <= sizeof(written_bytes));
  memcpy(written_bytes + written_offset, buf, step.result);
  written_offset += step.result;
  return step.result;
}

static pid_t scripted_waitpid(pid_t pid, int *status, int options) {
  assert(pid == 4321 && options == WNOHANG && status);
  assert(wait_index < 2000); /* A nonterminating production loop fails the future test. */
  syscall_step step = wait_index < wait_count ? wait_steps[wait_index] : (syscall_step){0};
  wait_index++;
  if (step.result < 0) { errno = step.error; return -1; }
  if (step.result) { *status = step.status; return pid; }
  return 0;
}

static int scripted_kill(pid_t pid, int signal_number) {
  assert(pid > 0 && signal_number == SIGKILL);
  kill_count++;
  last_killed = pid;
  last_signal = signal_number;
  return 0;
}

static int scripted_nanosleep(const struct timespec *pause, struct timespec *remaining) {
  assert(pause && pause->tv_sec == 0 && pause->tv_nsec == 1000000 && !remaining);
  sleep_count++;
  fake_now++;
  return 0;
}

int main(void) {
  int status;
  execution_wait_budget_t budget;

  /* An already exited direct child is collected once, preserving its status. */
  reset_script();
  status = -1;
  budget = (execution_wait_budget_t){.deadline = 200};
  wait_steps[0] = (syscall_step){1, 0, 7 << 8}; wait_count = 1;
  assert(reap_execution_child(4321, &status, &budget) == 1);
  assert(status == (7 << 8) && wait_index == 1 && child_pid == 0 && !kill_count);

  /* EINTR does not consume a status or turn into a second blocking wait. */
  reset_script();
  budget = (execution_wait_budget_t){.deadline = 200};
  wait_steps[0] = (syscall_step){-1, EINTR, 0};
  wait_steps[1] = (syscall_step){1, 0, SIGTERM}; wait_count = 2;
  assert(reap_execution_child(4321, &status, &budget) == 1);
  assert(status == SIGTERM && wait_index == 2 && !kill_count && child_pid == 0);

  /* ECHILD is an explicit ownership failure, never a second PID probe loop. */
  reset_script();
  budget = (execution_wait_budget_t){.deadline = 200};
  wait_steps[0] = (syscall_step){-1, ECHILD, 0}; wait_count = 1;
  assert(reap_execution_child(4321, &status, &budget) == -1 && errno == ECHILD);
  assert(wait_index == 1 && !kill_count);

  /* Cancellation still collects an available zombie before attempting a kill. */
  reset_script(); stop_soon = 1;
  budget = (execution_wait_budget_t){.deadline = 200};
  wait_steps[0] = (syscall_step){1, 0, 0}; wait_count = 1;
  assert(reap_execution_child(4321, &status, &budget) == 1 && !kill_count);

  /* A live child on cancellation is killed by its positive PID, then reaped. */
  reset_script(); stop_soon = 1;
  budget = (execution_wait_budget_t){.deadline = 200};
  wait_steps[1] = (syscall_step){1, 0, SIGKILL}; wait_count = 2;
  assert(reap_execution_child(4321, &status, &budget) == 1);
  assert(kill_count == 1 && last_killed == 4321 && last_signal == SIGKILL);
  assert(!child_timed_out && status == SIGKILL && child_pid == 0);

  /* A child that never becomes waitable cannot turn timeout cleanup unbounded. */
  reset_script();
  budget = (execution_wait_budget_t){.deadline = 102};
  assert(reap_execution_child(4321, &status, &budget) == -1 && errno == ETIMEDOUT);
  assert(child_timed_out && kill_count == 1 && sleep_count <= 1002);
  assert(fake_now == budget.cleanup_deadline);

  /* A preexisting cleanup budget is shared, never renewed by another phase. */
  reset_script();
  budget = (execution_wait_budget_t){.deadline = 90, .cleanup_deadline = 103};
  assert(reap_execution_child(4321, &status, &budget) == -1 && errno == ETIMEDOUT);
  assert(fake_now == 103 && !kill_count);

  /* Forkserver partial reads and EINTR only publish an entire status/PID word. */
  reset_script();
  budget = (execution_wait_budget_t){.deadline = 200};
  uint32_t word = 0x12345678u, expected = 4321;
  memcpy(io_bytes, &expected, 4);
  poll_steps[0] = (syscall_step){-1, EINTR, 0}; poll_count = 1;
  io_steps[0] = (syscall_step){1, 0, 0};
  io_steps[1] = (syscall_step){-1, EINTR, 0};
  io_steps[2] = (syscall_step){3, 0, 0}; io_count = 3;
  assert(transfer_execution_word(91, &word, 0, &budget, NULL) == 1);
  assert(word == expected && io_index == 3 && !kill_count);

  reset_script();
  budget = (execution_wait_budget_t){.deadline = 200};
  word = 0x12345678u;
  io_steps[0] = (syscall_step){2, 0, 0}; io_steps[1] = (syscall_step){0, 0, 0}; io_count = 2;
  assert(transfer_execution_word(91, &word, 0, &budget, NULL) == -1 && errno == EPIPE);
  assert(word == 0x12345678u); /* Never expose a partial positive child PID. */

  reset_script();
  budget = (execution_wait_budget_t){.deadline = 200};
  word = 0x12345678u;
  io_steps[0] = (syscall_step){-1, EINTR, 0};
  io_steps[1] = (syscall_step){4, 0, 0}; io_count = 2;
  assert(transfer_execution_word(92, &word, 1, &budget, NULL) == 1);
  assert(written_offset == 4 && !memcmp(written_bytes, &word, 4));

  /* PID handshakes are timed too; an unknown PID never becomes kill(-1, ...). */
  reset_script(); child_pid = -1; poll_silent = 1;
  struct forkserver fake_fsrv = {.forksrv_pid = 6789};
  budget = (execution_wait_budget_t){.deadline = 102};
  assert(transfer_execution_word(91, &word, 0, &budget, &fake_fsrv) == -1);
  assert(errno == ETIMEDOUT && kill_count == 1 && last_killed == 6789);
  assert(child_timed_out && fake_now == budget.cleanup_deadline);

  reset_script(); child_pid = 0; poll_silent = 1;
  budget = (execution_wait_budget_t){.deadline = 102};
  assert(transfer_execution_word(91, &word, 0, &budget, NULL) == -1 && errno == ETIMEDOUT);
  assert(!kill_count);

  reset_script(); stop_soon = 1;
  budget = (execution_wait_budget_t){.deadline = 200};
  assert(transfer_execution_word(91, &word, 0, &budget, NULL) == 0);
  assert(!kill_count && !io_index);

  reset_script();
  assert(reap_execution_child(0, &status, &budget) == -1 && errno == EINVAL);
  assert(reap_execution_child(-1, &status, &budget) == -1 && errno == EINVAL);
  assert(reap_execution_child(4321, NULL, &budget) == -1 && errno == EINVAL);
  assert(reap_execution_child(4321, &status, NULL) == -1 && errno == EINVAL);
  assert(transfer_execution_word(-1, &word, 0, &budget, NULL) == -1 && errno == EINVAL);
  assert(transfer_execution_word(91, NULL, 0, &budget, NULL) == -1 && errno == EINVAL);
  assert(transfer_execution_word(91, &word, 0, NULL, NULL) == -1 && errno == EINVAL);
  assert(!wait_index && !kill_count);
  return 0;
}
