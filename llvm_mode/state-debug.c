#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "state-tracer.h"

int main(int argc, char** argv) {


    int id;

    if(argc > 1) {

      // Reusing SHM from id

      errno = 0;
      char *end;
      long parsed = strtol(argv[1], &end, 10);

      if(errno != 0 || !*argv[1] || *end || parsed < 0 || parsed > INT_MAX) {
        fprintf(stderr, "Usage: %s <shm-id>\n", argv[0]);
        exit(1);
      }
      id = (int)parsed;

    } else {

      // Creating new SHM

      id = shmget(IPC_PRIVATE, sizeof(struct state_shared), IPC_CREAT | 0600);
      if (id < 0) { perror("shmget"); return 1; }

      printf("New SHM id: %d\n", id);
    }


    struct shmid_ds info;
    if (shmctl(id, IPC_STAT, &info) < 0 || info.shm_segsz != sizeof(struct state_shared)) {
      fprintf(stderr, "Shared segment size does not match tracer ABI %u\n", STATE_SHARED_VERSION);
      return 1;
    }
    struct state_shared * p = shmat(id, NULL, 0);

    if(p == (void*)-1) {
      fprintf(stderr, "Unable to attach to shared memory\n");
      exit(1);
    }

    if (argc <= 1) {
      memset(p, 0, sizeof(*p));
      p->magic = STATE_SHARED_MAGIC;
      p->version = STATE_SHARED_VERSION;
      p->capacity = MAX_NUM_STATES;
      p->exec_id = 1;
    }
    uint32_t status = __atomic_load_n(&p->status, __ATOMIC_ACQUIRE);
    if (p->magic != STATE_SHARED_MAGIC || p->version != STATE_SHARED_VERSION ||
        p->capacity != MAX_NUM_STATES || p->seq_len > MAX_NUM_STATES ||
        p->boundary_count > MAX_NUM_STATES) {
      fprintf(stderr, "Invalid tracer header or out-of-range publication\n");
      shmdt(p);
      return 1;
    }

    printf("MAGIC: 0x%08x\n", p->magic);
    printf("VERSION: %u\n", p->version);
    printf("CAPACITY: %u\n", p->capacity);
    printf("STATUS: %u\n", status);
    printf("EXECUTION: %u (producer %u, pid %u, conflict %u)\n",
           p->exec_id, p->producer_exec_id, p->producer_pid, p->producer_conflict);
    printf("TRUNCATED: %u\n", p->truncated);
    printf("TOTAL STATES: %u\n", p->total_states);
    printf("ITERATIONS: %d\n", p->iterations);

    printf("SEQ LEN: %d\n", p->seq_len);

    printf("SEQ: ");
    uint32_t count = p->seq_len;
    if (count > MAX_NUM_STATES) count = MAX_NUM_STATES;
    for(uint32_t i=0; i<count; i++) {
      printf("%d ", p->seq[i]);
    }
    printf("\n");
    shmdt(p);
    return 0;

}

