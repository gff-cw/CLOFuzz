#include <sys/types.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "state-tracer.h"

int main(int argc, char** argv) {


    int id;

    if(argc > 1) {

      // Reusing SHM from id

      errno = 0;
      id = strtol(argv[1], NULL, 10);

      if(errno != 0) {
        fprintf(stderr, "Usage: %s <shm-id>\n", argv[0]);
        exit(1);
      }

    } else {

      // Creating new SHM

      id = shmget(IPC_PRIVATE, sizeof(struct state_shared), IPC_CREAT | 0666);

      printf("New SHM id: %d\n", id);
    }


    struct state_shared * p = shmat(id, NULL, 0);

    if(p == (void*)-1) {
      fprintf(stderr, "Unable to attach to shared memory\n");
      exit(1);
    }

    printf("MAGIC: 0x%08x\n", p->magic);
    printf("VERSION: %u\n", p->version);
    printf("CAPACITY: %u\n", p->capacity);
    printf("STATUS: %u\n", p->status);
    printf("TRUNCATED: %u\n", p->truncated);
    printf("TOTAL STATES: %u\n", p->total_states);
    printf("ITERATIONS: %d\n", p->iterations);

    printf("SEQ LEN: %d\n", p->seq_len);

    printf("SEQ: ");
    for(int i=0; i<p->seq_len; i++) {
      printf("%d ", p->seq[i]);
    }
    printf("\n");

}

