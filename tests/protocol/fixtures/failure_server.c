/* A local test double with an intentional assertion failure. It verifies
 * sample saving/replay; it is not a defect in BACnet Stack. */
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc,char **argv) {
  if(argc!=2)return 2;
  int fd=socket(AF_INET,SOCK_DGRAM,0),one=1;
  if(fd<0)return 3;
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
  struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons(atoi(argv[1]))};
  if(bind(fd,(void*)&address,sizeof(address)))return 4;
  unsigned char *state=malloc(1024),*buffer=malloc(65536);
  if(!state || !buffer)return 5;
  for(unsigned i=0;i<1024;i++)state[i]=(i*113)^0x95;
  for(unsigned i=0;i<8;i++){
    struct sockaddr_in peer;socklen_t length=sizeof(peer);
    ssize_t n=recvfrom(fd,buffer,65536,0,(void*)&peer,&length);
    if(n<4)continue;
    /* This intentional test assertion exercises the fuzzer's existing fault
     * saving path when near_valid changes one length constraint. */
    assert(((unsigned)buffer[2]<<8|buffer[3])==(unsigned)n);
    state[0]++;
    unsigned char response[2]={state[0],state[57]};
    sendto(fd,response,sizeof(response),0,(void*)&peer,length);
  }
  free(buffer);free(state);close(fd);return 0;
}
