/* Seventh-protocol loopback target. It validates packets independently of C grammar. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc,char **argv){
  if(argc!=2&&argc!=3)return 2;
  unsigned long port=strtoul(argv[1],NULL,10);if(port<1024||port>65535)return 2;
  int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return 3;
  int trace=argc==3?open(argv[2],O_WRONLY|O_CREAT|O_APPEND,0600):-1;
  if(argc==3&&trace<0){close(fd);return 3;}
  int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
  struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),
                           .sin_port=htons((uint16_t)port)};
  if(bind(fd,(void*)&addr,sizeof(addr))){close(fd);return 4;}
  struct timeval timeout={.tv_sec=0,.tv_usec=200000};
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  unsigned char data[2048];unsigned char *state=malloc(256);if(!state){close(fd);return 5;}
  for(unsigned i=0;i<256;i++)state[i]=(unsigned char)(i*13+7);
  int valid=0,invalid=0;
  for(unsigned i=0;i<32;i++){
    struct sockaddr_in peer;socklen_t peer_len=sizeof(peer);
    ssize_t n=recvfrom(fd,data,sizeof(data),0,(void*)&peer,&peer_len);
    if(n<0)break;
    int accepted=n>=7&&n<=14&&data[0]==0xa7&&data[3]==1&&
       ((((unsigned)data[1])<<8)|data[2])==(unsigned)n-3&&
       ((((unsigned)data[4])<<8)|data[5])!=0;
    if(accepted){
      valid++;state[0]^=data[4];state[1]^=data[5];state[2]+=data[6];
      if(n>=9)state[3]=(unsigned char)n;
      for(unsigned j=16;j<256;j++)state[j]=(unsigned char)(j*13+data[4]*7+data[5]*3+data[6]);
    }else invalid++;
    if(trace>=0)dprintf(trace,"{\"valid\":%s,\"size\":%zd}\n",accepted?"true":"false",n);
    unsigned char reply[2]={state[0],(unsigned char)(valid+invalid)};
    sendto(fd,reply,sizeof(reply),0,(void*)&peer,peer_len);
  }
  fprintf(stderr,"fixture valid=%d invalid=%d\n",valid,invalid);
  free(state);if(trace>=0)close(trace);close(fd);return 0;
}
