#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "alloc-inl.h"
#include "aflnet.h"

int main(void) {
  int a=socket(AF_INET,SOCK_DGRAM,0),b=socket(AF_INET,SOCK_DGRAM,0);
  assert(a>=0 && b>=0);
  struct sockaddr_in x={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)}, y=x;
  assert(!bind(a,(void*)&x,sizeof(x)) && !bind(b,(void*)&y,sizeof(y)));
  socklen_t n=sizeof(x);
  assert(!getsockname(a,(void*)&x,&n) && !getsockname(b,(void*)&y,&n));
  assert(!connect(a,(void*)&y,sizeof(y)) && !connect(b,(void*)&x,sizeof(x)));
  struct timeval timeout={.tv_usec=1000};
  char data[7000], copy[8000]; for(unsigned i=0;i<sizeof(data);i++) data[i]=i;
  assert(net_send(a,timeout,data,sizeof(data))==sizeof(data));
  assert(recv(b,copy,sizeof(copy),0)==sizeof(data));
  assert(!memcmp(data,copy,sizeof(data)));
  assert(send(b,data,sizeof(data),0)==sizeof(data));
  char *out=NULL; unsigned len=0;
  assert(!net_recv(a,timeout,10,&out,&len));
  assert(len==sizeof(data) && !memcmp(out,data,len));
  ck_free(out);out=NULL;len=0;
  assert(send(b,"abc",3,0)==3 && send(b,"defg",4,0)==4);
  assert(!net_recv(a,timeout,10,&out,&len));
  assert(len==7 && !memcmp(out,"abcdefg",7));ck_free(out);
  close(a);close(b);
  int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
  assert(net_send(pair[0],timeout,data,sizeof(data))==sizeof(data));
  out=NULL;len=0;assert(!net_recv(pair[1],timeout,10,&out,&len));
  assert(len==sizeof(data) && !memcmp(out,data,len));ck_free(out);close(pair[0]);close(pair[1]);
  klist_t(lms) *list=kl_init(lms);
  for(unsigned i=0;i<2;i++) { message_t *m=ck_alloc(sizeof(*m));m->msize=3;m->mdata=ck_alloc(3);memcpy(m->mdata,"abc",3);*kl_pushp(lms,list)=m; }
  char path[]="/tmp/stateafl-records-XXXXXX"; int fd=mkstemp(path);assert(fd>=0);close(fd);
  assert(save_kl_messages_to_file(list,(u8*)path,1,2)==14);
  assert(save_kl_messages_to_file(list,(u8*)path,1,1)==7);
  struct stat st;assert(!stat(path,&st) && st.st_size==7);
  FILE *f=fopen(path,"rb");assert(f && fread(copy,1,7,f)==7);fclose(f);
  assert(!memcmp(copy,"\3\0\0\0abc",7));unlink(path);delete_kl_messages(list);
  puts("PASS: atomic UDP, 7000-byte datagram, multi-datagram receive, TCP, LE32 records and truncation");
  return 0;
}
