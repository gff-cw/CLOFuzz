/* Offline IEC104 APCI session tests; no sockets or service. */
#include "protocol_iec104_session.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s (%s)\n",__LINE__,#x,err);return 1; } } while(0)
static void number(unsigned char *p,unsigned n){n<<=1;p[0]=(unsigned char)n;p[1]=(unsigned char)(n>>8);}
int main(void){
 char err[256]={0};ies_session s,before;unsigned char i[]={0x68,14,0,0,0,0,100,1,6,0,1,0,0,0,0,20};
 unsigned char start[]={0x68,4,7,0,0,0},startcon[]={0x68,4,11,0,0,0};
 unsigned char ack[]={0x68,4,1,0,0,0},test[]={0x68,4,0x43,0,0,0},testcon[]={0x68,4,0x83,0,0,0};
 ies_reset(&s,0);CHECK(ies_configure(&s,2,2,100,50,20,1000,err,sizeof(err))==0);
 CHECK(ies_before_send(&s,start,sizeof(start),1,err,sizeof(err))==0);
 CHECK(ies_after_response(&s,startcon,sizeof(startcon),2,err,sizeof(err))==0);
 s.send_next=s.send_acked=32767;s.receive_next=s.receive_acked=32767;
 CHECK(ies_before_send(&s,i,sizeof(i),3,err,sizeof(err))==0);CHECK(i[2]==0xfe&&i[3]==0xff&&i[4]==0xfe&&i[5]==0xff);
 CHECK(ies_before_send(&s,i,sizeof(i),8,err,sizeof(err))==0);CHECK(i[2]==0&&i[3]==0&&s.send_next==1);
 before=s;unsigned char old[sizeof(i)];memcpy(old,i,sizeof(i));CHECK(ies_before_send(&s,i,sizeof(i),9,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s))&&!memcmp(i,old,sizeof(i)));
 number(ack+4,0);CHECK(ies_after_response(&s,ack,sizeof(ack),10,err,sizeof(err))==0);CHECK(s.send_acked==0&&s.first_unacked_at==8);
 number(ack+4,2);before=s;CHECK(ies_after_response(&s,ack,sizeof(ack),11,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 number(ack+4,1);before=s;CHECK(ies_after_response(&s,ack,sizeof(ack),58,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 CHECK(ies_after_response(&s,ack,sizeof(ack),57,err,sizeof(err))==0);
 /* Receive wrapping I frames; an outgoing S binds and clears receive debt. */
 number(i+2,32767);number(i+4,1);CHECK(ies_after_response(&s,i,sizeof(i),58,err,sizeof(err))==0);CHECK(s.receive_next==0);
 before=s;CHECK(ies_after_response(&s,i,sizeof(i),59,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 CHECK(ies_before_send(&s,ack,sizeof(ack),60,err,sizeof(err))==0);CHECK(ack[4]==0&&ack[5]==0&&s.receive_acked==0);
 CHECK(ies_before_send(&s,test,sizeof(test),61,err,sizeof(err))==0);CHECK(ies_after_response(&s,testcon,sizeof(testcon),62,err,sizeof(err))==0);
 /* t2 and t3 require S and TESTFR, respectively; failed sends are atomic. */
 number(i+2,0);CHECK(ies_after_response(&s,i,sizeof(i),63,err,sizeof(err))==0);before=s;memcpy(old,i,sizeof(i));
 CHECK(ies_before_send(&s,test,sizeof(test),83,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 CHECK(ies_before_send(&s,ack,sizeof(ack),83,err,sizeof(err))==0);
 before=s;memcpy(old,i,sizeof(i));CHECK(ies_before_send(&s,i,sizeof(i),1083,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s))&&!memcmp(old,i,sizeof(i)));
 CHECK(ies_before_send(&s,test,sizeof(test),1083,err,sizeof(err))==0);
 before=s;CHECK(ies_after_response(&s,testcon,sizeof(testcon),1133,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 /* A due receive ACK must remain possible when idle t3 has also elapsed. */
 ies_reset(&s,0);CHECK(ies_configure(&s,2,2,100,50,20,30,err,sizeof(err))==0);
 CHECK(ies_before_send(&s,start,sizeof(start),1,err,sizeof(err))==0);CHECK(ies_after_response(&s,startcon,sizeof(startcon),2,err,sizeof(err))==0);
 number(i+2,0);number(i+4,0);CHECK(ies_after_response(&s,i,sizeof(i),3,err,sizeof(err))==0);
 before=s;CHECK(ies_before_send(&s,test,sizeof(test),33,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 CHECK(ies_before_send(&s,ack,sizeof(ack),33,err,sizeof(err))==0);CHECK(s.receive_acked==1);
 CHECK(ies_before_send(&s,test,sizeof(test),34,err,sizeof(err))==0);
 ies_reset(&s,0);CHECK(ies_configure(&s,2,2,100,50,20,1000,err,sizeof(err))==0);before=s;CHECK(ies_before_send(&s,start,sizeof(start),100,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 /* The host uses UINT64_MAX when the monotonic clock is unavailable. */
 ies_reset(&s,0);before=s;CHECK(ies_before_send(&s,start,sizeof(start),UINT64_MAX,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 ies_reset(&s,UINT64_MAX);before=s;CHECK(ies_before_send(&s,start,sizeof(start),1,err,sizeof(err))<0);CHECK(!memcmp(&s,&before,sizeof(s)));
 puts("PASS: IEC104 sequence wrap, windows, timers and atomic rejection");return 0;
}
