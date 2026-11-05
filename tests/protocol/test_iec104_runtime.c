/* Offline runtime integration of control traffic while interrogation is pending. */
#include "protocol_runtime.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s (%s)\n",__LINE__,#x,err);return 1; } } while(0)
static unsigned completed(proto_engine *e){char b[8192];unsigned n=0;proto_write_stats(e,"/tmp/stateafl-iec104-runtime-stats.json");FILE *f=fopen("/tmp/stateafl-iec104-runtime-stats.json","rb");if(!f)return 0;size_t z=fread(b,1,sizeof(b)-1,f);fclose(f);b[z]=0;char *p=strstr(b,"\"completed_responses\":");if(p)sscanf(p,"\"completed_responses\":%u",&n);return n;}
int main(void){
 char err[512]={0};proto_engine *e=proto_load("protocols/iec60870_5_104/protocol_ir.json","protocols/iec60870_5_104/state_ir.json",err,sizeof(err));CHECK(e);
 unsigned char start[]={0x68,4,7,0,0,0},startcon[]={0x68,4,11,0,0,0};
 unsigned char req[]={0x68,14,0,0,0,0,100,1,6,0,1,0,0,0,0,20};
 unsigned char con[]={0x68,14,0,0,2,0,100,1,7,0,1,0,0,0,0,20};
 unsigned char term[]={0x68,14,2,0,2,0,100,1,10,0,1,0,0,0,0,20};
 unsigned char s[]={0x68,4,1,0,0,0},ack[]={0x68,4,1,0,2,0};
 unsigned char test[]={0x68,4,0x43,0,0,0},testcon[]={0x68,4,0x83,0,0,0};
 CHECK(proto_before_send(e,start,sizeof(start),err,sizeof(err))==0);proto_after_response(e,startcon,sizeof(startcon));
 CHECK(proto_before_send(e,req,sizeof(req),err,sizeof(err))==0);unsigned n=completed(e);
 CHECK(proto_before_send(e,s,sizeof(s),err,sizeof(err))==0);proto_after_response(e,ack,sizeof(ack));CHECK(completed(e)==n);
 CHECK(proto_before_send(e,test,sizeof(test),err,sizeof(err))==0);proto_after_response(e,testcon,sizeof(testcon));CHECK(completed(e)==n+1);
 proto_after_response(e,con,sizeof(con));CHECK(completed(e)==n+2);
 CHECK(proto_before_send(e,s,sizeof(s),err,sizeof(err))==0);CHECK(s[4]==2);
 proto_after_response(e,term,sizeof(term));
 proto_free(e);puts("PASS: IEC104 runtime control frames during pending interrogation");return 0;
}
