/* Runtime API regression and sanitizer harness. No network/server required. */
#include "protocol_runtime.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)){fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);} } while(0)
static uint8_t rp[]={0x81,0x0a,0,17,1,0,0,5,1,12,0x0c,2,0,0,123,0x19,77};
static uint8_t wi[]={0x81,0x0a,0,8,1,0,0x10,8};
static uint32_t state=0x51a7u;
static uint32_t random_n(uint32_t n){state^=state<<13;state^=state>>17;state^=state<<5;return n?state%n:0;}
static unsigned script[32],ns,at;
static uint32_t scripted(uint32_t n){unsigned v=at<ns?script[at++]:0;return n?v%n:0;}
static void draws(unsigned a,unsigned b,unsigned c,unsigned d){script[0]=a;script[1]=b;script[2]=c;script[3]=d;ns=4;at=0;}
static size_t append(uint8_t *b,size_t p,const uint8_t *wire,size_t n){b[p]=(uint8_t)n;b[p+1]=n>>8;b[p+2]=n>>16;b[p+3]=n>>24;memcpy(b+p+4,wire,n);return p+4+n;}
static void set_len(uint8_t *b,size_t n){b[2]=n>>8;b[3]=n;}
static int field(uint8_t *b,size_t n,const char *loc,size_t expected,size_t width){char err[256];size_t o,w;int r=proto_bacnet_field(b,n,loc,&o,&w,err,sizeof(err));return r==1 && o==expected && w==width;}
static proto_engine *engine(const char *p,const char *s){char err[512];proto_engine *e=proto_load(p,s,err,sizeof(err));if(!e){fprintf(stderr,"load: %s\n",err);exit(1);}return e;}
static void records_tests(void){
  uint8_t *b=calloc(1,MAX_FILE+1);size_t count=0,n=append(b,0,rp,sizeof(rp));char err[256];
  CHECK(proto_records_validate(b,n,&count,err,sizeof(err))==0 && count==1);
  CHECK(proto_records_validate(NULL,0,&count,err,sizeof(err))<0);
  CHECK(proto_records_validate(b,n,NULL,err,sizeof(err))<0);
  for(size_t i=0;i<n;i++)CHECK(proto_records_validate(b,i,&count,err,sizeof(err))<0);
  b[0]=0;CHECK(proto_records_validate(b,n,&count,err,sizeof(err))<0);
  memset(b,0,MAX_FILE+1);b[0]=0xe3;b[1]=0xff;CHECK(proto_records_validate(b,65511,&count,err,sizeof(err))==0);
  b[0]++;CHECK(proto_records_validate(b,65512,&count,err,sizeof(err))<0);
  n=0;for(unsigned i=0;i<64;i++)n=append(b,n,wi,sizeof(wi));CHECK(proto_records_validate(b,n,&count,err,sizeof(err))==0 && count==64);
  n=append(b,n,wi,sizeof(wi));CHECK(proto_records_validate(b,n,&count,err,sizeof(err))<0);
  CHECK(proto_records_validate(b,MAX_FILE+1,&count,err,sizeof(err))<0);free(b);
}
static void codec_tests(void){
  char err[256];size_t o,w;uint8_t b[1024];
  CHECK(field(rp,sizeof(rp),"apdu.invoke",8,1));CHECK(field(rp,sizeof(rp),"bacnet.object",11,4));CHECK(field(rp,sizeof(rp),"bacnet.property",16,1));
  CHECK(proto_bacnet_field(wi,sizeof(wi),"apdu.invoke",&o,&w,err,sizeof(err))==0);
  CHECK(proto_bacnet_field(NULL,8,"apdu.invoke",&o,&w,err,sizeof(err))<0);
  CHECK(proto_bacnet_field(rp,sizeof(rp),NULL,&o,&w,err,sizeof(err))<0);
  CHECK(proto_bacnet_field(rp,sizeof(rp),"bvlc.length",NULL,&w,err,sizeof(err))<0);
  CHECK(proto_bacnet_field(rp,sizeof(rp),"abs:",&o,&w,err,sizeof(err))<0);
  CHECK(proto_bacnet_field(rp,sizeof(rp),"abs:+1",&o,&w,err,sizeof(err))<0);
  CHECK(proto_bacnet_field(rp,sizeof(rp),"abs:18446744073709551616",&o,&w,err,sizeof(err))<0);
  const uint8_t routed[]={1,0x28,0,1,1,42,0,2,1,43,255};
  memcpy(b,rp,4);memcpy(b+4,routed,sizeof(routed));memcpy(b+15,rp+6,sizeof(rp)-6);size_t n=sizeof(rp)+9;set_len(b,n);
  CHECK(field(b,n,"apdu.invoke",17,1));CHECK(field(b,n,"bacnet.object",20,4));
  for(size_t i=0;i<n;i++){uint8_t old[1024];memcpy(old,b,n);set_len(old,i);CHECK(proto_bacnet_field(old,i,"apdu.invoke",&o,&w,err,sizeof(err))<0);}
  memcpy(b,rp,sizeof(rp));b[17]=0x2c;b[18]=0;b[19]=0;b[20]=0;b[21]=5;set_len(b,22);CHECK(field(b,22,"bacnet.array",18,4));
  memcpy(b,rp,sizeof(rp));b[15]=0x1d;b[16]=4;b[17]=0;b[18]=0;b[19]=0;b[20]=77;set_len(b,21);CHECK(field(b,21,"bacnet.property",17,4));
  memcpy(b,wi,sizeof(wi));b[8]=0x0b;b[9]=0;b[10]=0;b[11]=2;b[12]=0x1b;b[13]=0;b[14]=0;b[15]=1;set_len(b,16);CHECK(proto_bacnet_field(b,16,"apdu.content",&o,&w,err,sizeof(err))<0);
  memcpy(b,wi,sizeof(wi));b[7]=9;b[8]=0x3e;b[9]=0x4f;set_len(b,10);CHECK(proto_bacnet_field(b,10,"bvlc.length",&o,&w,err,sizeof(err))<0);
  b[8]=0x12;set_len(b,9);CHECK(proto_bacnet_field(b,9,"bvlc.length",&o,&w,err,sizeof(err))<0);
  b[8]=0x65;b[9]=255;b[10]=255;b[11]=255;b[12]=255;b[13]=255;set_len(b,14);CHECK(proto_bacnet_field(b,14,"apdu.content",&o,&w,err,sizeof(err))<0);
}
static void mutation_tests(const char *p,const char *s){
  proto_engine *e=engine(p,s);uint8_t input[2048],candidate[2048],wire[1024];size_t n=append(input,0,rp,sizeof(rp)),outn,count;const uint8_t *out;char err[512];
  memcpy(candidate,rp,sizeof(rp));candidate[11]=0x12;candidate[12]=0x34;candidate[13]=0x56;candidate[14]=0x78;
  draws(0,0,0,0);CHECK(proto_mutate(e,input,n,candidate,sizeof(rp),PROTO_VALID,PROTO_CONTENT,scripted,&out,&outn,err,sizeof(err))==0);
  CHECK(outn==n && !memcmp(out+4+11,candidate+11,4));CHECK(out[4+15]==0x19 && out[4+16]==77);
  draws(0,0,0,0);CHECK(proto_mutate(e,input,n,NULL,0,PROTO_VALID,PROTO_CONTENT,scripted,&out,&outn,err,sizeof(err))<0 && out==NULL && outn==0);
  n=append(input,0,wi,sizeof(wi));memcpy(candidate,wi,sizeof(wi));uint8_t limits[]={0x0b,0,0,10,0x1b,0,0,20};memcpy(candidate+8,limits,8);
  draws(0,0,1,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_CONTENT,scripted,&out,&outn,err,sizeof(err))==0);
  CHECK(outn==20 && !memcmp(out+12,limits,8));CHECK(out[7]==16);
  n=append(input,0,wi,sizeof(wi));n=append(input,n,rp,sizeof(rp));memcpy(candidate,wi,sizeof(wi));memcpy(candidate+sizeof(wi),rp,sizeof(rp));
  draws(0,0,1,0);CHECK(proto_mutate(e,input,n,candidate,sizeof(wi)+sizeof(rp),PROTO_VALID,PROTO_CONTENT,scripted,&out,&outn,err,sizeof(err))==0 && outn==n && out[7]==8);
  n=append(input,0,rp,sizeof(rp));draws(0,1,0,0);CHECK(proto_mutate(e,input,n,rp,sizeof(rp),PROTO_NEAR_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))==0);
  memcpy(wire,out+4,outn-4);CHECK(wire[3]==sizeof(rp)+1);CHECK(proto_before_send(e,wire,outn-4,err,sizeof(err))<0);CHECK(wire[3]==sizeof(rp)+1);
  n=append(input,0,rp,sizeof(rp));n=append(input,n,wi,sizeof(wi));draws(0,3,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))==0);
  CHECK(out[4+7]==8 && proto_records_validate(out,outn,&count,err,sizeof(err))==0 && count==2);
  n=append(input,0,rp,sizeof(rp));n=append(input,n,wi,sizeof(wi));draws(0,1,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))==0 && outn==12);
  n=append(input,0,wi,sizeof(wi));draws(0,2,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))==0 && outn==24);
  draws(0,0,1,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))==0 && outn==33 && out[4+9]==12);
  n=0;for(unsigned i=0;i<4;i++)n=append(input,n,wi,sizeof(wi));draws(0,2,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))<0);
  n=0;for(unsigned i=0;i<32;i++)n=append(input,n,wi,sizeof(wi));draws(0,0,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))<0 && strstr(err,"max_messages"));
  n=0;for(unsigned i=0;i<5;i++)n=append(input,n,wi,sizeof(wi));draws(0,0,0,0);CHECK(proto_mutate(e,input,n,candidate,16,PROTO_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))<0);
  CHECK(proto_mutate(e,input,n,candidate,16,PROTO_RAW,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))<0);
  CHECK(proto_mutate(NULL,input,n,candidate,16,PROTO_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))<0);
  proto_free(e);
}
static void session_tests(const char *p,const char *s){
  proto_engine *e=engine(p,s),*other=engine(p,s);char err[256];uint8_t b[32],ack[]={0x81,0x0a,0,20,1,0,0x30,55,12,0x0c,2,0,0,123,0x19,77,0x3e,0x75,0,0x3f},records[64];size_t n=append(records,0,rp,sizeof(rp)),outn;const uint8_t *out;
  memcpy(b,rp,sizeof(rp));CHECK(proto_before_send(e,b,sizeof(rp),err,sizeof(err))<0);
  proto_after_response(e,ack,sizeof(ack));CHECK(proto_before_send(e,b,sizeof(rp),err,sizeof(err))==0 && b[8]==55);
  memcpy(b,rp,sizeof(rp));CHECK(proto_before_send(other,b,sizeof(rp),err,sizeof(err))<0);
  /* Offline candidates retain placeholders; only live I/O binds real replies.
   * Simulating a candidate must preserve the already established live cache. */
  draws(0,0,0,0);CHECK(proto_mutate(e,records,n,rp,sizeof(rp),PROTO_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))==0);
  CHECK(proto_before_send(e,b,sizeof(rp),err,sizeof(err))==0 && b[8]==55);
  proto_session_begin(e);memcpy(b,rp,sizeof(rp));CHECK(proto_before_send(e,b,sizeof(rp),err,sizeof(err))<0);
  proto_free(e);proto_free(other);
}
static void binding_transaction_tests(const char *p,const char *s){
  proto_engine *e=engine(p,s);char err[256];uint8_t b[sizeof(rp)];
  const uint8_t ack[]={0x81,0x0a,0,20,1,0,0x30,55,12,0x0c,2,0,0,123,0x19,77,0x3e,0x75,0,0x3f};
  memcpy(b,rp,sizeof(b));
  /* The sequence binding writes invoke=0 before the unresolved object binding.
   * A rejection must preserve every original byte and not consume a number. */
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))<0);
  CHECK(!memcmp(b,rp,sizeof(b)) && strstr(err,"unresolved session"));
  CHECK(proto_before_send(e,NULL,sizeof(b),err,sizeof(err))<0);
  CHECK(proto_before_send(e,b,0,err,sizeof(err))<0);
  CHECK(proto_before_send(e,b,65508,err,sizeof(err))<0);
  CHECK(!memcmp(b,rp,sizeof(b)));
  proto_after_response(e,ack,sizeof(ack));
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))==0 && b[8]==0 && !*err);
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))==0 && b[8]==1);
  b[3]++;uint8_t invalid[sizeof(b)];memcpy(invalid,b,sizeof(b));
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))<0);
  CHECK(!memcmp(b,invalid,sizeof(b)));
  proto_session_begin(e);memcpy(b,rp,sizeof(b));
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))<0);
  CHECK(!memcmp(b,rp,sizeof(b)));
  proto_free(e);
}
static void dependency_tests(const char *p,const char *s,const char *loc,uint64_t expected){
  proto_engine *e=engine(p,s);uint8_t records[64];size_t n=append(records,0,rp,sizeof(rp)),outn,o,w;const uint8_t *out;char err[256];
  draws(0,1,0,0);CHECK(proto_mutate(e,records,n,rp,sizeof(rp),PROTO_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))==0);
  CHECK(proto_bacnet_field(out+4,outn-4,loc,&o,&w,err,sizeof(err))==1 && w<=8);
  uint64_t actual=0;for(size_t i=0;i<w;i++)actual=(actual<<8)|out[4+o+i];CHECK(actual==expected);proto_free(e);
}
static void limit_tests(const char *p,const char *s){
  proto_engine *e=engine(p,s);uint8_t records[64];size_t n=append(records,0,rp,sizeof(rp)),outn;const uint8_t *out;char err[256];
  draws(0,1,0,0);CHECK(proto_mutate(e,records,n,rp,sizeof(rp),PROTO_VALID,PROTO_HEAD,scripted,&out,&outn,err,sizeof(err))==0 && outn==21);
  n=append(records,0,wi,sizeof(wi));draws(0,0,1,0);CHECK(proto_mutate(e,records,n,rp,sizeof(rp),PROTO_VALID,PROTO_SEQUENCE,scripted,&out,&outn,err,sizeof(err))<0 && strstr(err,"max_bytes"));proto_free(e);
}
static void sequence_number_tests(const char *p,const char *s){
  proto_engine *e=engine(p,s);char err[256];uint8_t b[sizeof(rp)];memcpy(b,rp,sizeof(rp));
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))==0 && b[8]==0);
  CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))==0 && b[8]==1);
  proto_session_begin(e);CHECK(proto_before_send(e,b,sizeof(b),err,sizeof(err))==0 && b[8]==0);proto_free(e);
}
static void random_tests(const char *p,const char *s,unsigned iterations){
  proto_engine *e=engine(p,s);uint8_t b[1024],records[2048],candidate[1024];char err[256];size_t count,o,w,outn;const uint8_t *out;
  const char *loc[]={"apdu.invoke","bvlc.length","bacnet.object","apdu.content","bacnet.array","abs:0","abs:9999999999999999999999999999999999","unknown"};
  for(unsigned i=0;i<iterations;i++){
    size_t n=random_n(sizeof(b));for(size_t j=0;j<n;j++)b[j]=random_n(256);
    if(i%3==0 && n>=8){b[0]=0x81;b[1]=10;set_len(b,n);b[4]=1;b[5]=random_n(256);}
    CHECK(proto_records_validate(b,n,&count,err,sizeof(err))<=0);
    CHECK(proto_bacnet_field(b,n,loc[random_n(sizeof(loc)/sizeof(*loc))],&o,&w,err,sizeof(err))<=1);
    proto_after_response(e,b,n);(void)proto_before_send(e,b,n,err,sizeof(err));
    size_t rn=append(records,0,i%2?rp:wi,i%2?sizeof(rp):sizeof(wi));
    if(i%4==0 && n)rn=append(records,rn,b,n);
    for(size_t j=0;j<sizeof(candidate);j++)candidate[j]=random_n(256);
    int r=proto_mutate(e,records,rn,candidate,random_n(sizeof(candidate)),random_n(3),1u<<random_n(3),random_n,&out,&outn,err,sizeof(err));
    CHECK(r==0 || r==-1);if(r==0)CHECK(proto_records_validate(out,outn,&count,err,sizeof(err))==0);else CHECK(out==NULL && outn==0);
  }proto_free(e);
}
int main(int argc,char **argv){
  if(argc<4)return 3;
  if(!strcmp(argv[1],"load")){char err[512]={0};proto_engine *e=proto_load(argv[2],argv[3],err,sizeof(err));if(!e){if(!*err)return 4;fprintf(stderr,"%s\n",err);return 2;}proto_free(e);return 0;}
  if(!strcmp(argv[1],"session"))session_tests(argv[2],argv[3]);
  else if(!strcmp(argv[1],"binding_transaction"))binding_transaction_tests(argv[2],argv[3]);
  else if(!strcmp(argv[1],"dependency") && argc==6)dependency_tests(argv[2],argv[3],argv[4],strtoull(argv[5],NULL,10));
  else if(!strcmp(argv[1],"limits"))limit_tests(argv[2],argv[3]);
  else if(!strcmp(argv[1],"sequence_number"))sequence_number_tests(argv[2],argv[3]);
  else {records_tests();codec_tests();mutation_tests(argv[2],argv[3]);random_tests(argv[2],argv[3],argc>4?strtoul(argv[4],NULL,10):10000);}
  printf("{\"checks\":%u,\"status\":\"passed\"}\n",checks);return 0;
}
