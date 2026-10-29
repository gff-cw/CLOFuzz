/* Seventh protocol exercises the production proto_* dispatch without a codec. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "generic_wire.h"
#include "native_json.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
static const unsigned char seed[]={0xa7,0,5,1,0,1,0x55,0x66};
static uint32_t draws[8];
static size_t draw_at;
static uint32_t draw(uint32_t limit){uint32_t v=draws[draw_at<8?draw_at++:7];return limit?v%limit:0;}
static void set_draws(uint32_t a,uint32_t b,uint32_t c,uint32_t d){
  memset(draws,0,sizeof(draws));draws[0]=a;draws[1]=b;draws[2]=c;draws[3]=d;draw_at=0;
}
static size_t append(unsigned char *out,size_t at,const unsigned char *wire,size_t n){
  for(unsigned i=0;i<4;i++)out[at+i]=(unsigned char)(n>>(8*i));
  memcpy(out+at+4,wire,n);return at+4+n;
}
static size_t record_wire(const unsigned char *records,size_t n,size_t at,const unsigned char **wire){
  if(at+4>n)return 0;
  size_t size=(size_t)records[at]|((size_t)records[at+1]<<8)|
    ((size_t)records[at+2]<<16)|((size_t)records[at+3]<<24);
  if(!size||size>n-at-4)return 0;
  *wire=records+at+4;return size;
}
static int valid(const unsigned char *wire,size_t n){
  return n>=7&&n<=14&&wire[0]==0xa7&&wire[3]==1&&
    (((unsigned)wire[1]<<8)|wire[2])==n-3;
}
static int status(proto_engine *e,const char *path,const char *needle){
  proto_write_stats(e,path);FILE *f=fopen(path,"rb");if(!f)return 0;
  char buffer[1024];size_t n=fread(buffer,1,sizeof(buffer)-1,f);fclose(f);buffer[n]=0;
  const char *found=strstr(buffer,needle);size_t length=strlen(needle);
  if(!found)return 0;
  /* Numeric fragments must end at a JSON delimiter: 1 must not match 10. */
  if(length&&needle[length-1]>='0'&&needle[length-1]<='9'){
    const char *end=found+length;
    while(*end&&strchr(" \t\r\n",*end))end++;
    return *end==','||*end=='}';
  }
  return 1;
}
static proto_engine *variant(const char *source,const char *needle,const char *replacement,
                             int all,char *error,size_t cap){
  FILE *f=fopen(source,"rb");if(!f)return NULL;
  if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}long size=ftell(f);rewind(f);
  if(size<=0||size>65535){fclose(f);return NULL;}
  char *data=malloc((size_t)size+1);if(!data){fclose(f);return NULL;}
  size_t read=fread(data,1,(size_t)size,f);fclose(f);data[read]=0;
  if(read!=(size_t)size||!needle[0]||!strstr(data,needle)){free(data);return NULL;}
  char path[]="/tmp/stateafl-generic-runtime-XXXXXX";int fd=mkstemp(path);
  if(fd<0){free(data);return NULL;}f=fdopen(fd,"wb");
  if(!f){close(fd);remove(path);free(data);return NULL;}
  char *start=data,*at;size_t width=strlen(needle),rn=strlen(replacement);int ok=1;
  while((at=strstr(start,needle))!=NULL){
    size_t prefix=(size_t)(at-start);
    if(fwrite(start,1,prefix,f)!=prefix||fwrite(replacement,1,rn,f)!=rn)ok=0;
    start=at+width;if(!all)break;
  }
  size_t tail=strlen(start);if(fwrite(start,1,tail,f)!=tail)ok=0;
  if(fclose(f))ok=0;free(data);
  proto_engine *e=ok?proto_load_generic(path,error,cap):NULL;remove(path);return e;
}
static int bad_package(const char *source,const char *needle,const char *replacement){
  char error[512]={0};proto_engine *e=variant(source,needle,replacement,0,error,sizeof(error));
  if(e){proto_free(e);return 0;}return error[0]!=0;
}
static int json_stream(FILE *stream){
  rewind(stream);char line[2048],error[512];unsigned lines=0;
  while(fgets(line,sizeof(line),stream)){
    nj_document *d=NULL;if(nj_parse_buffer((const unsigned char *)line,strlen(line),&d,error,sizeof(error))<0)return 0;
    nj_free(d);lines++;
  }return lines>0&&!ferror(stream);
}
static proto_engine *matching_package(unsigned requests,unsigned responses,char *error,size_t cap){
  /* All one-byte grammars overlap. Opposite directions must remain separate. */
  char path[]="/tmp/stateafl-generic-matching-XXXXXX";int fd=mkstemp(path);
  if(fd<0){snprintf(error,cap,"matching fixture creation failed");return NULL;}
  FILE *f=fdopen(fd,"wb");
  if(!f){close(fd);remove(path);snprintf(error,cap,"matching fixture open failed");return NULL;}
  fputs("{\"format\":\"stateafl.generic-wire\",\"version\":1,\"protocol_id\":\"matching\","
        "\"online\":true,\"transport\":\"udp\",\"framing\":{\"kind\":\"datagram\"},\"messages\":[",f);
  for(unsigned i=0;i<requests+responses;i++){
    int response=i>=requests;unsigned ordinal=response?i-requests:i;
    if(i)fputc(',',f);
    fprintf(f,"{\"id\":\"%s%u\",\"direction\":\"%s\",\"weight\":1,\"example_hex\":\"%02x\","
      "\"grammar\":{\"kind\":\"struct\",\"fields\":["
      "{\"id\":\"value\",\"kind\":\"uint\",\"width\":1,\"byte_order\":\"big\","
      "\"role\":\"content\",\"min\":0,\"max\":255}]}}",
      response?"response":"request",ordinal,response?"response":"request",ordinal+1);
  }
  fputs("],\"states\":{\"initial\":\"ready\",\"transitions\":["
        "{\"from\":\"ready\",\"to\":\"done\",\"message\":\"request0\",\"response\":\"response0\"}]},"
        "\"limits\":{\"max_messages\":8,\"max_repeat\":4,\"max_bytes\":256}}",f);
  int ok=!ferror(f);if(fclose(f))ok=0;
  proto_engine *e=NULL;
  if(ok)e=proto_load_generic(path,error,cap);
  else snprintf(error,cap,"matching fixture write failed");
  remove(path);return e;
}
static int matching_regressions(void){
  char error[512];proto_engine *e=matching_package(2,1,error,sizeof(error));
  CHECK(e==NULL&&strstr(error,"example for request0")&&strstr(error,"ambiguous message grammars"));
  e=matching_package(1,2,error,sizeof(error));
  CHECK(e==NULL&&strstr(error,"example for response0")&&strstr(error,"ambiguous message grammars"));
  /* Equal request/response examples are legal because direction disambiguates.
   * Without equality rules, completion must not claim field correlation. */
  e=matching_package(1,1,error,sizeof(error));CHECK(e!=NULL);
  const char *stats="/tmp/stateafl-generic-matching-stats.json";
  unsigned char wire[]={1},wrong_size[]={1,2};
  CHECK(status(e,stats,"\"stats_version\":2"));
  CHECK(status(e,stats,"\"completed_responses\":0"));
  CHECK(proto_before_send(e,wire,sizeof(wire),error,sizeof(error))==0);
  proto_after_response(e,wrong_size,sizeof(wrong_size));
  CHECK(status(e,stats,"\"responses\":0"));
  CHECK(status(e,stats,"\"completed_responses\":0"));
  CHECK(status(e,stats,"\"correlated_responses\":0"));
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"ready\""));
  proto_after_response(e,wire,sizeof(wire));
  CHECK(status(e,stats,"\"completed_responses\":1"));
  CHECK(status(e,stats,"\"correlated_responses\":0"));
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"done\""));
  proto_after_response(e,wire,sizeof(wire));
  CHECK(status(e,stats,"\"responses\":2"));
  CHECK(status(e,stats,"\"completed_responses\":1"));
  CHECK(status(e,stats,"\"correlated_responses\":0"));
  proto_free(e);remove(stats);return 0;
}
static int limit_regressions(const char *path){
  char error[512];unsigned char records[128],candidate[32];const unsigned char *out;
  size_t length=0,n;memcpy(candidate,seed,sizeof(seed));
  proto_engine *e=proto_load_generic(path,error,sizeof(error));CHECK(e!=NULL);
  for(unsigned i=0;i<4;i++)length=append(records,length,seed,sizeof(seed));
  CHECK(proto_set_prefix(e,records,length,error,sizeof(error))==0);
  set_draws(0,0,0,0);n=1;out=(void *)1;
  CHECK(proto_mutate(e,records,12,candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
  CHECK(out==NULL&&n==0&&strstr(error,"max_repeat"));
  length=append(records,length,seed,sizeof(seed));
  CHECK(proto_set_prefix(e,records,length,error,sizeof(error))<0);
  CHECK(strstr(error,"max_repeat"));
  CHECK(proto_mutate(e,records,12,candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
  CHECK(strstr(error,"prefix"));
  CHECK(proto_set_prefix(e,NULL,0,error,sizeof(error))==0);
  /* Every operation and selection boundary executes in C. */
  for(unsigned op=0;op<4;op++){
    set_draws(1,op,0,0);
    CHECK(proto_mutate(e,records,24,candidate,sizeof(seed),PROTO_VALID,PROTO_SEQUENCE,draw,&out,&n,error,sizeof(error))==0);
    size_t count=0;CHECK(proto_records_validate(out,n,&count,error,sizeof(error))==0);
    CHECK(count==(op==1?1:op==3?2:3));
  }
  for(int mode=PROTO_NEAR_VALID;mode<=PROTO_HYBRID;mode++){
    out=(void *)1;n=1;
    CHECK(proto_mutate(e,records,12,candidate,sizeof(seed),mode,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
    CHECK(out==NULL&&n==0);
  }
  proto_free(e);
  e=variant(path,"\"max_messages\": 32","\"max_messages\": 2",0,error,sizeof(error));CHECK(e!=NULL);
  CHECK(proto_set_prefix(e,records,24,error,sizeof(error))==0);set_draws(0,0,0,0);
  CHECK(proto_mutate(e,records,12,candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
  CHECK(strstr(error,"max_messages"));proto_free(e);
  e=variant(path,"\"max_bytes\": 1048576","\"max_bytes\": 24",0,error,sizeof(error));CHECK(e!=NULL);
  CHECK(proto_set_prefix(e,records,24,error,sizeof(error))==0);set_draws(0,0,0,0);
  CHECK(proto_mutate(e,records,12,candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
  CHECK(strstr(error,"max_bytes"));
  CHECK(proto_set_prefix(e,records,36,error,sizeof(error))<0);proto_free(e);
  return 0;
}
static int diagnostics_regressions(const char *path){
  char error[512];
  proto_engine *e=variant(path,"a700050100015566","0000050100015566",0,error,sizeof(error));
  CHECK(e==NULL&&strstr(error,"invalid example for pulse")&&strstr(error,"magic"));
  CHECK(bad_package(path,"a700050100015566","\\u0000700050100015566"));
  /* State, protocol and message identifiers may contain JSON escapes. The
   * stats writer must preserve the decoded state string in valid JSON. */
  e=variant(path,"ready","r\\\"x\\\\\\n",1,error,sizeof(error));CHECK(e!=NULL);
  const char *stats="/tmp/stateafl-generic-escaped-stats.json";proto_write_stats(e,stats);
  nj_document *d=NULL;CHECK(nj_load_file(stats,&d,error,sizeof(error))==0);
  CHECK(nj_string_equal(nj_get(d->root,"protocol_semantic_state"),"r\"x\\\n"));
  nj_free(d);remove(stats);proto_free(e);
  e=variant(path,"pulse","p\\\"q",1,error,sizeof(error));CHECK(e!=NULL);proto_free(e);
  e=variant(path,"fictional_seventh","p\\\"q",0,error,sizeof(error));CHECK(e!=NULL);proto_free(e);
  /* Rejection logs remain one valid JSON object per physical line. */
  e=proto_load_generic(path,error,sizeof(error));CHECK(e!=NULL);FILE *log=tmpfile();CHECK(log!=NULL);
  proto_set_log(e,log);unsigned char records[12],candidate[8];append(records,0,seed,sizeof(seed));
  memcpy(candidate,seed,sizeof(candidate));const unsigned char *out;size_t n;
  set_draws(0,0,0,0);CHECK(proto_mutate(e,records,sizeof(records),NULL,0,PROTO_VALID,PROTO_CONTENT,draw,&out,&n,error,sizeof(error))<0);
  set_draws(0,0,0,0);CHECK(proto_mutate(e,records,sizeof(records),candidate,sizeof(candidate),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))==0);
  CHECK(json_stream(log));proto_set_log(e,NULL);fclose(log);proto_free(e);return 0;
}
static int session_regressions(void){
  /* Two requests share one response grammar but use different source IDs.
   * No protocol codec or profile-specific C path participates. */
  char path[]="/tmp/stateafl-generic-session-XXXXXX",error[512];int fd=mkstemp(path);CHECK(fd>=0);
  FILE *f=fdopen(fd,"wb");CHECK(f!=NULL);
  fputs("{\"format\":\"stateafl.generic-wire\",\"version\":1,\"protocol_id\":\"shared\","
        "\"online\":true,\"transport\":\"udp\",\"framing\":{\"kind\":\"datagram\"},\"messages\":[",f);
  const char *ids[]={"req_a","req_b","reply","notice"};
  const char *fields[]={"a","b","echo","c"};
  for(unsigned i=0;i<4;i++){
    if(i)fputc(',',f);
    fprintf(f,"{\"id\":\"%s\",\"direction\":\"%s\",\"weight\":1,\"example_hex\":\"%02x11\","
      "\"grammar\":{\"kind\":\"struct\",\"fields\":["
      "{\"id\":\"op\",\"kind\":\"uint\",\"width\":1,\"byte_order\":\"big\",\"role\":\"fixed\",\"min\":%u,\"max\":%u,\"expected\":%u},"
      "{\"id\":\"%s\",\"kind\":\"uint\",\"width\":1,\"byte_order\":\"big\",\"role\":\"content\",\"min\":0,\"max\":255}]}",
      ids[i],i==2?"response":"request",i+1,i+1,i+1,i+1,fields[i]);
    if(i==2)fputs(",\"correlate\":[{\"field\":\"echo\",\"request\":\"req_a\",\"source\":\"a\"},"
                  "{\"field\":\"echo\",\"request\":\"req_b\",\"source\":\"b\"}]",f);
    fputc('}',f);
  }
  fputs("],\"states\":{\"initial\":\"ready\",\"transitions\":["
        "{\"from\":\"ready\",\"to\":\"waiting\",\"message\":\"req_a\",\"response\":\"reply\"},"
        "{\"from\":\"waiting\",\"to\":\"ready\",\"message\":\"req_b\",\"response\":\"reply\"},"
        "{\"from\":\"ready\",\"to\":\"waiting\",\"message\":\"notice\"}]},"
        "\"limits\":{\"max_messages\":8,\"max_repeat\":4,\"max_bytes\":256}}",f);
  CHECK(fclose(f)==0);
  proto_engine *e=proto_load_generic(path,error,sizeof(error));CHECK(e!=NULL);
  unsigned char a[]={1,17},b[]={2,34},reply[]={3,17},notice[]={4,0};
  const char *stats="/tmp/stateafl-generic-session-stats.json";
  CHECK(proto_before_send(e,a,sizeof(a),error,sizeof(error))==0);
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"ready\""));
  CHECK(proto_before_send(e,notice,sizeof(notice),error,sizeof(error))<0&&strstr(error,"outstanding"));
  reply[1]=18;proto_after_response(e,reply,sizeof(reply));
  CHECK(status(e,stats,"\"completed_responses\":0"));
  CHECK(status(e,stats,"\"correlated_responses\":0"));
  CHECK(proto_before_send(e,a,sizeof(a),error,sizeof(error))<0&&strstr(error,"outstanding"));
  reply[1]=17;proto_after_response(e,reply,sizeof(reply));
  CHECK(status(e,stats,"\"completed_responses\":1"));
  CHECK(status(e,stats,"\"correlated_responses\":1"));
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"waiting\""));
  CHECK(proto_before_send(e,a,sizeof(a),error,sizeof(error))<0);
  CHECK(proto_before_send(e,b,sizeof(b),error,sizeof(error))==0);
  reply[1]=17;proto_after_response(e,reply,sizeof(reply));
  CHECK(status(e,stats,"\"completed_responses\":1"));
  CHECK(status(e,stats,"\"correlated_responses\":1"));
  CHECK(proto_before_send(e,b,sizeof(b),error,sizeof(error))<0&&strstr(error,"outstanding"));
  reply[1]=34;proto_after_response(e,reply,sizeof(reply));
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"ready\""));
  CHECK(status(e,stats,"\"completed_responses\":2"));
  CHECK(status(e,stats,"\"correlated_responses\":2"));
  proto_session_begin(e);reply[1]=17;proto_after_response(e,reply,sizeof(reply));
  CHECK(status(e,stats,"\"protocol_semantic_state\":\"ready\""));proto_free(e);
  CHECK(bad_package(path,"\"message\":\"req_a\",\"response\":\"reply\"","\"message\":\"req_a\""));
  CHECK(bad_package(path,"\"request\":\"req_b\"","\"request\":\"notice\""));
  CHECK(bad_package(path,"\"example_hex\":\"0111\"","\"example_hex\":\"\\u0000111\""));
  remove(path);remove(stats);return 0;
}
int main(int argc,char **argv){
  CHECK(argc==2);char error[512]={0};
  CHECK(matching_regressions()==0);
  CHECK(limit_regressions(argv[1])==0);
  CHECK(diagnostics_regressions(argv[1])==0);
  CHECK(session_regressions()==0);
  CHECK(bad_package(argv[1],"\"online\": true","\"online\": false"));
  CHECK(bad_package(argv[1],"\"message\": \"pulse\"","\"message\": \"missing_request\""));
  CHECK(bad_package(argv[1],"\"initial\": \"ready\"","\"initial\": \"unreachable\""));
  CHECK(bad_package(argv[1],"\"kind\": \"datagram\"","\"kind\": \"unknown\""));
  CHECK(bad_package(argv[1],"\"max_bytes\": 1048576","\"max_bytes\": 8"));
  proto_engine *exact_budget=variant(argv[1],"\"max_bytes\": 1048576","\"max_bytes\": 12",0,error,sizeof(error));
  CHECK(exact_budget!=NULL);proto_free(exact_budget);
  proto_engine *e=proto_load_generic(argv[1],error,sizeof(error));
  if(!e)fprintf(stderr,"generic load failed: %s\n",error);
  CHECK(e!=NULL);CHECK(!strcmp(proto_transport(e),"udp"));
  CHECK(proto_set_prefix(e,NULL,0,error,sizeof(error))==0);
  unsigned char records[96],candidate[32],wire[32];size_t input_n=append(records,0,seed,sizeof(seed));
  const unsigned char *out=NULL,*w=NULL;size_t n=0,count=0,z=0;
  CHECK(proto_records_validate(records,input_n,&count,error,sizeof(error))==0&&count==1);
  memcpy(candidate,seed,sizeof(seed));
  set_draws(0,0,0,0);
  CHECK(proto_mutate(e,records,input_n,candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))==0);
  CHECK(proto_records_validate(out,n,&count,error,sizeof(error))==0&&count==1);
  z=record_wire(out,n,0,&w);CHECK(valid(w,z));CHECK(w[0]==seed[0]&&w[3]==seed[3]);
  CHECK(w[6]==seed[6]&&w[7]==seed[7]);
  memcpy(candidate,seed,sizeof(seed));candidate[6]=0x22;candidate[7]=0x33;
  set_draws(0,0,0,0);
  CHECK(proto_mutate(e,records,input_n,candidate,sizeof(seed),PROTO_VALID,PROTO_CONTENT,draw,&out,&n,error,sizeof(error))==0);
  z=record_wire(out,n,0,&w);CHECK(valid(w,z)&&w[6]==0x22&&w[7]==0x33);
  CHECK(w[0]==seed[0]&&w[3]==seed[3]);
  set_draws(0,2,0,0);
  CHECK(proto_mutate(e,records,input_n,candidate,sizeof(seed),PROTO_VALID,PROTO_SEQUENCE,draw,&out,&n,error,sizeof(error))==0);
  CHECK(proto_records_validate(out,n,&count,error,sizeof(error))==0&&count==2);
  z=record_wire(out,n,0,&w);CHECK(valid(w,z));
  size_t offset=4+z;z=record_wire(out,n,offset,&w);CHECK(valid(w,z));
  CHECK(offset+4+z==n);
  set_draws(0,1,0,0);out=(void*)0x1;n=1;
  CHECK(proto_mutate(e,records,input_n,candidate,sizeof(seed),PROTO_VALID,PROTO_SEQUENCE,draw,&out,&n,error,sizeof(error))<0);
  CHECK(out==NULL&&n==0);
  set_draws(0,0,0,0);out=(void*)0x1;n=1;
  CHECK(proto_mutate(e,records,input_n,NULL,0,PROTO_VALID,PROTO_CONTENT,draw,&out,&n,error,sizeof(error))<0);
  CHECK(out==NULL&&n==0);
  unsigned char bad[12];append(bad,0,seed,sizeof(seed));bad[4]=0;out=(void*)0x1;n=1;
  CHECK(proto_mutate(e,bad,sizeof(bad),candidate,sizeof(seed),PROTO_VALID,PROTO_HEAD,draw,&out,&n,error,sizeof(error))<0);
  CHECK(out==NULL&&n==0);
  memcpy(wire,seed,sizeof(seed));CHECK(proto_before_send(e,wire,sizeof(seed),error,sizeof(error))==0);
  wire[0]=0;CHECK(proto_before_send(e,wire,sizeof(seed),error,sizeof(error))<0);
  CHECK(wire[0]==0);
  CHECK(status(e,"/tmp/stateafl-generic-seventh-stats.json","\"engine\":\"generic-wire\""));
  CHECK(status(e,"/tmp/stateafl-generic-seventh-stats.json","\"SEQUENCE\":1"));
  proto_free(e);
  printf("PASS: seventh-protocol C runtime HEAD/CONTENT/SEQUENCE and rejection (%u checks)\n",checks);
  return 0;
}
