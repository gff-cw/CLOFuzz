/* Stateful TCP integration for the limited description-only Modbus FC03 pair. */
#include "protocol_runtime.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
static const unsigned char request[]={0,1,0,0,0,6,1,3,0,0,0,1};
static const unsigned char response[]={0,1,0,0,0,5,1,3,2,0,1};
static uint32_t zero(uint32_t n){(void)n;return 0;}
static size_t append(unsigned char *out,const unsigned char *wire,size_t n){
  out[0]=(unsigned char)n;out[1]=(unsigned char)(n>>8);out[2]=out[3]=0;
  memcpy(out+4,wire,n);return n+4;
}
static int stat_has(proto_engine *e,const char *value){
  const char *path="/tmp/stateafl-generic-modbus-stats.json";proto_write_stats(e,path);
  FILE *f=fopen(path,"rb");if(!f)return 0;char text[1024];
  size_t n=fread(text,1,sizeof(text)-1,f);fclose(f);text[n]=0;return strstr(text,value)!=NULL;
}
int main(int argc,char **argv){
  CHECK(argc==2);char err[512]={0};
  proto_engine *e=proto_load_generic(argv[1],err,sizeof(err));
  if(!e)fprintf(stderr,"Modbus generic load: %s\n",err);
  CHECK(e!=NULL);
  CHECK(!strcmp(proto_transport(e),"tcp"));
  unsigned char record[32],candidate[32],wire[sizeof(request)];
  size_t input_n=append(record,request,sizeof(request)),n=0;const unsigned char *out=NULL;
  memcpy(candidate,request,sizeof(request));candidate[8]=0x12;candidate[9]=0x34;
  CHECK(proto_set_prefix(e,NULL,0,err,sizeof(err))==0);
  CHECK(proto_mutate(e,record,input_n,candidate,sizeof(request),PROTO_VALID,PROTO_CONTENT,zero,&out,&n,err,sizeof(err))==0);
  CHECK(n==input_n&&out[4+8]==0x12&&out[4+9]==0x34);
  CHECK(out[4+5]==6&&out[4+7]==3);
  CHECK(proto_before_send(e,wire,0,err,sizeof(err))<0);
  memcpy(wire,request,sizeof(request));CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  CHECK(stat_has(e,"\"correlated_responses\":0"));
  proto_after_response(e,response,3);CHECK(stat_has(e,"\"responses\":0"));
  proto_after_response(e,response+3,sizeof(response)-3);
  CHECK(stat_has(e,"\"responses\":1"));
  CHECK(stat_has(e,"\"correlated_responses\":1"));
  /* A second send cannot replace an outstanding transaction's cache. */
  memcpy(wire,request,sizeof(wire));CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  wire[1]=2;CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))<0);
  CHECK(wire[1]==2&&strstr(err,"outstanding")!=NULL);
  unsigned char reply[sizeof(response)];memcpy(reply,response,sizeof(reply));reply[1]=2;
  proto_after_response(e,reply,sizeof(reply));
  CHECK(stat_has(e,"\"correlated_responses\":1"));
  memcpy(wire,request,sizeof(wire));CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))<0);
  proto_after_response(e,response,sizeof(response));
  CHECK(stat_has(e,"\"correlated_responses\":2"));
  memcpy(wire,request,sizeof(wire));CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  memcpy(reply,response,sizeof(reply));reply[6]=2;
  proto_after_response(e,reply,sizeof(reply));
  CHECK(stat_has(e,"\"correlated_responses\":2"));
  proto_after_response(e,response,sizeof(response));
  CHECK(stat_has(e,"\"correlated_responses\":3"));
  /* Duplicates and unsolicited responses never advance semantic state. */
  proto_after_response(e,response,sizeof(response));
  CHECK(stat_has(e,"\"correlated_responses\":3"));
  memcpy(wire,request,sizeof(wire));wire[1]=3;
  CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  proto_session_begin(e);memcpy(reply,response,sizeof(reply));reply[1]=3;
  proto_after_response(e,reply,sizeof(reply));
  CHECK(stat_has(e,"\"correlated_responses\":3"));
  /* Reset also discards an incomplete TCP frame, and invalid frame lengths
   * cannot poison the following complete response. */
  memcpy(wire,request,sizeof(wire));CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  proto_after_response(e,response,3);proto_session_begin(e);
  CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  memcpy(reply,response,sizeof(reply));reply[4]=reply[5]=0;
  proto_after_response(e,reply,6);proto_after_response(e,response,sizeof(response));
  CHECK(stat_has(e,"\"correlated_responses\":4"));
  /* Coalesced frames are counted separately and consume a pending request
   * only once. */
  CHECK(proto_before_send(e,wire,sizeof(wire),err,sizeof(err))==0);
  unsigned char joined[2*sizeof(response)];memcpy(joined,response,sizeof(response));
  memcpy(joined+sizeof(response),response,sizeof(response));
  proto_after_response(e,joined,sizeof(joined));
  CHECK(stat_has(e,"\"responses\":10"));
  CHECK(stat_has(e,"\"correlated_responses\":5"));
  proto_session_begin(e);CHECK(stat_has(e,"\"protocol_semantic_state\":\"ready\""));
  proto_free(e);printf("PASS: generic Modbus FC03 TCP response framing/correlation (%u checks)\n",checks);return 0;
}
