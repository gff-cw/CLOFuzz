/* File-only checks of the production runtime; no target or socket is started. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include "native_json.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t zero(uint32_t limit){(void)limit;return 0;}

static uint64_t counter(proto_engine *engine,const char *key,const char *path){
  char error[256]={0};nj_document *doc=NULL;uint64_t value=0;
  assert(proto_write_stats(engine,path)==0);
  assert(nj_load_file(path,&doc,error,sizeof(error))==0);
  assert(nj_u64(nj_get(doc->root,key),&value,error,sizeof(error))==0);
  nj_free(doc);
  return value;
}

static void check_legacy_modbus(const char *path){
  uint8_t request[]={0,1,0,0,0,6,1,3,0,0,0,1};
  uint8_t response[]={0,1,0,0,0,5,1,3,2,0,1};
  char error[512]={0};
  proto_engine *engine=proto_load("protocols/modbus_tcp/protocol_ir.json",
                                  "protocols/modbus_tcp/state_ir.json",error,sizeof(error));
  assert(engine);
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  request[1]=2;
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))<0);
  assert(strstr(error,"one outstanding request"));
  assert(request[1]==2);
  assert(proto_commit_send(engine,error,sizeof(error))<0);
  proto_after_stream(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==1);
  assert(counter(engine,"correlated_responses",path)==1);
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  response[1]=2;proto_after_stream(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==2);
  assert(counter(engine,"correlated_responses",path)==2);
  proto_free(engine);
}

static void check_iec104_followup(const char *path){
  uint8_t start[]={0x68,4,7,0,0,0},ack[]={0x68,4,11,0,0,0};
  uint8_t request[]={0x68,14,0,0,0,0,0x64,1,6,0,1,0,0,0,0,20};
  uint8_t confirmation[]={0x68,14,0,0,2,0,0x64,1,7,0,1,0,0,0,0,20};
  uint8_t termination[]={0x68,14,2,0,2,0,0x64,1,10,0,1,0,0,0,0,20};
  uint8_t s_ack[]={0x68,4,1,0,0,0};
  char error[512]={0};
  proto_engine *engine=proto_load("protocols/iec60870_5_104/protocol_ir.json",
                                  "protocols/iec60870_5_104/state_ir.json",error,sizeof(error));
  assert(engine);
  assert(proto_prepare_send(engine,start,sizeof(start),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  proto_after_stream(engine,ack,sizeof(ack));
  assert(counter(engine,"completed_responses",path)==1);
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  proto_after_stream(engine,confirmation,sizeof(confirmation));
  assert(counter(engine,"completed_responses",path)==2);
  proto_after_stream(engine,termination,sizeof(termination));
  assert(counter(engine,"responses",path)==3);
  assert(counter(engine,"completed_responses",path)==2);
  assert(counter(engine,"correlated_responses",path)==0);
  /* ACT_TERM must return to active without claiming another completed pending
   * request. Only active permits the next interrogation request. */
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))==0);
  proto_cancel_send(engine);
  /* S-format acknowledgments expect no response and cannot create a pending
   * entry that permanently blocks the next legal request. */
  for(unsigned i=0;i<2;i++){
    assert(proto_prepare_send(engine,s_ack,sizeof(s_ack),error,sizeof(error))==0);
    assert(proto_commit_send(engine,error,sizeof(error))==0);
  }
  assert(proto_prepare_send(engine,request,sizeof(request),error,sizeof(error))==0);
  proto_cancel_send(engine);
  assert(counter(engine,"completed_responses",path)==2);
  proto_free(engine);
}

int main(void){
  static const uint8_t request[]={
    0x81,0x0a,0,0x11,1,4,0,5,1,0x0c,0x0c,2,0,0,0x7b,0x19,0x4d
  };
  static const uint8_t response[]={
    0x81,0x0a,0,0x1b,1,0,0x30,1,0x0c,0x0c,2,0,0,0x7b,0x19,0x4d,
    0x3e,0x75,7,0,0x44,0x65,0x76,0x69,0x63,0x65,0x3f
  };
  char error[512]={0},path[]="/tmp/stateafl-response-transaction-XXXXXX";
  int fd=mkstemp(path);assert(fd>=0);close(fd);
  proto_engine *engine=proto_load("protocols/bacnet_ip/protocol_ir.json",
                                  "protocols/bacnet_ip/state_ir.json",
                                  error,sizeof(error));
  assert(engine!=NULL);
  uint8_t wire[sizeof(request)],wrong[sizeof(response)];
  memcpy(wire,request,sizeof(wire));
  proto_session_begin(engine);
  assert(proto_prepare_send(engine,wire,sizeof(wire),error,sizeof(error))==0);
  proto_after_dgram(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==0);
  assert(counter(engine,"correlated_responses",path)==0);
  proto_cancel_send(engine);

  assert(proto_prepare_send(engine,wire,sizeof(wire),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  /* A different invoke still shares the request model cache. Reject it before
   * that cache can replace the committed first transaction's evidence. */
  uint8_t second[sizeof(request)];memcpy(second,request,sizeof(second));second[8]=2;
  assert(proto_prepare_send(engine,second,sizeof(second),error,sizeof(error))<0);
  assert(strstr(error,"one outstanding request"));
  assert(second[8]==2);
  assert(proto_commit_send(engine,error,sizeof(error))<0);
  memcpy(wrong,response,sizeof(wrong));
  wrong[8]=0x0d; /* Same invoke ID, but not the declared response service. */
  proto_after_dgram(engine,wrong,sizeof(wrong));
  assert(counter(engine,"completed_responses",path)==0);
  assert(counter(engine,"correlated_responses",path)==0);

  /* Rejected content must not consume the outstanding invoke ID. */
  proto_after_dgram(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==1);
  assert(counter(engine,"correlated_responses",path)==1);
  proto_after_dgram(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==1);
  assert(counter(engine,"correlated_responses",path)==1);
  assert(proto_prepare_send(engine,second,sizeof(second),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  memcpy(wrong,response,sizeof(wrong));wrong[7]=2;
  proto_after_dgram(engine,wrong,sizeof(wrong));
  assert(counter(engine,"completed_responses",path)==2);
  assert(counter(engine,"correlated_responses",path)==2);
  /* Exact intentional-damage provenance does not authorize overwriting a live
   * pending request. Its valid projection must prepare in this session too. */
  uint8_t seed[4+sizeof(request)];
  for(unsigned i=0;i<4;i++)seed[i]=(uint8_t)(sizeof(request)>>(8*i));
  memcpy(seed+4,request,sizeof(request));
  const uint8_t *candidate=NULL;size_t candidate_size=0;
  assert(proto_set_prefix(engine,NULL,0,error,sizeof(error))==0);
  assert(proto_mutate(engine,seed,sizeof(seed),request,sizeof(request),PROTO_INVALID,
                      PROTO_HEAD,zero,&candidate,&candidate_size,error,sizeof(error))==0);
  assert(candidate_size==sizeof(seed));
  assert(proto_is_intentional_violation(engine,candidate+4,sizeof(request))==1);
  memcpy(wire,request,sizeof(wire));
  assert(proto_prepare_send(engine,wire,sizeof(wire),error,sizeof(error))==0);
  assert(proto_commit_send(engine,error,sizeof(error))==0);
  assert(proto_is_intentional_violation(engine,candidate+4,sizeof(request))==0);
  proto_after_dgram(engine,response,sizeof(response));
  assert(counter(engine,"completed_responses",path)==3);
  assert(proto_is_intentional_violation(engine,candidate+4,sizeof(request))==1);
  proto_free(engine);
  check_legacy_modbus(path);
  check_iec104_followup(path);
  unlink(path);
  puts("PASS: production send transactions, completion and declared follow-up responses");
  return 0;
}
