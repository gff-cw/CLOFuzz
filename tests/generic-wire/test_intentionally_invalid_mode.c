/* Real runtime validation of a bounded fixture, entirely in files/memory. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t zero(uint32_t limit){(void)limit;return 0;}
static size_t append(uint8_t *out,size_t at,const uint8_t *wire,size_t size){
  for(unsigned i=0;i<4;i++)out[at+i]=(uint8_t)(size>>(8*i));
  memcpy(out+at+4,wire,size);
  return at+4+size;
}
static void write_text(const char *path,const char *text){
  FILE *f=fopen(path,"wb");assert(f);
  assert(fwrite(text,1,strlen(text),f)==strlen(text));
  assert(fclose(f)==0);
}

static const char protocol_json[]=
  "{\"format\":\"stateafl.protocol-ir\",\"ir_version\":1,"
  "\"protocol_id\":\"projection_contract\",\"codec\":\"bacnet\",\"transport\":\"udp\","
  "\"support\":{\"runtime\":true},\"messages\":["
  "{\"id\":\"start\",\"direction\":\"request\",\"weight\":1,"
  "\"example\":\"810b000801001008\","
  "\"fields\":["
  "{\"id\":\"function\",\"locator\":\"bvlc.function\",\"width\":1,\"type\":\"uint8\","
  "\"endian\":\"big\",\"role\":\"fixed\",\"mutability\":\"fixed\",\"min\":11,\"max\":11,\"values\":[11],\"strategies\":[\"enum\"]},"
  "{\"id\":\"length\",\"locator\":\"bvlc.length\",\"width\":2,\"type\":\"uint16\","
  "\"endian\":\"big\",\"role\":\"derived\",\"mutability\":\"derived\",\"min\":8,\"max\":16,\"values\":[],\"strategies\":[]},"
  "{\"id\":\"priority\",\"locator\":\"npdu.control\",\"width\":1,\"type\":\"uint8\","
  "\"endian\":\"big\",\"role\":\"head\",\"mutability\":\"fuzzable\",\"min\":0,\"max\":3,\"values\":[0,1],\"strategies\":[\"enum\"]}],"
  "\"dependencies\":[{\"op\":\"length_of\",\"target\":\"length\",\"source\":\"$message\",\"unit\":1,\"multiply\":1,\"add\":0}]},"
  "{\"id\":\"finish\",\"direction\":\"request\",\"weight\":1,"
  "\"example\":\"810a000801001008\","
  "\"fields\":["
  "{\"id\":\"function\",\"locator\":\"bvlc.function\",\"width\":1,\"type\":\"uint8\","
  "\"endian\":\"big\",\"role\":\"fixed\",\"mutability\":\"fixed\",\"min\":10,\"max\":10,\"values\":[10],\"strategies\":[\"enum\"]},"
  "{\"id\":\"length\",\"locator\":\"bvlc.length\",\"width\":2,\"type\":\"uint16\","
  "\"endian\":\"big\",\"role\":\"derived\",\"mutability\":\"derived\",\"min\":8,\"max\":16,\"values\":[],\"strategies\":[]},"
  "{\"id\":\"priority\",\"locator\":\"npdu.control\",\"width\":1,\"type\":\"uint8\","
  "\"endian\":\"big\",\"role\":\"head\",\"mutability\":\"fuzzable\",\"min\":0,\"max\":3,\"values\":[0,1],\"strategies\":[\"enum\"]}],"
  "\"dependencies\":[{\"op\":\"length_of\",\"target\":\"length\",\"source\":\"$message\",\"unit\":1,\"multiply\":1,\"add\":0}]}]}";
static const char state_json[]=
  "{\"format\":\"stateafl.state-ir\",\"ir_version\":1,\"protocol_id\":\"projection_contract\","
  "\"states\":[{\"id\":\"ready\"},{\"id\":\"started\"}],\"initial\":\"ready\","
  "\"transitions\":["
  "{\"from\":\"ready\",\"message\":\"start\",\"to\":\"started\",\"response\":\"\"},"
  "{\"from\":\"started\",\"message\":\"finish\",\"to\":\"ready\",\"response\":\"\"}],"
  "\"limits\":{\"max_messages\":3,\"max_repeat\":2,\"max_bytes\":36}}";

int main(void){
  char protocol_path[]="/tmp/stateafl-projection-protocol-XXXXXX";
  char state_path[]="/tmp/stateafl-projection-state-XXXXXX";
  int pfd=mkstemp(protocol_path),sfd=mkstemp(state_path);
  assert(pfd>=0&&sfd>=0);close(pfd);close(sfd);
  write_text(protocol_path,protocol_json);write_text(state_path,state_json);
  char error[512]={0};
  proto_engine *engine=proto_load(protocol_path,state_path,error,sizeof(error));
  if(!engine)fprintf(stderr,"load: %s\n",error);
  assert(engine);
  const uint8_t start[]={0x81,11,0,8,1,0,16,8};
  const uint8_t finish[]={0x81,10,0,8,1,0,16,8};
  const uint8_t long_finish[]={0x81,10,0,16,1,0,16,8,0x0b,0,0,0,0x1b,0,0,1};
  uint8_t seed[32],suffix[80],tampered[32],original[32];
  size_t seed_size=append(seed,0,start,sizeof(start));
  const uint8_t *candidate=NULL;size_t candidate_size=0;
  assert(proto_set_prefix(engine,NULL,0,error,sizeof(error))==0);

  /* A mode flag cannot invent model provenance for arbitrary damaged input. */
  proto_set_mutating_mode(engine,PROTO_INVALID);
  memcpy(tampered,seed,seed_size);tampered[7]++;
  assert(proto_validate_sequence(engine,NULL,0,tampered,seed_size,NULL,0,error,sizeof(error))<0);
  assert(strstr(error,"provenance"));

  const int modes[]={PROTO_NEAR_VALID,PROTO_INVALID};
  for(size_t m=0;m<sizeof(modes)/sizeof(modes[0]);m++){
    assert(proto_mutate(engine,seed,seed_size,start,sizeof(start),modes[m],
                        PROTO_HEAD,zero,&candidate,&candidate_size,error,sizeof(error))==0);
    assert(candidate_size==seed_size);
    memcpy(original,candidate,candidate_size);
    assert(candidate[7]==9); /* The generated BVLC length remains intentionally wrong. */
    assert(proto_is_intentional_violation(engine,candidate+4,candidate_size-4)==1);
    assert(proto_is_intentional_violation(engine,start,sizeof(start))==0);
    assert(proto_is_intentional_violation(engine,finish,sizeof(finish))==0);
    proto_session_begin(engine);
    assert(proto_set_prefix(engine,NULL,0,error,sizeof(error))==0);
    assert(proto_is_intentional_violation(engine,candidate+4,candidate_size-4)==1);
    uint8_t send_wire[sizeof(start)];memcpy(send_wire,candidate+4,sizeof(send_wire));
    assert(proto_prepare_send(engine,send_wire,sizeof(send_wire),error,sizeof(error))<0);
    assert(memcmp(send_wire,candidate+4,sizeof(send_wire))==0);
    assert(proto_commit_send(engine,error,sizeof(error))<0);
    /* Exact damaged bytes cannot bypass a live semantic-state error. These two
     * normal no-response requests must also avoid creating a permanent pending. */
    memcpy(send_wire,start,sizeof(send_wire));
    assert(proto_prepare_send(engine,send_wire,sizeof(send_wire),error,sizeof(error))==0);
    assert(proto_commit_send(engine,error,sizeof(error))==0);
    assert(proto_is_intentional_violation(engine,candidate+4,sizeof(start))==0);
    memcpy(send_wire,finish,sizeof(send_wire));
    assert(proto_prepare_send(engine,send_wire,sizeof(send_wire),error,sizeof(error))==0);
    assert(proto_commit_send(engine,error,sizeof(error))==0);
    assert(proto_is_intentional_violation(engine,candidate+4,sizeof(start))==1);
    size_t suffix_size=append(suffix,0,finish,sizeof(finish));
    assert(proto_validate_sequence(engine,NULL,0,candidate,candidate_size,
                                    suffix,suffix_size,error,sizeof(error))==0);
    assert(memcmp(candidate,original,candidate_size)==0);

    /* M3 must follow the projected outcome of start, not the initial state. */
    suffix_size=append(suffix,0,start,sizeof(start));
    assert(proto_validate_sequence(engine,NULL,0,candidate,candidate_size,
                                    suffix,suffix_size,error,sizeof(error))<0);
    assert(strstr(error,"state graph"));

    memcpy(tampered,candidate,candidate_size);tampered[11]^=1;
    assert(proto_validate_sequence(engine,NULL,0,tampered,candidate_size,
                                    NULL,0,error,sizeof(error))<0);
    assert(strstr(error,"provenance"));

    suffix_size=append(suffix,0,finish,sizeof(finish));
    suffix_size=append(suffix,suffix_size,start,sizeof(start));
    suffix_size=append(suffix,suffix_size,finish,sizeof(finish));
    assert(proto_validate_sequence(engine,NULL,0,candidate,candidate_size,
                                    suffix,suffix_size,error,sizeof(error))<0);
    assert(strstr(error,"max_messages"));

    suffix_size=append(suffix,0,long_finish,sizeof(long_finish));
    suffix_size=append(suffix,suffix_size,start,sizeof(start));
    assert(proto_validate_sequence(engine,NULL,0,candidate,candidate_size,
                                    suffix,suffix_size,error,sizeof(error))<0);
    assert(strstr(error,"max_bytes"));
  }
  /* Host sending examines one wire record at a time, while provenance stores
   * the entire M2 sequence. Only its damaged member may bypass preparation. */
  uint8_t multi_seed[32],multi_wire[sizeof(start)+sizeof(finish)];
  size_t multi_size=append(multi_seed,0,start,sizeof(start));
  multi_size=append(multi_seed,multi_size,finish,sizeof(finish));
  memcpy(multi_wire,start,sizeof(start));
  memcpy(multi_wire+sizeof(start),finish,sizeof(finish));
  assert(proto_mutate(engine,multi_seed,multi_size,multi_wire,sizeof(multi_wire),
                      PROTO_INVALID,PROTO_HEAD,zero,&candidate,&candidate_size,
                      error,sizeof(error))==0);
  assert(candidate_size==24);
  assert(proto_is_intentional_violation(engine,candidate+4,sizeof(start))==1);
  assert(proto_is_intentional_violation(engine,candidate+16,sizeof(finish))==0);
  size_t suffix_size=append(suffix,0,start,sizeof(start));
  assert(proto_validate_sequence(engine,NULL,0,candidate,candidate_size,
                                  suffix,suffix_size,error,sizeof(error))==0);
  proto_free(engine);unlink(protocol_path);unlink(state_path);
  puts("PASS: production mutation provenance and full-sequence resource/state validation");
  return 0;
}
