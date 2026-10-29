/* File-only configuration rejection checks; no target or sockets are used. */
#define _POSIX_C_SOURCE 200809L
#include "protocol_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static proto_engine *load_framing(const char *framing,const char *request,
                                 const char *response,char *error,size_t cap){
  char path[]="/tmp/stateafl-generic-load-XXXXXX";int fd=mkstemp(path);
  if(fd<0){snprintf(error,cap,"fixture creation failed");return NULL;}
  FILE *file=fdopen(fd,"wb");
  if(!file){close(fd);remove(path);snprintf(error,cap,"fixture open failed");return NULL;}
  fprintf(file,"{\"format\":\"stateafl.generic-wire\",\"version\":1,\"protocol_id\":\"framing_check\","
    "\"online\":true,\"transport\":\"tcp\",\"framing\":%s,\"messages\":[",framing);
  for(unsigned i=0;i<2;i++){
    if(i)fputc(',',file);
    const char *direction=i?"response":"request";
    fprintf(file,"{\"id\":\"%s\",\"direction\":\"%s\",\"weight\":1,\"example_hex\":\"%s\","
      "\"grammar\":{\"kind\":\"struct\",\"fields\":[{\"id\":\"value\",\"kind\":\"uint\","
      "\"width\":2,\"byte_order\":\"big\",\"role\":\"content\"}]}}",
      direction,direction,i?response:request);
  }
  fputs("],\"states\":{\"initial\":\"ready\",\"transitions\":[{\"from\":\"ready\","
    "\"to\":\"ready\",\"message\":\"request\",\"response\":\"response\"}]},"
    "\"limits\":{\"max_messages\":8,\"max_repeat\":4,\"max_bytes\":256}}",file);
  int ok=!ferror(file);if(fclose(file))ok=0;
  proto_engine *engine=NULL;
  if(ok)engine=proto_load_generic(path,error,cap);
  else snprintf(error,cap,"fixture write failed");
  remove(path);return engine;
}

int main(void){
  static const struct {
    const char *framing,*request,*response,*error_message;
  } cases[]={
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":0}","0002","0002",NULL},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"little\",\"add\":0}","0200","0200",NULL},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":1}","0001","0001",NULL},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":-1}","0003","0003",NULL},
    {"{\"kind\":\"length_field\",\"offset\":1,\"width\":2,\"byte_order\":\"big\",\"add\":0}","0002","0002","request: length field outside example"},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":0}","0003","0002","request: declared length differs from example"},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":0}","0002","0003","response: declared length differs from example"},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":9223372036854775807}","ffff","0002","request: declared length differs from example"},
    {"{\"kind\":\"length_field\",\"offset\":0,\"width\":2,\"byte_order\":\"big\",\"add\":-9223372036854775808}","0000","0002","request: declared length differs from example"},
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
    char error[512]={0};
    proto_engine *engine=load_framing(cases[i].framing,cases[i].request,cases[i].response,error,sizeof(error));
    if(cases[i].error_message){
      int rejected=engine==NULL;
      if(engine)proto_free(engine);
      CHECK(rejected);
      CHECK(strstr(error,"invalid TCP framing for ")!=NULL);
      CHECK(strstr(error,cases[i].error_message)!=NULL);
    }else{
      CHECK(engine!=NULL);proto_free(engine);
    }
  }
  printf("PASS: generic configuration framing checks (%u assertions)\n",checks);return 0;
}
