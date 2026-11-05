/* File-only real Modbus/TCP grammar and session regression. */
#define _POSIX_C_SOURCE 200809L
#include "generic_runtime.h"
#include "generic_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s (%s)\n",__LINE__,#x,err); return 1; } } while (0)
static unsigned completed(gr_engine *e) {
  char buf[4096], path[]="/tmp/stateafl-full-modbus-stats-XXXXXX";
  FILE *f; unsigned n=0; int fd=mkstemp(path);
  if(fd<0)return 0;
  close(fd);
  if(gr_write_stats(e,path)<0){unlink(path);return 0;}
  f=fopen(path,"rb"); if(!f){unlink(path);return 0;}
  size_t z=fread(buf,1,sizeof(buf)-1,f);fclose(f);unlink(path);buf[z]=0;
  char *p=strstr(buf,"\"completed_responses\":");if(p)sscanf(p,"\"completed_responses\":%u",&n);return n;
}
int main(void){
 char err[512]={0};uint64_t transformed=0;
 CHECK(gw_transform_u64(9,8,1,0,GW_CEIL,&transformed,err,sizeof(err))==0 && transformed==2);
 CHECK(gw_transform_u64(9,8,1,0,GW_FLOOR,&transformed,err,sizeof(err))==0 && transformed==1);
 CHECK(gw_transform_u64(9,8,1,0,GW_EXACT,&transformed,err,sizeof(err))<0);
 CHECK(gw_transform_u64(UINT64_MAX,1,2,0,GW_EXACT,&transformed,err,sizeof(err))<0);
 CHECK(gw_transform_u64(0,1,1,-1,GW_EXACT,&transformed,err,sizeof(err))<0);
 gr_engine *e=gr_load("tests/generic-wire/full_modbus.json",err,sizeof(err));CHECK(e);
 unsigned char req[]={0,1,0,0,0,6,1,1,0,0,0,9};
 unsigned char good[]={0,1,0,0,0,5,1,1,2,1,1};
 unsigned char bad[]={0,1,0,0,0,5,1,1,2,1,0x81};
 unsigned char exception[]={0,1,0,0,0,3,1,0x81,2};
 CHECK(gr_prepare_send(e,req,sizeof(req),err,sizeof(err))==0);gr_cancel_send(e);
 CHECK(gr_commit_send(e,err,sizeof(err))<0);
 CHECK(gr_prepare_send(e,req,sizeof(req),err,sizeof(err))==0);CHECK(gr_commit_send(e,err,sizeof(err))==0);
 gr_after_stream(e,bad,sizeof(bad));CHECK(completed(e)==0);
 gr_after_stream(e,good,3);CHECK(completed(e)==0);gr_after_stream(e,good+3,sizeof(good)-3);CHECK(completed(e)==1);
 CHECK(gr_before_send(e,req,sizeof(req),err,sizeof(err))==0);
 unsigned char join[sizeof(exception)*2];memcpy(join,exception,sizeof(exception));memcpy(join+sizeof(exception),exception,sizeof(exception));
 gr_after_stream(e,join,sizeof(join));CHECK(completed(e)==2);
 unsigned char write[]={0,1,0,0,0,9,1,15,0,0,0,9,2,1,0x81};
 CHECK(gr_before_send(e,write,sizeof(write),err,sizeof(err))<0);
 write[14]=1;CHECK(gr_before_send(e,write,sizeof(write),err,sizeof(err))==0);
 unsigned char wr[]={0,1,0,0,0,6,1,15,0,0,0,9};gr_after_stream(e,wr,sizeof(wr));CHECK(completed(e)==3);
 /* Each remaining function is exercised through the production matcher. */
 static const unsigned char funcs[]={2,3,4,5,6,16};
 for(size_t i=0;i<sizeof(funcs);i++){
   unsigned char fc=funcs[i];unsigned char q[]={0,1,0,0,0,6,1,0,0,0,0,2};
   unsigned char r[]={0,1,0,0,0,7,1,0,4,0,1,0,2};size_t rn=sizeof(r);
   q[7]=r[7]=fc;
   if(fc==2){q[11]=9;r[5]=5;r[8]=2;r[9]=1;r[10]=1;rn=11;}
   else if(fc==5||fc==6){q[10]=0xff;q[11]=0;memcpy(r,q,sizeof(q));rn=sizeof(q);}
   else if(fc==16){unsigned char w[]={0,1,0,0,0,11,1,16,0,0,0,2,4,0,1,0,2};
     CHECK(gr_before_send(e,w,sizeof(w),err,sizeof(err))==0);
     unsigned char a[]={0,1,0,0,0,6,1,16,0,0,0,2};gr_after_stream(e,a,sizeof(a));CHECK(completed(e)==4+i);continue;}
   CHECK(gr_before_send(e,q,sizeof(q),err,sizeof(err))==0);gr_after_stream(e,r,rn);CHECK(completed(e)==4+i);
 }
 gr_free(e);puts("PASS: variable Modbus quantities, padding, alternatives and TCP transactions");return 0;
}
