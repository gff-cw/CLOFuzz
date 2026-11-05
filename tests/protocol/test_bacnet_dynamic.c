/* Controlled in-process BACnet codec/session regression; no network I/O. */
#include "protocol_runtime.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static char error[512];
static size_t decode(const char *s,unsigned char *b){size_t n=0;unsigned x;while(*s){assert(sscanf(s,"%2x",&x)==1);b[n++]=x;s+=2;}b[2]=n>>8;b[3]=n;return n;}
static void field(unsigned char *b,size_t n,const char *l,size_t want_o,size_t want_w){size_t o,w;assert(proto_bacnet_field(b,n,l,&o,&w,error,sizeof(error))==1);assert(o==want_o && w==want_w);}
static size_t route(unsigned char *b,size_t n){/* DNET/DADR + SNET/SADR + hop count */
 const unsigned char addr[]={0,1,1,42,0,2,1,43,255};memmove(b+15,b+6,n-6);memcpy(b+6,addr,9);b[5]|=40;n+=9;b[2]=n>>8;b[3]=n;return n;}
static unsigned select_count, selected_field=1;
static uint32_t select_property(uint32_t limit){unsigned x=select_count++;return limit?(x==1?selected_field:0)%limit:0;}
int main(int argc,char **argv){assert(argc==3);unsigned char b[256],r[256];size_t n,o,w;
 n=decode("810a000001001000c40200007b24000005c494000000032200ff",b);
 field(b,n,"bacnet.iam.device",9,4);field(b,n,"bacnet.iam.max_apdu",14,4);field(b,n,"bacnet.iam.segmentation",19,4);field(b,n,"bacnet.iam.vendor",24,2);
 n=route(b,n);field(b,n,"bacnet.iam.vendor",33,2);b[18]=0;assert(proto_bacnet_field(b,n,"bacnet.iam.device",&o,&w,error,sizeof(error))<0);
 n=decode("810a0000010050010c9200029400000120",b);n=route(b,n);field(b,n,"bacnet.error.class",19,2);field(b,n,"bacnet.error.code",22,4);
 for(unsigned kind=6;kind<=7;kind++){n=decode("810a00000100600109",b);b[6]=kind<<4;n=route(b,n);field(b,n,"apdu.reason",17,1);assert(proto_bacnet_field(b,n,"apdu.service",&o,&w,error,sizeof(error))==0);}
 n=decode("810a0000010030010c0c0200007b1c000001023e29073f",b);field(b,n,"bacnet.value",20,2);assert(proto_bacnet_field(b,n,"bacnet.array",&o,&w,error,sizeof(error))==0);
 n=route(b,n);field(b,n,"bacnet.property",24,4);field(b,n,"bacnet.value",29,2);
 /* Every request property/index wire width, including nonminimal legal widths. */
 for(unsigned width=1;width<=4;width++){
  n=decode("810a000001040005010c0c0200007b",b);b[n++]=0x18|width;memset(b+n,0,width);b[n+width-1]=77;n+=width;b[n++]=0x28|width;memset(b+n,0,width);b[n+width-1]=3;n+=width;b[3]=n;
  field(b,n,"bacnet.property",16,width);field(b,n,"bacnet.array",17+width,width);
  n=route(b,n);field(b,n,"bacnet.array",26+width,width);
 }
 proto_engine *e=proto_load(argv[1],argv[2],error,sizeof(error));if(!e)fprintf(stderr,"%s\n",error);assert(e);
 /* Mutation grows a one-byte property to a four-byte UInt32 and repairs BVLC. */
 n=decode("810a000001040005010c0c0200007b194d",b);unsigned char records[300]={0},candidate[256];records[0]=n;memcpy(records+4,b,n);memcpy(candidate,b,n);candidate[16]=1;candidate[17]=2;candidate[18]=3;candidate[19]=4;
 const unsigned char *out;size_t out_n;select_count=0;
 assert(proto_mutate(e,records,n+4,candidate,20,PROTO_VALID,PROTO_CONTENT,select_property,&out,&out_n,error,sizeof(error))==0);
 field((unsigned char *)out+4,out_n-4,"bacnet.property",16,4);assert(out[20]==1 && out[23]==4);
 /* Optional index growth uses the same typed serializer, independently of property. */
 n=decode("810a000001040005010c0c0200007b194d2903",b);records[0]=n;memcpy(records+4,b,n);memcpy(candidate,b,n);candidate[18]=1;candidate[19]=2;candidate[20]=3;candidate[21]=4;
 select_count=0;selected_field=2;
 assert(proto_mutate(e,records,n+4,candidate,22,PROTO_VALID,PROTO_CONTENT,select_property,&out,&out_n,error,sizeof(error))==0);
 field((unsigned char *)out+4,out_n-4,"bacnet.array",18,4);assert(out[22]==1 && out[25]==4);
 /* Real response correlation rejects mismatched property then accepts matching ACK. */
 proto_session_begin(e);n=decode("810a000001040005010c0c0200007b194d",b);assert(proto_before_send(e,b,n,error,sizeof(error))==0);
 size_t rn=decode("810a0000010030010c0c0200007b194e3e21013f",r);r[7]=b[8];proto_after_dgram(e,r,rn);assert(proto_prepare_send(e,b,n,error,sizeof(error))<0);
 r[15]=77;proto_after_dgram(e,r,rn);assert(proto_prepare_send(e,b,n,error,sizeof(error))==0);proto_cancel_send(e);
 /* Optional array presence is part of the echoed reference, not just its value. */
 for(unsigned request_array=0;request_array<2;request_array++){
  proto_session_begin(e);
  n=decode(request_array?"810a000001040005010c0c0200007b194d2903":"810a000001040005010c0c0200007b194d",b);
  assert(proto_before_send(e,b,n,error,sizeof(error))==0);
  rn=decode(request_array?"810a0000010030010c0c0200007b194d3e21013f":"810a0000010030010c0c0200007b194d29033e21013f",r);
  r[7]=b[8];proto_after_dgram(e,r,rn);assert(proto_prepare_send(e,b,n,error,sizeof(error))<0);
  rn=decode(request_array?"810a0000010030010c0c0200007b1a004d2c000000033e21013f":"810a0000010030010c0c0200007b1a004d3e21013f",r);
  r[7]=b[8];rn=route(r,rn);proto_after_dgram(e,r,rn);
  assert(proto_prepare_send(e,b,n,error,sizeof(error))==0);proto_cancel_send(e);
 }
 proto_free(e);puts("BACnet dynamic locators, routing, UInt32 mutation and response correlation passed");return 0;}
