/* Bounded EtherNet/IP explicit-message codec. SendUnitData requires an
 * externally established class-3 connection (ForwardOpen is not encoded). */
#include "protocol_codecs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static int bad(char *e,size_t z,const char *s){if(e&&z)snprintf(e,z,"ENIP: %s",s);return -1;}
static unsigned u16(const uint8_t *p){return p[0]|((unsigned)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void w16(uint8_t *p,size_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
struct layout{size_t cip,cn,path,pn,additional,an,result,rn;unsigned command;};
/* Logical segment widths may differ while the bounded Identity path stays
 * class 1 / instance 1 / attribute 1. This also permits meaningful resizing. */
static int path_ok(const uint8_t *p,size_t n){
 size_t at=0;unsigned i;
 static const unsigned base[3]={0x20,0x24,0x30};
 for(i=0;i<3;i++){
  unsigned fmt;uint32_t v;
  if(at>=n||(p[at]&0xfc)!=base[i])return 0;
  fmt=p[at]&3;
  if(fmt==0){if(n-at<2)return 0;v=p[at+1];at+=2;}
  else if(fmt==1){if(n-at<4||p[at+1])return 0;v=u16(p+at+2);at+=4;}
  else if(fmt==2){if(n-at<6||p[at+1])return 0;v=u32(p+at+2);at+=6;}
  else return 0;
  if(v!=1)return 0;
 }
 return at==n;
}
static int parse(uint8_t *p,size_t n,int fix,struct layout *l,char *e,size_t z){
 size_t data,dl;unsigned c,status,connected;
 memset(l,0,sizeof(*l));
 if(!p||n<24||n-24>65535)return bad(e,z,"invalid encapsulation size");
 c=u16(p);l->command=c;status=u32(p+8);
 if(c!=101&&c!=102&&c!=111&&c!=112)return bad(e,z,"command outside Register/Unregister/explicit profile");
 if(u32(p+20))return bad(e,z,"encapsulation options must be zero");
 if(fix)w16(p+2,n-24);else if(u16(p+2)!=n-24)return bad(e,z,"encapsulation length");
 if(status){
  if(n!=24||!((c==101&&status==0x69)||(c!=101&&status==0x64)))return bad(e,z,"encapsulation error outside profile");
  return 0;
 }
 if(c==101){if(n!=28||u16(p+24)!=1||u16(p+26))return bad(e,z,"RegisterSession version/options");return 0;}
 if(!u32(p+4))return bad(e,z,"nonzero registered session required");
 if(c==102)return n==24?0:bad(e,z,"UnregisterSession payload");
 connected=c==112;data=connected?44:40;
 if(n<data+4||u32(p+24)|| (connected&&u16(p+28)))return bad(e,z,"CPF header or connected timeout");
 if(u16(p+32)!=(connected?0xa1:0)||u16(p+(connected?40:36))!=(connected?0xb1:0xb2))return bad(e,z,"CPF item types/order outside profile");
 if(connected&&!u32(p+36))return bad(e,z,"external ForwardOpen connection ID required");
 if(fix){w16(p+30,2);w16(p+34,connected?4:0);w16(p+data-2,n-data);}
 else if(u16(p+30)!=2||u16(p+34)!=(connected?4:0)||u16(p+data-2)!=n-data)return bad(e,z,"CPF item count/length");
 l->cip=data+(connected?2:0);l->cn=n-l->cip;
 dl=l->cn;
 if(p[l->cip]==0x0e){
  if(dl<2||dl-2>510||!path_ok(p+l->cip+2,dl-2))return bad(e,z,"GetAttributeSingle Identity EPATH outside profile");
  l->path=l->cip+2;l->pn=dl-2;
  if(fix)p[l->cip+1]=(uint8_t)(l->pn/2);
  else if(p[l->cip+1]*2u!=l->pn)return bad(e,z,"CIP path word count");
 }else if(p[l->cip]==0x8e){
  unsigned general;
  if(dl<4||p[l->cip+1])return bad(e,z,"CIP response service/reserved byte");
  general=p[l->cip+2];
  if(general!=0&&general!=0x14)return bad(e,z,"CIP status outside Vendor-ID profile");
  l->rn=general?0:2;
  if(dl<4+l->rn||(dl-4-l->rn)%2||dl-4-l->rn>510)return bad(e,z,"CIP additional status/result size");
  l->additional=l->cip+4;l->an=dl-4-l->rn;l->result=l->additional+l->an;
  if(fix)p[l->cip+3]=(uint8_t)(l->an/2);
  else if(p[l->cip+3]*2u!=l->an)return bad(e,z,"CIP additional-status word count");
 }else return bad(e,z,"CIP service outside GetAttributeSingle profile");
 return 0;
}
int pc_enip_validate(const uint8_t *p,size_t n,char *e,size_t z){struct layout l;return parse((uint8_t *)p,n,0,&l,e,z);}
int pc_enip_repair(uint8_t *p,size_t n,char *e,size_t z){struct layout l;return parse(p,n,1,&l,e,z);}
static size_t scalar(int t){switch(t){case PC_UINT8:return 1;case PC_UINT16:return 2;case PC_UINT24:return 3;case PC_UINT32:return 4;case PC_UINT64:return 8;default:return 0;}}
static int absolute(const char *s,size_t *a){size_t v=0;if(!s||strncmp(s,"abs:",4))return 0;s+=4;if(!*s)return -1;for(;*s;s++){if(*s<'0'||*s>'9'||v>(SIZE_MAX-(unsigned)(*s-'0'))/10)return -1;v=v*10+(unsigned)(*s-'0');}*a=v;return 1;}
int pc_enip_field(const uint8_t *p,size_t n,const char *loc,int t,size_t width,size_t *off,size_t *len,char *e,size_t z){
 struct layout l;size_t a=0,b=0;int abs;
 if(!off||!len)return bad(e,z,"missing field result");
 if(parse((uint8_t *)p,n,0,&l,e,z))return -1;
 abs=absolute(loc,&a);if(abs<0)return bad(e,z,"invalid absolute locator");
 if(abs){
  b=width?width:scalar(t);
  if(!b){if(t==PC_EPATH&&a==l.path&&l.pn)b=l.pn;else if(t==PC_BYTES&&a==l.cip&&l.cn)b=l.cn;else return 0;}
 }else if(loc&&!strcmp(loc,"cip:additional_status")&&l.additional){a=l.additional;b=l.an;}
 else if(loc&&!strcmp(loc,"cip:response_data")&&l.additional){a=l.result;b=l.rn;}
 else if(loc&&!strcmp(loc,"cip:epath")&&l.pn){a=l.path;b=l.pn;}
 else return 0;
 if(a>n||b>n-a)return bad(e,z,"field outside packet");
 *off=a;*len=b;return 1;
}
int pc_enip_replace(uint8_t *p,size_t *np,size_t cap,const char *loc,int t,const uint8_t *value,size_t vn,char *e,size_t z){
 struct layout l;size_t a,b,n,newn;uint8_t *q;int r;
 if(!p||!np||(!value&&vn))return bad(e,z,"invalid replacement arguments");
 n=*np;
 if(n>cap)return bad(e,z,"packet exceeds replacement capacity");
 if(parse(p,n,0,&l,e,z))return -1;
 r=pc_enip_field(p,n,loc,t,0,&a,&b,e,z);if(r!=1)return bad(e,z,"unsupported replacement locator");
 if(t==PC_EPATH){if(a!=l.path||!path_ok(value,vn))return bad(e,z,"replacement EPATH outside Identity profile");}
 else if(t==PC_BYTES){
  if(loc&&!strcmp(loc,"cip:response_data")){if(vn!=l.rn)return bad(e,z,"Vendor-ID result must be UInt16");}
  else if(a==l.additional){if(vn>510||(vn&1))return bad(e,z,"additional status must be UInt16 words");}
  else return bad(e,z,"opaque CIP/container replacement unsupported");
 }else if(!scalar(t)||vn!=b)return bad(e,z,"replacement is not a supported leaf");
 if(vn>SIZE_MAX-(n-b)||(newn=n-b+vn)>cap||newn>65559)return bad(e,z,"replacement capacity");
 q=(uint8_t *)malloc(newn?newn:1);if(!q)return bad(e,z,"allocation failed");
 memcpy(q,p,a);if(vn)memcpy(q+a,value,vn);memcpy(q+a+vn,p+a+b,n-a-b);
 r=pc_enip_repair(q,newn,e,z);if(!r){memcpy(p,q,newn);*np=newn;}free(q);return r;
}
int pc_enip_frame(const uint8_t *p,size_t n,size_t *size,char *e,size_t z){
 size_t total;unsigned c;if(!p||!size)return bad(e,z,"invalid frame arguments");if(n<4)return 0;
 c=u16(p);if(c!=101&&c!=102&&c!=111&&c!=112)return bad(e,z,"unsupported frame command");
 total=24u+u16(p+2);if(n<24)return 0;
 if(u32(p+20))return bad(e,z,"frame options outside profile");
 if(n<total)return 0;
 if(pc_enip_validate(p,total,e,z))return -1;
 *size=total;return 1;
}

int pc_enip_same_kind(const uint8_t *p,size_t n,const uint8_t *q,size_t m){
 struct layout a,b;
 if(parse((uint8_t *)p,n,0,&a,0,0)||parse((uint8_t *)q,m,0,&b,0,0))return 0;
 if(a.command!=b.command||u32(p+8)!=u32(q+8))return 0;
 if(a.cip&&b.cip){if(p[a.cip]!=q[b.cip])return 0;return !(p[a.cip]&128)||p[a.cip+2]==q[b.cip+2];}
 return !a.cip&&!b.cip;
}
