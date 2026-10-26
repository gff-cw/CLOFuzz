/* OPC UA TCP, single final chunks and SecurityPolicy None only. The parser
 * walks complete UA Binary service bodies; encrypted/chunked data is rejected. */
#include "protocol_codecs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#define UA_MAX (1024u*1024u)
#define UA_ARRAY 64
#define NO_PREFIX SIZE_MAX
static const char none_uri[]="http://opcfoundation.org/UA/SecurityPolicy#None";
static const char transport_uri[]="http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
static int bad(char *e,size_t n,const char *s){if(e&&n)snprintf(e,n,"OPCUA: %s",s);return -1;}
static uint32_t rd32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void wr32(uint8_t *p,uint32_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)(n>>16);p[3]=(uint8_t)(n>>24);}
static size_t scalar(int t){switch(t){case PC_UINT8:return 1;case PC_UINT16:return 2;case PC_UINT24:return 3;case PC_UINT32:return 4;case PC_UINT64:return 8;default:return 0;}}
struct reader{
 const uint8_t *p;size_t n,at;const char *why,*want;int want_type,absolute,found;
 size_t absolute_at,off,len,prefix;int kind,is_null;unsigned service;char typ[4];
};
static int fail(struct reader *r,const char *s){r->why=s;return 0;}
static int take(struct reader *r,size_t n,size_t *off){if(n>r->n-r->at)return fail(r,"truncated UA Binary field");if(off)*off=r->at;r->at+=n;return 1;}
static void mark(struct reader *r,const char *name,int type,size_t off,size_t len,size_t prefix,int is_null){
 int match=0;
 if(r->absolute)match=(r->absolute_at==off||r->absolute_at==prefix)&&r->want_type==type;
 else if(r->want&&name)match=!strcmp(r->want,name);
 if(match&&!r->found){r->off=off;r->len=len;r->prefix=prefix;r->kind=type;r->is_null=is_null;r->found=1;}
}
static int number(struct reader *r,const char *name,int type,uint32_t *value){size_t off,w=scalar(type);if(!take(r,w,&off))return 0;mark(r,name,type,off,w,NO_PREFIX,0);if(value)*value=w==1?r->p[off]:w==2?(r->p[off]|((uint32_t)r->p[off+1]<<8)):rd32(r->p+off);return 1;}
static int utf8(const uint8_t *p,size_t n){
 size_t i=0;while(i<n){uint32_t c=p[i++];unsigned more,j;uint32_t min;
 if(c<128)continue;
 if(c>=0xc2&&c<=0xdf){more=1;c&=31;min=0x80;}
 else if(c>=0xe0&&c<=0xef){more=2;c&=15;min=0x800;}
 else if(c>=0xf0&&c<=0xf4){more=3;c&=7;min=0x10000;}else return 0;
 if(more>n-i)return 0;
 for(j=0;j<more;j++){if((p[i]&0xc0)!=0x80)return 0;c=(c<<6)|(p[i++]&63);}
 if(c<min||c>0x10ffff||(c>=0xd800&&c<=0xdfff))return 0;
 }return 1;
}
struct blob{size_t off,len,prefix;int null;};
static int blob(struct reader *r,const char *name,int type,struct blob *out){
 size_t off,pre;int32_t n;struct blob b;
 if(!take(r,4,&pre))return 0;
 n=(int32_t)rd32(r->p+pre);
 if(n < -1||(uint32_t)(n<0?0:n)>UA_MAX)return fail(r,"invalid String/ByteString length");
 if(!take(r,n<0?0:(size_t)n,&off))return 0;
 if(type==PC_STRING&&n>0&&!utf8(r->p+off,(size_t)n))return fail(r,"invalid UTF-8 String");
 b.off=off;b.len=n<0?0:(size_t)n;b.prefix=pre;b.null=n<0;
 mark(r,name,type,off,b.len,pre,b.null);if(out)*out=b;return 1;
}
static int equal_blob(const struct reader *r,const struct blob *b,const char *s){return !b->null&&b->len==strlen(s)&&!memcmp(r->p+b->off,s,b->len);}
struct node{uint32_t ns,id;int numeric;size_t off,len;};
static int nodeid(struct reader *r,const char *name,struct node *out){
 size_t start=r->at,off;unsigned tag;struct node n;struct blob b;
 memset(&n,0,sizeof(n));n.off=start;
 if(!take(r,1,&off))return 0;
 tag=r->p[off];
 if(tag==0){if(!take(r,1,&off))return 0;n.id=r->p[off];n.numeric=1;}
 else if(tag==1){if(!take(r,3,&off))return 0;
  n.ns=r->p[off];n.id=r->p[off+1]|((uint32_t)r->p[off+2]<<8);n.numeric=1;}
 else if(tag==2){if(!take(r,6,&off))return 0;
  n.ns=r->p[off]|((uint32_t)r->p[off+1]<<8);n.id=rd32(r->p+off+2);n.numeric=1;}
 else if(tag>=3&&tag<=5){
  if(!take(r,2,&off))return 0;
  n.ns=r->p[off]|((uint32_t)r->p[off+1]<<8);
  if(tag==4){if(!take(r,16,0))return 0;}else if(!blob(r,0,tag==3?PC_STRING:PC_BYTES,&b))return 0;
 }else return fail(r,"NodeId flags/encoding outside bounded profile");
 n.len=r->at-start;mark(r,name,PC_NODEID,start,n.len,NO_PREFIX,0);if(out)*out=n;return 1;
}
static void join(char *out,size_t cap,const char *base,const char *leaf){snprintf(out,cap,"%s.%s",base,leaf);}
static int named_num(struct reader *r,const char *base,const char *leaf,int type,uint32_t *v){char key[192];join(key,sizeof(key),base,leaf);return number(r,key,type,v);}
static int named_blob(struct reader *r,const char *base,const char *leaf,int type,struct blob *b){char key[192];join(key,sizeof(key),base,leaf);return blob(r,key,type,b);}
static int count(struct reader *r,const char *base,int32_t *n){uint32_t u;char key[192];join(key,sizeof(key),base,"count");if(!number(r,key,PC_UINT32,&u))return 0;*n=(int32_t)u;if(*n < -1||*n>UA_ARRAY)return fail(r,"array count outside bounded profile");
 return 1;}
static int strings(struct reader *r,const char *base){int32_t n,i;char key[192];if(!count(r,base,&n))return 0;for(i=0;i<n;i++){snprintf(key,sizeof(key),"%s.%d",base,(int)i);if(!blob(r,key,PC_STRING,0))return 0;}return 1;}
static int diagnostic(struct reader *r,const char *base,unsigned depth){
 uint32_t bits;char key[192];unsigned bit;static const char *names[]={"symbolic_id","namespace_uri","localized_text","locale"};
 if(depth>8)return fail(r,"DiagnosticInfo nesting limit");
 if(!named_num(r,base,"mask",PC_UINT8,&bits))return 0;
 if(bits&128)return fail(r,"DiagnosticInfo mask");
 for(bit=0;bit<4;bit++)if((bits&(1u<<bit))&&!named_num(r,base,names[bit],PC_UINT32,0))return 0;
 if((bits&16)&&!named_blob(r,base,"additional_info",PC_STRING,0))return 0;
 if((bits&32)&&!named_num(r,base,"inner_status",PC_UINT32,0))return 0;
 if(bits&64){join(key,sizeof(key),base,"inner");if(!diagnostic(r,key,depth+1))return 0;}return 1;
}
static int additional(struct reader *r){struct node node;uint32_t enc;if(!nodeid(r,"header.additional_header.type_id",&node)||!number(r,"header.additional_header.encoding",PC_UINT8,&enc))return 0;if(!node.numeric||node.ns||node.id||enc)return fail(r,"nonempty AdditionalHeader outside discovery profile");
 return 1;}
static int header(struct reader *r,int response,uint32_t *result){
 struct node auth;char key[192];
 if(!response){if(!nodeid(r,"header.authentication_token",&auth))return 0;if(!auth.numeric||auth.ns||auth.id)return fail(r,"discovery requires null authentication token");}
 if(!number(r,"header.timestamp",PC_UINT64,0)||!number(r,"header.request_handle",PC_UINT32,0))return 0;
 if(response){
  if(!number(r,"header.service_result",PC_UINT32,result)||!diagnostic(r,"header.service_diagnostics",0))return 0;
  if(!strings(r,"header.string_table"))return 0;
 }else{
  if(!number(r,"header.return_diagnostics",PC_UINT32,0)||!blob(r,"header.audit_entry_id",PC_STRING,0)||!number(r,"header.timeout_hint",PC_UINT32,0))return 0;
 }
 (void)key;return additional(r);
}
static int localized(struct reader *r,const char *base){uint32_t mask;if(!named_num(r,base,"mask",PC_UINT8,&mask))return 0;if(mask&~3u)return fail(r,"LocalizedText mask");if((mask&1)&&!named_blob(r,base,"locale",PC_STRING,0))return 0;return !(mask&2)||named_blob(r,base,"text",PC_STRING,0);}
static int application(struct reader *r,const char *base){
 char key[192];uint32_t type;
 if(!named_blob(r,base,"application_uri",PC_STRING,0)||!named_blob(r,base,"product_uri",PC_STRING,0))return 0;
 join(key,sizeof(key),base,"application_name");if(!localized(r,key)||!named_num(r,base,"application_type",PC_UINT32,&type))return 0;
 if(type>3)return fail(r,"ApplicationType outside profile");
 if(!named_blob(r,base,"gateway_uri",PC_STRING,0)||!named_blob(r,base,"discovery_profile_uri",PC_STRING,0))return 0;
 join(key,sizeof(key),base,"discovery_urls");return strings(r,key);
}
static int user_token(struct reader *r,const char *base){uint32_t type;struct blob policy;
 if(!named_blob(r,base,"policy_id",PC_STRING,0)||!named_num(r,base,"token_type",PC_UINT32,&type)||!named_blob(r,base,"issued_token_type",PC_STRING,0)||!named_blob(r,base,"issuer_endpoint_url",PC_STRING,0)||!named_blob(r,base,"security_policy_uri",PC_STRING,&policy))return 0;
 if(type!=0||(!policy.null&&policy.len&&!equal_blob(r,&policy,none_uri)))return fail(r,"only anonymous None user token policies supported");
 return 1;
}
static int endpoint(struct reader *r,const char *base){
 char key[192],item[192];struct blob cert,policy,transport;uint32_t mode;int32_t n,i;
 if(!named_blob(r,base,"endpoint_url",PC_STRING,0))return 0;
 join(key,sizeof(key),base,"server");if(!application(r,key)||!named_blob(r,base,"certificate",PC_BYTES,&cert)||!named_num(r,base,"security_mode",PC_UINT32,&mode)||!named_blob(r,base,"security_policy_uri",PC_STRING,&policy))return 0;
 if(!cert.null||mode!=1||!equal_blob(r,&policy,none_uri))return fail(r,"endpoint security outside None profile");
 join(key,sizeof(key),base,"user_tokens");if(!count(r,key,&n))return 0;
 for(i=0;i<n;i++){snprintf(item,sizeof(item),"%.170s.%d",key,(int)i);if(!user_token(r,item))return 0;}
 if(!named_blob(r,base,"transport_profile_uri",PC_STRING,&transport)||!named_num(r,base,"security_level",PC_UINT8,0))return 0;
 if(!equal_blob(r,&transport,transport_uri))return fail(r,"endpoint transport outside UA TCP binary profile");
 return 1;
}
static int parse(struct reader *r){
 uint32_t size,protocol,receive,send,channel=0,token=0,mode,reqtype,result=0,token_channel,lifetime;struct blob b,cert,thumb,nonce;struct node service;int32_t n,i;char key[192];
 if(!r->p||r->n<8||r->n>UA_MAX)return fail(r,"invalid TCP message size");
 memcpy(r->typ,r->p,3);r->typ[3]=0;r->at=4;
 if(r->p[3]!='F')return fail(r,"only final unencrypted chunks supported");
 mark(r,"message_type",PC_UINT24,0,3,NO_PREFIX,0);mark(r,"chunk",PC_UINT8,3,1,NO_PREFIX,0);
 if(!number(r,"message_size",PC_UINT32,&size)||size!=r->n)return fail(r,"TCP MessageSize mismatch");
 if(!strcmp(r->typ,"HEL")||!strcmp(r->typ,"ACK")){
  if(!number(r,"protocol_version",PC_UINT32,&protocol)||!number(r,"receive_buffer",PC_UINT32,&receive)||!number(r,"send_buffer",PC_UINT32,&send)||!number(r,"max_message_size",PC_UINT32,0)||!number(r,"max_chunk_count",PC_UINT32,0))return 0;
  if(protocol||receive<8192||send<8192)return fail(r,"UA negotiation outside version/buffer profile");
  if(!strcmp(r->typ,"HEL")){if(!blob(r,"endpoint",PC_STRING,&b))return 0;
  if(b.null||b.len+4>=4096)return fail(r,"transport endpoint String outside profile");}
 }else if(!strcmp(r->typ,"ERR")){if(!number(r,"error_code",PC_UINT32,0)||!blob(r,"reason",PC_STRING,0))return 0;
 }else if(!strcmp(r->typ,"RHE")){
  if(!blob(r,"server_uri",PC_STRING,&b))return 0;
  if(b.null||b.len+4>=4096)return fail(r,"reverse server URI outside profile");
  if(!blob(r,"endpoint",PC_STRING,&b))return 0;
  if(b.null||b.len+4>=4096)return fail(r,"reverse endpoint outside profile");
 }else if(!strcmp(r->typ,"OPN")||!strcmp(r->typ,"MSG")||!strcmp(r->typ,"CLO")){
  if(!number(r,"channel",PC_UINT32,&channel))return 0;
  if(!strcmp(r->typ,"OPN")){
   if(!blob(r,"policy_uri",PC_STRING,&b)||!blob(r,"sender_certificate",PC_BYTES,&cert)||!blob(r,"receiver_thumbprint",PC_BYTES,&thumb))return 0;
   if(!equal_blob(r,&b,none_uri)||!cert.null||!thumb.null)return fail(r,"asymmetric header outside SecurityPolicy None");
  }else{if(!number(r,"token",PC_UINT32,&token))return 0;if(!channel||!token)return fail(r,"bound channel/token required");}
  if(!number(r,"sequence",PC_UINT32,0)||!number(r,"request_id",PC_UINT32,0)||!nodeid(r,"service_nodeid",&service))return 0;
  if(!service.numeric||service.ns)return fail(r,"service NodeId outside namespace zero profile");
  r->service=service.id;
  if(service.id!=446&&service.id!=449&&service.id!=428&&service.id!=431&&service.id!=397&&service.id!=452)return fail(r,"service encoding ID outside bounded profile");
  if(!header(r,service.id==449||service.id==431||service.id==397,&result))return 0;
  if(service.id==446){
   if(strcmp(r->typ,"OPN"))return fail(r,"OpenSecureChannel request requires OPN");
   if(!number(r,"open.protocol_version",PC_UINT32,&protocol)||!number(r,"open.request_type",PC_UINT32,&reqtype)||!number(r,"open.security_mode",PC_UINT32,&mode)||!blob(r,"open.nonce",PC_BYTES,&nonce)||!number(r,"open.lifetime",PC_UINT32,0))return 0;
   if(protocol||reqtype>1||mode!=1||!nonce.null||(!reqtype&&channel))return fail(r,"OpenSecureChannel request outside None profile");
  }else if(service.id==449){
   if(strcmp(r->typ,"OPN"))return fail(r,"OpenSecureChannel response requires OPN");
   if(!number(r,"open.protocol_version",PC_UINT32,&protocol)||!number(r,"token.channel_id",PC_UINT32,&token_channel)||!number(r,"token.token_id",PC_UINT32,&token)||!number(r,"token.created_at",PC_UINT64,0)||!number(r,"token.lifetime",PC_UINT32,&lifetime)||!blob(r,"open.nonce",PC_BYTES,&nonce))return 0;
   if(protocol||result||!channel||channel!=token_channel||!token||!lifetime||!nonce.null)return fail(r,"OpenSecureChannel response token/profile");
  }else if(service.id==428){
   if(strcmp(r->typ,"MSG"))return fail(r,"GetEndpoints request requires MSG");
   if(!blob(r,"endpoint",PC_STRING,0)||!strings(r,"locale_ids")||!strings(r,"profile_uris"))return 0;
  }else if(service.id==431){
   if(strcmp(r->typ,"MSG"))return fail(r,"GetEndpoints response requires MSG");
   if(!count(r,"endpoints",&n))return 0;
   for(i=0;i<n;i++){snprintf(key,sizeof(key),"endpoints.%d",(int)i);if(!endpoint(r,key))return 0;}
  }else if(service.id==397){if(strcmp(r->typ,"MSG")||!(result&0x80000000u))return fail(r,"ServiceFault type/result");}
  else if(strcmp(r->typ,"CLO"))return fail(r,"CloseSecureChannel requires CLO");
 }else return fail(r,"TCP message type outside bounded profile");
 if(r->at!=r->n)return fail(r,"trailing UA Binary fields");
 return 1;
}
static void init(struct reader *r,const uint8_t *p,size_t n){memset(r,0,sizeof(*r));r->p=p;r->n=n;r->prefix=NO_PREFIX;}
int pc_opcua_validate(const uint8_t *p,size_t n,char *e,size_t z){struct reader r;init(&r,p,n);return parse(&r)?0:bad(e,z,r.why?r.why:"malformed UA Binary");}
int pc_opcua_repair(uint8_t *p,size_t n,char *e,size_t z){
 if(!p||n<8||n>UA_MAX)return bad(e,z,"invalid repair size");
 /* Inner signed lengths/counts cannot be reconstructed unambiguously from
  * opaque bytes. Structured replace updates the one known changed prefix. */
 wr32(p+4,(uint32_t)n);return pc_opcua_validate(p,n,e,z);
}
static int locator(struct reader *r,const char *loc,int type,char *key,size_t keysize){
 size_t a=0,k=0;const char *s;
 if(!loc)return 0;
 if(!strncmp(loc,"abs:",4)){
  s=loc+4;if(!*s)return -1;
  for(;*s;s++){if(*s<'0'||*s>'9'||a>(SIZE_MAX-(unsigned)(*s-'0'))/10)return -1;a=a*10+(unsigned)(*s-'0');}
  r->absolute=1;r->absolute_at=a;r->want_type=type;return 1;
 }
 s=!strncmp(loc,"uabin:",6)?loc+6:loc;
 /* Both endpoints[0].server and endpoints.0.server are accepted. */
 for(;*s;s++){
  char c=*s;if(c=='[')c='.';else if(c==']')continue;
  if(k+1>=keysize)return -1;
  key[k++]=c;
 }key[k]=0;
 if(!strcmp(key,"header.audit"))strcpy(key,"header.audit_entry_id");
 else if(!strcmp(key,"header.timeout"))strcpy(key,"header.timeout_hint");
 else if(!strcmp(key,"header.auth_token"))strcpy(key,"header.authentication_token");
 else if(!strcmp(key,"header.diagnostics"))strcpy(key,"header.service_diagnostics");
 r->want=key;r->want_type=type;return 1;
}
static int locate(const uint8_t *p,size_t n,const char *loc,int type,size_t width,struct reader *r,char *e,size_t z){
 char key[192];size_t w;int l;
 init(r,p,n);l=locator(r,loc,type,key,sizeof(key));if(l<0)return bad(e,z,"invalid field locator");
 if(!parse(r))return bad(e,z,r->why?r->why:"malformed UA Binary");
 if(!l)return 0;
 if(r->absolute&&(w=width?width:scalar(type))){
  if(r->absolute_at>n||w>n-r->absolute_at)return bad(e,z,"field outside message");
  r->off=r->absolute_at;r->len=w;r->kind=type;r->prefix=NO_PREFIX;r->found=1;
 }else if(r->absolute&&r->absolute_at==8&&type==PC_BYTES){r->off=8;r->len=n-8;r->kind=PC_BYTES;r->prefix=NO_PREFIX;r->found=1;}
 if(r->found&&r->kind!=type)return 0;
 return r->found?1:0;
}
int pc_opcua_field(const uint8_t *p,size_t n,const char *loc,int type,size_t width,size_t *off,size_t *len,char *e,size_t z){
 struct reader r;int result;if(!off||!len)return bad(e,z,"missing field result");
 result=locate(p,n,loc,type,width,&r,e,z);if(result==1){*off=r.off;*len=r.len;}return result;
}
int pc_opcua_replace(uint8_t *p,size_t *np,size_t cap,const char *loc,int type,const uint8_t *value,size_t vn,char *e,size_t z){
 struct reader r;size_t n,newn;uint8_t *q;int status;
 if(!p||!np||(!value&&vn))return bad(e,z,"invalid replacement arguments");
 n=*np;
 if(n>cap)return bad(e,z,"packet exceeds replacement capacity");
 status=locate(p,n,loc,type,0,&r,e,z);if(status!=1)return bad(e,z,"unsupported replacement locator");
 if(type==PC_STRING||type==PC_BYTES){
  if(r.prefix==NO_PREFIX)return bad(e,z,"opaque whole-container replacement unsupported");
  if(vn>INT32_MAX|| (type==PC_STRING&&!utf8(value,vn)))return bad(e,z,"replacement String/ByteString invalid");
 }else if(type!=PC_NODEID&&(!scalar(type)||vn!=r.len))return bad(e,z,"replacement is not a supported leaf");
 if(vn>SIZE_MAX-(n-r.len)||(newn=n-r.len+vn)>cap||newn>UA_MAX)return bad(e,z,"replacement capacity");
 q=(uint8_t *)malloc(newn?newn:1);if(!q)return bad(e,z,"allocation failed");
 memcpy(q,p,r.off);if(vn)memcpy(q+r.off,value,vn);memcpy(q+r.off+vn,p+r.off+r.len,n-r.off-r.len);
 if(r.prefix!=NO_PREFIX)wr32(q+r.prefix,(uint32_t)((r.is_null&&!vn)?UINT32_MAX:vn));
 status=pc_opcua_repair(q,newn,e,z);if(!status){memcpy(p,q,newn);*np=newn;}free(q);return status;
}
int pc_opcua_frame(const uint8_t *p,size_t n,size_t *size,char *e,size_t z){
 size_t total;if(!p||!size)return bad(e,z,"invalid frame arguments");if(n<8)return 0;
 if(p[3]!='F')return bad(e,z,"only final chunks supported");
 if(memcmp(p,"HEL",3)&&memcmp(p,"ACK",3)&&memcmp(p,"ERR",3)&&memcmp(p,"RHE",3)&&memcmp(p,"OPN",3)&&memcmp(p,"MSG",3)&&memcmp(p,"CLO",3))return bad(e,z,"unsupported frame type");
 total=rd32(p+4);if(total<8||total>UA_MAX)return bad(e,z,"invalid frame MessageSize");if(n<total)return 0;
 if(pc_opcua_validate(p,total,e,z))return -1;
 *size=total;return 1;
}
int pc_opcua_same_kind(const uint8_t *p,size_t n,const uint8_t *q,size_t m){
 struct reader a,b;init(&a,p,n);init(&b,q,m);return parse(&a)&&parse(&b)&&!strcmp(a.typ,b.typ)&&a.service==b.service;
}
