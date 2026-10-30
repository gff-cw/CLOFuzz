/* Declarative model execution for a bounded BACnet/IP scope. No scripting or
 * changes to instrumentation, memory hashing, queue selection or feedback. */
#include "protocol_runtime.h"
#include "protocol_codecs.h"
#include "generic_runtime.h"
#include "config.h"
#include "alloc-inl.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#define PMAX 128
#define FMAX 64
#define DMAX 128
#define SMAX 64
#define TMAX 256
#define NMAX 64
#define JMAX 65536
#define WMAX 65507

static int fail(char *e, size_t cap, const char *fmt, ...) {
  va_list ap; va_start(ap,fmt); if(e && cap) vsnprintf(e,cap,fmt,ap); va_end(ap); return -1;
}

/* Small strict JSON tokenizer: depth/size/token limits, exact delimiters,
 * duplicate-key rejection, no executable values. Strings are never evaluated. */
typedef struct { size_t a,b; int next,type; } jt;
typedef struct { const char *s; size_t pos,len; jt *t; int n; char *err; size_t cap; } jp;
static void ws(jp *p) { while(p->pos<p->len && p->s[p->pos] && strchr(" \r\n\t",p->s[p->pos])) p->pos++; }
static int jvalue(jp *p, int depth);
static int jstring(jp *p) {
  int k=++p->n; if(k>=JMAX) return fail(p->err,p->cap,"JSON token limit");
  jt *t=&p->t[k]; t->type='s';t->a=++p->pos;
  while(p->pos<p->len && p->s[p->pos]!='"') {
    unsigned char c=p->s[p->pos++];
    if(c<32) return fail(p->err,p->cap,"JSON control character");
    if(c>=128) {
      unsigned cp,min;int trailing;
      if(c>=0xc2 && c<=0xdf){cp=c&31;min=0x80;trailing=1;}
      else if(c>=0xe0 && c<=0xef){cp=c&15;min=0x800;trailing=2;}
      else if(c>=0xf0 && c<=0xf4){cp=c&7;min=0x10000;trailing=3;}
      else return fail(p->err,p->cap,"invalid JSON UTF-8");
      for(int i=0;i<trailing;i++){if(p->pos>=p->len || ((unsigned char)p->s[p->pos]&0xc0)!=0x80)return fail(p->err,p->cap,"invalid JSON UTF-8");cp=(cp<<6)|((unsigned char)p->s[p->pos++]&63);}
      if(cp<min || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff))return fail(p->err,p->cap,"invalid JSON UTF-8 scalar");
    }
    if(c=='\\') {
      if(p->pos>=p->len) return fail(p->err,p->cap,"truncated JSON escape");
      c=p->s[p->pos++];
      if(c=='u') { for(int i=0;i<4;i++) if(p->pos>=p->len || !isxdigit((unsigned char)p->s[p->pos++])) return fail(p->err,p->cap,"JSON unicode escape"); }
      else if(!strchr("\"\\/bfnrt",c)) return fail(p->err,p->cap,"JSON escape");
    }
  }
  if(p->pos==p->len) return fail(p->err,p->cap,"unterminated JSON string");
  t->b=p->pos++;t->next=p->n+1;return k;
}
static int jeq(jp *p,int a,int b) {
  return p->t[a].b-p->t[a].a==p->t[b].b-p->t[b].a &&
    !memcmp(p->s+p->t[a].a,p->s+p->t[b].a,p->t[a].b-p->t[a].a);
}
static int jvalue(jp *p,int depth) {
  ws(p);if(depth>24 || p->pos>=p->len) return fail(p->err,p->cap,"JSON depth or truncation");
  char c=p->s[p->pos]; if(c=='"') return jstring(p);
  int k=++p->n; if(k>=JMAX) return fail(p->err,p->cap,"JSON token limit");
  jt *t=&p->t[k];t->a=p->pos;t->type=c;
  if(c=='{' || c=='[') {
    p->pos++;ws(p);char close=c=='{'?'}':']';
    if(p->pos<p->len && p->s[p->pos]==close) {p->pos++;goto done;}
    for(;;) {
      if(c=='{') {
        ws(p);if(p->pos>=p->len || p->s[p->pos]!='"') return fail(p->err,p->cap,"JSON object key");
        int key=jstring(p);if(key<0)return -1;
        if(memchr(p->s+p->t[key].a,'\\',p->t[key].b-p->t[key].a)) return fail(p->err,p->cap,"escaped IR keys are unsupported; recompile YAML");
        for(int old=k+1;old<key;old=p->t[old+1].next) if(jeq(p,old,key)) return fail(p->err,p->cap,"duplicate JSON key");
        ws(p);if(p->pos>=p->len || p->s[p->pos++]!=':')return fail(p->err,p->cap,"JSON colon");
      }
      if(jvalue(p,depth+1)<0)return -1;
      ws(p);if(p->pos>=p->len)return fail(p->err,p->cap,"truncated JSON container");
      c=p->s[t->a];char sep=p->s[p->pos++];if(sep==close)break;
      if(sep!=',')return fail(p->err,p->cap,"JSON comma");
    }
  } else {
    size_t a=p->pos;
    if(c=='t' || c=='f' || c=='n') {
      const char *v=c=='t'?"true":c=='f'?"false":"null";size_t n=strlen(v);
      if(n>p->len-a || memcmp(p->s+a,v,n))return fail(p->err,p->cap,"invalid JSON literal");p->pos+=n;
    } else {
      if(c=='-')p->pos++;
      if(p->pos>=p->len || !isdigit((unsigned char)p->s[p->pos]))return fail(p->err,p->cap,"JSON number");
      if(p->s[p->pos]=='0')p->pos++;else while(p->pos<p->len && isdigit((unsigned char)p->s[p->pos]))p->pos++;
      /* The compiler emits integer-only numbers. Reject fractions explicitly. */
      if(p->pos<p->len && p->s[p->pos] && strchr(".eE",p->s[p->pos]))return fail(p->err,p->cap,"IR requires integer numbers");
      t->type='i';
    }
  }
done:t->b=p->pos;t->next=p->n+1;return k;
}
static int key(jp *p,int o,const char *name) {
  if(o<=0 || p->t[o].type!='{')return 0;
  for(int i=o+1;i<p->t[o].next;i=p->t[i+1].next)
    if(p->t[i].b-p->t[i].a==strlen(name) && !memcmp(p->s+p->t[i].a,name,strlen(name)))return i+1;
  return 0;
}
static int str(jp *p,int k,char *out,size_t cap) {
  if(k<=0 || p->t[k].type!='s' || p->t[k].b-p->t[k].a>=cap)return fail(p->err,p->cap,"missing/oversize IR string");
  size_t n=p->t[k].b-p->t[k].a;
  if(memchr(p->s+p->t[k].a,'\\',n))return fail(p->err,p->cap,"escaped runtime identifiers unsupported; recompile YAML");
  memcpy(out,p->s+p->t[k].a,n);out[n]=0;return 0;
}
static int number(jp *p,int k,int64_t *v) {
  if(k<=0 || p->t[k].type!='i' || p->t[k].b-p->t[k].a>20)return fail(p->err,p->cap,"missing/invalid IR integer");
  char b[24],*end;size_t n=p->t[k].b-p->t[k].a;memcpy(b,p->s+p->t[k].a,n);b[n]=0;
  errno=0;*v=strtoll(b,&end,10);if(errno || *end)return fail(p->err,p->cap,"IR integer overflow");return 0;
}
static int unsigned_number(jp *p,int k,uint64_t *v) {
  if(k<=0 || p->t[k].type!='i' || p->t[k].b-p->t[k].a>20 || p->s[p->t[k].a]=='-')
    return fail(p->err,p->cap,"missing/invalid unsigned IR integer");
  char b[24],*end;size_t n=p->t[k].b-p->t[k].a;
  memcpy(b,p->s+p->t[k].a,n);b[n]=0;errno=0;*v=strtoull(b,&end,10);
  if(errno || *end)return fail(p->err,p->cap,"unsigned IR integer overflow");return 0;
}
static int parse_file(const char *path,jp *p,char *err,size_t cap) {
  memset(p,0,sizeof(*p));p->err=err;p->cap=cap;
  if(!path)return fail(err,cap,"missing IR path");
  FILE *f=fopen(path,"rb");if(!f)return fail(err,cap,"cannot open IR %s: %s",path,strerror(errno));
  if(fseek(f,0,SEEK_END) || (long)(p->len=ftell(f))<0 || p->len>MAX_FILE) {fclose(f);return fail(err,cap,"IR size limit");}
  rewind(f);char *s=ck_alloc(p->len+1);size_t n=fread(s,1,p->len,f);fclose(f);p->s=s;
  if(n!=p->len) {ck_free(s);p->s=NULL;return fail(err,cap,"IR short read");}
  p->t=ck_alloc(JMAX*sizeof(jt));int k=jvalue(p,0);ws(p);
  if(k<0)return -1;
  if(k!=1 || p->pos!=p->len || p->t[1].type!='{')return fail(err,cap,"invalid IR JSON document");
  int64_t version;if(number(p,key(p,1,"ir_version"),&version)<0 || version!=1)return fail(err,cap,"unsupported IR version (expected 1)");
  return 0;
}
static void json_free(jp *p) {ck_free((void*)p->s);ck_free(p->t);}

typedef struct {char id[64],loc[64];uint64_t min,max,values[32];int nv,width,role,mut,little,type,strategies;} pf;
typedef struct {int op,target,source,message,unit,add,algorithm,multiply;} pd;
typedef struct {char id[64];pf f[FMAX];pd d[DMAX];int nf,nd,weight,response;uint8_t *example;size_t size;} pm;
typedef struct {int from,to,message,response;} pt;
typedef struct {size_t offset,size,wire_offset;int model;} pr;
struct proto_engine {
  gr_engine *generic;
  int codec,simulating,prefix_state,prefix_valid;
  size_t prefix_count,prefix_bytes;
  size_t prefix_repeats[PMAX];
  pm m[PMAX];int nm,ns,nt,initial,max_messages,max_repeat,canonical[PMAX];size_t max_bytes;
  char state[SMAX][64];pt tr[TMAX];FILE *log;
  uint8_t work[MAX_FILE],output[MAX_FILE];pr records[NMAX];size_t count;
  uint64_t cache[PMAX][FMAX];uint8_t cached[PMAX][FMAX];uint8_t outstanding[256];
  uint8_t pending[PMAX];
  uint64_t attempts,success,errors,layer_count[3],responses,correlated;
  unsigned semantic_state;
  uint32_t ua_sequence;
  uint8_t receive[MAX_FILE];size_t receive_size;
};

typedef struct {
  const char *name;
  int (*validate)(const uint8_t *,size_t,char *,size_t);
  int (*field)(const uint8_t *,size_t,const char *,int,size_t,size_t *,size_t *,char *,size_t);
  int (*repair)(uint8_t *,size_t,char *,size_t);
  int (*replace)(uint8_t *,size_t *,size_t,const char *,int,const uint8_t *,size_t,char *,size_t);
  int (*frame)(const uint8_t *,size_t,size_t *,char *,size_t);
  int (*same)(const uint8_t *,size_t,const uint8_t *,size_t);
} wire_codec;
#define CODEC(n) {#n,pc_##n##_validate,pc_##n##_field,pc_##n##_repair,pc_##n##_replace,pc_##n##_frame,pc_##n##_same_kind}
static const wire_codec codecs[]={{.name="bacnet"},CODEC(modbus),CODEC(iec104),CODEC(mms),CODEC(enip),CODEC(opcua)};
#undef CODEC

static const char *ops[]={"length_of","count_of","offset_of","checksum_of","copy_from_message","bind_from_response","correlate_request_response","sequence_number","conditional_presence","tagged_length"};
static int find_msg(proto_engine *e,const char *id) {for(int i=0;i<e->nm;i++)if(!strcmp(e->m[i].id,id))return i;return -1;}
static int find_field(pm *m,const char *id) {for(int i=0;i<m->nf;i++)if(!strcmp(m->f[i].id,id))return i;return -1;}
static int find_state(proto_engine *e,const char *id) {for(int i=0;i<e->ns;i++)if(!strcmp(e->state[i],id))return i;return -1;}
static int hex(const char *s,uint8_t **out,size_t *n,char *err,size_t cap) {
  size_t len=strlen(s);if(!len || len%2 || len>WMAX*2)return fail(err,cap,"invalid message hex size");
  *n=len/2;*out=ck_alloc(*n);
  for(size_t i=0;i<*n;i++) {int a=(unsigned char)s[2*i],b=(unsigned char)s[2*i+1];if(!isxdigit(a)||!isxdigit(b))return fail(err,cap,"invalid message hex digit");(*out)[i]=(isdigit(a)?a-'0':tolower(a)-'a'+10)*16+(isdigit(b)?b-'0':tolower(b)-'a'+10);}
  return 0;
}
static uint64_t getint(const uint8_t *b,size_t n,int little) {uint64_t v=0;for(size_t i=0;i<n;i++)v=(v<<8)|b[little?n-1-i:i];return v;}
static void putint(uint8_t *b,size_t n,int little,uint64_t v) {for(size_t i=0;i<n;i++){b[little?i:n-1-i]=v&255;v>>=8;}}

typedef struct {size_t npdu,apdu,service,invoke,content,max_apdu;int kind;} layout;
static int bacnet_layout(const uint8_t *b,size_t n,layout *v,char *err,size_t cap) {
  memset(v,0,sizeof(*v));v->invoke=v->max_apdu=SIZE_MAX;
  if(!b || n<8 || n>WMAX || b[0]!=129 || (b[1]!=10 && b[1]!=11) || getint(b+2,2,0)!=n)return fail(err,cap,"BACnet BVLC type/function/length");
  size_t p=4;v->npdu=p;if(b[p++]!=1)return fail(err,cap,"BACnet NPDU version");
  unsigned ctl=b[p++];if(ctl&0xd0)return fail(err,cap,"BACnet reserved/network-layer NPDU outside APDU scope");
  if(ctl&32) {if(n-p<3)return fail(err,cap,"truncated DNET/DLEN");size_t len=b[p+2];p+=3;if(len>n-p)return fail(err,cap,"truncated DADR");p+=len;}
  if(ctl&8) {if(n-p<3)return fail(err,cap,"truncated SNET/SLEN");size_t len=b[p+2];p+=3;if(!len || len>n-p)return fail(err,cap,"truncated SADR");p+=len;}
  if(ctl&32){if(p>=n)return fail(err,cap,"missing hop count");p++;}
  if(p>=n)return fail(err,cap,"missing APDU");v->apdu=p;v->kind=b[p]>>4;
  switch(v->kind) {
    case 0:if(n-p<4 || b[p]&13)return fail(err,cap,"truncated/segmented confirmed APDU");v->max_apdu=p+1;v->invoke=p+2;v->service=p+3;p+=4;break;
    case 1:if(n-p<2 || b[p]&15)return fail(err,cap,"truncated/invalid unconfirmed APDU");v->service=p+1;p+=2;break;
    case 2:case 3:case 5:if(n-p<3 || b[p]&15)return fail(err,cap,"truncated/segmented response APDU");v->invoke=p+1;v->service=p+2;p+=3;break;
    case 6:case 7:if(n-p<3 || (b[p]&15)>(v->kind==7?1:0))return fail(err,cap,"truncated/invalid reject/abort APDU");v->invoke=p+1;v->service=p+2;p+=3;break;
    default:return fail(err,cap,"unsupported APDU type");
  }
  v->content=p;return 0;
}
/* BACnet's LVT: not BER. Track matching context opening/closing tags. */
static int tag(const uint8_t *b,size_t n,size_t *pos,unsigned *num,int *ctx,int *kind,size_t *data,size_t *len) {
  if(*pos>=n)return -1;unsigned h=b[(*pos)++];*num=h>>4;*ctx=!!(h&8);*kind=0;unsigned lvt=h&7;
  if(*num==15){if(*pos>=n)return -1;*num=b[(*pos)++];}
  *len=lvt;
  if(*ctx && (lvt==6 || lvt==7)){*kind=lvt==6?1:2;*len=0;}
  else if(!*ctx && *num==1) {if(lvt>1)return -1;*len=0;} /* BOOLEAN value is in LVT. */
  else if(lvt==5){if(*pos>=n)return -1;*len=b[(*pos)++];if(*len==254 || *len==255){size_t w=*len==254?2:4;if(w>n-*pos)return -1;*len=getint(b+*pos,w,0);*pos+=w;}}
  else if(lvt>5)return -1;
  *data=*pos;if(*len>n-*pos)return -1;*pos+=*len;return 0;
}
static int tags_valid(const uint8_t *b,size_t n,size_t p) {
  unsigned stack[24],depth=0,num;int ctx,k;size_t data,len;
  while(p<n) {if(tag(b,n,&p,&num,&ctx,&k,&data,&len)<0)return -1;
    if(k==1){if(depth==24)return -1;stack[depth++]=num;}
    if(k==2){if(!depth || stack[--depth]!=num)return -1;}
  }return depth?-1:0;
}
static int content_valid(const uint8_t *b,size_t n,const layout *v) {
  if(tags_valid(b,n,v->content)<0)return -1;
  /* These request services are the only content encoders in this runtime. */
  if((v->kind==1 && b[v->service]==8) || (v->kind==0 && b[v->service]==12)) {
    size_t p=v->content,data,len;unsigned num;int ctx,k;
    if(v->kind==1 && p==n)return 0;
    uint64_t low=0;
    for(unsigned wanted=0;wanted<2;wanted++) {
      if(tag(b,n,&p,&num,&ctx,&k,&data,&len)<0 || !ctx || k || num!=wanted || !len || len>4)return -1;
      if(v->kind==0 && wanted==0 && len!=4)return -1;
      if(v->kind==1){uint64_t val=getint(b+data,len,0);if(val>4194303 || (wanted && val<low))return -1;low=val;}
    }
    if(v->kind==0 && p<n)if(tag(b,n,&p,&num,&ctx,&k,&data,&len)<0 || !ctx || k || num!=2 || !len || len>4)return -1;
    if(p!=n)return -1;
  }
  return 0;
}
int proto_bacnet_field(const uint8_t *b,size_t n,const char *loc,size_t *off,size_t *width,char *err,size_t cap) {
  if(!loc || !off || !width)return fail(err,cap,"missing BACnet locator/output");
  *off=*width=0;layout v;if(bacnet_layout(b,n,&v,err,cap)<0)return -1;
  if(content_valid(b,n,&v)<0)return fail(err,cap,"malformed BACnet tag/content structure");
  *width=1;
  if(!strcmp(loc,"bvlc.type"))*off=0;
  else if(!strcmp(loc,"bvlc.function"))*off=1;
  else if(!strcmp(loc,"bvlc.length")){*off=2;*width=2;}
  else if(!strcmp(loc,"npdu.version"))*off=v.npdu;
  else if(!strcmp(loc,"npdu.control"))*off=v.npdu+1;
  else if(!strcmp(loc,"apdu.type"))*off=v.apdu;
  else if(!strcmp(loc,"apdu.service"))*off=v.service;
  else if(!strcmp(loc,"apdu.invoke")){if(v.invoke==SIZE_MAX)return 0;*off=v.invoke;}
  else if(!strcmp(loc,"apdu.max_apdu")){if(v.max_apdu==SIZE_MAX)return 0;*off=v.max_apdu;}
  else if(!strcmp(loc,"apdu.content")){*off=v.content;*width=n-v.content;}
  else if(!strncmp(loc,"abs:",4)){char *end;errno=0;unsigned long a=strtoul(loc+4,&end,10);if(!isdigit((unsigned char)loc[4]) || errno || *end || a>=n)return fail(err,cap,"invalid absolute locator");*off=a;}
  else if(!strcmp(loc,"bacnet.object") || !strcmp(loc,"bacnet.property") || !strcmp(loc,"bacnet.array")) {
    unsigned wanted=!strcmp(loc,"bacnet.object")?0:!strcmp(loc,"bacnet.property")?1:2;
    size_t p=v.content,data,len;unsigned num;int ctx,k;
    while(p<n){if(tag(b,n,&p,&num,&ctx,&k,&data,&len)<0)return fail(err,cap,"malformed BACnet tag");
      if(ctx && !k && num==wanted){*off=data;*width=len;return 1;}}
    return 0;
  } else return fail(err,cap,"unsupported BACnet locator %s",loc);
  return 1;
}
static int locate(proto_engine *e,const uint8_t *b,size_t n,pf *f,size_t *o,size_t *w,char *err,size_t cap) {
  int r=e->codec?codecs[e->codec].field(b,n,f->loc,f->type,f->width,o,w,err,cap):proto_bacnet_field(b,n,f->loc,o,w,err,cap);if(r<=0)return r;
  if(!e->codec && !strncmp(f->loc,"abs:",4))*w=f->width?f->width:n-*o;
  if(*o>n || *w>n-*o || (f->width && (!*w || *w>8)))return fail(err,cap,"field %s exceeds packet",f->id);
  return r;
}
static int model_for(proto_engine *e,const uint8_t *b,size_t n,int response) {
  char err[128];layout v;if(e->codec?codecs[e->codec].validate(b,n,err,sizeof(err))<0:bacnet_layout(b,n,&v,err,sizeof(err))<0)return -1;
  for(int m=0;m<e->nm;m++) {
    if(e->m[m].response!=response || (e->codec && !codecs[e->codec].same(b,n,e->m[m].example,e->m[m].size)))continue;
    int ok=1;
    for(int f=0;f<e->m[m].nf;f++) {
      pf *p=&e->m[m].f[f];if(!e->codec && (p->mut!=0 || !p->width))continue;
      size_t o,w;int present=locate(e,b,n,p,&o,&w,err,sizeof(err));
      if(!present && p->mut==3)continue;
      if(present!=1){ok=0;break;}
      uint64_t value=p->width?getint(b+o,w,p->little):w;
      if(value<p->min || value>p->max){ok=0;break;}
    }
    if(ok)return e->canonical[m];
  }return -1;
}
int proto_validate_message_fields(const proto_engine *e, int mi, const uint8_t *b, size_t n, char *err, size_t cap) {
  if (!e || !b || !n) return fail(err, cap, "missing engine/packet for field validation");
  if (mi < 0 || mi >= e->nm) return fail(err, cap, "invalid message model index %d", mi);

  if (e->codec) {
    if (codecs[e->codec].validate(b, n, err, cap) < 0) return -1;
  } else {
    layout v;
    if (bacnet_layout(b, n, &v, err, cap) < 0) return -1;
    if (content_valid(b, n, &v) < 0) return fail(err, cap, "malformed BACnet content");
  }

  const pm *m = &e->m[mi];
  for (int f = 0; f < m->nf; f++) {
    pf *p = (pf *)&m->f[f];
    size_t o = 0, w = 0;
    int present = locate((proto_engine *)e, b, n, p, &o, &w, err, cap);
    if (present < 0) return -1;
    if (present == 0) {
      if (p->mut == 3) continue; /* conditional field may be absent */
      return fail(err, cap, "required field %s.%s is absent", m->id, p->id);
    }
    if (p->width > 0) {
      if (w > 8) return fail(err, cap, "field %s.%s width %zu exceeds scalar capacity", m->id, p->id, w);
      uint64_t val = getint(b + o, w, p->little);
      if (val < p->min || val > p->max)
        return fail(err, cap, "field %s.%s value %llu outside bounds [%llu, %llu]",
                    m->id, p->id, (unsigned long long)val,
                    (unsigned long long)p->min, (unsigned long long)p->max);
      if (p->role == 3 /* fixed */ && p->nv > 0) {
        int match = 0;
        for (int v = 0; v < p->nv; v++) {
          if (val == p->values[v]) { match = 1; break; }
        }
        if (!match) return fail(err, cap, "fixed field %s.%s value %llu does not match expected",
                                m->id, p->id, (unsigned long long)val);
      }
    } else {
      /* Variable-length field */
      if (w < p->min || w > p->max)
        return fail(err, cap, "variable field %s.%s length %zu outside bounds [%llu, %llu]",
                    m->id, p->id, w,
                    (unsigned long long)p->min, (unsigned long long)p->max);
    }
  }
  return 0;
}
static int cycle(proto_engine *e,int mi,int fi,uint8_t visited[PMAX][FMAX]) {
  if(visited[mi][fi]==1)return -1;if(visited[mi][fi]==2)return 0;visited[mi][fi]=1;
  pm *m=&e->m[mi];for(int i=0;i<m->nd;i++){pd *d=&m->d[i];if(d->target==fi && d->source>=0 && d->op!=6 && d->op!=7 && cycle(e,d->message,d->source,visited)<0)return -1;}
  visited[mi][fi]=2;return 0;
}
static int equal_field(const pf *a,const pf *b){
  return !strcmp(a->loc,b->loc) && a->type==b->type && a->width==b->width &&
    a->min==b->min && a->max==b->max && a->role==b->role && a->mut==b->mut &&
    a->little==b->little && a->strategies==b->strategies && a->nv==b->nv &&
    !memcmp(a->values,b->values,a->nv*sizeof(a->values[0]));
}
/* Only aliases with identical executed constraints/dependencies share cache
 * values. Fixture bytes and author-chosen IDs are not message identities. */
static int equivalent_models(proto_engine *e,int ai,int bi){
  pm *a=&e->m[ai],*b=&e->m[bi];
  if(!e->codec || a->response!=b->response || a->nf!=b->nf || a->nd!=b->nd || a->weight!=b->weight ||
     !codecs[e->codec].same(a->example,a->size,b->example,b->size) ||
     !codecs[e->codec].same(b->example,b->size,a->example,a->size))return 0;
  for(int f=0;f<a->nf;f++){int found=0;for(int g=0;g<b->nf;g++)if(equal_field(&a->f[f],&b->f[g])){found=1;break;}if(!found)return 0;}
  for(int d=0;d<a->nd;d++){pd *x=&a->d[d];int found=0;
    for(int j=0;j<b->nd;j++){pd *y=&b->d[j];
      if(x->op!=y->op || x->unit!=y->unit || x->add!=y->add || x->multiply!=y->multiply || x->algorithm!=y->algorithm ||
         !equal_field(&a->f[x->target],&b->f[y->target]) || (x->source<0)!=(y->source<0))continue;
      if(x->source>=0){pm *xm=&e->m[x->message],*ym=&e->m[y->message];
        if(xm->response!=ym->response || !equal_field(&xm->f[x->source],&ym->f[y->source]) ||
           !codecs[e->codec].same(xm->example,xm->size,ym->example,ym->size) ||
           !codecs[e->codec].same(ym->example,ym->size,xm->example,xm->size))continue;
      }found=1;break;
    }if(!found)return 0;
  }return 1;
}
/* P14: Verify that aliases also have equivalent state transitions before sharing identity */
static int equivalent_transitions(proto_engine *e,int ai,int bi){
  for(int t=0;t<e->nt;t++){
    if(e->tr[t].message==ai){
      int found=0;
      for(int u=0;u<e->nt;u++){
        if(e->tr[u].message==bi && e->tr[u].from==e->tr[t].from && e->tr[u].to==e->tr[t].to){
          int rt=e->tr[t].response>=0?e->canonical[e->tr[t].response]:-1;
          int ru=e->tr[u].response>=0?e->canonical[e->tr[u].response]:-1;
          if(rt==ru){found=1;break;}
        }
      }
      if(!found)return 0;
    }
    if(e->tr[t].response==ai){
      int found=0;
      for(int u=0;u<e->nt;u++){
        if(e->tr[u].response==bi && e->tr[u].from==e->tr[t].from && e->tr[u].to==e->tr[t].to &&
           e->canonical[e->tr[u].message]==e->canonical[e->tr[t].message]){found=1;break;}
      }
      if(!found)return 0;
    }
  }
  for(int t=0;t<e->nt;t++){
    if(e->tr[t].message==bi){
      int found=0;
      for(int u=0;u<e->nt;u++){
        if(e->tr[u].message==ai && e->tr[u].from==e->tr[t].from && e->tr[u].to==e->tr[t].to){
          int rt=e->tr[t].response>=0?e->canonical[e->tr[t].response]:-1;
          int ru=e->tr[u].response>=0?e->canonical[e->tr[u].response]:-1;
          if(rt==ru){found=1;break;}
        }
      }
      if(!found)return 0;
    }
    if(e->tr[t].response==bi){
      int found=0;
      for(int u=0;u<e->nt;u++){
        if(e->tr[u].response==ai && e->tr[u].from==e->tr[t].from && e->tr[u].to==e->tr[t].to &&
           e->canonical[e->tr[u].message]==e->canonical[e->tr[t].message]){found=1;break;}
      }
      if(!found)return 0;
    }
  }
  return 1;
}

proto_engine *proto_load(const char *pp,const char *sp,char *err,size_t cap) {
  proto_engine *e=ck_alloc(sizeof(*e));jp p={0},s={0};char b[WMAX*2+1],id[64],other[64];int64_t v;
  if(parse_file(pp,&p,err,cap)<0 || parse_file(sp,&s,err,cap)<0)goto bad;
  if(str(&p,key(&p,1,"protocol_id"),id,sizeof(id))<0 || str(&s,key(&s,1,"protocol_id"),other,sizeof(other))<0 || strcmp(id,other)){fail(err,cap,"protocol/state ID mismatch");goto bad;}
  if(!*id)goto malformed;
  if(str(&p,key(&p,1,"codec"),b,sizeof(b))<0)goto bad;
  e->codec=-1;for(int ci=0;ci<6;ci++)if(!strcmp(b,codecs[ci].name))e->codec=ci;
  if(e->codec<0){fail(err,cap,"runtime encoder '%s' unavailable",b);goto bad;}
  if(str(&p,key(&p,1,"transport"),b,sizeof(b))<0 || strcmp(b,e->codec?"tcp":"udp")){fail(err,cap,"codec/transport mismatch");goto bad;}
  int sup=key(&p,1,"support"),rt=key(&p,sup,"runtime");
  if(!rt || p.t[rt].type!='t'){fail(err,cap,"model is not enabled for runtime");goto bad;}
  int arr=key(&p,1,"messages");if(!arr || p.t[arr].type!='[')goto malformed;
  for(int m=arr+1;m<p.t[arr].next;m=p.t[m].next) {
    if(e->nm==PMAX)goto malformed;pm *msg=&e->m[e->nm++];
    if(str(&p,key(&p,m,"id"),msg->id,sizeof(msg->id))<0 || !*msg->id || find_msg(e,msg->id)!=e->nm-1)goto malformed;
    if(number(&p,key(&p,m,"weight"),&v)<0 || v<1 || v>1000)goto malformed;msg->weight=v;
    if(str(&p,key(&p,m,"direction"),b,sizeof(b))<0)goto bad;msg->response=!strcmp(b,"response");if(strcmp(b,"request") && !msg->response)goto malformed;
    if(str(&p,key(&p,m,"example"),b,sizeof(b))<0 || hex(b,&msg->example,&msg->size,err,cap)<0)goto bad;
    int fa=key(&p,m,"fields");if(!fa || p.t[fa].type!='[')goto malformed;
    for(int f=fa+1;f<p.t[fa].next;f=p.t[f].next) {
      if(msg->nf==FMAX)goto malformed;pf *field=&msg->f[msg->nf++];
      if(str(&p,key(&p,f,"id"),field->id,sizeof(field->id))<0 || !*field->id || find_field(msg,field->id)!=msg->nf-1 || str(&p,key(&p,f,"locator"),field->loc,sizeof(field->loc))<0)goto malformed;
      if(key(&p,f,"when") || (key(&p,f,"repeat") && e->codec!=1)){fail(err,cap,"conditional/repeated runtime fields unavailable");goto bad;}
      if(number(&p,key(&p,f,"width"),&v)<0 || v<0 || v>8)goto malformed;field->width=v;
      if(str(&p,key(&p,f,"type"),b,sizeof(b))<0)goto bad;
      const char *types[]={"uint8","uint16","uint24","uint32","uint64","bytes","string","bacnet_tags","ber_tlv","epath","nodeid"};int widths[]={1,2,3,4,8,0,0,0,0,0,0},found=0;
      for(int x=0;x<11;x++)if(!strcmp(b,types[x]) && field->width==widths[x]){found=1;field->type=x;}
      if(!found){fail(err,cap,"unsupported runtime field type/width: %s",b);goto bad;}
      if(unsigned_number(&p,key(&p,f,"min"),&field->min)<0)goto malformed;
      if(unsigned_number(&p,key(&p,f,"max"),&field->max)<0 || field->max<field->min)goto malformed;
      if(field->width<8 && field->max>(field->width?((1ULL<<(8*field->width))-1):WMAX))goto malformed;
      if(str(&p,key(&p,f,"endian"),b,sizeof(b))<0)goto bad;field->little=!strcmp(b,"little");if(strcmp(b,"big") && !field->little)goto malformed;
      if(str(&p,key(&p,f,"role"),b,sizeof(b))<0)goto bad;
      field->role=!strcmp(b,"head")?1:!strcmp(b,"content")?2:!strcmp(b,"fixed")?3:!strcmp(b,"derived")?4:0;if(!field->role)goto malformed;
      if(str(&p,key(&p,f,"mutability"),b,sizeof(b))<0)goto bad;
      field->mut=!strcmp(b,"fixed")?0:!strcmp(b,"fuzzable")?1:!strcmp(b,"derived")?2:!strcmp(b,"conditional")?3:!strcmp(b,"runtime_bound")?4:-1;if(field->mut<0)goto malformed;
      if((field->role==3)!=(field->mut==0)){fail(err,cap,"fixed role and mutability mismatch for %s",field->id);goto bad;}
      if((field->role==4)!=(field->mut==2)){fail(err,cap,"derived role and mutability mismatch for %s",field->id);goto bad;}
      if(!field->mut && field->min!=field->max)goto malformed;
      int va=key(&p,f,"values");if(!va || p.t[va].type!='[')goto malformed;
      for(int x=va+1;x<p.t[va].next;x=p.t[x].next){uint64_t uv;if(field->nv==32 || unsigned_number(&p,x,&uv)<0 || uv<field->min || uv>field->max)goto malformed;field->values[field->nv++]=uv;}
      int sa=key(&p,f,"strategies");if(!sa || p.t[sa].type!='[')goto malformed;
      const char *strategy_names[]={"enum","boundary","bitflip","arithmetic","afl","resize"};
      for(int x=sa+1;x<p.t[sa].next;x=p.t[x].next){
        if(str(&p,x,b,sizeof(b))<0)goto bad;
        int known=0;for(int j=0;j<6;j++)if(!strcmp(b,strategy_names[j])){field->strategies|=1<<j;known=1;}
        if(!known){fail(err,cap,"unsupported runtime strategy %s",b);goto bad;}
      }
      if(!field->strategies)field->strategies=15; /* Empty list uses scalar defaults. */
      if(field->role==1 && (field->mut==1 || field->mut==3) && !(field->strategies&15))goto malformed;
      size_t o,w;int present=locate(e,msg->example,msg->size,field,&o,&w,err,cap);if(present<0)goto bad;
      if(!present && field->mut!=3)goto malformed;
      if(present){uint64_t actual=field->width?getint(msg->example+o,w,field->little):w;if(actual<field->min || actual>field->max)goto malformed;}
    }
    if(!msg->nf)goto malformed;
  }
  if(!e->nm)goto malformed;
  /* Second pass resolves every dependency after all message IDs exist. */
  for(int mi=0,m=arr+1;m<p.t[arr].next;mi++,m=p.t[m].next){
    int fa=key(&p,m,"fields");
    for(int fi=0,f=fa+1;f<p.t[fa].next;fi++,f=p.t[f].next){
      int repeat=key(&p,f,"repeat");if(!repeat)continue;
      pm *msg=&e->m[mi];pf *field=&msg->f[fi];int coil=msg->size>7 && msg->example[7]==15;
      int64_t lo,hi,ew;
      if(e->codec!=1 || msg->response || msg->size<=13 || (!coil && msg->example[7]!=16) ||
         field->width || field->type!=PC_BYTES || field->role!=2 || strcmp(field->loc,"abs:13") ||
         field->min!=(unsigned)(coil?1:2) || field->max!=246 ||
         str(&p,key(&p,repeat,"count"),b,sizeof(b))<0)goto malformed;
      int count=find_field(msg,b);
      if(count<0 || strcmp(msg->f[count].loc,coil?"abs:12":"abs:10") || msg->f[count].type!=(coil?PC_UINT8:PC_UINT16) ||
         number(&p,key(&p,repeat,"min"),&lo)<0 || lo!=1 ||
         number(&p,key(&p,repeat,"max"),&hi)<0 || hi!=(coil?246:123) ||
         number(&p,key(&p,repeat,"element_width"),&ew)<0 || ew!=(coil?1:2))goto malformed;
    }
    pm *msg=&e->m[mi];int da=key(&p,m,"dependencies");if(!da || p.t[da].type!='[')goto malformed;
    for(int d=da+1;d<p.t[da].next;d=p.t[d].next){
      if(msg->nd==DMAX)goto malformed;pd *dst=&msg->d[msg->nd++];dst->message=mi;dst->unit=dst->multiply=1;
      if(str(&p,key(&p,d,"op"),b,sizeof(b))<0)goto bad;dst->op=-1;for(int x=0;x<10;x++)if(!strcmp(b,ops[x]))dst->op=x;if(dst->op<0){fail(err,cap,"unsupported runtime dependency %s",b);goto bad;}
      if(str(&p,key(&p,d,"target"),b,sizeof(b))<0 || (dst->target=find_field(msg,b))<0)goto malformed;
      if(!msg->f[dst->target].width && !(dst->op==9 && e->codec==3))goto malformed;
      if(dst->op==8 || (dst->op==9 && e->codec!=3))goto malformed;
      if(dst->op!=6 && dst->op!=8 && msg->f[dst->target].mut==0){fail(err,cap,"dependency cannot write fixed field %s",b);goto bad;}
      for(int old=0;old<msg->nd-1;old++)if(msg->d[old].target==dst->target){fail(err,cap,"multiple dependency writers for %s",b);goto bad;}
      int ref=key(&p,d,"message");if(ref && (str(&p,ref,b,sizeof(b))<0 || (dst->message=find_msg(e,b))<0))goto malformed;
      if(str(&p,key(&p,d,"source"),b,sizeof(b))<0)goto bad;dst->source=!strcmp(b,"$message")?-1:find_field(&e->m[dst->message],b);if(dst->source<0 && strcmp(b,"$message"))goto malformed;
      if((ref=key(&p,d,"unit"))){if(number(&p,ref,&v)<0 || v<1 || v>WMAX)goto malformed;dst->unit=v;}
      if((ref=key(&p,d,"add"))){if(number(&p,ref,&v)<0 || v < -WMAX || v>WMAX)goto malformed;dst->add=v;}
      if((ref=key(&p,d,"multiply"))){if(number(&p,ref,&v)<0 || v<1 || v>WMAX)goto malformed;dst->multiply=v;}
      if(dst->op>1 && dst->multiply!=1)goto malformed;
      if(dst->op!=0 && dst->op!=1 && dst->op!=7 && dst->unit!=1)goto malformed;
      if(dst->op>2 && dst->add)goto malformed;
      if(dst->op<4 && dst->message!=mi)goto malformed;
      if(dst->op>=4 && dst->op<=6){if(dst->source<0)goto malformed;pf *a=&msg->f[dst->target],*bf=&e->m[dst->message].f[dst->source];if(a->type!=bf->type || !a->width)goto malformed;}
      if(dst->op==5 && !e->m[dst->message].response)goto malformed;
      if(dst->op==6 && (!msg->response || e->m[dst->message].response))goto malformed;
      if(dst->op==7 && (dst->message!=mi || (dst->source>=0 && dst->source!=dst->target)))goto malformed;
      if(dst->op==9 && (dst->message!=mi || dst->source!=-1 || strcmp(msg->f[dst->target].loc,"ber:presentation")))goto malformed;
      if(dst->op==3){if(str(&p,key(&p,d,"algorithm"),b,sizeof(b))<0)goto bad;dst->algorithm=!strcmp(b,"sum8")?1:!strcmp(b,"crc32")?2:0;if(!dst->algorithm)goto malformed;}
    }
    for(int fi=0;fi<msg->nf;fi++){
      pf *field=&msg->f[fi];
      if(field->mut==2 || field->mut==4){
        int writer_idx=-1;
        for(int di=0;di<msg->nd;di++){
          if(msg->d[di].target==fi){writer_idx=di;break;}
        }
        if(writer_idx<0){fail(err,cap,"%s: %s field requires a dependency writer",field->id,field->mut==2?"derived":"runtime_bound");goto bad;}
        int op=msg->d[writer_idx].op;
        if(field->mut==2 && (op==6 || op==8)){fail(err,cap,"%s: derived field requires value-producing dependency",field->id);goto bad;}
        if(field->mut==4 && (op<4 || op>7)){fail(err,cap,"%s: runtime_bound field requires binding dependency",field->id);goto bad;}
      }
    }
  }
  {uint8_t visited[PMAX][FMAX]={{0}};for(int mi=0;mi<e->nm;mi++)for(int f=0;f<e->m[mi].nf;f++)if(cycle(e,mi,f,visited)<0){fail(err,cap,"dependency graph cycle");goto bad;}}
  arr=key(&s,1,"states");if(!arr || s.t[arr].type!='[')goto malformed;
  for(int st=arr+1;st<s.t[arr].next;st=s.t[st].next){if(e->ns==SMAX || str(&s,key(&s,st,"id"),e->state[e->ns],64)<0 || !*e->state[e->ns])goto malformed;e->ns++;if(find_state(e,e->state[e->ns-1])!=e->ns-1)goto malformed;}
  if(str(&s,key(&s,1,"initial"),b,sizeof(b))<0 || (e->initial=find_state(e,b))<0)goto malformed;
  arr=key(&s,1,"transitions");if(!arr || s.t[arr].type!='[')goto malformed;
  for(int t=arr+1;t<s.t[arr].next;t=s.t[t].next){
    if(e->nt==TMAX)goto malformed;pt *dst=&e->tr[e->nt++];
    if(str(&s,key(&s,t,"from"),b,sizeof(b))<0 || (dst->from=find_state(e,b))<0 || str(&s,key(&s,t,"to"),b,sizeof(b))<0 || (dst->to=find_state(e,b))<0 || str(&s,key(&s,t,"message"),b,sizeof(b))<0 || (dst->message=find_msg(e,b))<0)goto malformed;
    dst->response=-1;if(str(&s,key(&s,t,"response"),b,sizeof(b))<0 || (*b && (dst->response=find_msg(e,b))<0))goto malformed;
    if(dst->response>=0 && !e->m[dst->response].response)goto malformed;
    for(int old=0;old<e->nt-1;old++)if(e->tr[old].from==dst->from && e->tr[old].message==dst->message){fail(err,cap,"ambiguous runtime state transition");goto bad;}
  }
  int lim=key(&s,1,"limits");
  if(number(&s,key(&s,lim,"max_messages"),&v)<0 || v<1 || v>NMAX)goto malformed;e->max_messages=v;
  if(number(&s,key(&s,lim,"max_repeat"),&v)<0 || v<1 || v>8)goto malformed;e->max_repeat=v;
  if(number(&s,key(&s,lim,"max_bytes"),&v)<0 || v<1 || v>MAX_FILE)goto malformed;e->max_bytes=v;
  for(int mi=0;mi<e->nm;mi++)if(!e->m[mi].response && e->m[mi].size+4>e->max_bytes)goto malformed;
  {uint8_t reachable[SMAX]={0};reachable[e->initial]=1;for(int i=0;i<e->ns;i++)for(int t=0;t<e->nt;t++)if(reachable[e->tr[t].from])reachable[e->tr[t].to]=1;for(int i=0;i<e->ns;i++)if(!reachable[i]){fail(err,cap,"unreachable IR state %s",e->state[i]);goto bad;}}
  for(int mi=0;mi<e->nm;mi++)e->canonical[mi]=mi;
  for(int mi=0;mi<e->nm;mi++){for(int prior=0;prior<mi;prior++)if(equivalent_models(e,mi,prior)&&equivalent_transitions(e,mi,prior)){e->canonical[mi]=e->canonical[prior];break;}}
  for(int old=0;old<e->nt;old++)for(int prior=0;prior<old;prior++)if(e->tr[old].from==e->tr[prior].from && e->canonical[e->tr[old].message]==e->canonical[e->tr[prior].message]){fail(err,cap,"ambiguous runtime state transition");goto bad;}
  for(int mi=0;mi<e->nm;mi++){for(int prior=0;prior<mi;prior++){
    if(e->codec>0 && e->m[mi].response==e->m[prior].response && codecs[e->codec].same(e->m[mi].example,e->m[mi].size,e->m[prior].example,e->m[prior].size)){
      if(e->canonical[mi]!=e->canonical[prior]){fail(err,cap,"ambiguous wire identity with differing semantics: %s and %s",e->m[prior].id,e->m[mi].id);goto bad;}
    }
  }}
  json_free(&p);json_free(&s);e->prefix_state=e->initial;e->prefix_valid=1;proto_session_begin(e);return e;
malformed:fail(err,cap,"invalid IR field, reference, type, width or limit");
bad:json_free(&p);json_free(&s);proto_free(e);return NULL;
}
proto_engine *proto_load_generic(const char *path, char *err, size_t cap){
  proto_engine *e=ck_alloc(sizeof(*e));
  e->generic=gr_load(path,err,cap);
  if(!e->generic){ck_free(e);return NULL;}
  return e;
}
void proto_free(proto_engine *e){if(!e)return;gr_free(e->generic);for(int i=0;i<e->nm;i++)ck_free(e->m[i].example);ck_free(e);}
int proto_mode_parse(const char *s){const char *names[]={"valid","near_valid","invalid","raw","hybrid"};if(s)for(int i=0;i<5;i++)if(!strcmp(s,names[i]))return i;return -1;}
int proto_layers_parse(const char *s){if(!s)return -1;if(!strcmp(s,"head"))return 1;if(!strcmp(s,"head,content"))return 3;if(!strcmp(s,"head,content,sequence"))return 7;return -1;}
void proto_set_log(proto_engine *e,FILE *f){if(e){e->log=f;gr_set_log(e->generic,f);}}
const char *proto_transport(const proto_engine *e){return e&&e->generic?gr_transport(e->generic):e&&e->codec?"tcp":"udp";}

int proto_records_validate(const uint8_t *b,size_t n,size_t *count,char *err,size_t cap){
  if(!count)return fail(err,cap,"missing replayable count output");*count=0;if(!b || !n || n>MAX_FILE)return fail(err,cap,"empty or oversized replayable input");size_t p=0;
  while(p<n){if(n-p<4)return fail(err,cap,"truncated LE32 record length at %zu",p);size_t z=getint(b+p,4,1);p+=4;
    if(!z || z>WMAX || z>n-p || *count==NMAX)return fail(err,cap,"invalid replayable record length/count at %zu",p-4);
    p+=z;(*count)++;
  }return 0;
}
static int unpack(proto_engine *e,const uint8_t *b,size_t n,char *err,size_t cap){
  if(proto_records_validate(b,n,&e->count,err,cap)<0)return -1;
  if(!e->count)return fail(err,cap,"empty replay records sequence");
  size_t p=0,o=0;for(size_t i=0;i<e->count;i++){size_t z=getint(b+p,4,1);p+=4;pr *r=&e->records[i];r->offset=o;r->wire_offset=o;r->size=z;memcpy(e->work+o,b+p,z);r->model=model_for(e,e->work+o,z,0);if(r->model<0)return fail(err,cap,"message %zu has no supported model or malformed BVLC/NPDU",i);o+=z;p+=z;}
  return 0;
}
static int pack(proto_engine *e,const uint8_t **out,size_t *len,char *err,size_t cap){
  if(!e->count)return fail(err,cap,"empty sequence cannot be packed");
  size_t p=0;for(size_t i=0;i<e->count;i++){pr *r=&e->records[i];if(!r->size || p>e->max_bytes || r->size>e->max_bytes-p || e->max_bytes-p-r->size<4)return fail(err,cap,"serialized sequence exceeds max_bytes");putint(e->output+p,4,1,r->size);memcpy(e->output+p+4,e->work+r->offset,r->size);p+=4+r->size;}
  *out=e->output;*len=p;return 0;
}
static uint32_t crc(const uint8_t *b,size_t n){uint32_t c=~0u;for(size_t i=0;i<n;i++){c^=b[i];for(int j=0;j<8;j++)c=(c>>1)^((0u-(c&1))&0xedb88320u);}return ~c;}
/* Dependencies are evaluated recursively in graph order; cache keys are model
 * ID AND field ID. No name-only binding is permitted. */
static int repair_field(proto_engine *e,int mi,int fi,uint8_t *b,size_t n,uint8_t *done,char *err,size_t cap){
  if(done[fi])return 0;pm *m=&e->m[mi];
  for(int i=0;i<m->nd;i++){
    pd *d=&m->d[i];if(d->target!=fi || d->op==6 || d->op==8 || d->op==9)continue;
    if(d->source>=0 && d->message==mi && (d->op<5) && repair_field(e,mi,d->source,b,n,done,err,cap)<0)return -1;
    size_t o,w,so=0,sw=n;
    if(locate(e,b,n,&m->f[fi],&o,&w,err,cap)!=1 || !w || w>8)return fail(err,cap,"dependency target absent or nonscalar");
    if(d->source>=0 && d->message==mi && d->op<5 && locate(e,b,n,&m->f[d->source],&so,&sw,err,cap)!=1)return fail(err,cap,"dependency source absent");
    uint64_t val;
    if(d->op<=1){if(sw%(size_t)d->unit)return fail(err,cap,"count/length not divisible by unit");int64_t sized=(int64_t)(sw/d->unit)*d->multiply+d->add;if(sized<0)return fail(err,cap,"negative derived length");val=sized;}
    else if(d->op==2){int64_t sized=(int64_t)so+d->add;if(sized<0)return fail(err,cap,"negative derived offset");val=sized;}
    else if(d->op==3){if(o>=so && o+w<=so+sw)memset(b+o,0,w);if(d->algorithm==1){val=0;for(size_t k=0;k<sw;k++)val=(val+b[so+k])&255;}else val=crc(b+so,sw);}
    else if(d->op==7){
      size_t seqoff,seqwidth;int ua=e->codec==5 && pc_opcua_field(b,n,"uabin:sequence",PC_UINT32,4,&seqoff,&seqwidth,err,cap)==1 && seqoff==o && seqwidth==w;
      uint64_t mask=w==8?UINT64_MAX:((1ULL<<(8*w))-1);
      val=ua?e->ua_sequence:e->cached[mi][fi]?((e->cache[mi][fi]+(uint64_t)d->unit)&mask):0;
    }
    else if(d->op==4 && d->message==mi)val=getint(b+so,sw,m->f[d->source].little);
    else {if(!e->cached[d->message][d->source]){if(e->simulating && d->message!=mi)continue;return fail(err,cap,"unresolved session dependency %s.%s",e->m[d->message].id,e->m[d->message].f[d->source].id);}val=e->cache[d->message][d->source];}
    if((w<8 && val>=(1ULL<<(8*w))) || val<m->f[fi].min || val>m->f[fi].max)return fail(err,cap,"dependency integer overflow/range");
    putint(b+o,w,m->f[fi].little,val);
  }done[fi]=1;return 0;
}
static int repair(proto_engine *e,int mi,uint8_t *b,size_t n,char *err,size_t cap){
  if(e->codec){
    if(codecs[e->codec].repair(b,n,err,cap)<0)return -1;
    uint8_t done[FMAX]={0};for(int f=0;f<e->m[mi].nf;f++)if(repair_field(e,mi,f,b,n,done,err,cap)<0)return -1;
    return codecs[e->codec].validate(b,n,err,cap);
  }
  /* BVLC must be usable while resolving dynamic NPDU/APDU field locations. */
  if(n<4 || n>WMAX)return fail(err,cap,"BACnet size limit");putint(b+2,2,0,n);
  uint8_t done[FMAX]={0};for(int f=0;f<e->m[mi].nf;f++)if(repair_field(e,mi,f,b,n,done,err,cap)<0)return -1;
  layout v;if(bacnet_layout(b,n,&v,err,cap)<0 || content_valid(b,n,&v)<0)return fail(err,cap,"invalid BACnet structure after dependency repair");
  if(v.kind==0 && b[v.service]==12){size_t o,w;for(int x=0;x<2;x++){const char *loc=x?"bacnet.property":"bacnet.object";if(proto_bacnet_field(b,n,loc,&o,&w,err,cap)!=1 || (x?(w<1||w>4):w!=4))return fail(err,cap,"ReadProperty required context tag missing");}}
  return 0;
}
void proto_session_begin(proto_engine *e){if(!e)return;if(e->generic){gr_session_begin(e->generic);return;}memset(e->cached,0,sizeof(e->cached));memset(e->cache,0,sizeof(e->cache));memset(e->outstanding,0,sizeof(e->outstanding));memset(e->pending,0,sizeof(e->pending));e->semantic_state=e->initial;e->ua_sequence=0;if(!e->simulating)e->receive_size=0;}
static void remember(proto_engine *e,int mi,uint8_t *b,size_t n){
  char err[128];for(int model=0;model<e->nm;model++)if(e->canonical[model]==e->canonical[mi]){
    for(int f=0;f<e->m[model].nf;f++){size_t o,w;pf *p=&e->m[model].f[f];
      if(p->width && locate(e,b,n,p,&o,&w,err,sizeof(err))==1){e->cache[model][f]=getint(b+o,w,p->little);e->cached[model][f]=1;}
    }
  }
  if(e->codec==5 && !e->m[mi].response){size_t o,w;
    if(pc_opcua_field(b,n,"uabin:sequence",PC_UINT32,4,&o,&w,err,sizeof(err))==1)e->ua_sequence=(uint32_t)getint(b+o,w,1)+1;
  }
}
/* Resolve against a private wire copy. Until all bindings validate, this
 * routine only reads session state; remember/pending updates commit last. */
static int bind_before_send(proto_engine *e,uint8_t *b,size_t n,char *err,size_t cap){
  int mi=model_for(e,b,n,0);if(mi<0)return fail(err,cap,"request outside supported model (raw or intentionally invalid input)");
  int target_tr=-1;
  for(int t=0;t<e->nt;t++)if(e->tr[t].from==(int)e->semantic_state && e->canonical[e->tr[t].message]==e->canonical[mi]){target_tr=t;break;}
  if(target_tr<0)return fail(err,cap,"request outside current semantic state %s",e->state[e->semantic_state]);
  /* Only session bindings here. Wire-invalid tests must never be repaired again. */
  pm *m=&e->m[mi];for(int i=0;i<m->nd;i++){pd *d=&m->d[i];if(d->op==4 || d->op==5 || d->op==7){uint8_t done[FMAX]={0};if(repair_field(e,mi,d->target,b,n,done,err,cap)<0)return -1;}}
  if(e->codec && (codecs[e->codec].validate(b,n,err,cap)<0 || model_for(e,b,n,0)<0))return fail(err,cap,"live binding violates wire structure or model bounds");
  if(proto_validate_message_fields(e,mi,b,n,err,cap)<0)return fail(err,cap,"live binding violates field bounds: %s",err);
  remember(e,mi,b,n);for(int model=0;model<e->nm;model++)if(e->canonical[model]==e->canonical[mi])e->pending[model]=1;layout v;if(!e->codec && bacnet_layout(b,n,&v,err,cap)==0 && v.kind==0)e->outstanding[b[v.invoke]]=1;
  e->semantic_state=e->tr[target_tr].to;
  return 0;
}
int proto_before_send(proto_engine *e,uint8_t *b,size_t n,char *err,size_t cap){
  if(e&&e->generic)return gr_before_send(e->generic,b,n,err,cap);
  if(err && cap)err[0]=0;
  if(!e || !b || !n || n>WMAX)return fail(err,cap,"missing engine/wire or unsupported request size");
  uint8_t *bound=ck_alloc(n);memcpy(bound,b,n);
  int result=bind_before_send(e,bound,n,err,cap);
  if(result==0)memcpy(b,bound,n);
  ck_free(bound);return result;
}
/* Live responses may arrive split across net_recv calls or coalesced. Only a
 * complete validated, correlated response may supply connection bindings. */
static void response_frame(proto_engine *e,const uint8_t *b,size_t n){
  char err[128];int mi=-1,target_tr=-1;
  if(!e->codec){layout v;if(bacnet_layout(b,n,&v,err,sizeof(err))<0)return;e->responses++;
    if(v.invoke!=SIZE_MAX && v.kind>=2 && e->outstanding[b[v.invoke]]){e->correlated++;e->outstanding[b[v.invoke]]=0;}
  }
  for(int m=0;m<e->nm;m++){
    if(!e->m[m].response)continue;
    if(e->codec && !codecs[e->codec].same(b,n,e->m[m].example,e->m[m].size))continue;
    int resp_tr=-1;
    for(int t=0;t<e->nt;t++){
      if(e->tr[t].from==(int)e->semantic_state && e->canonical[e->tr[t].message]==e->canonical[m]){
        resp_tr=t;break;
      }
    }
    if(resp_tr<0)continue;
    int fits=1,linked=0;
    for(int f=0;f<e->m[m].nf;f++){pf *field=&e->m[m].f[f];size_t o,w;
      int present=locate(e,b,n,field,&o,&w,err,sizeof(err));if(!present && field->mut==3)continue;
      if(present!=1){fits=0;break;}
      uint64_t value=field->width?getint(b+o,w,field->little):w;
      if(value<field->min || value>field->max){fits=0;break;}
    }
    if(!fits)continue;
    for(int d=0;d<e->m[m].nd;d++){pd *dep=&e->m[m].d[d];if(dep->op!=4 && dep->op!=5 && dep->op!=6)continue;
      if(dep->op==6)linked=1;
      size_t o,w;pf *field=&e->m[m].f[dep->target];
      uint64_t source;
      if(dep->op==4 && e->canonical[dep->message]==e->canonical[m]){
        size_t so,sw;pf *sf=&e->m[dep->message].f[dep->source];
        if(locate(e,b,n,sf,&so,&sw,err,sizeof(err))!=1){fits=0;break;}source=getint(b+so,sw,sf->little);
      }else{
        if((dep->op==6 && !e->pending[dep->message]) || !e->cached[dep->message][dep->source]){fits=0;break;}
        source=e->cache[dep->message][dep->source];
      }
      if(locate(e,b,n,field,&o,&w,err,sizeof(err))!=1 || getint(b+o,w,field->little)!=source){fits=0;break;}
    }
    if(!fits)continue;
    if(e->codec){e->responses++;if(linked)e->correlated++;}
    mi=m;target_tr=resp_tr;for(int d=0;d<e->m[m].nd;d++){pd *dep=&e->m[m].d[d];if(dep->op==6)for(int model=0;model<e->nm;model++)if(e->canonical[model]==e->canonical[dep->message])e->pending[model]=0;}break;
  }
  if(mi>=0 && target_tr>=0){remember(e,mi,(uint8_t*)b,n);e->semantic_state=e->tr[target_tr].to;}
}
void proto_after_response(proto_engine *e,const uint8_t *b,size_t n){
  if(e&&e->generic){gr_after_response(e->generic,b,n);return;}
  if(!e || !b || !n)return;
  if(!e->codec){size_t p=0;while(n-p>=4){size_t z=getint(b+p+2,2,0);if(z<4 || z>n-p)break;response_frame(e,b+p,z);p+=z;}return;}
  if(n>MAX_FILE-e->receive_size){e->receive_size=0;if(e->log)fputs("{\"event\":\"response_rejected\",\"reason\":\"receive_limit\"}\n",e->log);return;}
  memcpy(e->receive+e->receive_size,b,n);e->receive_size+=n;size_t p=0;char err[128];
  while(p<e->receive_size){size_t z=0;int result=codecs[e->codec].frame(e->receive+p,e->receive_size-p,&z,err,sizeof(err));
    if(result<0){e->receive_size=0;if(e->log)fputs("{\"event\":\"response_rejected\",\"reason\":\"malformed_framing\"}\n",e->log);return;}
    if(!result)break;if(!z || z>e->receive_size-p){e->receive_size=0;return;}response_frame(e,e->receive+p,z);p+=z;
  }
  if(p){memmove(e->receive,e->receive+p,e->receive_size-p);e->receive_size-=p;}
}
static int semantic_step(proto_engine *e,int state,int model){
  if(e->m[model].response)return -1;
  int c_model=e->canonical[model];
  for(int t=0;t<e->nt;t++){pt *tr=&e->tr[t];if(tr->from!=state || e->canonical[tr->message]!=c_model)continue;
    state=tr->to;if(tr->response>=0){int answered=0;int c_resp=e->canonical[tr->response];for(int u=0;u<e->nt;u++)if(e->tr[u].from==state && e->canonical[e->tr[u].message]==c_resp){state=e->tr[u].to;answered=1;break;}if(!answered)return -1;}
    return state;
  }return -1;
}
int proto_set_prefix(proto_engine *e,const uint8_t *b,size_t n,char *err,size_t cap){
  if(e&&e->generic)return gr_set_prefix(e->generic,b,n,err,cap);
  if(!e)return fail(err,cap,"missing protocol engine");e->prefix_state=e->initial;e->prefix_valid=0;
  e->prefix_count=0;e->prefix_bytes=0;memset(e->prefix_repeats,0,sizeof(e->prefix_repeats));
  if(!n){e->prefix_valid=1;return 0;}
  size_t count;if(proto_records_validate(b,n,&count,err,cap)<0)return -1;
  size_t p=0;while(p<n){
    size_t z=getint(b+p,4,1);p+=4;
    int m=model_for(e,b+p,z,0);
    if(m<0 || (e->prefix_state=semantic_step(e,e->prefix_state,m))<0)return fail(err,cap,"M1 prefix outside semantic model");
    int c_model=e->canonical[m];
    if(++e->prefix_repeats[c_model]>(size_t)e->max_repeat)return fail(err,cap,"M1 max_repeat exceeded");
    p+=z;
  }
  e->prefix_count=count;e->prefix_bytes=n;e->prefix_valid=1;return 0;
}
static int sequence_ok(proto_engine *e) {
  if(!e->prefix_valid)return -1;
  if(e->prefix_count + e->count > (size_t)e->max_messages)return -1;
  size_t m2_bytes = 0;
  for(size_t i=0;i<e->count;i++) m2_bytes += 4 + e->records[i].size;
  if(e->prefix_bytes + m2_bytes > e->max_bytes)return -1;
  int state=e->prefix_state;
  size_t repeats[PMAX];
  memcpy(repeats, e->prefix_repeats, sizeof(repeats));
  for(size_t i=0;i<e->count;i++){
    int model=e->records[i].model;if((state=semantic_step(e,state,model))<0)return -1;
    int c_model=e->canonical[model];
    if(++repeats[c_model]>(size_t)e->max_repeat)return -1;
  }return 0;
}
int proto_validate_sequence(proto_engine *e,
                            const uint8_t *m1, size_t m1_len,
                            const uint8_t *m2, size_t m2_len,
                            const uint8_t *m3, size_t m3_len,
                            char *err, size_t cap) {
  if (e && e->generic)
    return gr_validate_sequence(e->generic, m1, m1_len, m2, m2_len, m3, m3_len, err, cap);
  if (!e) return fail(err, cap, "missing protocol engine");
  if (!m2 || !m2_len) return fail(err, cap, "M2 candidate record sequence cannot be empty");

  const uint8_t *segs[3] = {m1, m2, m3};
  size_t lens[3] = {m1_len, m2_len, m3_len};
  const char *seg_names[3] = {"M1", "M2", "M3"};

  size_t total_messages = 0;
  size_t total_replay_bytes = 0;
  size_t repeats[PMAX] = {0};
  int state = e->initial;

  for (int s = 0; s < 3; s++) {
    const uint8_t *buf = segs[s];
    size_t len = lens[s];
    if (!len) continue;

    size_t count;
    if (proto_records_validate(buf, len, &count, err, cap) < 0)
      return -1;

    size_t p = 0;
    while (p < len) {
      size_t z = getint(buf + p, 4, 1);
      p += 4;
      total_messages++;
      total_replay_bytes += 4 + z;

      if (total_messages > (size_t)e->max_messages)
        return fail(err, cap, "max_messages exceeded across sequence (%zu > %d)",
                    total_messages, e->max_messages);

      if (total_replay_bytes > e->max_bytes)
        return fail(err, cap, "max_bytes exceeded across sequence (%zu > %zu)",
                    total_replay_bytes, e->max_bytes);

      int m = model_for(e, buf + p, z, 0);
      if (m < 0)
        return fail(err, cap, "%s message outside semantic model", seg_names[s]);

      int c_model = e->canonical[m];
      if (++repeats[c_model] > (size_t)e->max_repeat)
        return fail(err, cap, "max_repeat exceeded across sequence for message %s (%zu > %d)",
                    e->m[m].id, repeats[c_model], e->max_repeat);

      state = semantic_step(e, state, m);
      if (state < 0)
        return fail(err, cap, "%s sequence outside state graph", seg_names[s]);

      p += z;
    }
  }

  if (!total_messages)
    return fail(err, cap, "empty sequence across M1/M2/M3");

  return 0;
}
typedef struct {uint64_t cache[PMAX][FMAX];uint8_t cached[PMAX][FMAX],outstanding[256],pending[PMAX];unsigned state;uint32_t ua_sequence;} session_snapshot;
static void save_session(proto_engine *e,session_snapshot *s){memcpy(s->cache,e->cache,sizeof(s->cache));memcpy(s->cached,e->cached,sizeof(s->cached));memcpy(s->outstanding,e->outstanding,sizeof(s->outstanding));memcpy(s->pending,e->pending,sizeof(s->pending));s->state=e->semantic_state;s->ua_sequence=e->ua_sequence;}
static void restore_session(proto_engine *e,const session_snapshot *s){memcpy(e->cache,s->cache,sizeof(s->cache));memcpy(e->cached,s->cached,sizeof(s->cached));memcpy(e->outstanding,s->outstanding,sizeof(s->outstanding));memcpy(e->pending,s->pending,sizeof(s->pending));e->semantic_state=s->state;e->ua_sequence=s->ua_sequence;e->simulating=0;}
static unsigned draw(proto_random rng,unsigned limit){return limit?rng(limit)%limit:0;}
static int resize_record(proto_engine *e,size_t ri,size_t newlen,char *err,size_t cap){
  pr *r=&e->records[ri];size_t end=e->records[e->count-1].offset+e->records[e->count-1].size;
  if(!newlen || newlen>WMAX || newlen>r->size+(MAX_FILE-end))return fail(err,cap,"resize exceeds buffer");
  ptrdiff_t delta=(ptrdiff_t)newlen-(ptrdiff_t)r->size;memmove(e->work+r->offset+newlen,e->work+r->offset+r->size,end-r->offset-r->size);
  r->size=newlen;for(size_t i=ri+1;i<e->count;i++)e->records[i].offset+=delta;return 0;
}
/* Message IDs belong to the description author. Choose the wire codec from
 * parsed APDU semantics, so renaming a request never changes its encoder. */
static int who_is_content(const uint8_t *b,size_t n,const char *locator){
  layout v;char error[128];
  return !strcmp(locator,"apdu.content") && bacnet_layout(b,n,&v,error,sizeof(error))==0 &&
         v.kind==1 && b[v.service]==8;
}
int proto_mutate(proto_engine *e,const uint8_t *records,size_t length,const uint8_t *candidate,size_t cn,int mode,int layer,proto_random rng,const uint8_t **out,size_t *olen,char *err,size_t cap){
  if(e&&e->generic)return gr_mutate(e->generic,records,length,candidate,cn,mode,layer,rng,out,olen,err,cap);
  if(out)*out=NULL;if(olen)*olen=0;
  if(!e || !rng || !out || !olen || (!candidate && cn))return fail(err,cap,"missing mutation engine, random callback, candidate or output");
  session_snapshot live;save_session(e,&live);
  size_t ri=0,before=0;int fi=-1,mi=-1;const char *strategy="none";int broken=mode==PROTO_NEAR_VALID || mode==PROTO_INVALID;
  e->attempts++;if(mode<0 || mode>PROTO_INVALID || (layer!=1 && layer!=2 && layer!=4)){fail(err,cap,"invalid structured mode/layer");goto bad;}
  if(unpack(e,records,length,err,cap)<0)goto bad;before=e->count;
  if(!e->count){fail(err,cap,"empty sequence cannot be mutated");goto bad;}
  if(e->count>(size_t)e->max_messages){fail(err,cap,"model max_messages exceeded");goto bad;}
  /* Work in a fresh simulated session, separate from the live connection cache. */
  e->simulating=1;proto_session_begin(e);
  unsigned total=0;for(size_t i=0;i<e->count;i++)total+=e->m[e->records[i].model].weight;
  unsigned pick=draw(rng,total);for(ri=0;ri+1<e->count;ri++){unsigned w=e->m[e->records[ri].model].weight;if(pick<w)break;pick-=w;}
  mi=e->records[ri].model;pm *m=&e->m[mi];pr *r=&e->records[ri];
  if(layer==PROTO_SEQUENCE){
    unsigned op=draw(rng,4);strategy=op==0?"insert":op==1?"delete":op==2?"repeat":"reorder";
    if(op==1){
      if(e->count<=1){fail(err,cap,"cannot delete the only request");goto bad;}
      size_t end=e->records[e->count-1].offset+e->records[e->count-1].size,z=r->size;
      memmove(e->work+r->offset,e->work+r->offset+z,end-r->offset-z);
      for(size_t i=ri+1;i<e->count;i++){e->records[i-1]=e->records[i];e->records[i-1].offset-=z;}e->count--;
    } else if(op==3){
      if(e->count<=1){fail(err,cap,"reorder requires two requests");goto bad;}
      size_t other=draw(rng,e->count-1);if(other>=ri)other++;
      pr tmp=e->records[ri];e->records[ri]=e->records[other];e->records[other]=tmp;
    } else {
      if(e->count==(size_t)e->max_messages){fail(err,cap,"sequence insertion max_messages");goto bad;}
      if(op==0){int choices[PMAX],n=0;for(int j=0;j<e->nm;j++)if(!e->m[j].response)choices[n++]=j;if(!n){fail(err,cap,"no request template");goto bad;}mi=choices[draw(rng,n)];m=&e->m[mi];}
      size_t z=op==0?m->size:r->size,end=e->records[e->count-1].offset+e->records[e->count-1].size;
      if(!z){fail(err,cap,"zero-length template or record cannot be inserted");goto bad;}
      if(z>MAX_FILE-end){fail(err,cap,"sequence insertion max_bytes");goto bad;}
      /* Save repeats before moving a randomly positioned suffix. */
      uint8_t *copy=ck_alloc(z);memcpy(copy,op==0?m->example:e->work+r->offset,z);
      size_t at=draw(rng,e->count+1),off=at<e->count?e->records[at].offset:end;
      memmove(e->work+off+z,e->work+off,end-off);memcpy(e->work+off,copy,z);ck_free(copy);
      for(size_t i=e->count;i>at;i--){e->records[i]=e->records[i-1];e->records[i].offset+=z;}
      e->records[at]=(pr){.offset=off,.size=z,.wire_offset=0,.model=mi};e->count++;ri=at;
    }
  } else {
    int choices[FMAX],nf=0;uint8_t *b=e->work+r->offset;
    for(int f=0;f<m->nf;f++){pf *p=&m->f[f];size_t o,w;if(p->role==(layer==1?1:2) && (p->mut==1 || p->mut==3) && locate(e,b,r->size,p,&o,&w,err,cap)==1)choices[nf++]=f;}
    if(!nf){fail(err,cap,"selected message has no mutable field in selected layer");goto bad;}fi=choices[draw(rng,nf)];pf *f=&m->f[fi];size_t o,w;
    if(locate(e,b,r->size,f,&o,&w,err,cap)!=1){fail(err,cap,"selected optional field absent");goto bad;}
    if(f->width){
      uint64_t val=getint(b+o,w,f->little);int operations[4],operation_count=0;for(int j=0;j<4;j++)if(f->strategies&(1<<j))operations[operation_count++]=j;unsigned op=layer==1?operations[draw(rng,operation_count)]:draw(rng,4);strategy=layer==2?"afl_field_projection":op==0?"enum":op==1?"boundary":op==2?"bitflip":"arithmetic";
      if(layer==2){if(!candidate || r->wire_offset+o>cn || w>cn-r->wire_offset-o){fail(err,cap,"AFL candidate does not contain selected CONTENT field");goto bad;}val=getint(candidate+r->wire_offset+o,w,f->little);}
      else if(op==0 && f->nv)val=f->values[draw(rng,f->nv)];
      else if(op==1){uint64_t boundary[]={f->min,f->max,f->min+1,f->max?f->max-1:0,0};val=boundary[draw(rng,5)];}
      else if(op==2)val^=1ULL<<draw(rng,w*8);else val+=draw(rng,2)?1:(uint64_t)-1;
      if(val<f->min || val>f->max)val=f->min;
      if(!strcmp(f->loc,"npdu.control")) {
        uint64_t candidate_val = (b[o] & ~7u) | (val & 7u);
        if (candidate_val < f->min || candidate_val > f->max) {
          uint64_t clamped = (b[o] & ~7u) | (f->min & 7u);
          if (clamped >= f->min && clamped <= f->max) candidate_val = clamped;
          else {
            clamped = (b[o] & ~7u) | (f->max & 7u);
            if (clamped >= f->min && clamped <= f->max) candidate_val = clamped;
            else {
              fail(err, cap, "npdu.control cannot satisfy bounds [%llu, %llu] with layout bits 0x%02x",
                   (unsigned long long)f->min, (unsigned long long)f->max, b[o] & ~7u);
              goto bad;
            }
          }
        }
        val = candidate_val;
      }
      if(e->codec==3 && !strncmp(f->loc,"ber:",4)){
        uint8_t integer[5];size_t iw=1;while(iw<4 && val>=(1ULL<<(8*iw)))iw++;
        putint(integer,iw,0,val);if(integer[0]&128){memmove(integer+1,integer,iw);integer[0]=0;iw++;}
        size_t resized=r->size;memcpy(e->output,b,r->size);
        if(pc_mms_replace(e->output,&resized,WMAX,f->loc,f->type,integer,iw,err,cap)<0 || resize_record(e,ri,resized,err,cap)<0)goto bad;
        b=e->work+r->offset;memcpy(b,e->output,resized);
      }else{if(w<8 && val>=(1ULL<<(8*w))){fail(err,cap,"mutation exceeds encoded scalar width");goto bad;}putint(b+o,w,f->little,val);}
    } else if(!e->codec && who_is_content(b,r->size,f->loc)){
      strategy="afl_limits_resize";size_t base=r->wire_offset+o,available=base<=cn?cn-base:0;
      /* A concatenated AFL candidate has no message delimiters. Never consume
       * the following datagram as newly inserted content for this request. */
      if(ri+1<e->count && available>r->size-o)available=r->size-o;
      int can_0 = (0 >= f->min && 0 <= f->max);
      int can_8 = (8 >= f->min && 8 <= f->max && candidate && available >= 8);
      size_t newwidth = 0;
      if (can_0 && can_8) newwidth = draw(rng, 2) ? 8 : 0;
      else if (can_8) newwidth = 8;
      else if (can_0) newwidth = 0;
      else {
        fail(err, cap, "Who-Is content length cannot satisfy bounds [%llu, %llu]",
             (unsigned long long)f->min, (unsigned long long)f->max);
        goto bad;
      }
      if(resize_record(e,ri,o+newwidth,err,cap)<0)goto bad;b=e->work+r->offset;
      if(newwidth){uint32_t low=0,high=4194303;low=(uint32_t)getint(candidate+base+1,3,0)&0x3fffff;high=(uint32_t)getint(candidate+base+5,3,0)&0x3fffff;if(low>high){uint32_t tmp=low;low=high;high=tmp;}b[o]=0x0b;putint(b+o+1,3,0,low);b[o+4]=0x1b;putint(b+o+5,3,0,high);}
    } else if(e->codec){
      strategy="afl_codec_leaf";size_t base=r->wire_offset+o;
      if(!candidate || base>cn){fail(err,cap,"AFL candidate lacks selected leaf");goto bad;}
      size_t available=cn-base;if(ri+1<e->count && available>r->size-o)available=r->size-o;
      size_t width=w;if((f->strategies&32) && draw(rng,3)==0){
        size_t bound=available<256?available:256;
        if(bound<f->min){fail(err,cap,"candidate too short for leaf minimum");goto bad;}
        if(bound>f->max)bound=f->max;width=f->min+draw(rng,(unsigned)(bound-f->min+1));
      }
      if(width>available || width<f->min || width>f->max){fail(err,cap,"candidate leaf length outside bounds");goto bad;}
      uint8_t *leaf=ck_alloc(width?width:1);for(size_t j=0;j<width;j++)leaf[j]=f->type==PC_STRING?32+candidate[base+j]%95:candidate[base+j];
      size_t resized=r->size;memcpy(e->output,b,r->size);
      int status=codecs[e->codec].replace(e->output,&resized,WMAX,f->loc,f->type,leaf,width,err,cap);ck_free(leaf);
      if(status<0 || resize_record(e,ri,resized,err,cap)<0)goto bad;
      memcpy(e->work+r->offset,e->output,resized);
    } else {fail(err,cap,"no runtime content encoder for %s.%s",m->id,f->id);goto bad;}
  }
  if(sequence_ok(e)<0){fail(err,cap,"semantic transition or repeat constraint rejects sequence");goto bad;}
  /* Derive fields, then cache explicit message.field values in sequence order. */
  for(size_t i=0;i<e->count;i++){pr *x=&e->records[i];if(!x->size){fail(err,cap,"zero-length message record produced");goto bad;}uint8_t *b=e->work+x->offset;if(repair(e,x->model,b,x->size,err,cap)<0)goto bad;
    if(e->codec && !codecs[e->codec].same(b,x->size,e->m[x->model].example,e->m[x->model].size)){fail(err,cap,"mutation changed request semantic family");goto bad;}
    if(model_for(e,b,x->size,0)!=e->canonical[x->model]){fail(err,cap,"mutation changed message model");goto bad;}
    if(proto_validate_message_fields(e,x->model,b,x->size,err,cap)<0){fail(err,cap,"mutation violated field constraints: %s",err);goto bad;}
    remember(e,x->model,b,x->size);
  }
  if(broken){ri=ri<e->count?ri:0;pr *x=&e->records[ri];uint8_t *b=e->work+x->offset;
    size_t offset=e->codec==1?4:e->codec==2?1:e->codec==5?4:2;
    size_t width=e->codec==2?1:e->codec==5?4:2;int little=e->codec>=4;
    putint(b+offset,width,little,getint(b+offset,width,little)+1);
  }
  if(pack(e,out,olen,err,cap)<0)goto bad;
  e->success++;e->layer_count[layer==1?0:layer==2?1:2]++;
  if(e->log)fprintf(e->log,"{\"event\":\"mutation\",\"layer\":\"%s\",\"message\":\"%s\",\"field\":\"%s\",\"strategy\":\"%s\",\"derived_repaired\":true,\"intentional_violation\":%s,\"constraint\":\"%s\",\"messages_before\":%zu,\"messages_after\":%zu,\"parse_failed\":false,\"serialize_failed\":false}\n",layer==1?"HEAD":layer==2?"CONTENT":"SEQUENCE",mi>=0?e->m[mi].id:"none",fi>=0?e->m[mi].f[fi].id:"sequence",strategy,broken?"true":"false",broken?"wire_length":"none",before,e->count);
  restore_session(e,&live);return 0;
bad:e->errors++;if(e->log)fprintf(e->log,"{\"event\":\"rejected\",\"layer_id\":%d,\"reason\":\"%s\",\"parse_or_constraint_failed\":true,\"serialize_failed\":false}\n",layer,err && cap?err:"error");restore_session(e,&live);return -1;
}
void proto_write_stats(proto_engine *e,const char *path){if(e&&e->generic){gr_write_stats(e->generic,path);return;}if(!e || !path)return;FILE *f=fopen(path,"w");if(!f)return;fprintf(f,"{\"attempts\":%llu,\"structured_success\":%llu,\"rejected\":%llu,\"HEAD\":%llu,\"CONTENT\":%llu,\"SEQUENCE\":%llu,\"responses\":%llu,\"correlated_responses\":%llu,\"protocol_semantic_state\":\"%s\"}\n",(unsigned long long)e->attempts,(unsigned long long)e->success,(unsigned long long)e->errors,(unsigned long long)e->layer_count[0],(unsigned long long)e->layer_count[1],(unsigned long long)e->layer_count[2],(unsigned long long)e->responses,(unsigned long long)e->correlated,e->state[e->semantic_state]);fclose(f);}
