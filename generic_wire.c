/* Protocol-name-independent, bounded wire grammar for one message. */
#include "generic_wire.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GW_FIELDS 256u
#define GW_VALUES 32u
enum kind { K_UINT, K_BYTES };
enum role { R_FIXED, R_HEAD, R_CONTENT, R_DERIVED };
enum length_kind { L_CONST, L_REST, L_REF };
typedef struct {
  char id[64], target_id[64]; enum kind kind; enum role role; enum length_kind length_kind;
  unsigned width, little; size_t length, ref, target;
  int64_t add, length_add; uint64_t min, max, expected, values[GW_VALUES];
  size_t value_count; int has_expected, has_derived;
  uint8_t *fixed; size_t fixed_size;
} field;
struct gw_schema { field fields[GW_FIELDS]; size_t count; };
typedef struct {
  uint64_t number; uint8_t *bytes; size_t size, offset;
  size_t original_size, original_offset;
} cell;
struct gw_packet {
  const gw_schema *schema; cell cells[GW_FIELDS];
  uint8_t *original; size_t original_length;
};
static int fail(char *err,size_t cap,const char *fmt,...){
  if(err&&cap){va_list ap;va_start(ap,fmt);vsnprintf(err,cap,fmt,ap);va_end(ap);}return -1;
}
static int find(const gw_schema *s,const char *id){
  for(size_t i=0;i<s->count;i++)if(!strcmp(s->fields[i].id,id))return (int)i;
  return -1;
}
static uint64_t width_max(unsigned w){return w==8?UINT64_MAX:(UINT64_C(1)<<(w*8))-1;}
static int digit(char c){
  if(c>='0'&&c<='9')return c-'0';
  if(c>='a'&&c<='f')return c-'a'+10;
  if(c>='A'&&c<='F')return c-'A'+10;
  return -1;
}
static int hex(const nj_value *v,uint8_t **data,size_t *n,char *err,size_t cap){
  *data=NULL;*n=0;
  if(!v||v->type!=NJ_STRING||v->text_length%2||v->text_length/2>GW_MAX_WIRE)
    return fail(err,cap,"invalid hex");
  uint8_t *p=malloc(v->text_length/2+1);if(!p)return fail(err,cap,"out of memory");
  for(size_t i=0;i<v->text_length;i+=2){
    int a=digit(v->text[i]),b=digit(v->text[i+1]);
    if(a<0||b<0){free(p);return fail(err,cap,"invalid hex digit");}
    p[i/2]=(uint8_t)(a*16+b);
  }
  *data=p;*n=v->text_length/2;return 0;
}
void gw_free(gw_schema *s){
  if(!s)return;for(size_t i=0;i<GW_FIELDS;i++)free(s->fields[i].fixed);free(s);
}
static int compile_field(gw_schema *s,const nj_value *v,char *err,size_t cap){
  static const char *req[]={"id","kind","role"};
  static const char *opt[]={"width","byte_order","length","min","max",
    "expected","expected_hex","values","derived"};
  field *f=&s->fields[s->count];uint64_t x;char name[64];
  if(nj_keys(v,req,3,opt,9,err,cap)<0||
     nj_string_copy(nj_get(v,"id"),f->id,sizeof(f->id),err,cap)<0)return -1;
  size_t n=strlen(f->id);if(!n||find(s,f->id)>=0)return fail(err,cap,"empty or duplicate field id");
  for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)f->id[i];
    if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||
      (i&&c>='0'&&c<='9')))return fail(err,cap,"invalid field id");}
  const nj_value *role=nj_get(v,"role");
  if(nj_string_equal(role,"fixed"))f->role=R_FIXED;
  else if(nj_string_equal(role,"head"))f->role=R_HEAD;
  else if(nj_string_equal(role,"content"))f->role=R_CONTENT;
  else if(nj_string_equal(role,"derived"))f->role=R_DERIVED;
  else return fail(err,cap,"invalid role");
  if(nj_string_equal(nj_get(v,"kind"),"uint"))f->kind=K_UINT;
  else if(nj_string_equal(nj_get(v,"kind"),"bytes"))f->kind=K_BYTES;
  else return fail(err,cap,"invalid kind");
  if(f->kind==K_UINT){
    if(nj_get(v,"length")||nj_get(v,"expected_hex"))
      return fail(err,cap,"uint with bytes attributes");
    if(nj_u64(nj_get(v,"width"),&x,err,cap)<0||x<1||x>8)
      return fail(err,cap,"uint width must be 1..8");
    f->width=(unsigned)x;f->max=width_max(f->width);
    if(nj_string_equal(nj_get(v,"byte_order"),"little"))f->little=1;
    else if(!nj_string_equal(nj_get(v,"byte_order"),"big"))
      return fail(err,cap,"byte_order required");
  }else{
    if(nj_get(v,"width")||nj_get(v,"byte_order")||nj_get(v,"values")||
       nj_get(v,"expected")||nj_get(v,"derived"))
      return fail(err,cap,"bytes with uint attributes");
    const nj_value *length=nj_get(v,"length");if(!length)return fail(err,cap,"bytes length missing");
    if(length->type==NJ_INTEGER){
      if(nj_u64(length,&x,err,cap)<0||x>GW_MAX_WIRE)return fail(err,cap,"invalid bytes length");
      f->length_kind=L_CONST;f->length=(size_t)x;
    }else if(nj_string_equal(length,"rest"))f->length_kind=L_REST;
    else if(length->type==NJ_OBJECT){
      static const char *r[]={"ref"},*o[]={"add"};
      if(nj_keys(length,r,1,o,1,err,cap)<0||
         nj_string_copy(nj_get(length,"ref"),name,sizeof(name),err,cap)<0)return -1;
      int ix=find(s,name);if(ix<0||s->fields[ix].kind!=K_UINT)
        return fail(err,cap,"length ref must name earlier uint");
      f->length_kind=L_REF;f->ref=(size_t)ix;
      if(nj_get(length,"add")&&nj_i64(nj_get(length,"add"),&f->length_add,err,cap)<0)return -1;
    }else return fail(err,cap,"invalid bytes length");
    f->max=GW_MAX_WIRE;
  }
  if(nj_get(v,"min")&&nj_u64(nj_get(v,"min"),&f->min,err,cap)<0)return -1;
  if(nj_get(v,"max")&&nj_u64(nj_get(v,"max"),&f->max,err,cap)<0)return -1;
  if(f->max<f->min||f->max>(f->kind==K_UINT?width_max(f->width):GW_MAX_WIRE))
    return fail(err,cap,"field bounds invalid");
  if(f->kind==K_BYTES){
    const nj_value *fixed=nj_get(v,"expected_hex");
    if(fixed&&hex(fixed,&f->fixed,&f->fixed_size,err,cap)<0)return -1;
    if(f->role==R_FIXED&&!fixed)return fail(err,cap,"fixed bytes need expected_hex");
    if(f->role==R_HEAD||f->role==R_DERIVED)return fail(err,cap,"bytes role unsupported");
    if(f->length_kind==L_CONST&&(f->length<f->min||f->length>f->max))
      return fail(err,cap,"constant length outside bounds");
    if(fixed&&(f->fixed_size<f->min||f->fixed_size>f->max||
       (f->length_kind==L_CONST&&f->fixed_size!=f->length)))
      return fail(err,cap,"expected bytes length invalid");
  }else{
    const nj_value *expected=nj_get(v,"expected");
    if(expected){
      if(nj_u64(expected,&f->expected,err,cap)<0)return -1;
      f->has_expected=1;if(f->expected<f->min||f->expected>f->max)
        return fail(err,cap,"expected outside bounds");
    }
    if(f->role==R_FIXED&&!expected)return fail(err,cap,"fixed uint needs expected");
    const nj_value *derived=nj_get(v,"derived");
    if(f->role==R_DERIVED){
      static const char *r[]={"op","target"},*o[]={"add"};
      if(nj_keys(derived,r,2,o,1,err,cap)<0||
         !nj_string_equal(nj_get(derived,"op"),"size_of")||
         nj_string_copy(nj_get(derived,"target"),f->target_id,sizeof(f->target_id),err,cap)<0)
        return fail(err,cap,"size_of rule required");
      f->target=(size_t)-1;
      if(nj_get(derived,"add")&&nj_i64(nj_get(derived,"add"),&f->add,err,cap)<0)return -1;
      f->has_derived=1;
    }else if(derived)return fail(err,cap,"unexpected derived rule");
    const nj_value *values=nj_get(v,"values");
    if(values){
      if(values->type!=NJ_ARRAY||values->count>GW_VALUES)return fail(err,cap,"invalid enum count");
      for(size_t i=0;i<values->count;i++){
        if(nj_u64(values->items[i],&x,err,cap)<0||x<f->min||x>f->max)
          return fail(err,cap,"enum outside bounds");
        f->values[f->value_count++]=x;
      }
    }
  }
  s->count++;return 0;
}
gw_schema *gw_compile(const nj_value *grammar,char *err,size_t cap){
  static const char *r[]={"kind","fields"};if(err&&cap)err[0]=0;
  if(nj_keys(grammar,r,2,NULL,0,err,cap)<0||
     !nj_string_equal(nj_get(grammar,"kind"),"struct")){
    fail(err,cap,"grammar must be struct");return NULL;
  }
  const nj_value *a=nj_get(grammar,"fields");
  if(!a||a->type!=NJ_ARRAY||!a->count||a->count>GW_FIELDS){
    fail(err,cap,"invalid field array");return NULL;
  }
  gw_schema *s=calloc(1,sizeof(*s));if(!s){fail(err,cap,"out of memory");return NULL;}
  for(size_t i=0;i<a->count;i++)if(compile_field(s,a->items[i],err,cap)<0)goto bad;
  for(size_t i=0;i<s->count;i++){
    field *f=&s->fields[i];
    if(f->kind==K_BYTES&&f->length_kind==L_REST&&i+1!=s->count){
      fail(err,cap,"rest must be final");goto bad;
    }
    if(f->has_derived&&strcmp(f->target_id,"$message")){
      int ix=find(s,f->target_id);
      if(ix<0){fail(err,cap,"unknown size_of target: %s",f->target_id);goto bad;}
      f->target=(size_t)ix;
    }
  }
  return s;
bad:gw_free(s);return NULL;
}
static uint64_t read_uint(const uint8_t *p,unsigned n,int little){
  uint64_t v=0;if(little){for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);}
  else{for(unsigned i=0;i<n;i++)v=(v<<8)|p[i];}return v;
}
static void write_uint(uint8_t *p,unsigned n,int little,uint64_t v){
  for(unsigned i=0;i<n;i++)p[little?i:n-i-1]=(uint8_t)(v>>(8*i));
}
static int derived_value(const gw_packet *p,size_t i,size_t message_length,
                         uint64_t *out,char *err,size_t cap){
  const field *f=&p->schema->fields[i];
  size_t base=f->target==(size_t)-1?message_length:p->cells[f->target].size;
  __int128 value=(__int128)base+f->add;
  if(value<0||value>(__int128)UINT64_MAX)return fail(err,cap,"derived overflow");
  *out=(uint64_t)value;return 0;
}
static int referenced_size(const field *f,uint64_t number,size_t *out,
                           char *err,size_t cap){
  __int128 value=(__int128)number+f->length_add;
  if(value<0||value>GW_MAX_WIRE)return fail(err,cap,"%s length ref outside budget",f->id);
  *out=(size_t)value;return 0;
}
void gw_packet_free(gw_packet *p){
  if(!p)return;for(size_t i=0;i<GW_FIELDS;i++)free(p->cells[i].bytes);
  free(p->original);free(p);
}
int gw_parse(const gw_schema *s,const uint8_t *wire,size_t n,gw_packet **out,
             char *err,size_t cap){
  size_t off=0;gw_packet *p=NULL;
  if(out)*out=NULL;if(err&&cap)err[0]=0;
  if(!s||(!wire&&n)||!out||n>GW_MAX_WIRE)return fail(err,cap,"invalid parse arguments");
  p=calloc(1,sizeof(*p));if(!p)return fail(err,cap,"out of memory");p->schema=s;
  p->original=malloc(n?n:1);if(!p->original){fail(err,cap,"out of memory");goto bad;}
  if(n)memcpy(p->original,wire,n);p->original_length=n;
  for(size_t i=0;i<s->count;i++){
    const field *f=&s->fields[i];cell *c=&p->cells[i];size_t z;
    c->offset=off;
    if(f->kind==K_UINT){
      z=f->width;if(z>n-off){fail(err,cap,"%s truncated",f->id);goto bad;}
      c->number=read_uint(wire+off,f->width,f->little);
    }else{
      if(f->length_kind==L_CONST)z=f->length;
      else if(f->length_kind==L_REF){
        if(referenced_size(f,p->cells[f->ref].number,&z,err,cap)<0)goto bad;
      }else z=n-off;
      if(z>n-off){fail(err,cap,"%s truncated",f->id);goto bad;}
      c->bytes=malloc(z?z:1);if(!c->bytes){fail(err,cap,"out of memory");goto bad;}
      if(z)memcpy(c->bytes,wire+off,z);
    }
    c->size=c->original_size=z;c->original_offset=off;off+=z;
    uint64_t observed=f->kind==K_UINT?c->number:z;
    if(observed<f->min||observed>f->max){fail(err,cap,"%s outside bounds",f->id);goto bad;}
    if(f->kind==K_UINT&&f->has_expected&&c->number!=f->expected){
      fail(err,cap,"%s fixed mismatch",f->id);goto bad;
    }
    if(f->kind==K_BYTES&&f->fixed&&
       (z!=f->fixed_size||memcmp(c->bytes,f->fixed,z))){
      fail(err,cap,"%s fixed mismatch",f->id);goto bad;
    }
  }
  if(off!=n){fail(err,cap,"unconsumed wire tail");goto bad;}
  for(size_t i=0;i<s->count;i++){
    const field *f=&s->fields[i];if(!f->has_derived)continue;uint64_t expected;
    if(derived_value(p,i,n,&expected,err,cap)<0)goto bad;
    if(expected!=p->cells[i].number){fail(err,cap,"%s derived mismatch",f->id);goto bad;}
  }
  *out=p;return 0;
bad:gw_packet_free(p);return -1;
}
static int encode_internal(const gw_packet *p,uint8_t *out,size_t capacity,size_t *length,
                           char *err,size_t cap){
  size_t n=0;const gw_schema *s=p->schema;uint64_t numbers[GW_FIELDS];
  for(size_t i=0;i<s->count;i++){
    const field *f=&s->fields[i];const cell *c=&p->cells[i];
    size_t z=f->kind==K_UINT?f->width:c->size;
    if(z>GW_MAX_WIRE-n||z>capacity-n)return fail(err,cap,"wire exceeds budget");
    n+=z;numbers[i]=c->number;
  }
  for(size_t i=0;i<s->count;i++){
    if(!s->fields[i].has_derived)continue;uint64_t v;
    if(derived_value(p,i,n,&v,err,cap)<0)return -1;numbers[i]=v;
  }
  size_t off=0;for(size_t i=0;i<s->count;i++){
    const field *f=&s->fields[i];const cell *c=&p->cells[i];
    size_t z=f->kind==K_UINT?f->width:c->size;uint64_t observed=f->kind==K_UINT?numbers[i]:z;
    if(observed<f->min||observed>f->max)return fail(err,cap,"%s outside bounds",f->id);
    if(f->kind==K_UINT){
      if(f->has_expected&&numbers[i]!=f->expected)return fail(err,cap,"%s fixed mismatch",f->id);
      write_uint(out+off,f->width,f->little,numbers[i]);
    }else{
      if(f->length_kind==L_CONST&&z!=f->length)return fail(err,cap,"%s constant size changed",f->id);
      if(f->length_kind==L_REF){
        size_t expected;
        if(referenced_size(f,numbers[f->ref],&expected,err,cap)<0)return -1;
        if(z!=expected)return fail(err,cap,"%s referenced size mismatch",f->id);
      }
      if(f->fixed&&(z!=f->fixed_size||memcmp(c->bytes,f->fixed,z)))return fail(err,cap,"%s fixed mismatch",f->id);
      if(z)memcpy(out+off,c->bytes,z);
    }
    off+=z;
  }
  *length=n;return 0;
}
int gw_encode(gw_packet *p,uint8_t *out,size_t capacity,size_t *length,
              char *err,size_t cap){
  uint8_t *tmp=NULL;gw_packet *verified=NULL;size_t n=0;int status=-1;
  if(length)*length=0;if(err&&cap)err[0]=0;
  if(!p||!out||!length)return fail(err,cap,"invalid encode arguments");
  if(capacity>GW_MAX_WIRE)capacity=GW_MAX_WIRE;
  tmp=malloc(capacity?capacity:1);if(!tmp)return fail(err,cap,"out of memory");
  if(encode_internal(p,tmp,capacity,&n,err,cap)<0)goto done;
  if(gw_parse(p->schema,tmp,n,&verified,err,cap)<0)goto done;
  for(size_t i=0;i<p->schema->count;i++){
    p->cells[i].number=verified->cells[i].number;
    p->cells[i].offset=verified->cells[i].offset;
  }
  if(n)memcpy(out,tmp,n);*length=n;status=0;
done:gw_packet_free(verified);free(tmp);return status;
}
int gw_get_u64(const gw_packet *p,const char *name,uint64_t *value){
  int i;if(!p||!name||!value||(i=find(p->schema,name))<0||
    p->schema->fields[i].kind!=K_UINT)return -1;
  *value=p->cells[i].number;return 0;
}
int gw_set_u64(gw_packet *p,const char *name,uint64_t value,char *err,size_t cap){
  int i;if(!p||!name||(i=find(p->schema,name))<0)return fail(err,cap,"unknown field");
  const field *f=&p->schema->fields[i];
  if(f->kind!=K_UINT||f->role==R_FIXED||f->role==R_DERIVED||
     value<f->min||value>f->max||f->has_expected)
    return fail(err,cap,"field not editable");
  p->cells[i].number=value;return 0;
}
int gw_field_range(const gw_packet *p,const char *name,size_t *offset,size_t *length){
  int i;if(!p||!name||!offset||!length||(i=find(p->schema,name))<0)return -1;
  *offset=p->cells[i].offset;*length=p->cells[i].size;return 0;
}
static gw_packet *clone_packet(const gw_packet *p){
  gw_packet *q=calloc(1,sizeof(*q));if(!q)return NULL;
  q->schema=p->schema;q->original_length=p->original_length;
  q->original=malloc(q->original_length?q->original_length:1);
  if(!q->original){gw_packet_free(q);return NULL;}
  if(q->original_length)memcpy(q->original,p->original,q->original_length);
  for(size_t i=0;i<p->schema->count;i++){
    q->cells[i]=p->cells[i];q->cells[i].bytes=NULL;
    if(p->schema->fields[i].kind==K_BYTES){
      size_t n=p->cells[i].size;q->cells[i].bytes=malloc(n?n:1);
      if(!q->cells[i].bytes){gw_packet_free(q);return NULL;}
      if(n)memcpy(q->cells[i].bytes,p->cells[i].bytes,n);
    }
  }
  return q;
}
static uint32_t draw(gw_random rng,uint32_t limit){return limit?rng(limit)%limit:0;}
int gw_mutate(gw_packet *p,int layer,const uint8_t *candidate,size_t cn,
              gw_random rng,char *err,size_t cap){
  gw_packet *q=NULL,*verified=NULL;uint8_t *wire=NULL;size_t n=0;
  if(err&&cap)err[0]=0;
  if(!p||!rng||(!candidate&&cn)||cn>GW_MAX_WIRE||(layer!=1&&layer!=2))
    return fail(err,cap,"invalid mutation arguments");
  size_t count=0,chosen=0;enum role requested=layer==1?R_HEAD:R_CONTENT;
  for(size_t i=0;i<p->schema->count;i++)if(p->schema->fields[i].role==requested)count++;
  if(!count)return fail(err,cap,"no mutable field in selected layer");
  uint32_t ordinal=draw(rng,(uint32_t)count);
  for(size_t i=0;i<p->schema->count;i++)if(p->schema->fields[i].role==requested){
    if(!ordinal--){chosen=i;break;}
  }
  q=clone_packet(p);if(!q)return fail(err,cap,"out of memory");
  const field *f=&p->schema->fields[chosen];cell *c=&q->cells[chosen];
  if(f->kind==K_UINT){
    uint64_t v=c->number;
    if(layer==1){
      switch(draw(rng,4)){
        case 0:v=f->value_count?f->values[draw(rng,(uint32_t)f->value_count)]:f->min;break;
        case 1:v=draw(rng,2)?f->min:f->max;break;
        case 2:v^=UINT64_C(1)<<draw(rng,f->width*8);break;
        default:v=draw(rng,2)?v+1:v-1;break;
      }
      if(v<f->min||v>f->max)v=f->min;
    }else{
      if(c->original_offset>cn||c->original_size>cn-c->original_offset){fail(err,cap,"candidate lacks scalar");goto bad;}
      v=read_uint(candidate+c->original_offset,f->width,f->little);
      if(v<f->min||v>f->max){fail(err,cap,"candidate scalar outside bounds");goto bad;}
    }
    c->number=v;
  }else{
    if(layer!=2){fail(err,cap,"HEAD bytes unsupported");goto bad;}
    if(c->original_offset>cn){fail(err,cap,"candidate lacks bytes");goto bad;}
    size_t available=cn-c->original_offset,z=c->size;
    if(f->length_kind==L_REST||
       (f->length_kind==L_REF&&q->schema->fields[f->ref].has_derived)){
      /* Candidate replaces this original leaf; later fields keep their bytes.
       * Derived scalars are recomputed from sizes by encode, including add. */
      size_t tail=p->original_length-c->original_offset-c->original_size;
      if(available<tail){fail(err,cap,"candidate lacks trailing fields");goto bad;}
      available-=tail;
      z=available<f->max?available:(size_t)f->max;
    }
    if(z>available||z<f->min||z>f->max){fail(err,cap,"candidate bytes outside bounds");goto bad;}
    uint8_t *replacement=malloc(z?z:1);
    if(!replacement){fail(err,cap,"out of memory");goto bad;}
    if(z)memcpy(replacement,candidate+c->original_offset,z);
    free(c->bytes);c->bytes=replacement;c->size=z;
  }
  wire=malloc(GW_MAX_WIRE);if(!wire){fail(err,cap,"out of memory");goto bad;}
  if(gw_encode(q,wire,GW_MAX_WIRE,&n,err,cap)<0||
     gw_parse(q->schema,wire,n,&verified,err,cap)<0)goto bad;
  for(size_t i=0;i<p->schema->count;i++){
    verified->cells[i].original_offset=p->cells[i].original_offset;
    verified->cells[i].original_size=p->cells[i].original_size;
    free(p->cells[i].bytes);
  }
  memcpy(p->cells,verified->cells,sizeof(p->cells));
  memset(verified->cells,0,sizeof(verified->cells));
  gw_packet_free(verified);gw_packet_free(q);free(wire);return 0;
bad:gw_packet_free(verified);gw_packet_free(q);free(wire);return -1;
}
int gw_has_role(const gw_schema *s, int layer) {
  if (!s || (layer != 1 && layer != 2)) return 0;
  enum role req = (layer == 1) ? R_HEAD : R_CONTENT;
  for (size_t i = 0; i < s->count; i++) {
    if (s->fields[i].role == req) return 1;
  }
  return 0;
}
