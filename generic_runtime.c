/* Package-level execution for description-driven wire grammars. */
#include "generic_runtime.h"
#include "generic_wire.h"
#include "config.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define GR_MESSAGES 128u
#define GR_STATES 64u
#define GR_TRANSITIONS 256u
#define GR_CORRELATIONS 16u
#define GR_RECORDS 64u
#define GR_WIRE 65507u
typedef struct {char field[64],source[64];unsigned request;} gr_correlation;
typedef struct {char id[64];int response;unsigned weight;uint8_t *example;size_t size;
                gw_schema *schema;gr_correlation correlations[GR_CORRELATIONS];
                size_t correlation_count;} gr_message;
typedef struct {unsigned from,to,message;int response;} gr_transition;
typedef struct {uint8_t *wire;size_t size,original_offset;unsigned model;} gr_record;
struct gr_engine {
  nj_document *document;char protocol_id[64],transport[4],states[GR_STATES][64];
  gr_message messages[GR_MESSAGES];gr_transition transitions[GR_TRANSITIONS];
  unsigned count,state_count,transition_count,initial,state,prefix_state,prefix_valid;
  size_t prefix_count,prefix_bytes;unsigned prefix_repeats[GR_MESSAGES];
  unsigned max_messages,max_repeat;size_t max_bytes;
  unsigned frame_offset,frame_width,frame_little;int64_t frame_add;
  uint8_t *receive;size_t receive_size;
  uint8_t *output;size_t output_size;
  uint64_t attempts,success,errors,layer_count[3],responses,completed,correlated;
  unsigned pending,pending_request,pending_response,pending_next;
  uint64_t cache[GR_CORRELATIONS];
  FILE *log;
};
static int gr_error(char *err,size_t cap,const char *fmt,...){
  if(err&&cap){va_list args;va_start(args,fmt);vsnprintf(err,cap,fmt,args);va_end(args);}return -1;
}
static int gr_text(const nj_value *v,char *s,size_t n,char *err,size_t cap){
  return nj_string_copy(v,s,n,err,cap);
}
static int gr_unsigned(const nj_value *v,uint64_t lo,uint64_t hi,unsigned *out,
                       char *err,size_t cap){
  uint64_t x;if(nj_u64(v,&x,err,cap)<0||x<lo||x>hi)return gr_error(err,cap,"integer out of bounds");
  *out=(unsigned)x;return 0;
}
static int gr_find_message(const gr_engine *e,const char *id){
  for(unsigned i=0;i<e->count;i++)if(!strcmp(e->messages[i].id,id))return (int)i;return -1;
}
static int gr_find_state(const gr_engine *e,const char *id){
  for(unsigned i=0;i<e->state_count;i++)if(!strcmp(e->states[i],id))return (int)i;return -1;
}
static int gr_hex(const nj_value *v,uint8_t **data,size_t *size,char *err,size_t cap){
  static const char digits[]="0123456789abcdef";*data=NULL;*size=0;
  if(!v||v->type!=NJ_STRING||!v->text_length||v->text_length%2||v->text_length/2>GR_WIRE)
    return gr_error(err,cap,"invalid example_hex");
  *size=v->text_length/2;*data=malloc(*size);if(!*data)return gr_error(err,cap,"out of memory");
  for(size_t i=0;i<*size;i++){
    char a=v->text[2*i],b=v->text[2*i+1];const char *pa=strchr(digits,a),*pb=strchr(digits,b);
    if(!a||!b||!pa||!pb)return gr_error(err,cap,"example_hex must be lowercase hexadecimal");
    (*data)[i]=(uint8_t)(((unsigned)(pa-digits)<<4)|(unsigned)(pb-digits));
  }return 0;
}
static uint64_t gr_integer(const uint8_t *b,unsigned n,int little){
  uint64_t x=0;for(unsigned i=0;i<n;i++)x=little?x|((uint64_t)b[i]<<(8*i)):(x<<8)|b[i];return x;
}
static void gr_put32(uint8_t *b,size_t n){for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(n>>(8*i));}
static unsigned gr_get32(const uint8_t *b){return (unsigned)gr_integer(b,4,1);}
static uint32_t gr_draw(proto_random random,uint32_t limit){return limit?random(limit)%limit:0;}
static void gr_records_free(gr_record records[GR_RECORDS],size_t count){
  for(size_t i=0;i<count;i++){free(records[i].wire);records[i].wire=NULL;}
}
static int gr_match(const gr_engine *e,const uint8_t *wire,size_t size,int response,
                    unsigned *model,char *err,size_t cap){
  if(!wire||!size)return gr_error(err,cap,"wire message cannot be empty");
  int found=-1;for(unsigned i=0;i<e->count;i++){gw_packet *packet=NULL;
    if(e->messages[i].response!=response)continue;
    if(gw_parse(e->messages[i].schema,wire,size,&packet,NULL,0)==0){
      gw_packet_free(packet);if(found>=0)return gr_error(err,cap,"ambiguous message grammars");found=(int)i;
    }
  }if(found<0)return gr_error(err,cap,"message outside description grammar");
  *model=(unsigned)found;return 0;
}
static int gr_next(const gr_engine *e,unsigned state,unsigned model,
                   unsigned *next,int *response){
  for(unsigned i=0;i<e->transition_count;i++){const gr_transition *t=&e->transitions[i];
    if(t->from==state&&t->message==model){*next=t->to;*response=t->response;return 0;}
  }return -1;
}
static int gr_sequence(const gr_engine *e,const gr_record *records,size_t count,
                       char *err,size_t cap){
  if(!count)return gr_error(err,cap,"empty sequence cannot be validated");
  unsigned state=e->prefix_state;unsigned repeats[GR_MESSAGES];
  memcpy(repeats,e->prefix_repeats,sizeof(repeats));
  if(!e->prefix_valid)return gr_error(err,cap,"M1 prefix outside state graph");
  if(count>e->max_messages-e->prefix_count)return gr_error(err,cap,"max_messages exceeded with prefix");
  for(size_t i=0;i<count;i++){unsigned next;int response;unsigned model=records[i].model;
    if(++repeats[model]>e->max_repeat)return gr_error(err,cap,"max_repeat exceeded");
    if(gr_next(e,state,model,&next,&response)<0)return gr_error(err,cap,"sequence outside state graph");
    state=next; /* projected model outcome, not an observed target state */
  }return 0;
}
int gr_validate_framing(const gr_engine *e, const uint8_t *wire, size_t size,
                        const char *desc, char *err, size_t cap) {
  if (!e) return gr_error(err, cap, "missing generic engine for framing check");
  if (!wire || !size)
    return gr_error(err, cap, "invalid TCP framing for %s: empty or missing wire", desc ? desc : "message");
  if (!strcmp(e->transport, "tcp")) {
    const char *target_name = (desc && (strstr(desc, "example") || !strcmp(desc, "request") || !strcmp(desc, "response"))) ? "example" : "message";
    if (e->frame_offset > size || e->frame_width > size - e->frame_offset)
      return gr_error(err, cap, "invalid TCP framing for %s: length field outside %s",
                      desc ? desc : "message", target_name);
    uint64_t value = gr_integer(wire + e->frame_offset, e->frame_width, e->frame_little);
    __int128 framed = (__int128)value + e->frame_add;
    if (framed != (__int128)size)
      return gr_error(err, cap, "invalid TCP framing for %s: declared length differs from %s",
                      desc ? desc : "message", target_name);
  } else if (!strcmp(e->transport, "udp")) {
    if (size > GR_WIRE)
      return gr_error(err, cap, "UDP datagram for %s exceeds max wire budget (%zu > %u)",
                      desc ? desc : "message", size, GR_WIRE);
  }
  return 0;
}
static int gr_check_framing_grammar_consistency(const gr_engine *e, const nj_value *v,
                                                const char *mid, char *err, size_t cap) {
  if (!e || strcmp(e->transport, "tcp")) return 0;
  const nj_value *grammar = nj_get(v, "grammar");
  if (!grammar) return gr_error(err, cap, "missing grammar for %s", mid);
  const nj_value *fields = nj_get(grammar, "fields");
  if (!fields || fields->type != NJ_ARRAY)
    return gr_error(err, cap, "missing grammar fields for %s", mid);

  size_t cur_offset = 0;

  for (size_t i = 0; i < fields->count; i++) {
    const nj_value *f = fields->items[i];
    const nj_value *kind = nj_get(f, "kind");
    size_t field_len = 0;
    unsigned field_width = 0;
    int is_uint = 0;
    unsigned little = 0;

    if (nj_string_equal(kind, "uint")) {
      is_uint = 1;
      uint64_t w = 0;
      if (nj_u64(nj_get(f, "width"), &w, err, cap) < 0) return -1;
      field_width = (unsigned)w;
      field_len = field_width;
      if (nj_string_equal(nj_get(f, "byte_order"), "little")) little = 1;
      else if (!nj_string_equal(nj_get(f, "byte_order"), "big"))
        return gr_error(err, cap, "invalid byte_order for field in %s", mid);
    } else if (nj_string_equal(kind, "bytes")) {
      const nj_value *l = nj_get(f, "length");
      if (!l) return gr_error(err, cap, "missing bytes length in %s", mid);
      if (l->type == NJ_INTEGER) {
        uint64_t bl = 0;
        if (nj_u64(l, &bl, err, cap) < 0) return -1;
        field_len = (size_t)bl;
      } else {
        /* Variable length ("rest" or ref) */
        if (cur_offset <= e->frame_offset)
          return gr_error(err, cap, "variable-length field precedes TCP framing offset %u in %s",
                          e->frame_offset, mid);
        break;
      }
    } else {
      return gr_error(err, cap, "unknown field kind in %s", mid);
    }

    const nj_value *role = nj_get(f, "role");
    const nj_value *derived = nj_get(f, "derived");
    if (nj_string_equal(role, "derived") && derived) {
      if (nj_string_equal(nj_get(derived, "op"), "size_of") &&
          nj_string_equal(nj_get(derived, "target"), "$message")) {
        if (cur_offset != e->frame_offset) {
          return gr_error(err, cap, "message '%s': grammar derived rule offset %zu conflicts with global TCP framing offset %u",
                          mid, cur_offset, e->frame_offset);
        }
        if (!is_uint) {
          return gr_error(err, cap, "message '%s': derived TCP framing field must be uint", mid);
        }
        if (field_width != e->frame_width) {
          return gr_error(err, cap, "message '%s': TCP framing width %u conflicts with grammar field width %u",
                          mid, e->frame_width, field_width);
        }
        if (little != e->frame_little) {
          return gr_error(err, cap, "message '%s': TCP framing byte_order conflicts with grammar field", mid);
        }
        int64_t d_add = 0;
        if (nj_get(derived, "add") && nj_i64(nj_get(derived, "add"), &d_add, err, cap) < 0)
          return -1;
        if (d_add != -e->frame_add) {
          return gr_error(err, cap, "message '%s': grammar derived size_of add (%lld) conflicts with TCP framing add (%lld)",
                          mid, (long long)d_add, (long long)e->frame_add);
        }
      }
    }

    cur_offset += field_len;
  }

  return 0;
}
static int gr_unpack(gr_engine *e,const uint8_t *data,size_t length,
                     gr_record records[GR_RECORDS],size_t *count,char *err,size_t cap){
  size_t p=0,original=0;*count=0;
  if(!data||!length||length>e->max_bytes)return gr_error(err,cap,"empty or oversized replay records");
  while(p<length){
    if(length-p<4||*count>=e->max_messages||*count>=GR_RECORDS)return gr_error(err,cap,"truncated or excess replay record");
    size_t n=gr_get32(data+p);p+=4;
    if(!n||n>GR_WIRE||n>length-p)return gr_error(err,cap,"invalid replay length");
    gr_record *r=&records[(*count)++];r->wire=malloc(n);if(!r->wire)return gr_error(err,cap,"out of memory");
    memcpy(r->wire,data+p,n);r->size=n;r->original_offset=original;
    if(gr_validate_framing(e,r->wire,n,"replay message",err,cap)<0)return -1;
    if(gr_match(e,r->wire,n,0,&r->model,err,cap)<0)return -1;
    original+=n;p+=n;
  }
  if(!*count)return gr_error(err,cap,"empty replay records");
  return 0;
}
static int gr_pack(gr_engine *e,const gr_record *records,size_t count,
                   const uint8_t **out,size_t *length,char *err,size_t cap){
  if(!count)return gr_error(err,cap,"empty sequence cannot be packed");
  size_t n=0,available=e->max_bytes-e->prefix_bytes;for(size_t i=0;i<count;i++){
    if(!records[i].size||records[i].size>GR_WIRE||records[i].size>available-n||4>available-n-records[i].size)
      return gr_error(err,cap,"zero-length record or sequence exceeds max_bytes");
    n+=4+records[i].size;
  }uint8_t *p=realloc(e->output,n?n:1);if(!p)return gr_error(err,cap,"out of memory");
  e->output=p;e->output_size=n;size_t at=0;for(size_t i=0;i<count;i++){
    gr_put32(p+at,records[i].size);at+=4;memcpy(p+at,records[i].wire,records[i].size);at+=records[i].size;
  }*out=p;*length=n;return 0;
}
static int gr_message_load(gr_engine *e,const nj_value *v,unsigned i,char *err,size_t cap){
  static const char *required[]={"id","direction","weight","example_hex","grammar"};
  static const char *optional[]={"correlate"};gr_message *m=&e->messages[i];
  if(nj_keys(v,required,5,optional,1,err,cap)<0||
     gr_text(nj_get(v,"id"),m->id,sizeof(m->id),err,cap)<0||!m->id[0])
    return gr_error(err,cap,"invalid or duplicate message id");
  for(unsigned prior=0;prior<i;prior++)if(!strcmp(e->messages[prior].id,m->id))
    return gr_error(err,cap,"duplicate message id");
  const nj_value *d=nj_get(v,"direction");
  if(nj_string_equal(d,"response"))m->response=1;
  else if(!nj_string_equal(d,"request"))return gr_error(err,cap,"invalid message direction");
  if(gr_unsigned(nj_get(v,"weight"),1,1000,&m->weight,err,cap)<0||
     gr_hex(nj_get(v,"example_hex"),&m->example,&m->size,err,cap)<0)return -1;
  if(m->size==0)return gr_error(err,cap,"message example for %s cannot be zero-length",m->id);
  m->schema=gw_compile(nj_get(v,"grammar"),err,cap);if(!m->schema)return -1;
  gw_packet *zero_pkt=NULL;
  if(gw_parse(m->schema,NULL,0,&zero_pkt,NULL,0)==0){
    gw_packet_free(zero_pkt);
    return gr_error(err,cap,"message grammar for %s accepts zero-length wire message",m->id);
  }
  if(gr_check_framing_grammar_consistency(e,v,m->id,err,cap)<0)return -1;
  char detail[256];gw_packet *packet=NULL;
  int valid=gw_parse(m->schema,m->example,m->size,&packet,detail,sizeof(detail));gw_packet_free(packet);
  if(valid<0)return gr_error(err,cap,"invalid example for %s: %s",m->id,detail);
  if(!m->response&&m->size>e->max_bytes-4)
    return gr_error(err,cap,"request example for %s exceeds max_bytes including replay prefix",m->id);
  if(gr_validate_framing(e,m->example,m->size,m->id,err,cap)<0)return -1;
  return 0;
}

void gr_free(gr_engine *e){if(!e)return;for(unsigned i=0;i<e->count;i++){gw_free(e->messages[i].schema);free(e->messages[i].example);}
  free(e->receive);free(e->output);nj_free(e->document);free(e);
}
gr_engine *gr_load(const char *path,char *err,size_t cap){
  if(err&&cap)err[0]=0;
  gr_engine *e=calloc(1,sizeof(*e));if(!e){gr_error(err,cap,"out of memory");return NULL;}
  if(nj_load_file(path,&e->document,err,cap)<0)goto bad;
  const nj_value *root=e->document->root;
  static const char *required[]={"format","version","protocol_id","transport","online","framing","messages","states","limits"};
  static const char *optional[]={"unsupported","limitations"};unsigned version;uint64_t n;
  if(nj_keys(root,required,9,optional,2,err,cap)<0||
     !nj_string_equal(nj_get(root,"format"),"stateafl.generic-wire")||
     gr_unsigned(nj_get(root,"version"),1,1,&version,err,cap)<0||
     gr_text(nj_get(root,"protocol_id"),e->protocol_id,sizeof(e->protocol_id),err,cap)<0||
     !e->protocol_id[0]){gr_error(err,cap,"invalid generic-wire package header");goto bad;}
  int online=0;if(nj_boolean(nj_get(root,"online"),&online,err,cap)<0)goto bad;
  if(!online){gr_error(err,cap,"description is offline-only; required wire/session rules are not executable");goto bad;}
  if(gr_text(nj_get(root,"transport"),e->transport,sizeof(e->transport),err,cap)<0||
     (strcmp(e->transport,"udp")&&strcmp(e->transport,"tcp")))goto bad;
  const nj_value *fr=nj_get(root,"framing");
  if(!strcmp(e->transport,"udp")){
    static const char *r[]={"kind"};if(nj_keys(fr,r,1,NULL,0,err,cap)<0||
      !nj_string_equal(nj_get(fr,"kind"),"datagram"))goto bad;
  }else{
    static const char *r[]={"kind","offset","width","byte_order","add"};
    if(nj_keys(fr,r,5,NULL,0,err,cap)<0||
       !nj_string_equal(nj_get(fr,"kind"),"length_field")||
       gr_unsigned(nj_get(fr,"offset"),0,GR_WIRE,&e->frame_offset,err,cap)<0||
       gr_unsigned(nj_get(fr,"width"),1,4,&e->frame_width,err,cap)<0)goto bad;
    if(nj_string_equal(nj_get(fr,"byte_order"),"little"))e->frame_little=1;
    else if(!nj_string_equal(nj_get(fr,"byte_order"),"big"))goto bad;
    if(nj_i64(nj_get(fr,"add"),&e->frame_add,err,cap)<0||
       e->frame_offset+e->frame_width>GR_WIRE)goto bad;
  }
  const nj_value *lim=nj_get(root,"limits");static const char *lr[]={"max_messages","max_repeat","max_bytes"};
  if(nj_keys(lim,lr,3,NULL,0,err,cap)<0||
     gr_unsigned(nj_get(lim,"max_messages"),1,GR_RECORDS,&e->max_messages,err,cap)<0||
     gr_unsigned(nj_get(lim,"max_repeat"),1,GR_RECORDS,&e->max_repeat,err,cap)<0||
     nj_u64(nj_get(lim,"max_bytes"),&n,err,cap)<0||n<8||n>MAX_FILE)goto bad;
  e->max_bytes=(size_t)n;
  const nj_value *messages=nj_get(root,"messages");
  if(!messages||messages->type!=NJ_ARRAY||!messages->count||messages->count>GR_MESSAGES)goto bad;
  e->count=(unsigned)messages->count;for(unsigned i=0;i<e->count;i++)
    if(gr_message_load(e,messages->items[i],i,err,cap)<0)goto bad;
  /* Reject ambiguity at each declared example before accepting a package.
   * This finite check is not a proof that the grammars never overlap; gr_match
   * still rejects ambiguity for every actual request or response. */
  for(unsigned i=0;i<e->count;i++){
    gr_message *m=&e->messages[i];unsigned model;char detail[256];
    if(gr_match(e,m->example,m->size,m->response,&model,detail,sizeof(detail))<0){
      gr_error(err,cap,"example for %s cannot match uniquely: %s",m->id,detail);goto bad;
    }
    if(model!=i){gr_error(err,cap,"example for %s matched another message",m->id);goto bad;}
  }
  const nj_value *states=nj_get(root,"states");static const char *sr[]={"initial","transitions"};
  const nj_value *trs=nj_get(states,"transitions");
  if(nj_keys(states,sr,2,NULL,0,err,cap)<0||!trs||trs->type!=NJ_ARRAY||
     trs->count>GR_TRANSITIONS)goto bad;
  char initial[64];if(gr_text(nj_get(states,"initial"),initial,sizeof(initial),err,cap)<0||!initial[0])goto bad;
  for(size_t i=0;i<trs->count;i++){const nj_value *t=trs->items[i];static const char *r[]={"from","to","message"};
    static const char *o[]={"response"};char from[64],to[64],message[64],response[64];
    if(nj_keys(t,r,3,o,1,err,cap)<0||gr_text(nj_get(t,"from"),from,sizeof(from),err,cap)<0||
       gr_text(nj_get(t,"to"),to,sizeof(to),err,cap)<0||
       gr_text(nj_get(t,"message"),message,sizeof(message),err,cap)<0||!from[0]||!to[0])goto bad;
    int mi=gr_find_message(e,message);if(mi<0||e->messages[mi].response)goto bad;
    int ri=-1;if(nj_get(t,"response")){
      if(gr_text(nj_get(t,"response"),response,sizeof(response),err,cap)<0)goto bad;
      ri=gr_find_message(e,response);if(ri<0||!e->messages[ri].response)goto bad;
    }
    int fi=gr_find_state(e,from);if(fi<0){if(e->state_count>=GR_STATES)goto bad;
      fi=(int)e->state_count++;strcpy(e->states[fi],from);}
    int ti=gr_find_state(e,to);if(ti<0){if(e->state_count>=GR_STATES)goto bad;
      ti=(int)e->state_count++;strcpy(e->states[ti],to);}
    for(unsigned j=0;j<e->transition_count;j++)if(e->transitions[j].from==(unsigned)fi&&
      e->transitions[j].message==(unsigned)mi){gr_error(err,cap,"ambiguous transition");goto bad;}
    e->transitions[e->transition_count++]=(gr_transition){(unsigned)fi,(unsigned)ti,(unsigned)mi,ri};
  }
  int init=gr_find_state(e,initial);if(init<0)goto bad;e->initial=e->state=e->prefix_state=(unsigned)init;e->prefix_valid=1;
  for(unsigned i=0;i<e->count;i++){const nj_value *v=messages->items[i];const nj_value *cors=nj_get(v,"correlate");
    if(!cors)continue;if(!e->messages[i].response||cors->type!=NJ_ARRAY||cors->count>GR_CORRELATIONS)goto bad;
    for(size_t j=0;j<cors->count;j++){const nj_value *c=cors->items[j];static const char *r[]={"field","request","source"};
      gr_correlation *dst=&e->messages[i].correlations[j];char request[64];
      if(nj_keys(c,r,3,NULL,0,err,cap)<0||gr_text(nj_get(c,"field"),dst->field,sizeof(dst->field),err,cap)<0||
         gr_text(nj_get(c,"request"),request,sizeof(request),err,cap)<0||
         gr_text(nj_get(c,"source"),dst->source,sizeof(dst->source),err,cap)<0)goto bad;
      int mi=gr_find_message(e,request);if(mi<0||e->messages[mi].response)goto bad;dst->request=(unsigned)mi;
      gw_packet *rp=NULL,*sp=NULL;int ok=gw_parse(e->messages[i].schema,e->messages[i].example,e->messages[i].size,&rp,err,cap)==0&&
        gw_parse(e->messages[mi].schema,e->messages[mi].example,e->messages[mi].size,&sp,err,cap)==0;
      uint64_t a,b;if(ok)ok=gw_get_u64(rp,dst->field,&a)==0&&gw_get_u64(sp,dst->source,&b)==0;
      gw_packet_free(rp);gw_packet_free(sp);if(!ok)goto bad;
    }e->messages[i].correlation_count=cors->count;
  }
  /* Rules are scoped to a request/response pair even when response grammars
   * are shared. Do not silently ignore orphan rules or uncovered pairs. */
  for(unsigned i=0;i<e->count;i++)for(size_t j=0;j<e->messages[i].correlation_count;j++){
    int used=0;for(unsigned k=0;k<e->transition_count;k++)
      if(e->transitions[k].response==(int)i&&e->transitions[k].message==e->messages[i].correlations[j].request)used=1;
    if(!used){gr_error(err,cap,"correlation has no request/response transition");goto bad;}
  }
  for(unsigned i=0;i<e->transition_count;i++)if(e->transitions[i].response>=0){
    gr_transition *t=&e->transitions[i];gr_message *m=&e->messages[t->response];int found=0;
    for(size_t j=0;j<m->correlation_count;j++)if(m->correlations[j].request==t->message)found=1;
    if(m->correlation_count&&!found){gr_error(err,cap,"transition lacks request correlation");goto bad;}
  }
  e->receive=malloc(MAX_FILE);if(!e->receive){gr_error(err,cap,"out of memory");goto bad;}
  return e;
bad:if(err&&cap&&!err[0])gr_error(err,cap,"invalid generic-wire package or reference");gr_free(e);return NULL;
}
const char *gr_transport(const gr_engine *e){return e?e->transport:NULL;}
void gr_set_log(gr_engine *e,FILE *log){if(e)e->log=log;}
void gr_session_begin(gr_engine *e){if(e){e->state=e->initial;e->receive_size=0;e->pending=0;memset(e->cache,0,sizeof(e->cache));}}
int gr_set_prefix(gr_engine *e,const uint8_t *records,size_t length,char *err,size_t cap){
  if(err&&cap)err[0]=0;
  if(!e)return gr_error(err,cap,"missing generic engine");e->prefix_state=e->initial;e->prefix_valid=0;
  e->prefix_count=e->prefix_bytes=0;memset(e->prefix_repeats,0,sizeof(e->prefix_repeats));
  if(!length){e->prefix_valid=1;return 0;}
  gr_record rr[GR_RECORDS]={0};size_t count=0;int result=gr_unpack(e,records,length,rr,&count,err,cap);
  if(result<0)goto done;for(size_t i=0;i<count;i++){unsigned next;int response;
    if(++e->prefix_repeats[rr[i].model]>e->max_repeat){result=gr_error(err,cap,"M1 max_repeat exceeded");break;}
    if(gr_next(e,e->prefix_state,rr[i].model,&next,&response)<0){result=gr_error(err,cap,"M1 outside state graph");break;}
    e->prefix_state=next; /* predicted only; no response value is invented */
  }if(result==0){e->prefix_valid=1;e->prefix_count=count;e->prefix_bytes=length;}
done:gr_records_free(rr,count);return result;
}
int gr_validate_sequence(const gr_engine *e,
                         const uint8_t *m1, size_t m1_len,
                         const uint8_t *m2, size_t m2_len,
                         const uint8_t *m3, size_t m3_len,
                         char *err, size_t cap) {
  if (err && cap) err[0] = 0;
  if (!e) return gr_error(err, cap, "missing generic engine");
  if (!m2 || !m2_len) return gr_error(err, cap, "M2 candidate record sequence cannot be empty");

  const uint8_t *segs[3] = {m1, m2, m3};
  size_t lens[3] = {m1_len, m2_len, m3_len};
  const char *seg_names[3] = {"M1", "M2", "M3"};

  size_t total_messages = 0;
  size_t total_replay_bytes = 0;
  unsigned repeats[GR_MESSAGES] = {0};
  unsigned state = e->initial;

  for (int s = 0; s < 3; s++) {
    const uint8_t *buf = segs[s];
    size_t len = lens[s];
    if (!len) continue;

    size_t p = 0;
    while (p < len) {
      if (len - p < 4)
        return gr_error(err, cap, "%s truncated replay record", seg_names[s]);
      size_t n = gr_get32(buf + p);
      p += 4;
      if (!n || n > GR_WIRE || n > len - p)
        return gr_error(err, cap, "%s invalid replay length", seg_names[s]);

      total_messages++;
      total_replay_bytes += 4 + n;

      if (total_messages > e->max_messages)
        return gr_error(err, cap, "max_messages exceeded across sequence (%zu > %u)",
                        total_messages, e->max_messages);

      if (total_replay_bytes > e->max_bytes)
        return gr_error(err, cap, "max_bytes exceeded across sequence (%zu > %zu)",
                        total_replay_bytes, e->max_bytes);

      if (gr_validate_framing(e, buf + p, n, seg_names[s], err, cap) < 0)
        return -1;

      unsigned model = 0;
      if (gr_match(e, buf + p, n, 0, &model, err, cap) < 0)
        return gr_error(err, cap, "%s message outside description grammar", seg_names[s]);

      if (++repeats[model] > e->max_repeat)
        return gr_error(err, cap, "max_repeat exceeded across sequence for message %s (%u > %u)",
                        e->messages[model].id, repeats[model], e->max_repeat);

      unsigned next = 0;
      int response = 0;
      if (gr_next(e, state, model, &next, &response) < 0)
        return gr_error(err, cap, "%s sequence outside state graph", seg_names[s]);

      state = next;
      p += n;
    }
  }

  if (!total_messages)
    return gr_error(err, cap, "empty sequence across M1/M2/M3");

  return 0;
}
static void gr_log_rejection(gr_engine *e,int layer,const char *reason){
  e->errors++;if(e->log){fprintf(e->log,"{\"event\":\"rejected\",\"layer_id\":%d,\"reason\":",layer);
    const char *text=reason?reason:"unknown";nj_write_string(e->log,text,strlen(text));fputs("}\n",e->log);}
}
int gr_mutate(gr_engine *e,const uint8_t *data,size_t length,const uint8_t *candidate,size_t cn,
              int mode,int layer,proto_random random,const uint8_t **out,size_t *out_length,
              char *err,size_t cap){
  gr_record rr[GR_RECORDS]={0};size_t count=0,selected=0,before=0;int status=-1;
  if(out)*out=NULL;if(out_length)*out_length=0;if(err&&cap)err[0]=0;
  if(!e||!out||!out_length||!random||(!candidate&&cn)||cn>MAX_FILE||
     mode!=PROTO_VALID||
     (layer!=PROTO_HEAD&&layer!=PROTO_CONTENT&&layer!=PROTO_SEQUENCE))
    return gr_error(err,cap,"generic-wire structured calls require valid mode and HEAD/CONTENT/SEQUENCE");
  e->attempts++;if(gr_unpack(e,data,length,rr,&count,err,cap)<0)goto done;before=count;
  unsigned total=0;for(size_t i=0;i<count;i++)total+=e->messages[rr[i].model].weight;
  unsigned pick=gr_draw(random,total);for(selected=0;selected+1<count;selected++){
    unsigned w=e->messages[rr[selected].model].weight;if(pick<w)break;pick-=w;
  }
  if(layer==PROTO_SEQUENCE){
    unsigned op=gr_draw(random,4);
    if(op==1){ /* delete */
      if(count<=1){gr_error(err,cap,"cannot delete only request");goto done;}
      free(rr[selected].wire);memmove(rr+selected,rr+selected+1,(count-selected-1)*sizeof(*rr));
      rr[--count]=(gr_record){0};
    }else if(op==3){ /* reorder */
      if(count<=1){gr_error(err,cap,"reorder requires two requests");goto done;}
      size_t other=gr_draw(random,(uint32_t)count-1);if(other>=selected)other++;
      gr_record tmp=rr[selected];rr[selected]=rr[other];rr[other]=tmp;
    }else{ /* insert template or repeat */
      if(count>=e->max_messages||count>=GR_RECORDS){gr_error(err,cap,"max_messages exceeded");goto done;}
      unsigned model=rr[selected].model;const uint8_t *wire=rr[selected].wire;size_t n=rr[selected].size;
      if(op==0){unsigned choices[GR_MESSAGES],eligible=0;for(unsigned i=0;i<e->count;i++)
        if(!e->messages[i].response)choices[eligible++]=i;
        if(!eligible){gr_error(err,cap,"no request template");goto done;}
        model=choices[gr_draw(random,eligible)];wire=e->messages[model].example;n=e->messages[model].size;
      }
      if(!n||n>GR_WIRE){gr_error(err,cap,"zero-length template or record cannot be inserted");goto done;}
      uint8_t *copy=malloc(n);if(!copy){gr_error(err,cap,"out of memory");goto done;}
      memcpy(copy,wire,n);size_t at=gr_draw(random,(uint32_t)count+1);
      memmove(rr+at+1,rr+at,(count-at)*sizeof(*rr));
      rr[at]=(gr_record){copy,n,0,model};count++;
    }
  }else{
    gr_record *r=&rr[selected];gw_packet *packet=NULL;uint8_t *encoded=malloc(GR_WIRE);size_t n=0;
    if(!encoded){gr_error(err,cap,"out of memory");goto done;}
    if(gw_parse(e->messages[r->model].schema,r->wire,r->size,&packet,err,cap)<0){free(encoded);goto done;}
    const uint8_t *projection=NULL;size_t projection_length=0;
    if(candidate&&r->original_offset<=cn){projection=candidate+r->original_offset;
      projection_length=cn-r->original_offset;
      if(selected+1<before&&projection_length>r->size)projection_length=r->size;
    }
    if(gw_mutate(packet,layer,projection,projection_length,random,err,cap)<0||
       gw_encode(packet,encoded,GR_WIRE,&n,err,cap)<0||!n||n>GR_WIRE){
      gw_packet_free(packet);free(encoded);goto done;
    }
    gw_packet_free(packet);free(r->wire);r->wire=encoded;r->size=n;
  }
  if(gr_sequence(e,rr,count,err,cap)<0)goto done;
  for(size_t i=0;i<count;i++){
    if(!rr[i].size){gr_error(err,cap,"zero-length record in mutated sequence");goto done;}
    unsigned model;
    if(gr_match(e,rr[i].wire,rr[i].size,0,&model,err,cap)<0||model!=rr[i].model){
      gr_error(err,cap,"mutation changed message family");goto done;
    }
    if(gr_validate_framing(e,rr[i].wire,rr[i].size,e->messages[model].id,err,cap)<0)goto done;
  }
  if(gr_pack(e,rr,count,out,out_length,err,cap)<0)goto done;
  e->success++;e->layer_count[layer==PROTO_HEAD?0:layer==PROTO_CONTENT?1:2]++;status=0;
  if(e->log)fprintf(e->log,"{\"event\":\"mutation\",\"layer\":\"%s\",\"messages_before\":%zu,\"messages_after\":%zu,\"derived_repaired\":true}\n",
    layer==PROTO_HEAD?"HEAD":layer==PROTO_CONTENT?"CONTENT":"SEQUENCE",before,count);
done:if(status<0)gr_log_rejection(e,layer,err&&cap?err:"mutation failed");gr_records_free(rr,count);return status;
}
int gr_before_send(gr_engine *e,uint8_t *wire,size_t length,char *err,size_t cap){
  unsigned model,next;int response;if(err&&cap)err[0]=0;
  if(!e||!wire||!length||length>GR_WIRE)
    return gr_error(err,cap,"invalid wire length in generic before_send");
  if(gr_validate_framing(e,wire,length,"request",err,cap)<0)return -1;
  if(gr_match(e,wire,length,0,&model,err,cap)<0)
    return gr_error(err,cap,"request not accepted by generic-wire grammar");
  if(gr_next(e,e->state,model,&next,&response)<0)return gr_error(err,cap,"request outside current semantic state");
  if(e->pending)return gr_error(err,cap,"generic-wire permits one outstanding request per session");
  if(response>=0){
    gr_message *rm=&e->messages[response];gw_packet *packet=NULL;
    if(gw_parse(e->messages[model].schema,wire,length,&packet,err,cap)<0)return -1;
    uint64_t values[GR_CORRELATIONS]={0};
    for(size_t i=0;i<rm->correlation_count;i++){
      if(rm->correlations[i].request!=model)continue;
      if(gw_get_u64(packet,rm->correlations[i].source,&values[i])<0){
        gw_packet_free(packet);return gr_error(err,cap,"request correlation field absent");
      }
    }
    gw_packet_free(packet);
    memcpy(e->cache,values,sizeof(values));e->pending=1;e->pending_request=model;
    e->pending_response=(unsigned)response;e->pending_next=next;
  }else e->state=next;
  return 0;
}
static void gr_response_frame(gr_engine *e,const uint8_t *wire,size_t length){
  unsigned model;char err[128];if(gr_match(e,wire,length,1,&model,err,sizeof(err))<0)return;
  e->responses++;gr_message *m=&e->messages[model];gw_packet *packet=NULL;
  if(gw_parse(m->schema,wire,length,&packet,err,sizeof(err))<0)return;
  if(e->pending&&e->pending_response==model){
    int fits=1,checked=0;for(size_t j=0;j<m->correlation_count;j++){gr_correlation *c=&m->correlations[j];
      if(c->request!=e->pending_request)continue;
      checked=1;
      uint64_t observed;if(gw_get_u64(packet,c->field,&observed)<0||
         observed!=e->cache[j]){fits=0;break;}
    }
    if(fits){e->pending=0;e->state=e->pending_next;e->completed++;if(checked)e->correlated++;}
  }gw_packet_free(packet);
}
void gr_after_response(gr_engine *e,const uint8_t *wire,size_t length){
  if(!e||!wire||!length)return;
  if(!strcmp(e->transport,"udp")){if(length<=GR_WIRE)gr_response_frame(e,wire,length);return;}
  if(length>MAX_FILE-e->receive_size){e->receive_size=0;return;}
  memcpy(e->receive+e->receive_size,wire,length);e->receive_size+=length;size_t at=0;
  while(e->receive_size-at>=e->frame_offset+e->frame_width){
    const uint8_t *b=e->receive+at;uint64_t field=gr_integer(b+e->frame_offset,e->frame_width,e->frame_little);
    __int128 n=(__int128)field+e->frame_add;
    if(n<=0||n>GR_WIRE||n<e->frame_offset+e->frame_width){e->receive_size=0;return;}
    if((size_t)n>e->receive_size-at)break;gr_response_frame(e,b,(size_t)n);at+=(size_t)n;
  }if(at){memmove(e->receive,e->receive+at,e->receive_size-at);e->receive_size-=at;}
}
void gr_write_stats(gr_engine *e,const char *path){
  if(!e||!path)return;FILE *f=fopen(path,"w");if(!f)return;
  fprintf(f,"{\"stats_version\":2,\"attempts\":%" PRIu64 ",\"structured_success\":%" PRIu64 ",\"rejected\":%" PRIu64 ",\"HEAD\":%" PRIu64 ",\"CONTENT\":%" PRIu64 ",\"SEQUENCE\":%" PRIu64 ",\"responses\":%" PRIu64 ",\"completed_responses\":%" PRIu64 ",\"correlated_responses\":%" PRIu64 ",\"protocol_semantic_state\":",
    e->attempts,e->success,e->errors,e->layer_count[0],e->layer_count[1],e->layer_count[2],
    e->responses,e->completed,e->correlated);nj_write_string(f,e->states[e->state],strlen(e->states[e->state]));
  fputs(",\"engine\":\"generic-wire\"}\n",f);fclose(f);
}
