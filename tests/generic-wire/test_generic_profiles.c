/* Native grammar roundtrip for all six declared generic-wire profile subsets. */
#include "generic_wire.h"
#include "native_json.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
static int digit(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int hex(const nj_value *v,unsigned char **b,size_t *n){
  if(!v||v->type!=NJ_STRING||!v->text_length||v->text_length%2)return -1;
  *n=v->text_length/2;*b=malloc(*n);if(!*b)return -1;
  for(size_t i=0;i<*n;i++){int a=digit(v->text[i*2]),z=digit(v->text[i*2+1]);
    if(a<0||z<0){free(*b);*b=NULL;return -1;}(*b)[i]=(unsigned char)(a*16+z);
  }return 0;
}
int main(int argc,char **argv){
  static const char *names[]={"bacnet_ip","ethernet_ip_cip_tcp","iec60870_5_104",
    "iec61850_mms_tcp","modbus_tcp","opcua_tcp"};
  CHECK(argc==7);unsigned messages=0,seen=0;
  for(int a=1;a<argc;a++){nj_document *doc=NULL;char err[512]={0};
    CHECK(nj_load_file(argv[a],&doc,err,sizeof(err))==0);
    CHECK(nj_string_equal(nj_get(doc->root,"format"),"stateafl.generic-wire"));
    unsigned profile=0;for(;profile<6;profile++)
      if(nj_string_equal(nj_get(doc->root,"protocol_id"),names[profile]))break;
    CHECK(profile<6);CHECK(!(seen&(1u<<profile)));seen|=1u<<profile;
    int online=-1;CHECK(nj_boolean(nj_get(doc->root,"online"),&online,err,sizeof(err))==0);
    CHECK(online==!strcmp(names[profile],"modbus_tcp"));
    const nj_value *mm=nj_get(doc->root,"messages");
    CHECK(mm&&mm->type==NJ_ARRAY&&mm->count>0);
    for(size_t i=0;i<mm->count;i++){const nj_value *m=mm->items[i];
      unsigned char *wire=NULL,*encoded=NULL;size_t n=0,out_n=0;gw_packet *packet=NULL;
      gw_schema *schema=gw_compile(nj_get(m,"grammar"),err,sizeof(err));
      if(!schema)fprintf(stderr,"%s message %zu compile: %s\n",argv[a],i,err);
      CHECK(schema!=NULL);CHECK(hex(nj_get(m,"example_hex"),&wire,&n)==0);
      CHECK(gw_parse(schema,wire,n,&packet,err,sizeof(err))==0);
      encoded=malloc(n+1);CHECK(encoded!=NULL);
      CHECK(gw_encode(packet,encoded,n+1,&out_n,err,sizeof(err))==0);
      CHECK(out_n==n&&!memcmp(wire,encoded,n));
      const nj_value *fields=nj_get(nj_get(m,"grammar"),"fields");
      for(size_t f=0;f<fields->count;f++){
        const nj_value *field=fields->items[f];char id[64];size_t at=0,width=0;
        CHECK(nj_string_copy(nj_get(field,"id"),id,sizeof(id),err,sizeof(err))==0);
        CHECK(gw_field_range(packet,id,&at,&width)==0&&at+width<=n);
        /* Violate every fixed/derived constraint, including fixed byte slices
         * after the first field, and require a clean parse rejection. */
        if(width&&(nj_get(field,"expected")||nj_get(field,"expected_hex")||
                   nj_get(field,"derived"))){
          gw_packet *invalid=NULL;wire[at]^=1;
          CHECK(gw_parse(schema,wire,n,&invalid,err,sizeof(err))<0);
          CHECK(invalid==NULL);wire[at]^=1;
        }
        if(nj_string_equal(nj_get(field,"kind"),"uint")&&
           (nj_string_equal(nj_get(field,"role"),"head")||
            nj_string_equal(nj_get(field,"role"),"content"))&&
           !nj_get(field,"expected")){
          uint64_t original=0,bound=0;
          CHECK(gw_get_u64(packet,id,&original)==0);
          const char *bounds[]={"min","max"};
          for(unsigned b=0;b<2;b++){
            CHECK(nj_u64(nj_get(field,bounds[b]),&bound,err,sizeof(err))==0);
            CHECK(gw_set_u64(packet,id,bound,err,sizeof(err))==0);
            CHECK(gw_encode(packet,encoded,n+1,&out_n,err,sizeof(err))==0);
            CHECK(out_n==n);
            gw_packet *changed=NULL;
            CHECK(gw_parse(schema,encoded,out_n,&changed,err,sizeof(err))==0);
            uint64_t observed=0;CHECK(gw_get_u64(changed,id,&observed)==0&&observed==bound);
            gw_packet_free(changed);
          }
          CHECK(gw_set_u64(packet,id,original,err,sizeof(err))==0);
        }
      }
      CHECK(gw_encode(packet,encoded,n+1,&out_n,err,sizeof(err))==0);
      CHECK(out_n==n&&!memcmp(wire,encoded,n));
      gw_packet_free(packet);packet=NULL;
      CHECK(gw_parse(schema,wire,n-1,&packet,err,sizeof(err))<0&&packet==NULL);
      memcpy(encoded,wire,n);encoded[n]=0;
      CHECK(gw_parse(schema,encoded,n+1,&packet,err,sizeof(err))<0&&packet==NULL);
      free(encoded);free(wire);gw_free(schema);messages++;
    }nj_free(doc);
  }CHECK(seen==63);
  printf("PASS: six generic-wire subsets, %u roundtrips, scalar bounds and malformed-wire rejection (%u checks)\n",messages,checks);
  return 0;
}
