#!/usr/bin/env python3
"""Independent bounded fixture readers for the six declared protocol profiles.

Checks complete envelopes, nested bodies and protocol-specific constraints.
Not a general codec or a claim of whole-standard conformance.
"""
import struct

class Reader:
 def __init__(self,b):self.b=b;self.pos=0
 def get(self,n):
  if n<0 or self.pos+n>len(self.b):raise ValueError('truncated UA Binary')
  b=self.b[self.pos:self.pos+n];self.pos+=n;return b
 def number(self,fmt):return struct.unpack('<'+fmt,self.get(struct.calcsize('<'+fmt)))[0]
 def u8(self):return self.number('B')
 def u16(self):return self.number('H')
 def u32(self):return self.number('I')
 def i32(self):return self.number('i')
 def i64(self):return self.number('q')
 def blob(self):
  n=self.i32()
  if n == -1:return None
  if n<0 or n>1048576:raise ValueError('invalid UA ByteString length')
  return self.get(n)
 def string(self):
  b=self.blob();return None if b is None else b.decode('utf-8')
 def array(self,fn):
  n=self.i32()
  if n == -1:return None
  if n<0 or n>64:raise ValueError('array outside bounded profile')
  return [fn() for _ in range(n)]
 def nodeid(self):
  tag=self.u8()
  if tag==0:return (0,self.u8())
  if tag==1:return (self.u8(),self.u16())
  if tag==2:return (self.u16(),self.u32())
  if tag==3:return (self.u16(),self.string())
  if tag==4:return (self.u16(),self.get(16))
  if tag==5:return (self.u16(),self.blob())
  raise ValueError('NodeId encoding outside profile')
 def extension(self):
  nodeid=self.nodeid();enc=self.u8()
  if enc==0:return (nodeid,None)
  if enc in (1,2):return (nodeid,self.blob())
  raise ValueError('bad ExtensionObject encoding')
 def diagnostic(self,depth=0):
  if depth>8:raise ValueError('diagnostic too deep')
  bits=self.u8()
  if bits&128:raise ValueError('unknown DiagnosticInfo flag')
  values={}
  for bit,name in [(1,'symbolic'),(2,'namespace'),(4,'localized'),(8,'locale')]:
   if bits&bit:values[name]=self.i32()
  if bits&16:values['info']=self.string()
  if bits&32:values['status']=self.u32()
  if bits&64:values['inner']=self.diagnostic(depth+1)
  return values
 def localized_text(self):
  bits=self.u8()
  if bits&~3:raise ValueError('bad LocalizedText mask')
  return (self.string() if bits&1 else None,self.string() if bits&2 else None)
 def request_header(self):
  out=dict(auth_token=self.nodeid(),timestamp=self.i64(),request_handle=self.u32(),return_diagnostics=self.u32(),audit=self.string(),timeout=self.u32(),additional=self.extension())
  if out['auth_token']!=(0,0):raise ValueError('discovery profile auth token must be null')
  return out
 def response_header(self):
  return dict(timestamp=self.i64(),request_handle=self.u32(),service_result=self.u32(),diagnostics=self.diagnostic(),string_table=self.array(self.string),additional=self.extension())
 def application(self):
  return dict(uri=self.string(),product=self.string(),name=self.localized_text(),type=self.u32(),gateway=self.string(),profile=self.string(),discovery_urls=self.array(self.string))
 def user_token_policy(self):
  return dict(policy=self.string(),type=self.u32(),issued=self.string(),issuer=self.string(),security_uri=self.string())
 def endpoint(self):
  return dict(url=self.string(),server=self.application(),certificate=self.blob(),mode=self.u32(),security_uri=self.string(),tokens=self.array(self.user_token_policy),transport_uri=self.string(),level=self.u8())

def validate_ua_fixture(raw):
 r=Reader(raw);typ=r.get(3).decode('ascii');final=r.get(1)
 if final!=b'F' or r.u32()!=len(raw):raise ValueError('UA framing')
 out={'type':typ}
 if typ in ('HEL','ACK'):
  out.update(zip(('protocol','receive','send','max_message','max_chunks'),[r.u32() for _ in range(5)]))
  if typ=='HEL':out['endpoint']=r.string()
  if out['protocol']!=0 or out['receive']<8192 or out['send']<8192:raise ValueError('UA negotiation')
 elif typ=='ERR':out.update(error=r.u32(),reason=r.string())
 elif typ=='RHE':out.update(server_uri=r.string(),endpoint=r.string())
 elif typ in ('OPN','MSG','CLO'):
  out['channel']=r.u32()
  if typ=='OPN':
   out.update(policy=r.string(),sender_certificate=r.blob(),receiver_thumbprint=r.blob())
   if out['policy']!='http://opcfoundation.org/UA/SecurityPolicy#None' or out['sender_certificate'] is not None or out['receiver_thumbprint'] is not None:raise ValueError('outside None profile')
  else:out['token']=r.u32()
  out.update(sequence=r.u32(),request_id=r.u32(),type_id=r.nodeid())
  service=out['type_id']
  if service not in [(0,446),(0,449),(0,428),(0,431),(0,397),(0,452)]:raise ValueError('unknown service in bounded profile')
  if service in [(0,446),(0,428),(0,452)]:out['header']=r.request_header()
  else:out['header']=r.response_header()
  if service==(0,446):
   out.update(protocol=r.u32(),request_type=r.u32(),mode=r.u32(),nonce=r.blob(),lifetime=r.u32())
   if typ!='OPN' or out['mode']!=1 or out['nonce'] is not None or out['request_type'] not in (0,1):raise ValueError('OPN request')
  elif service==(0,449):
   out.update(protocol=r.u32(),channel_id=r.u32(),token_id=r.u32(),created=r.i64(),lifetime=r.u32(),nonce=r.blob())
   if typ!='OPN' or out['channel_id']!=out['channel'] or not out['token_id'] or out['lifetime']<=0 or out['nonce'] is not None:raise ValueError('OPN response')
  elif service==(0,428):
   out.update(endpoint=r.string(),locales=r.array(r.string),profiles=r.array(r.string))
   if typ!='MSG':raise ValueError('GetEndpoints request')
  elif service==(0,431):
   out['endpoints']=r.array(r.endpoint)
   if typ!='MSG':raise ValueError('GetEndpoints response')
  elif service==(0,397):
   if typ!='MSG' or not out['header']['service_result']&0x80000000:raise ValueError('ServiceFault')
  elif service==(0,452):
   if typ!='CLO':raise ValueError('CloseSecureChannel request')
 else:raise ValueError('unknown UA type')
 if r.pos!=len(raw):raise ValueError('trailing UA Binary fields')
 return out

def validate_ua(mid, raw):
 """Validate one complete fixture and return its semantic fields.

 This bounded profile accepts None security, F chunks and six binary service
 encoding IDs. It supports both the catalogue's historical ``message`` ID and
 the explicit ``get_endpoints`` alias. No socket is opened.
 """
 out=validate_ua_fixture(raw)
 expected={
  'hello':('HEL',None),'ack':('ACK',None),'error':('ERR',None),
  'reverse_hello':('RHE',None),'open_channel':('OPN',(0,446)),
  'open_channel_response':('OPN',(0,449)),
  'message':('MSG',(0,428)),'get_endpoints':('MSG',(0,428)),
  'message_response':('MSG',(0,431)),'get_endpoints_response':('MSG',(0,431)),
  'service_fault':('MSG',(0,397)),'close_channel':('CLO',(0,452)),
 }
 if mid not in expected:raise ValueError('unknown UA fixture ID')
 typ,node=expected[mid]
 if out['type']!=typ or (node is not None and out.get('type_id')!=node):raise ValueError('fixture ID and wire type disagree')
 if 'header' in out:
  hdr=out['header']
  if hdr['additional']!=((0,0),None):raise ValueError('nonempty AdditionalHeader outside profile')
  if hdr.get('diagnostics') or hdr.get('string_table'):raise ValueError('nonempty diagnostics outside profile')
 if typ=='OPN':
  if out['protocol']!=0:raise ValueError('protocol mismatch')
  if node==(0,446) and out['request_type']==0 and out['channel']!=0:raise ValueError('Issue requires channel zero')
  if node==(0,449) and (out['header']['service_result']!=0 or not out['channel']):raise ValueError('not a successful OPN response')
 if typ in ('MSG','CLO') and (not out['channel'] or not out['token']):raise ValueError('missing channel/token binding')
 if typ in ('HEL','RHE'):
  for key in ['endpoint']+(['server_uri'] if typ=='RHE' else []):
   v=out[key]
   if v is None or len(v.encode('utf-8'))+4>=4096:raise ValueError('transport String outside profile')
 return out



import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from proto_spec_compiler import load,validate


def need(ok,message):
    if not ok:raise ValueError(message)


def ber(data):
    """Decode a complete definite BER sequence and every constructed subtree."""
    result=[];p=0
    while p<len(data):
        tag=data[p];p+=1
        need(tag&31!=31,'high-tag-number BER outside fixture profile')
        need(p<len(data),'missing BER length');n=data[p];p+=1
        if n&128:
            width=n&127;need(0<width<=4 and p+width<=len(data),'invalid BER length')
            n=int.from_bytes(data[p:p+width],'big');p+=width
        need(p+n<=len(data),'truncated BER content');value=data[p:p+n];p+=n
        children=ber(value) if tag&32 else []
        if tag==2:need(0<len(value)<=5,'invalid BER integer')
        result.append((tag,value,children))
    return result


def child(node,tag):
    values=[n for n in node[2] if n[0]==tag]
    need(len(values)==1,f'expected exactly one BER tag {tag:02x}')
    return values[0]


def integer(node):return int.from_bytes(node[1],'big')


def validate_mms(mid,raw):
    need(raw[:2]==b'\x03\x00' and int.from_bytes(raw[2:4],'big')==len(raw),'TPKT')
    li=raw[4];need(5+li<=len(raw),'COTP LI')
    if mid in {'cotp_cr','cotp_cc'}:
        need(raw[5]==(0xe0 if mid=='cotp_cr' else 0xd0) and 5+li==len(raw),'COTP connection')
        need(raw[10]==0,'COTP class0');p=11;params={}
        while p<len(raw):
            tag,n=raw[p:p+2];p+=2;need(p+n<=len(raw),'COTP TLV');params[tag]=raw[p:p+n];p+=n
        need(params[0xc0]==b'\x0d' and params[0xc1]==params[0xc2]==b'\x00\x01','COTP parameters')
        return dict(type=raw[5])
    need(raw[4:7]==b'\x02\xf0\x80','complete COTP data')
    if raw[7:11]==b'\x01\x00\x01\x00':presentation=raw[11:]
    else:
        need(raw[7] in {13,14,9,10} and raw[8]+9==len(raw),'session SPDU length')
        p=9;params={}
        while p<len(raw):
            tag,n=raw[p:p+2];p+=2;need(p+n<=len(raw),'session parameter length');params[tag]=raw[p:p+n];p+=n
        need(0xc1 in params,'missing presentation user data');presentation=params[0xc1]
        if raw[7] in {13,14}:need(params[5]==bytes.fromhex('130100160102') and params[0x14]==b'\x00\x02','session negotiation')
    tree=ber(presentation);need(len(tree)==1,'single presentation PDU');root=tree[0]
    response=mid.endswith('_response')
    if mid in {'associate','associate_response'}:
        need(root[0]==0x31,'CP/CPA SET');need(child(child(root,0xa0),0x80)[1]==b'\x01','normal mode')
        normal=child(root,0xa2);data=child(normal,0x61)
        pdv=child(data,0x30);need(integer(child(pdv,2))==1,'ACSE context ID')
        acse=child(child(pdv,0xa0),0x61 if response else 0x60)
        need(child(child(acse,0xa1),6)[1]==bytes.fromhex('28ca220203'),'MMS application context OID')
        if response:need(integer(child(child(acse,0xa2),2))==0,'AARE accepted')
        external=child(child(acse,0xbe),0x28);need(integer(child(external,2))==3,'MMS indirect reference')
        initiate=child(child(external,0xa0),0xa9 if response else 0xa8)
        need(all(child(initiate,t) for t in (0x80,0x81,0x82,0x83,0xa4)),'complete initiate')
        detail=child(initiate,0xa4)
        for t in (0x81,0x82):
            bits=child(detail,t)[1];need(len(bits)>1 and bits[0]<8,'BIT STRING unused-bits octet')
            need(not bits[0] or not bits[-1]&((1<<bits[0])-1),'BIT STRING padding')
        return dict(associated=response)
    need(root[0]==0x61,'fully-encoded-data presentation')
    pdv=child(root,0x30);context=integer(child(pdv,2));payload=child(pdv,0xa0)
    need(len(payload[2])==1,'single presentation payload');mms=payload[2][0]
    if mid.startswith('release'):
        need(context==1 and mms[0]==(0x63 if response else 0x62),'ACSE release')
        if not response:need(child(mms,0x80)[1]==b'\0','release reason')
        return dict(released=response)
    need(context==3,'MMS presentation context')
    if mid.startswith('conclude'):
        need(mms[0]==(0x8c if response else 0x8b) and not mms[1],'complete MMS conclude')
        return dict(concluded=response)
    need(mms[0]==(0xa1 if response else 0xa0),'confirmed PDU direction')
    invoke=integer(child(mms,2));base=mid.removesuffix('_response');service=child(mms,{'get_name_list':0xa1,'read':0xa4,'write':0xa5}[base])
    if base=='get_name_list':
        if response:
            identifiers=child(service,0xa0);need(all(n[0]==0x1a for n in identifiers[2]),'identifiers VisibleString');need(child(service,0x81)[1] in {b'\0',b'\xff'},'more follows BOOLEAN')
        else:need(child(child(service,0xa0),0x80)[1]==b'\x09' and child(child(service,0xa1),0x80)[1]==b'','domain-class VMD scope')
    elif not response:
        access=child(service,0xa1) if base=='read' else service
        variables=child(access,0xa0) if base=='read' else service[2][0];need(variables[0]==0xa0 and len(variables[2])==1,'one reference variable')
        name=child(child(variables[2][0],0xa0),0xa1)
        need(len(name[2])==2 and all(n[0]==0x1a and n[1] for n in name[2]),'domain/item identifiers')
        if base=='write':need(service[2][-1][0]==0xa0 and service[2][-1][2][0][0]==0x8a,'MMS Write data')
    elif base=='read':
        result=child(service,0xa1);need(result[2] and all(n[0] in {0x80,0x83,0x85,0x86,0x87,0x89,0x8a,0x91} for n in result[2]),'Read access results')
    else:need(service[2] and all(n[0] in {0x80,0x81} for n in service[2]),'Write result choice')
    return dict(invoke=invoke)


def validate_modbus(mid,raw):
    need(8<=len(raw)<=260 and raw[2:4]==b'\0\0' and int.from_bytes(raw[4:6],'big')+6==len(raw),'MBAP')
    code=raw[7];response=mid.endswith('_response') or mid in {'read_response','exception'}
    if code&128:need(len(raw)==9 and raw[8] in {1,2,3,4,5,6,8,10,11},'exception layout');return
    if code in {1,2,3,4}:
        if response:need(raw[8]==len(raw)-9 and (code<3 or not raw[8]%2),'read response byte count')
        else:need(len(raw)==12 and 1<=int.from_bytes(raw[10:12],'big')<=(2000 if code<3 else 125),'read request quantity')
    elif code in {5,6}:
        need(len(raw)==12,'single-write echo/request')
        if code==5:need(int.from_bytes(raw[10:12],'big') in {0,0xff00},'coil value encoding')
    elif code in {15,16}:
        q=int.from_bytes(raw[10:12],'big');need(1<=q<=(1968 if code==15 else 123),'multiple-write quantity')
        if response:need(len(raw)==12,'multiple-write acknowledgement')
        else:
            count=(q+7)//8 if code==15 else q*2;need(raw[12]==count and len(raw)==13+count,'multiple-write byte count')
            if code==15 and q%8:need(raw[-1]>>(q%8)==0,'unused coil padding bits')
    else:raise ValueError('outside Modbus function profile')


def validate_enip(mid,raw):
    need(len(raw)>=24 and int.from_bytes(raw[2:4],'little')==len(raw)-24,'encapsulation length')
    command=int.from_bytes(raw[:2],'little');status=int.from_bytes(raw[8:12],'little');session=int.from_bytes(raw[4:8],'little')
    if status:need(len(raw)==24 and status in {0x64,0x69},'encapsulation error');return
    if command==101:
        need(len(raw)==28 and raw[24:]==b'\x01\0\0\0','RegisterSession version/options');need(session==(1 if mid.endswith('_response') else 0),'register assigned handle');return
    if command==102:need(len(raw)==24 and session!=0,'unregister no payload');return
    need(command in {111,112} and session!=0 and len(raw)>=44,'explicit-message profile')
    need(raw[24:28]==b'\0'*4 and int.from_bytes(raw[30:32],'little')==2,'CPF interface/count')
    p=32;items=[]
    for _ in range(2):
        need(p+4<=len(raw),'CPF item header');typ=int.from_bytes(raw[p:p+2],'little');n=int.from_bytes(raw[p+2:p+4],'little');p+=4
        need(p+n<=len(raw),'CPF item length');items.append((typ,raw[p:p+n]));p+=n
    need(p==len(raw),'CPF item consumption')
    connection={}
    if command==112:
        need(raw[28:30]==b'\0\0' and items[0][0]==0xa1 and len(items[0][1])==4 and items[1][0]==0xb1,'connected CPF address/data item layout')
        need(int.from_bytes(items[0][1],'little')!=0 and len(items[1][1])>=6,'connected ID/UInt16 sequence/CIP')
        connection=dict(connection_id=int.from_bytes(items[0][1],'little'),connected_sequence=int.from_bytes(items[1][1][:2],'little'))
        cip=items[1][1][2:]
    else:
        need(items[0]==(0,b'') and items[1][0]==0xb2,'unconnected CPF item order')
        cip=items[1][1]
    if cip[0]&128:
        need(len(cip)>=4 and cip[0]==0x8e and cip[1]==0 and 4+2*cip[3]<=len(cip),'CIP response status sizes')
        if cip[2]==0:need(len(cip)==6,'Identity Vendor-ID UInt16 result')
        else:need(cip[2]==20 and len(cip)==4,'attribute-not-supported response')
    else:need(cip[0]==14 and len(cip)==2+2*cip[1] and cip[2:]==bytes.fromhex('200124013001'),'CIP logical EPATH count')
    return connection


def validate_iec104(mid,raw):
    need(raw[:1]==b'\x68' and raw[1]+2==len(raw),'APCI length')
    if raw[2]&3==3:need(len(raw)==6 and raw[2] in {7,11,19,35,67,131} and raw[3:]==b'\0'*3,'U control');return
    if raw[2]&3==1:need(len(raw)==6 and raw[2:4]==b'\x01\0' and raw[4]&1==0,'S frame');return
    need(raw[2]&1==raw[4]&1==0 and len(raw)==16,'I sequence/ASDU size')
    need(raw[6]==100 and raw[7]==1 and raw[12:15]==b'\0'*3 and 20<=raw[15]<=36,'single C_IC_NA_1 ASDU')
    need(raw[8] in {6,7,10,71} and raw[9]==0,'interrogation cause')


def bacnet_tags(data):
    tags=[];stack=[];p=0
    while p<len(data):
        h=data[p];p+=1;tag=h>>4;context=bool(h&8);n=h&7
        if tag==15:need(p<len(data),'extended BACnet tag');tag=data[p];p+=1
        if context and n in {6,7}:
            if n==6:stack.append(tag)
            else:need(stack and stack.pop()==tag,'BACnet closing tag')
            tags.append((tag,context,n,b''));continue
        if not context and tag==1:n=0
        elif n==5:
            need(p<len(data),'BACnet extended length');n=data[p];p+=1
            if n in {254,255}:
                w=2 if n==254 else 4;need(p+w<=len(data),'BACnet long length');n=int.from_bytes(data[p:p+w],'big');p+=w
        need(p+n<=len(data),'BACnet tag length');value=data[p:p+n];p+=n
        if not context and tag==7:need(value and value[0]<=5,'CharacterString requires encoding octet')
        tags.append((tag,context,0,value))
    need(not stack,'unterminated BACnet tag');return tags


def validate_bacnet(mid,raw):
    need(raw[0]==129 and int.from_bytes(raw[2:4],'big')==len(raw) and raw[4]==1,'BVLC/NPDU')
    p=6;control=raw[5]
    for bit in [32,8]:
        if control&bit:need(p+3<=len(raw),'NPDU address');p+=3+raw[p+2]
    if control&32:p+=1
    kind=raw[p]>>4;service=raw[p+3] if kind==0 else raw[p+1] if kind==1 else raw[p+2]
    content=raw[p+(4 if kind==0 else 2 if kind==1 else 3):];tags=bacnet_tags(content)
    if mid=='who_is':need((kind,service)==(1,8) and len(tags) in {0,2},'WhoIs')
    elif mid=='i_am':need((kind,service)==(1,0) and [t[0] for t in tags]==[12,2,9,2] and all(not t[1] for t in tags),'IAm')
    elif mid in {'read_property','read_property_ack'}:
        need(service==12 and [t[0] for t in tags[:2]]==[0,1] and all(t[1] for t in tags[:2]),'ReadProperty object/property')
        if mid.endswith('_ack'):need(kind==3 and tags[-1][:3]==(3,True,7) and any(t[:3]==(3,True,6) for t in tags),'ReadProperty ACK value wrapper')
    elif mid=='read_property_error':need(kind==5 and service==12 and [t[0] for t in tags]==[9,9],'Error enumerated values')
    elif mid in {'reject','abort'}:need(kind==(6 if mid=='reject' else 7) and not content,'Reject/Abort reason byte and no payload')
    else:raise ValueError('unknown BACnet profile message')


VALIDATORS={'bacnet':validate_bacnet,'modbus':validate_modbus,'iec104':validate_iec104,'mms':validate_mms,'enip':validate_enip,'opcua':validate_ua}


class ModelCompletenessTests(unittest.TestCase):
    def test_all_declared_complete_fixtures_decode_without_trailing_bytes(self):
        for path in sorted((ROOT/'protocols').glob('*/protocol_spec.yaml')):
            protocol=load(path);state=load(path.with_name('state_transition.yaml'));validate(protocol,state)
            for msg in protocol['messages']:
                with self.subTest(protocol=protocol['protocol_id'],message=msg['id']):
                    self.assertEqual(msg['fixture_status'],'complete')
                    self.assertEqual(msg['runtime_encode'],protocol['support']['runtime'] and msg['direction']=='request')
                    VALIDATORS[protocol['codec']](msg['id'],bytes.fromhex(msg['example']))

    def test_deep_checks_reject_corrupt_inner_lengths_and_counts(self):
        corruptions=[('modbus_tcp','write_coils_partial',12,1),('ethernet_ip_cip_tcp','send_rr',30,3),('ethernet_ip_cip_tcp','send_rr',38,0),('ethernet_ip_cip_tcp','send_unit',34,0),('ethernet_ip_cip_tcp','send_unit',42,1),('iec61850_mms_tcp','read',12,0x7f),('opcua_tcp','open_channel',12,0x7f),('bacnet_ip','read_property_ack',18,0)]
        for pid,mid,offset,value in corruptions:
            p=load(ROOT/'protocols'/pid/'protocol_spec.yaml');m=next(m for m in p['messages'] if m['id']==mid);raw=bytearray.fromhex(m['example']);raw[offset]=value
            with self.subTest(protocol=pid,message=mid,offset=offset):
                with self.assertRaises((ValueError,IndexError,UnicodeError,struct.error)):VALIDATORS[p['codec']](mid,bytes(raw))

    def test_requests_declare_a_reply_or_document_no_reply(self):
        no_reply={'iec60870_5_104':{'s_ack'},'ethernet_ip_cip_tcp':{'unregister'},'opcua_tcp':{'close_channel'}}
        for path in (ROOT/'protocols').glob('*/protocol_spec.yaml'):
            p=load(path);st=load(path.with_name('state_transition.yaml'))
            for m in p['messages']:
                if m['direction']!='request':continue
                replies={t['response'] for t in st['transitions'] if t['message']==m['id'] and t.get('response')}
                self.assertTrue(replies or m['id'] in no_reply.get(p['protocol_id'],set()),(p['protocol_id'],m['id']))

    def test_partial_coil_quantity_and_padding(self):
        p=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml');m=next(m for m in p['messages'] if m['id']=='write_coils_partial');raw=bytearray.fromhex(m['example'])
        self.assertEqual(int.from_bytes(raw[10:12],'big'),9);validate_modbus(m['id'],raw)
        raw[-1]=0x81
        with self.assertRaisesRegex(ValueError,'padding'):validate_modbus(m['id'],raw)

    def test_complete_request_profiles_have_runtime_encoders(self):
        enabled=[]
        expected={'bacnet_ip':2,'modbus_tcp':9,'iec60870_5_104':5,
                  'iec61850_mms_tcp':7,'ethernet_ip_cip_tcp':4,'opcua_tcp':4}
        for path in (ROOT/'protocols').glob('*/protocol_spec.yaml'):
            p=load(path)
            self.assertTrue(p['support']['runtime'])
            requests=[m for m in p['messages'] if m['direction']=='request']
            self.assertEqual(len(requests),expected[p['protocol_id']])
            for message in p['messages']:
                self.assertEqual(message['runtime_encode'],message['direction']=='request')
                if message['runtime_encode']:
                    self.assertEqual(message['fixture_status'],'complete')
                    enabled.append((p['protocol_id'],message['id']))
        self.assertEqual(len(enabled),sum(expected.values()))

    def test_connected_enip_has_directional_ids_and_external_forward_open_precondition(self):
        p=load(ROOT/'protocols/ethernet_ip_cip_tcp/protocol_spec.yaml');st=load(ROOT/'protocols/ethernet_ip_cip_tcp/state_transition.yaml')
        self.assertTrue(p['support']['runtime'])
        req=next(m for m in p['messages'] if m['id']=='send_unit');resp=next(m for m in p['messages'] if m['id']=='send_unit_response')
        q=validate_enip(req['id'],bytes.fromhex(req['example']));a=validate_enip(resp['id'],bytes.fromhex(resp['example']))
        self.assertEqual(q['connection_id'],0x10000001);self.assertEqual(a['connection_id'],0x20000001)
        self.assertEqual(q['connected_sequence'],a['connected_sequence'])
        self.assertIn('EXTERNAL PRECONDITION',req['notes']);self.assertIn('ForwardOpen',req['notes'])
        self.assertTrue(req['runtime_encode']);self.assertFalse(resp['runtime_encode'])
        self.assertFalse(any(m['id']=='forward_open' for m in p['messages']))
        edge=next(t for t in st['transitions'] if t['message']=='send_unit')
        self.assertEqual((edge['from'],edge['to']),('registered','registered'))
        self.assertIn('EXTERNAL PRECONDITION',edge['guard']);self.assertIn('class-3',edge['guard'])
        # A session ID is not a CIP connection ID. No model dependency invents
        # either directional connection ID from RegisterSession.
        self.assertFalse(any(d['target']=='connection_id' for m in (req,resp) for d in m['dependencies']))

    def test_response_driven_connection_states(self):
        for pid,request,pending,response,established in [('ethernet_ip_cip_tcp','register','registering','register_response','registered'),('opcua_tcp','open_channel','channel_pending','open_channel_response','channel'),('iec61850_mms_tcp','associate','association_pending','associate_response','associated')]:
            s=load(ROOT/'protocols'/pid/'state_transition.yaml');req=next(t for t in s['transitions'] if t['message']==request);resp=next(t for t in s['transitions'] if t['message']==response)
            self.assertEqual(req['to'],pending);self.assertEqual(resp['from'],pending);self.assertEqual(resp['to'],established)

    def test_regeneration_preserves_all_committed_model_artifacts(self):
        import generate_protocol_models as generator
        import build_generic_wire_profiles as generic_generator
        oldroot=generator.ROOT
        old_generic_root=generic_generator.ROOT
        try:
            with tempfile.TemporaryDirectory() as tmp:
                generator.ROOT=Path(tmp);generator.main()
                generic_generator.ROOT=Path(tmp)/'protocols'
                for name in generic_generator.CHOICES:
                    generic_generator.generate(name)
                for path in sorted((ROOT/'protocols').glob('*/protocol_spec.yaml')):
                    for original in path.parent.rglob('*'):
                        if original.is_file():self.assertEqual(original.read_bytes(),(Path(tmp)/'protocols'/path.parent.name/original.relative_to(path.parent)).read_bytes(),str(original))
        finally:
            generator.ROOT=oldroot
            generic_generator.ROOT=old_generic_root


if __name__=='__main__':unittest.main(verbosity=2)
