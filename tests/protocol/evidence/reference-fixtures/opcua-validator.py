"""Independent bounded UA Binary fixture reader; no third-party dependencies.

Scope: single F chunks, SecurityPolicy None, the complete services in the report.
Not an implementation of arbitrary UA services, security modes or chunk assembly.
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

if __name__=='__main__':
 import json
 report=json.load(open('/tmp/opcua_fixture_report.json'))
 for name,fixture in report.items():
  print(name,validate_ua_fixture(bytes.fromhex(fixture['hex'])))
