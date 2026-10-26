import json,struct,sys,types
from datetime import datetime,timezone
p=types.ModuleType('asyncua');p.__path__=['/tmp/opcua-fixture-source/asyncua'];sys.modules['asyncua']=p
p=types.ModuleType('asyncua.common');p.__path__=['/tmp/opcua-fixture-source/asyncua/common'];sys.modules['asyncua.common']=p
from asyncua import ua
from asyncua.ua.ua_binary import struct_to_binary,struct_from_binary
from asyncua.common.utils import Buffer
TIME=datetime(2026,10,25,tzinfo=timezone.utc)
URL='opc.tcp://127.0.0.1:4840'
POLICY='http://opcfoundation.org/UA/SecurityPolicy#None'

def s(x):
 return struct.pack('<i',-1) if x is None else struct.pack('<i',len(x.encode()))+x.encode()
def header(r,handle):
 r.Timestamp=TIME;r.RequestHandle=handle
 if hasattr(r,'AuditEntryId'):r.AuditEntryId='';r.TimeoutHint=10000
 return r

def wire(typ,body,channel=None):
 if channel is not None:body=struct.pack('<I',channel)+body
 return typ.encode()+b'F'+struct.pack('<I',len(body)+8)+body

out={}
def add(mid,typ,obj,channel=None,security=b'',seq=None,req=None):
 body=struct_to_binary(obj)
 buf=Buffer(body);dec=struct_from_binary(type(obj),buf)
 assert len(buf)==0,(mid,'remaining',len(buf))
 assert struct_to_binary(dec)==body
 extra=security+(struct.pack('<II',seq,req) if seq is not None else b'')
 w=wire(typ,extra+body,channel)
 out[mid]={'hex':w.hex(),'length':len(w),'body_hex':body.hex(),'body_offset':8+(4 if channel is not None else 0)+len(extra),'decoded':str(dec)}

hello=ua.Hello(ProtocolVersion=0,ReceiveBufferSize=65536,SendBufferSize=65536,MaxMessageSize=0,MaxChunkCount=0,EndpointUrl=URL)
add('hello','HEL',hello)
ack=ua.Acknowledge(ProtocolVersion=0,ReceiveBufferSize=65536,SendBufferSize=65536,MaxMessageSize=0,MaxChunkCount=0)
add('ack','ACK',ack)
err=ua.ErrorMessage(Error=ua.StatusCode(ua.StatusCodes.BadTcpEndpointUrlInvalid),Reason='Unknown endpoint')
add('error','ERR',err)
body=s('urn:example:local:server')+s(URL)
w=wire('RHE',body)
out['reverse_hello']={'hex':w.hex(),'length':len(w),'body_hex':body.hex(),'body_offset':8,'decoded':'ServerUri urn:example:local:server; EndpointUrl '+URL}
asym=struct_to_binary(ua.AsymmetricAlgorithmHeader(SecurityPolicyURI=POLICY,SenderCertificate=None,ReceiverCertificateThumbPrint=None))
req=ua.OpenSecureChannelRequest();header(req.RequestHeader,1);req.Parameters.SecurityMode=ua.MessageSecurityMode.None_;req.Parameters.ClientNonce=None;req.Parameters.RequestedLifetime=600000
add('open_channel','OPN',req,0,asym,1,1)
resp=ua.OpenSecureChannelResponse();header(resp.ResponseHeader,1);resp.Parameters.SecurityToken.ChannelId=1;resp.Parameters.SecurityToken.TokenId=1;resp.Parameters.SecurityToken.CreatedAt=TIME;resp.Parameters.SecurityToken.RevisedLifetime=600000;resp.Parameters.ServerNonce=None
add('open_channel_response','OPN',resp,1,asym,1,1)
get=ua.GetEndpointsRequest();header(get.RequestHeader,2);get.Parameters.EndpointUrl=URL
add('message','MSG',get,1,struct.pack('<I',1),2,2)
getresp=ua.GetEndpointsResponse();header(getresp.ResponseHeader,2)
ep=ua.EndpointDescription();ep.EndpointUrl=URL;ep.Server.ApplicationUri='urn:example:local:server';ep.Server.ProductUri='urn:example:profile';ep.Server.ApplicationName=ua.LocalizedText('Local example server');ep.Server.ApplicationType=ua.ApplicationType.Server;ep.Server.DiscoveryUrls=[URL];ep.ServerCertificate=None;ep.SecurityMode=ua.MessageSecurityMode.None_;ep.SecurityPolicyUri=POLICY;token=ua.UserTokenPolicy();token.PolicyId='anonymous';token.TokenType=ua.UserTokenType.Anonymous;ep.UserIdentityTokens=[token];ep.TransportProfileUri='http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary';ep.SecurityLevel=0
getresp.Endpoints=[ep]
add('message_response','MSG',getresp,1,struct.pack('<I',1),2,2)
fault=ua.ServiceFault();header(fault.ResponseHeader,2);fault.ResponseHeader.ServiceResult=ua.StatusCode(ua.StatusCodes.BadServiceUnsupported)
add('service_fault','MSG',fault,1,struct.pack('<I',1),2,2)
clo=ua.CloseSecureChannelRequest();header(clo.RequestHeader,3)
add('close_channel','CLO',clo,1,struct.pack('<I',1),3,3)
print(json.dumps(out,indent=2))
