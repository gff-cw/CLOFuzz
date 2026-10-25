#!/usr/bin/env python3
"""Reproducible, bounded reference models; not a claim of whole-standard coverage."""
import copy
from pathlib import Path
import struct
import yaml
from proto_spec_compiler import compile_spec
from protocol_model_details import enrich

ROOT = Path(__file__).resolve().parents[1]


def field(fid, loc, typ="uint8", role="head", default=0, values=(), maximum=None,
          minimum=0, endian="big", mutable="fuzzable", **kw):
    widths = {"uint8":1,"uint16":2,"uint24":3,"uint32":4,"uint64":8}
    w = widths.get(typ, 0)
    return dict(id=fid, block="CONTENT" if role == "content" else "HEAD",
                path=loc, locator=loc, type=typ, width=w, endian=endian, role=role,
                mutability=mutable, default=default, min=minimum,
                max=maximum if maximum is not None else (2**(w*8)-1 if w else 4096),
                values=list(values), strategies=["afl","resize"] if role == "content" and not w else ["enum","boundary","bitflip","arithmetic"],
                evidence="wire", confidence="implementation", **kw)


def fixed(fid, loc, value, typ="uint8", endian="big"):
    return field(fid, loc, typ, "fixed", value, [value], value, value, endian, "fixed")


def length(fid, loc, typ="uint16", endian="big"):
    return field(fid, loc, typ, "derived", endian=endian, mutable="derived")


def dep(target, source="$message", op="length_of", **kw):
    return dict(op=op, target=target, source=source, **kw)


def message(mid, example, fields, deps=(), direction="request", match="", notes=""):
    return dict(id=mid, example=example, direction=direction, weight=2, match=match or mid,
                blocks=[dict(id=b, fields=[f['id'] for f in fields if f['block']==b]) for b in ("HEAD","CONTENT")],
                fields=fields, dependencies=list(deps), notes=notes)


def emit(pid, name, version, scope, codec, messages, states, transitions, url, sections,
         excluded=(), runtime=False, extra_sources=()):
    out=ROOT/'protocols'/pid; out.mkdir(parents=True,exist_ok=True)
    p=dict(format_version=1,protocol_id=pid,name=name,version=version,scope=scope,
           transport="udp" if codec=="bacnet" else "tcp",framing="datagram" if codec=="bacnet" else "protocol length inside replayable records",
           codec=codec,support=dict(runtime=runtime,level="runtime scoped codec" if runtime else "static description; runtime encoder unavailable",excluded=list(excluded)),
           sources=[dict(id="wire",url=url,basis="implementation",sections=sections),*extra_sources],messages=copy.deepcopy(messages))
    st=dict(format_version=1,protocol_id=pid,initial=states[0][0],
            states=[dict(id=k,meaning=v) for k,v in states],
            transitions=[dict(zip(("from","to","message","response","guard","actions"),t)) for t in transitions],
            limits=dict(max_messages=32,max_repeat=4,max_bytes=1048576),
            invalid_strategy="one explicitly logged length or semantic transition violation; preserve other dependencies")
    enrich(p,st,field,fixed,length,dep,message)
    for filename,v in (("protocol_spec.yaml",p),("state_transition.yaml",st)):
        (out/filename).write_text(yaml.safe_dump(v,sort_keys=False))
    result=compile_spec(p,st,out)
    (out/'evidence.yaml').write_text(yaml.safe_dump(dict(sources=p['sources'],scope=scope,
        confidence="Each field names its source and confidence; catalogue identity does not establish normative wire details.",
        accessed="2026-10-25", field_sources=[dict(message=m['id'],field=f['id'],source=f['evidence'],confidence=f['confidence']) for m in p['messages'] for f in m['fields']],
        availability="Public OPC Foundation, RFC1006, Modbus current official PDF and open-source implementations were consulted. Full ASHRAE, IEC and ODVA subscription texts were not accessed.",
        distinctions="semantic state IDs are unrelated to StateAFL memory-derived IDs",
        validation=result),sort_keys=False))
    (out/'README.md').write_text(f"# {name}\n\nVersion: {version}.\n\nScope: {scope}\n\nSupport: {p['support']['level']}. BACnet is the live integration target; see `docs/bacnet-integration-test.md` for actual results.\n\nExcluded: {'; '.join(p['support']['excluded'])}.\n\nEach field names a source ID and confidence; see `evidence.yaml` for the source mapping and access limits. Static nested `structure_model` trees and state guard/action strings document semantics and are not executable code. Only the C runtime's documented operations execute. Static-only fixtures pass header/length checks, but are not exchanges validated with a target. In particular MMS fixtures omit complete session/presentation wrappers, and OPC UA secure-conversation fixtures omit complete service bodies.\n\nRegenerate all files with `python3 tools/generate_protocol_models.py`; validate independently with `python3 tools/proto_spec_compiler.py --protocol protocols/{pid}/protocol_spec.yaml --state protocols/{pid}/state_transition.yaml --output-dir /tmp/{pid}`.\n")
    seeds=out/'seeds';seeds.mkdir(exist_ok=True)
    for m in p['messages']:
        if m['direction']=='request':
            b=bytes.fromhex(m['example']);(seeds/(m['id']+'.replay')).write_bytes(struct.pack('<I',len(b))+b)


def main():
    # BACnet locators are resolved by the NPDU/APDU/tag parser, never fixed APDU offsets.
    common=[fixed('bvlc_type','bvlc.type',129),fixed('bvlc_function','bvlc.function',10),length('bvlc_length','bvlc.length'),
            fixed('npdu_version','npdu.version',1),field('npdu_control','npdu.control',default=0,values=[0,4,32,8],mutable='conditional',
                structure='Destination DNET/DLEN/DADR and source SNET/SLEN/SADR appear when NPDU control bits 5 and 3 are set; hop count follows addresses only for destination; reject network-layer bit 7 in runtime APDU scope.')]
    who=message('who_is','810a000801001008',common+[fixed('apdu_type','apdu.type',16),fixed('service','apdu.service',8),
        field('limits','apdu.content','bacnet_tags','content',default='',structure='Optional context [0] low and [1] high device-instance limits (0..4194303), both absent or both present.')], [dep('bvlc_length')])
    rpfields=common+[fixed('apdu_type','apdu.type',0),fixed('max_apdu','apdu.max_apdu',5),
        field('invoke_id','apdu.invoke',default=1),fixed('service','apdu.service',12),
        field('object_id','bacnet.object','uint32','content',33554555,[33554555,33555666],structure='BACnet context tag 0; 10-bit object type and 22-bit instance.'),
        field('property_id','bacnet.property','uint8','content',77,[75,76,77,79,112,120,121]),
        field('array_index','bacnet.array','uint8','content',0,mutable='conditional',structure='Optional context tag 2 unsigned array index; decoder uses actual tag width.')]
    rp=message('read_property','810a001101000005010c0c0200007b194d',rpfields,[dep('bvlc_length')])
    ack=message('read_property_ack','810a0014010030010c0c0200007b194d3e75003f',
        common+[fixed('apdu_type','apdu.type',48),field('invoke_id','apdu.invoke',default=1,mutable='runtime_bound'),fixed('service','apdu.service',12),
                field('value','apdu.content','bacnet_tags','content',default='',structure='Context [3] opening/closing tags enclose application tags; BACnet LVT is not ASN.1 BER.')],
        [dep('bvlc_length'),dep('invoke_id','invoke_id','correlate_request_response',message='read_property',scope='transaction')], 'response',notes='Example is structural only; live server response is captured in integration evidence.')
    # Fix structural fixture BVLC size from actual bytes.
    ackbytes=bytearray.fromhex(ack['example']);ackbytes[2:4]=len(ackbytes).to_bytes(2,'big');ack['example']=ackbytes.hex()
    emit('bacnet_ip','BACnet/IP','BACnet Stack 1.5.0 / ASHRAE 135',
         'BVLC Original-Unicast-NPDU; routed NPDU address parsing; unsegmented Who-Is with optional limits and ReadProperty with optional array index; application/context tag walking and invoke correlation.',
         'bacnet',[who,rp,ack],[('ready','UDP endpoint ready; requests independent'),('pending','Confirmed request outstanding, scoped by invoke ID')],
         [('ready','ready','who_is','','valid Who-Is',[]),('ready','pending','read_property','read_property_ack','request sent',['cache invoke_id']),('pending','ready','read_property_ack','','matching invoke ID',['clear transaction']),('pending','pending','read_property','read_property_ack','additional independent invoke',[])],
         'https://github.com/bacnet-stack/bacnet-stack/tree/bacnet-stack-1.5.0','src/bacnet/{npdu,bacdcode,rp}.c; datalink/bvlc.c; apps/server/main.c',
         ['segmented APDUs','BACnet/SC','other services runtime encoding','BBMD/foreign-device lifecycle'],True)
    mb=[field('transaction','abs:0','uint16',default=1),fixed('protocol','abs:2',0,'uint16'),length('length','abs:4'),field('unit','abs:6',default=1)]
    msgs=[]
    for code,mid in [(1,'read_coils'),(2,'read_discrete'),(3,'read_holding'),(4,'read_input')]:
        msgs.append(message(mid,f'00010000000601{code:02x}00000001',copy.deepcopy(mb)+[fixed('function','abs:7',code),field('address','abs:8','uint16','content'),field('quantity','abs:10','uint16','content',1,maximum=2000 if code<3 else 125,minimum=1)], [dep('length',add=-6)]))
    for code,mid in [(5,'write_coil'),(6,'write_register')]:
        msgs.append(message(mid,f'00010000000601{code:02x}00000000',copy.deepcopy(mb)+[fixed('function','abs:7',code),field('address','abs:8','uint16','content'),field('value','abs:10','uint16','content',values=[0,65280] if code==5 else [0,1,65535])],[dep('length',add=-6)]))
    for code,mid,payload,count in [(15,'write_coils','01',8),(16,'write_registers','0001',1)]:
        hx=f'0001000000{(7+len(bytes.fromhex(payload))):02x}01{code:02x}0000{count:04x}{len(bytes.fromhex(payload)):02x}'+payload
        msgs.append(message(mid,hx,copy.deepcopy(mb)+[fixed('function','abs:7',code),field('address','abs:8','uint16','content'),length('quantity','abs:10'),length('byte_count','abs:12','uint8'),field('data','abs:13','bytes','content',payload,maximum=246,repeat={'count':'quantity','max':123},structure='Packed coils (8 per byte) or big-endian 16-bit registers according to function.')],
            [dep('byte_count','data'),dep('quantity','data','count_of',unit=1 if code==15 else 2),dep('length',add=-6)]))
    msgs.append(message('read_response','0001000000050103020001',copy.deepcopy(mb)+[fixed('function','abs:7',3),length('byte_count','abs:8','uint8'),field('data','abs:9','bytes','content','0001')],[dep('byte_count','data'),dep('length',add=-6),dep('transaction','transaction','correlate_request_response',message='read_holding',scope='transaction')],'response'))
    msgs.append(message('exception','000100000003018302',copy.deepcopy(mb)+[field('function','abs:7',default=131,values=[129,130,131,132,133,134,143,144]),field('exception','abs:8',default=2,values=[1,2,3,4,5,6,8,10,11])],[dep('length',add=-6),dep('transaction','transaction','correlate_request_response',message='read_holding',scope='transaction')],'response'))
    emit('modbus_tcp','Modbus TCP','Application Protocol 1.1b3; MBAP', 'Functions 01-06, 0F, 10, their field layouts, read-register response and exception response; no serial RTU CRC.', 'modbus',msgs,[('connected','TCP transport; independent transaction contexts')], [('connected','connected',m['id'],'','transaction-scoped MBAP matching',[]) for m in msgs], 'https://github.com/stephane/libmodbus/blob/master/src/modbus.c','libmodbus src/modbus.c and modbus-tcp.c; Modbus Application Protocol 1.1b3 sections 4,6', ['serial RTU','file-record and diagnostic function families'])
    h=[fixed('start','abs:0',104),length('length','abs:1','uint8')]
    msgs=[]
    for mid,c in [('start_act',7),('start_con',11),('stop_act',19),('stop_con',35),('test_act',67),('test_con',131)]:
        msgs.append(message(mid,f'6804{c:02x}000000',copy.deepcopy(h)+[fixed('control','abs:2',c,'uint32','little')],[dep('length',add=-2)],'response' if mid.endswith('con') else 'request'))
    msgs.append(message('s_ack','680401000000',copy.deepcopy(h)+[fixed('format','abs:2',1,'uint16','little'),field('receive_seq','abs:4','uint16',endian='little',structure='15-bit sequence number shifted left one; acknowledge next expected I frame.')],[dep('length',add=-2)]))
    msgs.append(message('interrogation','680e0000000064010600010000000014',copy.deepcopy(h)+[field('send_seq','abs:2','uint16',endian='little'),field('receive_seq','abs:4','uint16',endian='little'),fixed('type_id','abs:6',100),field('vsq','abs:7',default=1,structure='SQ bit7 chooses sequential IOAs; low7 is object count.'),field('cot','abs:8','uint16',default=6,endian='little'),field('common_address','abs:10','uint16','content',1,endian='little'),field('ioa','abs:12','uint24','content',endian='little'),field('qoi','abs:15','uint8','content',20,values=[20,21,36])],[dep('length',add=-2),dep('send_seq','$message','sequence_number',unit=2,scope='connection')],notes='ASDU C_IC_NA_1: count exactly one, IOA zero; sequence increments modulo 32768 before shift.'))
    emit('iec60870_5_104','IEC 60870-5-104','IEC 60870-5-104; lib60870 profile', 'I/S/U APCI; STARTDT, STOPDT, TESTFR and single-object C_IC_NA_1 ASDU; 2-byte COT/CA and 3-byte IOA.', 'iec104',msgs,[('stopped','Data transfer stopped'),('starting','STARTDT confirmation pending'),('active','STARTDT confirmed'),('stopping','STOPDT confirmation pending')], [('stopped','starting','start_act','start_con','TCP connected',[]),('starting','active','start_con','','matching STARTDT',[]),('active','stopping','stop_act','stop_con','',[]),('stopping','stopped','stop_con','','',[]),('active','active','interrogation','','increment N(S) modulo 32768',['cache send sequence']),('active','active','s_ack','','acknowledge received I frames',[]),*[('active','active',x,'','TESTFR keepalive',[]) for x in ['test_act','test_con']]], 'https://github.com/mz-automation/lib60870/blob/master/lib60870-C/src/iec60870/cs104/cs104_connection.c','APCI U controls, defaultAppLayerParameters, sequence update and acknowledgment handlers', ['other ASDU payload types','TLS','multi-object runtime generation'])
    # ISO-on-TCP and MMS are separate layers; BER payloads use trees, not fixed offsets.
    tp=[fixed('version','abs:0',3),fixed('reserved','abs:1',0),length('tpkt_length','abs:2')]
    cr=message('cotp_cr','0300001611e00000000100c0010ac1020001c2020001',copy.deepcopy(tp)+[length('cotp_li','abs:4','uint8'),fixed('cotp_type','abs:5',224),field('cotp_parameters','abs:6','bytes','content','0000000100c0010ac1020001c2020001',structure='COTP connection references, class and variable TLV parameters.')],[dep('tpkt_length'),dep('cotp_li',add=-5)])
    raw=bytearray.fromhex(cr['example']);raw[2:4]=len(raw).to_bytes(2,'big');cr['example']=raw.hex()
    mms=[]
    for mid,tag,body in [('associate',96,'a103020100'),('initiate',168,'800100810105820105830108a400'),('get_name_list',160,'020101a103800109'),('read',160,'020101a404a0028000'),('write',160,'020101a506a0028000a000'),('release',98,'800100')]:
        payload=bytes([tag,len(bytes.fromhex(body))])+bytes.fromhex(body);wire=bytes.fromhex('0300000002f080')+payload;wire=wire[:2]+len(wire).to_bytes(2,'big')+wire[4:]
        mms.append(message(mid,wire.hex(),copy.deepcopy(tp)+[fixed('cotp_li','abs:4',2),fixed('cotp_type','abs:5',240),fixed('eot','abs:6',128),field('pdu','mms.ber','ber_tlv','content',payload.hex(),structure='Definite BER TLV tree; ACSE associate/release and MMS initiate/confirmed service bodies are distinct. Full session/presentation wrappers required on real MMS association.')],[dep('tpkt_length'),dep('pdu','$message','tagged_length')],notes='Structural BER fixture only; not a complete on-wire MMS association. Runtime unavailable.'))
    emit('iec61850_mms_tcp','IEC 61850 MMS over TCP','IEC 61850-8-1 / ISO 9506 / RFC 1006','Transport COTP plus declarative ACSE/Initiate/confirmed GetNameList Read Write envelopes; nested BER; full session/presentation association requires an external complete codec.', 'mms',[cr,*mms],[('transport','TCP connected'),('cotp','COTP established'),('associating','ACSE AARQ/AARE and MMS initiate negotiation'),('associated','Successful AARE and initiate response required'),('released','ACSE association released')],[('transport','cotp','cotp_cr','','COTP CC received',[]),('cotp','associating','associate','','presentation/session wrappers required',[]),('associating','associated','initiate','','successful AARE/initiate response',[]),*[('associated','associated',mid,'','confirmed invoke must match response',['cache invoke ID']) for mid in ['get_name_list','read','write']],('associated','released','release','','ACSE release handshake',[])], 'https://github.com/mz-automation/libiec61850/tree/master/src/mms','iso_mms ASN.1 definitions, iso_acse and iso_presentation; RFC1006 section 6', ['complete session/presentation codec','runtime BER service encoding','all abstract IEC61850 services','TLS'])
    enc=[field('command','abs:0','uint16',default=101,endian='little'),length('length','abs:2',endian='little'),field('session','abs:4','uint32',endian='little',mutable='runtime_bound'),fixed('status','abs:8',0,'uint32','little'),field('context','abs:12','uint64',default=1,endian='little'),fixed('options','abs:20',0,'uint32','little')]
    en=[]
    for mid,cmd,payload in [('register',101,'01000000'),('unregister',102,''),('send_rr',111,'000000000000020000000000b20008000e03200124013001'),('send_unit',112,'0000000000000200a100040001000000b1000a0001000e03200124013001')]:
        b=struct.pack('<HHIIQI',cmd,len(bytes.fromhex(payload)),0,0,1,0)+bytes.fromhex(payload)
        fs=copy.deepcopy(enc);fs[0]=fixed('command','abs:0',cmd,'uint16','little')
        if payload:fs.append(field('payload','abs:24','bytes','content',payload,structure='RegisterSession version/options or Common Packet Format item count and items; CIP Service plus response bit, EPATH word count and logical class/instance/attribute segments; SendUnitData needs prior ForwardOpen connection.'))
        en.append(message(mid,b.hex(),fs,[dep('length',add=-24)],notes='Session handle bound from successful RegisterSession response; Sender Context echoed. Explicit TCP messaging only.'))
    emit('ethernet_ip_cip_tcp','EtherNet/IP and CIP explicit TCP','Encapsulation v1; public OpENer implementation', 'Encapsulation lifecycle, SendRRData/SendUnitData CPF and CIP path description. No implicit UDP I/O.', 'enip',en,[('connected','TCP connected'),('registered','Successful RegisterSession response; handle cached'),('closed','Unregistered session')],[('connected','registered','register','','successful register response',['bind session handle']),('registered','registered','send_rr','','valid session and CPF',['echo sender context']),('registered','registered','send_unit','','ForwardOpen connection prerequisite; not generated',[]),('registered','closed','unregister','','matching handle',['clear handle'])], 'https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/encap.c','encap.c encapsulation command definitions; cpf.c item lengths; CIP message router EPATH parser', ['implicit UDP I/O','ForwardOpen runtime binding','CIP Security','subscription-only ODVA details not independently verified'])
    ua=[]
    for mid,typ,body in [('hello','HEL',struct.pack('<IIIIIi',0,65536,65536,0,0,0)),('ack','ACK',struct.pack('<IIIII',0,65536,65536,0,0)),('error','ERR',struct.pack('<Ii',0x80000000,0)),('reverse_hello','RHE',struct.pack('<ii',0,0)),('open_channel','OPN',b'\0'*4+struct.pack('<i',47)+b'http://opcfoundation.org/UA/SecurityPolicy#None'+struct.pack('<iiII',-1,-1,1,1)),('message','MSG',struct.pack('<IIII',1,1,2,1)+b'\x01\x00\x77\x02'),('close_channel','CLO',struct.pack('<IIII',1,1,3,2)+b'\x01\x00\xc4\x01')]:
        wire=typ.encode()+b'F'+struct.pack('<I',8+len(body))+body
        fs=[fixed('message_type','abs:0',ord(typ[0])),fixed('chunk','abs:3',70),length('message_size','abs:4','uint32','little'),field('body','abs:8','bytes','content',body.hex(),structure='UA Binary little endian; Int32 length strings/arrays (-1 null); NodeId encoding mask selects two-byte/four-byte/numeric/string/guid/bytes. UASC OPN asymmetric and MSG/CLO symmetric headers differ. Final/intermediate/abort chunks F/C/A.')]
        if typ in ['MSG','CLO']:
            fs += [field('channel','abs:8','uint32',default=1,endian='little',mutable='runtime_bound'),field('token','abs:12','uint32',default=1,endian='little',mutable='runtime_bound'),field('sequence','abs:16','uint32',default=2 if typ=='MSG' else 3,endian='little'),field('request_id','abs:20','uint32',default=1 if typ=='MSG' else 2,endian='little'),field('service_nodeid','abs:24','nodeid','content','01007702',structure='Four-byte numeric NodeId encoding 0x01; namespace byte then UInt16 identifier; full service body intentionally not generated.')]
        ua.append(message(mid,wire.hex(),fs,[dep('message_size')],direction='response' if typ in ['ACK','ERR'] else 'request',notes='OPN/MSG/CLO are header fixtures without full service bodies; not valid complete services. SecurityPolicy None only; no signing/encryption.'))
    emit('opcua_tcp','OPC UA TCP','OPC 10000 Parts 4/6 v1.05','HEL/ACK/ERR/RHE transport and UASC OPN/MSG/CLO header structures, UA Binary/NodeId and lifecycle descriptions. Only SecurityPolicy None is described.', 'opcua',ua,[('tcp','TCP connected'),('hello_sent','HEL sent'),('acknowledged','ACK received'),('channel','Successful OpenSecureChannel response received'),('closed','CLO sent')],[('tcp','hello_sent','hello','','',[]),('hello_sent','acknowledged','ack','','negotiated buffers',[]),('acknowledged','channel','open_channel','','successful OPN response',['cache channel/token']),('channel','channel','message','','UA session activation required for session services',['increment sequence and correlate request ID']),('channel','closed','close_channel','','',['clear channel/token']),('tcp','tcp','reverse_hello','','reverse-connect role only',[]),('tcp','tcp','error','','transport error',[])], 'https://reference.opcfoundation.org/specs/OPC-10000-6','5.2 UA Binary; 6.7 UASC; 7.1 UACP', ['signed or encrypted security modes','complete service bodies','session activation','runtime chunk reassembly'])


if __name__ == '__main__':
    main()
