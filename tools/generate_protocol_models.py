#!/usr/bin/env python3
"""Reproducible, bounded reference models; not a claim of whole-standard coverage."""
import copy
from pathlib import Path
import struct
import yaml
from proto_spec_compiler import compile_spec
from protocol_model_details import enrich, mms_profile, opcua_profile

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


def message(mid, example, fields, deps=(), direction="request", match="", notes="", fixture_status="complete"):
    return dict(id=mid, example=example, direction=direction, weight=2, match=match or mid,
                blocks=[dict(id=b, fields=[f['id'] for f in fields if f['block']==b]) for b in ("HEAD","CONTENT")],
                fields=fields, dependencies=list(deps), notes=notes, fixture_status=fixture_status, runtime_encode=False)


def emit(pid, name, version, scope, codec, messages, states, transitions, url, sections,
         excluded=(), runtime=True, extra_sources=()):
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
    for m in p["messages"]:
        m["runtime_encode"]=runtime and m["direction"]=="request"
    for filename,v in (("protocol_spec.yaml",p),("state_transition.yaml",st)):
        (out/filename).write_text(yaml.safe_dump(v,sort_keys=False))
    result=compile_spec(p,st,out)
    (out/'evidence.yaml').write_text(yaml.safe_dump(dict(sources=p['sources'],scope=p['scope'],
        confidence="Each field names its source and confidence; catalogue identity does not establish normative wire details.",
        accessed="2026-10-25", field_sources=[dict(message=m['id'],field=f['id'],source=f['evidence'],confidence=f['confidence']) for m in p['messages'] for f in m['fields']],
        availability="Public OPC Foundation, RFC1006, Modbus current official PDF and open-source implementations were consulted. Full ASHRAE, IEC and ODVA subscription texts were not accessed.",
        distinctions="semantic state IDs are unrelated to StateAFL memory-derived IDs",
        fixture_counts=dict(complete=sum(m['fixture_status']=='complete' for m in p['messages']),fragment=sum(m['fixture_status']=='fragment' for m in p['messages'])),
        fixture_verification='Independent bounded structural readers: tests/protocol/test_model_completeness.py. Compiler validation covers the documented envelope/runtime subset, not complete service conformance.',
        fixture_provenance=('Complete loopback reference exchanges at libIEC61850 commit 6d231326bff8e9b6500aa1e345c076d3a329f211, connect/GetNameList/Read/Write/conclude all returned error=0. This constructs static fixtures; it is not StateAFL integration coverage.' if codec=='mms' else 'UA service fixtures were serialized and completely decoded/re-encoded with asyncua c321a240e53d083fd6e167c67f795915d8f236fd; no UA network exchange.' if codec=='opcua' else 'Constructed from the named public specification/implementation and checked by independent bounded structural readers; see audit for live-test limits.'),
        validation=result),sort_keys=False))
    complete=sum(m['fixture_status']=='complete' for m in p['messages'])
    status_note = ("" if codec == "bacnet" else "\n\nLatest test acceptance is recorded in "
                   "[task recovery](../../docs/task-recovery.md); fixture presence does not imply acceptance.")
    (out/'README.md').write_text(f"# {name}\n\nVersion: {version}.\n\nScope: {p['scope']}\n\nSupport: {p['support']['level']}. Complete fixtures: {complete}/{len(p['messages'])}; runtime request encoders: {sum(m['runtime_encode'] for m in p['messages'])}. BACnet is the industrial protocol implementation used for live integration; the five TCP profiles also have instrumented local fixture tests; see `docs/bacnet-integration-test.md`.{status_note}\n\nExcluded: {'; '.join(p['support']['excluded'])}.\n\nComplete means all bytes for the declared message/profile are present and checked by `tests/protocol/test_model_completeness.py`; it does not assert whole-standard conformance or successful exchanges with arbitrary products. A message marked `fragment` must never be presented as a valid service. `runtime_encode` records existing C runtime capability and is not an encoder selection switch. Nested `structure_model` trees and state guard/action strings are static descriptions.\n\nEach field names a source ID and confidence; `evidence.yaml` records sources and access limits. The six-protocol completeness matrix, corrections and verification limits are in `docs/protocol-model-audit.md`.\n\nNon-BACnet description compilation builds the bounded native validator with `CC` (or `cc`); a C11 compiler, `protocol_codecs.h`, `tools/native_protocol_codecs.py`, and all five `protocol_codec_*.c` sources are required. StateAFL links the codecs directly and runs no Python during mutation.\n\nRegenerate with `python3 tools/generate_protocol_models.py`; check complete fixtures with `python3 tests/protocol/test_model_completeness.py`; compile independently with `python3 tools/proto_spec_compiler.py --protocol protocols/{pid}/protocol_spec.yaml --state protocols/{pid}/state_transition.yaml --output-dir /tmp/{pid}`.\n")
    seeds=out/'seeds';seeds.mkdir(exist_ok=True)
    expected={m['id']+'.replay' for m in p['messages'] if m['direction']=='request' and m['fixture_status']=='complete'}
    for old in seeds.glob('*.replay'):
        if old.name not in expected: old.unlink()
    for m in p['messages']:
        if m['direction']=='request' and m['fixture_status']=='complete':
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
    ack=message('read_property_ack','810a001a010030010c0c0200007b194d3e7507004465766963653f',
        common+[fixed('apdu_type','apdu.type',48),field('invoke_id','apdu.invoke',default=1,mutable='runtime_bound'),fixed('service','apdu.service',12),
                field('value','apdu.content','bacnet_tags','content',default='',structure='Context [3] opening/closing tags enclose application tags; BACnet LVT is not ASN.1 BER.')],
        [dep('bvlc_length'),dep('invoke_id','invoke_id','correlate_request_response',message='read_property',scope='transaction')], 'response',notes='Complete static ACK fixture; live server response is captured separately in integration evidence.')
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
    mms_profile(emit, field, fixed, length, dep, message)
    enc=[field('command','abs:0','uint16',default=101,endian='little'),length('length','abs:2',endian='little'),field('session','abs:4','uint32',endian='little',mutable='runtime_bound'),fixed('status','abs:8',0,'uint32','little'),field('context','abs:12','uint64',default=1,endian='little'),fixed('options','abs:20',0,'uint32','little')]
    en=[]
    for mid,cmd,payload in [('register',101,'01000000'),('unregister',102,''),('send_rr',111,'000000000000020000000000b20008000e03200124013001'),('send_unit',112,'0000000000000200a100040001000000b1000a0001000e03200124013001')]:
        b=struct.pack('<HHIIQI',cmd,len(bytes.fromhex(payload)),0,0,1,0)+bytes.fromhex(payload)
        fs=copy.deepcopy(enc);fs[0]=fixed('command','abs:0',cmd,'uint16','little')
        if payload:fs.append(field('payload','abs:24','bytes','content',payload,structure='RegisterSession version/options or Common Packet Format item count and items; CIP Service plus response bit, EPATH word count and logical class/instance/attribute segments; SendUnitData needs prior ForwardOpen connection.'))
        en.append(message(mid,b.hex(),fs,[dep('length',add=-24)],notes='Session handle bound from successful RegisterSession response; Sender Context echoed. Explicit TCP messaging only.'))
    emit('ethernet_ip_cip_tcp','EtherNet/IP and CIP explicit TCP','Encapsulation v1; public OpENer implementation', 'Encapsulation lifecycle, SendRRData/SendUnitData CPF and CIP path description. No implicit UDP I/O.', 'enip',en,[('connected','TCP connected'),('registered','Successful RegisterSession response; handle cached'),('closed','Unregistered session')],[('connected','registered','register','','successful register response',['bind session handle']),('registered','registered','send_rr','','valid session and CPF',['echo sender context']),('registered','registered','send_unit','','ForwardOpen connection prerequisite; not generated',[]),('registered','closed','unregister','','matching handle',['clear handle'])], 'https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/encap.c','encap.c encapsulation command definitions; cpf.c item lengths; CIP message router EPATH parser', ['implicit UDP I/O','ForwardOpen runtime binding','CIP Security','subscription-only ODVA details not independently verified'])
    opcua_profile(emit, field, fixed, length, dep, message)



if __name__ == '__main__':
    main()
