"""Bounded protocol structures and reproducible, complete reference fixtures.

Structure trees and guards describe wire semantics; only the declared BACnet
request subset has a StateAFL C encoder. No arbitrary expressions execute.
"""
import copy
import struct


def leaf(name, typ, **kw):
    return dict(id=name, kind='field', type=typ, **kw)


def container(name, kind, children, **kw):
    return dict(id=name, kind=kind, children=children, **kw)


OFFICIAL = {
    'bacnet': ('https://www.ashrae.org/technical-resources/bookstore/bacnet',
               'ASHRAE 135 identity/scope only; paid text not consulted; wire details from BACnet Stack 1.5.0'),
    'modbus': ('https://www.modbus.org/file/secure/modbusprotocolspecification.pdf',
               'Application Protocol V1.1b3 sections 4, 6.1-6.6, 6.11-6.12 and 7'),
    'iec104': ('https://webstore.iec.ch/en/publication/25035',
               'IEC 60870-5-104:2006+AMD1:2016 catalogue only; paid text not consulted'),
    'mms': ('https://www.rfc-editor.org/rfc/rfc1006',
            'RFC 1006 section 6 TPKT/COTP only; MMS/ACSE/session/presentation from libIEC61850'),
    'enip': ('https://www.odva.org/subscriptions-services/specifications/',
             'ODVA catalogue/subscription boundary only; paid volumes not consulted; wire details from OpENer'),
    'opcua': ('https://reference.opcfoundation.org/specs/OPC-10000-6/full',
              'Part 6 5.2 UA Binary, 6.7 UASC, 7.1 UACP; SecurityPolicy None, single final chunk'),
}


def transition(frm, to, mid, response='', guard='', actions=()):
    return dict(zip(('from','to','message','response','guard','actions'),(frm,to,mid,response,guard,list(actions))))


def enrich(p, st, field, fixed, length, dep, message):
    codec=p['codec']; url,sections=OFFICIAL[codec]
    p['sources'].append(dict(id='official',url=url,
        basis='normative' if codec in {'modbus','opcua','mms'} else 'inferred',sections=sections))
    msgs={m['id']:m for m in p['messages']}
    if codec=='bacnet':
        enrich_bacnet(p,st,msgs,field,fixed,length,dep,message)
    elif codec=='modbus':
        enrich_modbus(p,st,msgs,field,fixed,length,dep,message)
    elif codec=='iec104':
        enrich_iec104(p,st,msgs,field,fixed,length,dep,message)
    elif codec=='enip':
        enrich_enip(p,st,msgs,field,fixed,length,dep,message)
    for m in p['messages']:
        for b in m['blocks']:
            b['fields']=[f['id'] for f in m['fields'] if f['block']==b['id']]
        if not p['support']['runtime']:
            m['blocks'].append(dict(id='REQUEST',fields=[]))
            for b in m['blocks']:
                if b['id']!='REQUEST':b['parent']='REQUEST'


def enrich_bacnet(p,st,msgs,field,fixed,length,dep,message):
    common=copy.deepcopy(msgs['who_is']['fields'][:5])
    # A nonempty CharacterString includes its encoding octet. The old fixture
    # used length zero and omitted that octet, which was not a complete value.
    ack=msgs['read_property_ack']
    raw=bytearray.fromhex('810a0000010030010c0c0200007b194d3e7507004465766963653f')
    raw[2:4]=len(raw).to_bytes(2,'big');ack['example']=raw.hex()
    ack['notes']='Complete unsegmented ReadProperty ACK with object-name CharacterString "Device" (encoding 0). Response encoding is static only.'
    next(f for f in ack['fields'] if f['id']=='value')['default']=raw[9:].hex()
    # Confirmed requests set the NPDU expecting-reply bit; address flags remain
    # codec-managed dynamic structure rather than fixed APDU byte offsets.
    rp=msgs['read_property'];raw=bytearray.fromhex(rp['example']);raw[5]=4;rp['example']=raw.hex()
    next(f for f in rp['fields'] if f['id']=='npdu_control')['default']=4
    def add(mid, apdu, fields, deps=(), notes=''):
        raw=bytearray.fromhex('810a00000100'+apdu);raw[2:4]=len(raw).to_bytes(2,'big')
        p['messages'].append(message(mid,raw.hex(),copy.deepcopy(common)+fields,[dep('bvlc_length'),*deps],'response',notes=notes))
    add('i_am','1000c40200007b2205c491032100',[
        fixed('apdu_type','apdu.type',16),fixed('service','apdu.service',0),
        field('device_identifier','abs:9','uint32','content',33554555,structure='Application tag 12 ObjectIdentifier; type Device (8), instance 123.'),
        field('max_apdu_accepted','abs:14','uint16','content',1476),
        field('segmentation','abs:17','uint8','content',3,values=[0,1,2,3]),
        field('vendor_identifier','abs:19','uint8','content',0)],
        notes='I-Am is an unconfirmed service request on the wire; response denotes its role following Who-Is. It may also be unsolicited; no invoke correlation exists.')
    add('read_property_error','50010c91029120',[
        fixed('apdu_type','apdu.type',80),field('invoke_id','apdu.invoke',default=1,mutable='runtime_bound'),fixed('service','apdu.service',12),
        field('error_class','abs:10',default=2,values=[0,1,2,3,4,5,6,7]),field('error_code','abs:12',default=32,values=[31,32,42])],
        [dep('invoke_id','invoke_id','correlate_request_response',message='read_property',scope='transaction')],
        'BACnet Error: two application ENUMERATED values; class property(2), unknown-property(32).')
    for mid,typ,reason in [('reject',96,9),('abort',113,4)]:
        add(mid,f'{typ:02x}01{reason:02x}',[fixed('apdu_type','apdu.type',typ),
            field('invoke_id','apdu.invoke',default=1,mutable='runtime_bound'),field('reason','abs:8',default=reason)],
            [dep('invoke_id','invoke_id','correlate_request_response',message='read_property',scope='transaction')],
            'Reject has no service choice; its final octet is reason.' if mid=='reject' else 'Server Abort has server bit 0 set; final octet is reason (segmentation-not-supported in fixture).')
    st['transitions'][0]['response']='i_am'
    st['transitions'] += [transition('ready','ready','i_am',guard='unsolicited or matching Who-Is device range'),
        *[transition('pending','ready',mid,guard='matching outstanding invoke ID',actions=['clear selected invoke context']) for mid in ['read_property_error','reject','abort']]]
    p['scope']='BVLC Original-Unicast-NPDU, optional routed NPDU addresses; unsegmented Who-Is/I-Am; ReadProperty request/ACK/Error and Reject/server-Abort. Runtime generates only Who-Is and ReadProperty requests; response layouts are complete static descriptions.'
    for m in p['messages']:
        ctl=next(f for f in m['fields'] if f['id']=='npdu_control')
        ctl['structure_model']=container('npdu_addresses','sequence',[
            leaf('dnet','uint16-big',condition='control bit5 set'),leaf('dlen','uint8',condition='control bit5 set'),
            container('dadr','repeat',[leaf('octet','uint8')],min=0,max=255,condition='DLEN octets'),
            leaf('snet','uint16-big',condition='control bit3 set'),leaf('slen','uint8',condition='control bit3 set'),
            container('sadr','repeat',[leaf('octet','uint8')],min=1,max=255,condition='SLEN octets'),
            leaf('hop_count','uint8',condition='destination address present')],encoding='BACnet-NPDU')
    next(f for f in msgs['who_is']['fields'] if f['id']=='limits')['structure_model']=container('device_limits','choice',[
        leaf('absent','empty'),container('range','sequence',[leaf('low','context-unsigned',tag=0,min=0,max=4194303),
        leaf('high','context-unsigned',tag=1,min=0,max=4194303)],condition='both limits present and low <= high')],encoding='BACnet-LVT')
    next(f for f in ack['fields'] if f['id']=='value')['structure_model']=container('read_property_ack','sequence',[
        leaf('object_identifier','context-object-id',tag=0),leaf('property_identifier','context-unsigned',tag=1),
        leaf('array_index','context-unsigned',tag=2,condition='optional'),
        container('property_value','tlv',[leaf('value','BACnet-application-value')],tag=3)],encoding='BACnet-LVT-opening-closing')
    for f in msgs['read_property']['fields']:
        if f['id']=='property_id':f['structure']='Context tag 1 unsigned property identifier, 1..4 octets on wire; this runtime mutation field is limited to UInt8 values.'
        if f['id']=='array_index':f['structure']='Optional context tag 2 unsigned array index, 1..4 octets on wire; this runtime mutation field is limited to UInt8 values. Absence differs from index zero (array length).'


def enrich_modbus(p,st,msgs,field,fixed,length,dep,message):
    # FC0F quantity is independent, including non-byte-aligned coil counts.
    # Never infer it as 8*data length: the final byte contains padding bits.
    wc=msgs['write_coils'];wr=msgs['write_registers']
    for m in (wc,wr):
        is_coils=m is wc;q=next(f for f in m['fields'] if f['id']=='quantity')
        q.update(role='content',block='CONTENT',mutability='fuzzable',min=1,max=1968 if is_coils else 123,default=8 if is_coils else 1)
        m['dependencies']=[d for d in m['dependencies'] if d['target']!='quantity']
        data=next(f for f in m['fields'] if f['id']=='data')
        data['repeat']={'count':'byte_count' if is_coils else 'quantity','min':1,'max':246 if is_coils else 123,'element_width':1 if is_coils else 2}
        data['min']=1 if is_coils else 2;data['max']=246
        data['structure']='Byte count = ceil(quantity/8), LSB first, unused high bits in final octet zero.' if is_coils else 'Byte count = 2*quantity, big-endian UInt16 register values.'
        data['structure_model']=container('values','repeat',[leaf('value','packed-coils-LSB-first' if is_coils else 'uint16-big')],min=1,max=246 if is_coils else 123,encoding='ceil(quantity/8)-octets' if is_coils else 'quantity*2-octets')
        m['notes']='Cross-field semantic constraint: byte_count equals ceil(quantity/8) and unused high bits zero.' if is_coils else 'Cross-field semantic constraint: byte_count equals quantity*2.'
    # Include a non-aligned 9-coil complete request so padding semantics are
    # tested rather than merely mentioned in an annotation.
    odd=copy.deepcopy(wc);odd.update(id='write_coils_partial',match='write_coils_partial',example='000100000009010f00000009020101')
    next(f for f in odd['fields'] if f['id']=='quantity')['default']=9
    next(f for f in odd['fields'] if f['id']=='data')['default']='0101'
    p['messages'].append(odd);msgs[odd['id']]=odd
    for code,request,mid in [(1,'read_coils','read_coils_response'),(2,'read_discrete','read_discrete_response'),(4,'read_input','read_input_response')]:
        payload='01' if code<3 else '0001';base=copy.deepcopy(msgs['read_response']['fields'][:4])
        raw=f'00010000{(3+len(bytes.fromhex(payload))):04x}01{code:02x}{len(bytes.fromhex(payload)):02x}'+payload
        p['messages'].append(message(mid,raw,base+[fixed('function','abs:7',code),length('byte_count','abs:8','uint8'),field('data','abs:9','bytes','content',payload)],
            [dep('byte_count','data'),dep('length',add=-6),dep('transaction','transaction','correlate_request_response',message=request,scope='transaction')],'response'))
    # Write acknowledgements echo address and value/quantity, not the request's
    # byte count or variable data payload.
    for code,request in [(5,'write_coil'),(6,'write_register'),(15,'write_coils'),(15,'write_coils_partial'),(16,'write_registers')]:
        req=msgs[request];q='quantity' if code>=15 else 'value';fs=copy.deepcopy(req['fields'][:7])
        for f in fs:
            if f['id'] in {'address',q}:f.update(mutability='runtime_bound')
        raw=bytearray.fromhex(req['example'][:24]);raw[4:6]=(6).to_bytes(2,'big')
        p['messages'].append(message(request+'_response',raw.hex(),fs,[dep('length',add=-6),
            dep('transaction','transaction','correlate_request_response',message=request,scope='transaction'),
            dep('address','address','copy_from_message',message=request,scope='transaction'),dep(q,q,'copy_from_message',message=request,scope='transaction')],'response'))
    for m in p['messages']:
        function=next(f for f in m['fields'] if f['id']=='function')
        if m['id']=='write_coil':
            value=next(f for f in m['fields'] if f['id']=='value');value['structure']='Valid coil values are exactly 0x0000 (OFF) and 0xFF00 (ON); other UInt16 encodings require exception 03.'
        if m['id']=='read_response':m['notes']='FC03 response: byte count is twice the correlated requested register quantity.'
        if m['id']=='exception':
            function['structure']='Function equals correlated request function OR 0x80; exception applies to all supported request function families. Fixture correlates FC03.'
            m['notes']='Generic exception layout; fixture FC03/illegal-data-address(02). Exceptional responses have exactly one exception byte and no byte-count field.'
        if m['direction']=='response':
            corr=next((d for d in m['dependencies'] if d['op']=='correlate_request_response'),None)
            if corr:m['dependencies'].append(dep('unit','unit','copy_from_message',message=corr['message'],scope='transaction'))
        for f in m['fields']:f['evidence']='official';f['confidence']='normative'
    st['transitions']=[transition('connected','connected',m['id'],
        response=({'read_holding':'read_response'}.get(m['id'],m['id']+'_response') if m['direction']=='request' else ''),
        guard='transaction ID + unit + function correlation; success or corresponding exception',actions=['cache or clear selected MBAP transaction']) for m in p['messages']]
    p['scope']='Modbus TCP MBAP plus FC01/02/03/04 reads, FC05/06 single writes, FC0F/10 multiple writes; all normal response layouts and generic exception layout; FC0F arbitrary 1..1968 coils including final-byte padding. Complete static profile; no runtime encoder.'


def enrich_iec104(p,st,msgs,field,fixed,length,dep,message):
    req=msgs['interrogation']
    for f in req['fields']:
        if f['id']=='vsq':f.update(min=1,max=1,default=1,values=[1],structure='Exactly one information object; SQ=0 in this profile.')
        if f['id']=='ioa':f.update(min=0,max=0,default=0,values=[0])
        if f['id']=='qoi':f.update(min=20,max=36,values=list(range(20,37)))
        if f['id']=='cot':f.update(default=6,values=[6],structure='Low six bits cause=activation(6); bit6 P/N, bit7 test; high octet originator address.')
    for mid,cause in [('interrogation_confirmation',7),('interrogation_termination',10),('interrogation_negative',71)]:
        response=copy.deepcopy(req);raw=bytearray.fromhex(req['example']);raw[2:4]=(2 if cause==10 else 0).to_bytes(2,'little');raw[4:6]=(2).to_bytes(2,'little');raw[8:10]=cause.to_bytes(2,'little')
        response.update(id=mid,match=mid,direction='response',example=raw.hex(),notes='C_IC_NA_1 activation confirmation or activation termination. Negative confirmation sets P/N bit6; fixture cause 7+64.')
        next(f for f in response['fields'] if f['id']=='cot')['default']=cause
        next(f for f in response['fields'] if f['id']=='cot')['values']=[cause]
        next(f for f in response['fields'] if f['id']=='receive_seq')['default']=2
        next(f for f in response['fields'] if f['id']=='send_seq')['default']=2 if cause==10 else 0
        response['dependencies'] += [dep('common_address','common_address','copy_from_message',message='interrogation',scope='transaction'),dep('qoi','qoi','copy_from_message',message='interrogation',scope='transaction')]
        p['messages'].append(response)
    for m in p['messages']:
        for f in m['fields']:
            if f['id'] in {'send_seq','receive_seq'}:
                f.update(max=65534,structure='Wire UInt16 is logical 15-bit sequence shifted left one; bit0 zero. Each direction has independent N(S); N(R) acknowledges next expected peer I frame. Advance modulo 32768 only for I frames.')
    req['notes']='C_IC_NA_1 request: SQ=0/count=1, IOA=0, QOI 20 global or 21..36 group. Data ASDUs between confirmation/termination are excluded, so completion does not mean an empty remote database.'
    st['states'] += [dict(id='interrogating',meaning='Activation sent; confirmation pending'),dict(id='interrogation_data',meaning='Positive activation confirmation; data/termination pending')]
    st['transitions']=[t for t in st['transitions'] if t['message']!='interrogation']
    st['transitions'] += [transition('active','interrogating','interrogation','interrogation_confirmation','send window available',['increment local N(S)']),
        transition('interrogating','interrogation_data','interrogation_confirmation',guard='positive activation confirmation; matching CA/QOI'),
        transition('interrogating','active','interrogation_negative',guard='negative activation confirmation'),
        transition('interrogation_data','active','interrogation_termination',guard='matching CA/QOI; all preceding I frames acknowledged')]
    for t in st['transitions']:
        if t['message']=='test_act':t['response']='test_con'
    for state in ['stopped','interrogating','interrogation_data']:
        st['transitions'] += [transition(state,state,mid,'test_con' if mid=='test_act' else '',guard='TESTFR does not depend on transfer phase') for mid in ['test_act','test_con']]
    p['scope']='IEC104 APCI I/S/U; STARTDT/STOPDT/TESTFR; single-object C_IC_NA_1 global/group interrogation request, positive/negative activation confirmation and termination; COT/CA/IOA widths 2/2/3. Other data ASDUs excluded. Complete static profile; no runtime encoder.'


def enrich_enip(p,st,msgs,field,fixed,length,dep,message):
    # Registration establishes only an encapsulation session. SendUnitData's
    # class-3 connection and directional IDs must come from an external
    # successful ForwardOpen; static guards cannot establish that connection.
    p['messages']=[m for m in p['messages'] if m['id'] not in {'send_rr','send_unit'}]
    reg=msgs['register'];unreg=msgs['unregister']
    for m in (reg,unreg):
        m['fields']=[f for f in m['fields'] if f['id']!='payload']
        for i,f in enumerate(m['fields']):
            if f['id']=='session' and m is reg:m['fields'][i]=fixed('session','abs:4',0,'uint32','little')
            elif f['id']=='session':f['default']=1
    reg['fields'] += [fixed('protocol_version','abs:24',1,'uint16','little'),fixed('option_flags','abs:26',0,'uint16','little')]
    reg['notes']='RegisterSession request handle is zero. A successful response assigns a nonzero handle; Sender Context is echoed. Registration request alone does not establish a registered session.'
    response=copy.deepcopy(reg);raw=bytearray.fromhex(response['example']);raw[4:8]=(1).to_bytes(4,'little')
    response.update(id='register_response',match='register_response',direction='response',example=raw.hex(),notes='Successful RegisterSession response: version/options echoed, nonzero peer-assigned session handle, Sender Context echoed.')
    response['fields'][2]=field('session','abs:4','uint32',default=1,minimum=1,endian='little')
    response['dependencies'].append(dep('context','context','correlate_request_response',message='register',scope='transaction'))
    p['messages'].append(response)
    unreg['example']=(struct.pack('<HHIIQI',102,0,1,0,1,0)).hex()
    unreg['dependencies'].append(dep('session','session','bind_from_response',message='register_response',scope='connection'))
    unreg['notes']='UnregisterSession has no command-specific data and no response; closes registered encapsulation session and its connections.'
    def rr(mid,cip,response_to=None):
        direction='response' if response_to else 'request'
        cpf=struct.pack('<IHHHHHH',0,0,2,0,0,0xb2,len(cip))+cip
        raw=struct.pack('<HHIIQI',111,len(cpf),1,0,1,0)+cpf
        fs=copy.deepcopy(unreg['fields']);fs[0]=fixed('command','abs:0',111,'uint16','little')
        fs += [fixed('interface_handle','abs:24',0,'uint32','little'),field('timeout','abs:28','uint16',endian='little'),
            fixed('item_count','abs:30',2,'uint16','little'),fixed('address_type','abs:32',0,'uint16','little'),
            fixed('address_length','abs:34',0,'uint16','little'),fixed('data_type','abs:36',178,'uint16','little'),
            length('data_length','abs:38','uint16','little'),field('cip','abs:40','bytes','content',cip.hex())]
        deps=[dep('length',add=-24),dep('data_length','cip'),dep('session','session','bind_from_response',message='register_response',scope='connection')]
        fs += [fixed('cip_service','abs:40',cip[0])]
        if response_to:
            fs += [fixed('reserved','abs:41',0),field('general_status','abs:42',default=cip[2],values=[0,5,8,14,20]),
                length('additional_status_words','abs:43','uint8'),field('additional_status','cip:additional_status','bytes','content','',maximum=64),
                field('response_data','cip:response_data','bytes','content',cip[4:].hex(),maximum=4096)]
            deps += [dep('additional_status_words','additional_status','count_of',unit=2),dep('context','context','correlate_request_response',message=response_to,scope='transaction')]
            fs[-2]['structure_model']=container('additional_status','repeat',[leaf('word','uint16-little')],min=0,max=32,encoding='additional_status_words*2')
        else:
            fs += [length('path_words','abs:41','uint8'),field('epath','abs:42','epath','content',cip[2:].hex(),maximum=128)]
            deps.append(dep('path_words','epath','count_of',unit=2))
            fs[-1]['structure_model']=container('epath','repeat',[container('logical_segment','choice',[
                leaf('class8','segment-0x20-value8'),leaf('instance8','segment-0x24-value8'),leaf('attribute8','segment-0x30-value8')])],min=0,max=64,encoding='padded-16-bit-words')
        next(f for f in fs if f['id']=='item_count')['structure_model']=container('cpf','sequence',[
            leaf('interface_handle','uint32-little-zero'),leaf('timeout','uint16-little'),leaf('item_count','uint16-little-2'),
            container('items','repeat',[container('item','tlv',[leaf('type','uint16-little'),leaf('length','uint16-little'),leaf('data','length-octets')])],min=2,max=2)],encoding='CPF NullAddress followed by UnconnectedData')
        p['messages'].append(message(mid,raw.hex(),fs,deps,direction,notes='CIP GetAttributeSingle Identity class 1/instance 1/attribute 1 (Vendor ID). Response bit7 set; additional-status size counts UInt16 words.'))
    rr('send_rr',bytes.fromhex('0e03200124013001'))
    rr('send_rr_response',bytes.fromhex('8e0000000100'),'send_rr')
    rr('send_rr_error',bytes.fromhex('8e001400'),'send_rr')
    # Complete connected packets, with explicit external connection ownership.
    # OpENer uses the consumed O->T ID for lookup, switches to produced T->O
    # ID in the response, and echoes the UInt16 class-3 sequence number.
    for mid,template,cip,cid in [
        ('send_unit','send_rr',bytes.fromhex('0e03200124013001'),0x10000001),
        ('send_unit_response','send_rr_response',bytes.fromhex('8e0000000100'),0x20000001)]:
        m=copy.deepcopy(next(x for x in p['messages'] if x['id']==template))
        payload=struct.pack('<IHHHHIHHH',0,0,2,0xa1,4,cid,0xb1,2+len(cip),1)+cip
        raw=struct.pack('<HHIIQI',112,len(payload),1,0,1,0)+payload
        m.update(id=mid,match=mid,example=raw.hex())
        for i,f in enumerate(m['fields']):
            fid=f['id']
            if fid=='command':m['fields'][i]=fixed('command','abs:0',112,'uint16','little')
            elif fid=='timeout':m['fields'][i]=fixed('timeout','abs:28',0,'uint16','little')
            elif fid=='address_type':m['fields'][i]=fixed('address_type','abs:32',0xa1,'uint16','little')
            elif fid=='address_length':m['fields'][i]=fixed('address_length','abs:34',4,'uint16','little')
            elif fid=='data_type':m['fields'][i]=fixed('data_type','abs:40',0xb1,'uint16','little')
            elif f['locator'].startswith('abs:'):
                off=int(f['locator'][4:])
                if off>=36:f['path']=f['locator']=f'abs:{off+(4 if off<40 else 6)}'
        m['fields'] += [field('connection_id','abs:36','uint32',default=cid,minimum=1,endian='little',mutable='conditional',
            structure='Externally negotiated O->T consumed ID in request; T->O produced ID in response. These illustrative IDs require replacement from successful external ForwardOpen on the same session; no model writer establishes them.'),
            field('connected_sequence','abs:44','uint16',default=1,endian='little',
                mutable='runtime_bound' if mid.endswith('_response') else 'conditional',
                structure='Class-3 sequence UInt16 precedes CIP; request advances modulo 65536, response echoes this request sequence. It is separate from Sender Context and CIP service bytes.')]
        for d in m['dependencies']:
            if d['target']=='data_length':d['add']=2
            if d.get('message')=='send_rr':d['message']='send_unit'
        m['dependencies'].append(dep('connected_sequence','connected_sequence','copy_from_message',message='send_unit',scope='transaction') if mid.endswith('_response') else dep('connected_sequence','$message','sequence_number',scope='connection'))
        count=next(f for f in m['fields'] if f['id']=='item_count')
        count['structure_model']=container('cpf','sequence',[
            leaf('interface_handle','uint32-little-zero'),leaf('timeout','uint16-little-zero'),leaf('item_count','uint16-little-2'),
            container('connected_address','tlv',[leaf('connection_id','UInt32-little-direction-specific')],tag=0xa1,encoding='UInt16 type + UInt16 length=4'),
            container('connected_data','tlv',[leaf('connected_sequence','UInt16-little'),leaf('cip','complete-CIP-request-or-response')],tag=0xb1,encoding='UInt16 type + UInt16 length=2+CIP-octets')],encoding='CPF-class3-connected-explicit')
        m['notes']='Complete static SendUnitData packet: ConnectedAddress(0xA1,length=4), ConnectedData(0xB1) with UInt16 sequence plus complete GetAttributeSingle CIP. EXTERNAL PRECONDITION: a successful ForwardOpen has already established an unexpired class-3 explicit connection in this registered session and supplied both directional connection IDs. RegisterSession alone is insufficient. IDs 0x10000001/0x20000001 are illustrative placeholders, not an automatically established connection; no ForwardOpen fixture or automatic provisioning is claimed.'
        for f in m['fields']:f['evidence']='wire';f['confidence']='implementation'
        p['messages'].append(m)
    # Encapsulation-layer failures do not contain a CPF/CIP response body.
    for mid,command,status,request in [('register_error',101,0x69,'register'),('invalid_session',111,0x64,'send_rr')]:
        raw=struct.pack('<HHIIQI',command,0,0 if request=='register' else 1,status,1,0)
        fs=copy.deepcopy(unreg['fields']);fs[0]=fixed('command','abs:0',command,'uint16','little');fs[3]=fixed('status','abs:8',status,'uint32','little')
        fs[2]=field('session','abs:4','uint32',default=0 if request=='register' else 1,endian='little')
        p['messages'].append(message(mid,raw.hex(),fs,[dep('length',add=-24),dep('context','context','correlate_request_response',message=request,scope='transaction')],'response',notes='Encapsulation status error; no command payload in this fixture.'))
    st['states']=[dict(id='connected',meaning='TCP connected; session unregistered'),dict(id='registering',meaning='RegisterSession response pending'),dict(id='registered',meaning='Successful response assigned nonzero session handle; class-3 connection availability is a separate external prerequisite, never implied by this state'),dict(id='closed',meaning='Session unregistered/transport closed')]
    st['transitions']=[
        transition('connected','registering','register','register_response'),
        transition('registering','registered','register_response',guard='status=0; version=1; nonzero assigned handle',actions=['cache peer session handle']),
        transition('registering','connected','register_error',guard='nonzero encapsulation status'),
        transition('registered','registered','send_rr','send_rr_response','valid session; cache Sender Context'),
        transition('registered','registered','send_rr_response',guard='echoed context, service bit7, general status=0'),
        transition('registered','registered','send_rr_error',guard='echoed context and nonzero CIP general status'),
        transition('registered','registered','send_unit','send_unit_response',guard='EXTERNAL PRECONDITION: successful ForwardOpen already established an unexpired class-3 explicit connection on this session; use external O->T consumed ID and T->O produced ID',actions=['advance externally initialized class-3 UInt16 sequence modulo 65536; cache Sender Context']),
        transition('registered','registered','send_unit_response',guard='external class-3 connection remains established; produced T->O ID; echoed connected sequence and Sender Context',actions=['clear selected connected request context']),
        transition('registered','connected','invalid_session',guard='encapsulation status invalid session',actions=['clear session handle']),
        transition('registered','closed','unregister',guard='matching session handle; no reply',actions=['clear session and connection contexts'])]
    p['scope']='EtherNet/IP TCP RegisterSession success/failure, UnregisterSession (no reply), SendRRData (NullAddress + UnconnectedData), SendUnitData (ConnectedAddress + ConnectedData with UInt16 class-3 sequence), complete GetAttributeSingle Identity Vendor-ID request/response layouts and encapsulation/CIP errors. SendUnitData requires an externally successful ForwardOpen establishing class-3 connection and supplying directional IDs; this model does not establish that prerequisite. Complete static explicit-message profile; no runtime encoder.'
    p['sources'][0].update(url='https://github.com/EIPStackGroup/OpENer/tree/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src',sections='encap.c; cpf.c NotifyConnectedCommonPacketFormat/AssembleLinearMessage; cipconnectionmanager.c GetConnectedObject/AssembleForwardOpenResponse; cipclass3connection.c EstablishClass3Connection. ForwardOpen request is not a verified fixture in this profile.')
    p['support']['excluded']=['ForwardOpen/ForwardClose fixture generation and automatic class-3 connection establishment (external prerequisite for SendUnitData)' ,'implicit UDP I/O','CIP Security','other CIP objects/services','full subscription-only ODVA normative conformance']


# Captured from the public reference implementation at the pinned revision,
# entirely on loopback; no runtime support is inferred from this exchange.
MMS_FIXTURES = {'cotp_cr': '0300001611e00000000100c0010dc2020001c1020001',
 'cotp_cc': '0300001611d00001000100c0010dc2020001c1020001',
 'associate': '030000bb02f0800db20506130100160102140200023302000134020001c19c318199a003800101a28191810400000001820400000001a423300f0201010604520100013004060251013010020103060528ca220201300406025101615e305c020101a0576055a107060528ca220203a20706052901876701a30302010ca606060429018767a70302010cbe2f282d020103a028a826800300fde881010582010583010aa416800101810305f100820c03ee1c00000408000079ef18',
 'associate_response': '0300008f02f0800e8605061301001601021402000234020001c1743172a003800101a26b830400000001a512300780010081025101300780010081025101614f304d020101a0486146a107060528ca220203a203020100a305a103020100be2f282d020103a028a926800300fde881010582010583010aa416800101810305f100820c03ee1c000000000000000118',
 'get_name_list': '0300002402f0800100010061173015020103a010a00e020101a109a003800109a1028000',
 'get_name_list_response': '0300003302f0800100010061263024020103a01fa11d020101a118a0131a1173696d706c65494f47656e65726963494f810100',
 'read': '0300005002f0800100010061433041020103a03ca03a020102a435a133a031302fa02da12b1a1173696d706c65494f47656e65726963494f1a164747494f31244443244e616d506c742476656e646f72',
 'read_response': '0300001f02f0800100010061123010020103a00ba109020102a404a1028a00',
 'write': '0300005702f08001000100614a3048020103a043a041020103a53ca031302fa02da12b1a1173696d706c65494f47656e65726963494f1a164747494f31244443244e616d506c742476656e646f72a0078a056175646974',
 'write_response': '0300001d02f080010001006110300e020103a009a107020103a5028100',
 'conclude': '0300001602f0800100010061093007020103a0028b00',
 'conclude_response': '0300001602f0800100010061093007020103a0028c00',
 'release': '0300001902f0800910c10e610c300a020101a0056203800100',
 'release_response': '0300001602f0800a0dc10b61093007020101a0026300'}


def mms_profile(emit, field, fixed, length, dep, message):
    tp=[fixed('version','abs:0',3),fixed('reserved','abs:1',0),length('tpkt_length','abs:2')]
    messages=[]
    for mid,rawhex in MMS_FIXTURES.items():
        raw=bytes.fromhex(rawhex);response=mid.endswith('_response') or mid=='cotp_cc'
        fs=copy.deepcopy(tp);deps=[dep('tpkt_length')]
        if mid in {'cotp_cr','cotp_cc'}:
            fs += [length('cotp_li','abs:4','uint8'),fixed('cotp_type','abs:5',raw[5]),
                field('destination_reference','abs:6','uint16',default=int.from_bytes(raw[6:8],'big')),
                field('source_reference','abs:8','uint16',default=1),fixed('class_options','abs:10',0),
                field('cotp_parameters','abs:11','bytes','content',raw[11:].hex())]
            deps.append(dep('cotp_li',add=-5))
            fs[-1]['structure_model']=container('cotp_parameters','sequence',[
                leaf('tpdu_size','TLV-0xC0-exponent',min=7,max=16),
                leaf('called_tsap','TLV-0xC2-octets'),leaf('calling_tsap','TLV-0xC1-octets')],encoding='COTP-TP0-parameters')
            if response:deps.append(dep('destination_reference','source_reference','correlate_request_response',message='cotp_cr',scope='connection'))
            notes='Complete RFC1006 TP0 connection request/confirm. LI counts bytes after LI, excluding TPKT; negotiated max TPDU is 2**13 in these reference fixtures.'
        else:
            if raw[7:11]==bytes.fromhex('01000100'):
                presentation_start=11
            else:
                presentation_start=9
                while raw[presentation_start]!=0xc1:
                    presentation_start+=2+raw[presentation_start+1]
                presentation_start+=2
            fs += [fixed('cotp_li','abs:4',2),fixed('cotp_type','abs:5',240),fixed('eot','abs:6',128),
                field('session','iso:session','bytes','content',raw[7:presentation_start].hex()),
                field('pdu','ber:presentation','ber_tlv','content',raw[presentation_start:].hex())]
            deps.append(dep('pdu','$message','tagged_length'))
            session=fs[-2];pdu=fs[-1]
            if mid in {'associate','associate_response'}:
                session['structure_model']=container('session','sequence',[
                    leaf('spdu_type','CONNECT-0x0D' if not response else 'ACCEPT-0x0E'),leaf('spdu_length','uint8'),
                    leaf('connect_accept_item','TLV-0x05-protocol-options-and-version2'),leaf('session_requirement','TLV-0x14-duplex'),
                    leaf('calling_selector','TLV-0x33',condition='CONNECT'),leaf('called_selector','TLV-0x34'),
                    leaf('user_data','TLV-0xC1-presentation')],encoding='ISO-session-short-length-profile')
                detail=container('initiate_detail','tlv',[leaf('version','context-Integer',tag=0),
                    leaf('parameter_cbb','context-BIT-STRING-unused-bits-first',tag=1),leaf('services_supported','context-BIT-STRING-unused-bits-first',tag=2)],tag=4)
                initiate=container('initiate','tlv',[leaf('local_detail','context-Unsigned32',tag=0),leaf('max_outstanding_calling','context-Unsigned16',tag=1),
                    leaf('max_outstanding_called','context-Unsigned16',tag=2),leaf('nesting_level','context-Unsigned8',tag=3),detail],tag=9 if response else 8)
                acse_fields=[leaf('application_context','OID-1.0.9506.2.3',tag=1)]
                acse_fields += [leaf('result','INTEGER-accepted-zero',tag=2),leaf('result_source_diagnostic','ACSE-user-zero',tag=3)] if response else [
                    leaf('called_ap_title','OID',tag=2),leaf('called_ae_qualifier','INTEGER',tag=3),leaf('calling_ap_title','OID',tag=6),leaf('calling_ae_qualifier','INTEGER',tag=7)]
                acse_fields += [container('user_information','tlv',[container('external','tlv',[leaf('indirect_reference','INTEGER-3'),container('single_asn1_type','tlv',[initiate],tag=0)],tag=8)],tag=30)]
                pdu['structure_model']=container('presentation_connect','sequence',[
                    leaf('mode_selector','normal-mode'),leaf('presentation_selectors','calling/called-or-responding-octets'),
                    leaf('context_definitions_or_results','ACSE-context-1/MMS-context-3-BER-transfer-syntax'),
                    container('fully_encoded_data','sequence',[leaf('context_id','INTEGER-1'),container('acse','tlv',acse_fields,tag=1 if response else 0)])],encoding='BER-CP/CPA-SET')
                fs += [field('presentation_context','ber:presentation.context','uint8',default=1),
                    field('max_outstanding_calling','ber:initiate.calling','uint16',default=5),field('max_outstanding_called','ber:initiate.called','uint16',default=5),
                    field('nesting_level','ber:initiate.nesting','uint8',default=10),field('version','ber:initiate.version','uint8',default=1)]
                # TPKT version and initiate version are different fields.
                fs[-1]['id']='mms_version'
                if response:fs.append(fixed('association_result','ber:acse.result',0))
                notes='Complete TPKT/COTP + session CONNECT/ACCEPT + presentation CP/CPA + ACSE AARQ/AARE; MMS initiate request/response is nested in user-information, never an independent TCP message.'
            else:
                is_release=mid.startswith('release')
                session['structure_model']=container('session','sequence',[
                    leaf('spdu','FINISH-0x09' if mid=='release' else 'DISCONNECT-0x0A' if is_release else 'give-tokens-0x0100-data-0x0100'),
                    leaf('user_data','parameter-0xC1' if is_release else 'presentation-follows')],encoding='ISO-session')
                body=[];base=mid.removesuffix('_response')
                if base in {'get_name_list','read','write'}:
                    invoke={'get_name_list':1,'read':2,'write':3}[base]
                    fs.append(field('invoke_id','ber:mms.invoke','uint32',default=invoke))
                    if response:deps.append(dep('invoke_id','invoke_id','correlate_request_response',message=base,scope='transaction'))
                    name=container('domain_specific_name','sequence',[leaf('domain_id','VisibleString'),leaf('item_id','VisibleString')],encoding='ObjectName-domain-specific-[1]')
                    access=container('variable_access','choice',[container('list_of_variable','repeat',[container('variable','sequence',[name])],min=1,max=64),leaf('variable_list_name','ObjectName')])
                    if base=='get_name_list':
                        body=[container('identifiers','repeat',[leaf('identifier','VisibleString')],min=0,max=64),leaf('more_follows','context-BOOLEAN',tag=1)] if response else [
                            leaf('object_class','ExtendedObjectClass-basic-domain-9',tag=0),leaf('object_scope','ObjectScope-vmd-specific-NULL',tag=1),leaf('continue_after','Identifier',tag=2,condition='optional')]
                    elif base=='read':
                        body=[container('access_results','repeat',[container('result','choice',[leaf('failure','DataAccessError-context-0'),leaf('success','MMS-Data-choice')])],min=1,max=64)] if response else [
                            leaf('specification_with_result','BOOLEAN-default-false',tag=0,condition='optional'),access]
                    else:
                        body=[container('write_results','repeat',[container('result','choice',[leaf('failure','DataAccessError-context-0'),leaf('success','NULL-context-1')])],min=1,max=64)] if response else [
                            access,container('list_of_data','repeat',[leaf('data','MMS-Data-choice')],min=1,max=64)]
                    service=container('service','tlv',body,tag={'get_name_list':1,'read':4,'write':5}[base])
                    body=[container('confirmed','tlv',[leaf('invoke_id','Unsigned32-universal-INTEGER'),service],tag=1 if response else 0)]
                    if base in {'read','write'} and not response:
                        fs += [field('domain_id','ber:mms.domain','string','content','simpleIOGenericIO'),field('item_id','ber:mms.item','string','content','GGIO1$DC$NamPlt$vendor')]
                        if base=='write':fs.append(field('value','ber:mms.data','string','content','audit'))
                elif base=='conclude':body=[leaf('conclude','MMS-conclude-response-NULL-tag12' if response else 'MMS-conclude-request-NULL-tag11')]
                else:body=[container('acse_release','tlv',[leaf('reason','normal-context-0',condition='request optional reason')],tag=3 if response else 2)]
                pdu['structure_model']=container('fully_encoded_data','sequence',[leaf('context_id','INTEGER-1' if is_release else 'INTEGER-3'),container('single_asn1_type','tlv',body,tag=0)],encoding='BER-application-1-PDV-list')
                notes='Complete reference profile message, including session DATA and presentation context 3.' if not is_release else 'Complete session FINISH/DISCONNECT carrying presentation context 1 and ACSE RLRQ/RLRE; distinct from MMS conclude handshake.'
        messages.append(message(mid,rawhex,fs,deps,'response' if response else 'request',notes=notes))
    states=[('tcp','TCP connected'),('cotp_pending','CR sent; CC required'),('cotp','COTP TP0 established'),('association_pending','AARQ/embedded-initiate sent'),('associated','AARE accepted and initiate response negotiated'),('concluding','MMS conclude response pending'),('concluded','MMS conclude accepted; association release remains'),('releasing','ACSE/session release response pending'),('closed','Association and transport released')]
    transitions=[('tcp','cotp_pending','cotp_cr','cotp_cc','',[]),('cotp_pending','cotp','cotp_cc','','matching transport reference',[]),
        ('cotp','association_pending','associate','associate_response','',[]),('association_pending','associated','associate_response','','AARE result accepted and valid initiate response',['cache negotiated limits']),
        *[('associated','associated',mid,mid+'_response','unique invoke ID within negotiated outstanding limit',['cache invoke context']) for mid in ['get_name_list','read','write']],
        *[('associated','associated',mid+'_response','','matching pending invoke ID',['clear invoke context']) for mid in ['get_name_list','read','write']],
        ('associated','concluding','conclude','conclude_response','no pending confirmed services',[]),('concluding','concluded','conclude_response','','conclude accepted',[]),
        ('concluded','releasing','release','release_response','',[]),('releasing','closed','release_response','','session disconnect and ACSE release complete',[])]
    emit('iec61850_mms_tcp','IEC 61850 MMS over TCP','RFC1006 / libIEC61850 v1.6 profile',
        'Complete TPKT/COTP TP0, session/presentation normal-mode association, ACSE AARQ/AARE with embedded MMS initiate, VMD-domain GetNameList, one domain-specific named-variable Read/Write, MMS conclude and ACSE/session release, all successful request/response layouts. BER definite lengths; no runtime encoder.',
        'mms',messages,states,transitions,
        'https://github.com/mz-automation/libiec61850/tree/6d231326bff8e9b6500aa1e345c076d3a329f211/src/mms',
        'iso_cotp, iso_session, iso_presentation, iso_acse, iso_mms client/server and asn1c definitions; complete loopback fixtures constructed with this revision',
        ['full IEC61850 ACSI mapping','reports/GOOSE/SV','generalized arrays/alternate access and data-set services','arbitrary ACSE authentication','association rejection/abort and MMS confirmed-error/reject fixtures unverified','TLS','runtime BER encoding'],
        extra_sources=[dict(id='iec_scope',url='https://webstore.iec.ch/en/publication/6021',basis='inferred',sections='IEC61850-8-1 catalogue only; paid normative MMS/IEC texts not consulted')])


def build_ua_fixtures():
 """Build deterministic complete fixtures using only struct.

 Values represent the reference date 2026-10-25T00:00:00Z. They are static
 examples: channel/token 1 are illustrative peer-assigned values, not handles
 which may be reused against a fresh connection.
 """
 def u32(n):return struct.pack('<I',n)
 def i64(n):return struct.pack('<q',n)
 def string(s):
  if s is None:return struct.pack('<i',-1)
  b=s.encode('utf-8');return struct.pack('<i',len(b))+b
 def array(values):return struct.pack('<i',len(values))+b''.join(values)
 def node(n):return b'\x01\x00'+struct.pack('<H',n)
 def request(handle):
  return b'\x00\x00'+i64(timestamp)+u32(handle)+u32(0)+string('')+u32(10000)+b'\x00\x00\x00'
 def response(handle,status=0):
  return i64(timestamp)+u32(handle)+u32(status)+b'\x00'+array([])+b'\x00\x00\x00'
 def wire(typ,body):return typ.encode('ascii')+b'F'+u32(8+len(body))+body
 def secure(typ,channel,seq,request_id,body):
  sec=asym if typ=='OPN' else u32(1)
  return wire(typ,u32(channel)+sec+u32(seq)+u32(request_id)+body)
 timestamp=134373600000000000
 endpoint='opc.tcp://127.0.0.1:4840'
 server_uri='urn:example:local:server'
 policy='http://opcfoundation.org/UA/SecurityPolicy#None'
 null=struct.pack('<i',-1)
 asym=string(policy)+null+null
 negotiate=u32(0)+u32(65536)+u32(65536)+u32(0)+u32(0)
 application=(string(server_uri)+string('urn:example:profile')+
              b'\x02'+string('Local example server')+u32(0)+null+null+
              array([string(endpoint)]))
 token=string('anonymous')+u32(0)+null+null+null
 endpoint_description=(string(endpoint)+application+null+u32(1)+string(policy)+
                       array([token])+string('http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary')+b'\x00')
 return {
  'hello':wire('HEL',negotiate+string(endpoint)),
  'ack':wire('ACK',negotiate),
  'error':wire('ERR',u32(0x80830000)+string('Unknown endpoint')),
  'reverse_hello':wire('RHE',string(server_uri)+string(endpoint)),
  'open_channel':secure('OPN',0,1,1,node(446)+request(1)+u32(0)+u32(0)+u32(1)+null+u32(600000)),
  'open_channel_response':secure('OPN',1,1,1,node(449)+response(1)+u32(0)+u32(1)+u32(1)+i64(timestamp)+u32(600000)+null),
  'message':secure('MSG',1,2,2,node(428)+request(2)+string(endpoint)+array([])+array([])),
  'message_response':secure('MSG',1,2,2,node(431)+response(2)+array([endpoint_description])),
  'service_fault':secure('MSG',1,2,2,node(397)+response(2,0x800b0000)),
  'close_channel':secure('CLO',1,3,3,node(452)+request(3)),
 }


def opcua_profile(emit,field,fixed,length,dep,message):
    messages=[]
    fixtures=build_ua_fixtures()
    for mid,raw in fixtures.items():
        typ=raw[:3].decode();is_response=mid in {'ack','error','reverse_hello','open_channel_response','message_response','service_fault'}
        fs=[fixed('message_type','abs:0',int.from_bytes(raw[:3],'little'),'uint24','little'),fixed('chunk','abs:3',70),length('message_size','abs:4','uint32','little'),
            field('body','abs:8','bytes','content',raw[8:].hex(),maximum=65507)]
        deps=[dep('message_size')];nodes=[]
        if typ in {'HEL','ACK'}:
            for i,key in enumerate(['protocol_version','receive_buffer','send_buffer','max_message_size','max_chunk_count']):
                fs.append(field(key,f'abs:{8+i*4}','uint32',default=int.from_bytes(raw[8+i*4:12+i*4],'little'),endian='little'))
                nodes.append(leaf(key,'UInt32-little'))
            if typ=='HEL':fs.append(field('endpoint','uabin:endpoint','string','content','opc.tcp://127.0.0.1:4840'));nodes.append(leaf('endpoint_url','String-Int32-length-UTF8'))
        elif typ=='ERR':
            fs += [field('error_code','abs:8','uint32',default=0x80830000,endian='little'),field('reason','uabin:reason','string','content','Unknown endpoint')]
            nodes=[leaf('error','StatusCode'),leaf('reason','String')]
        elif typ=='RHE':
            fs += [field('server_uri','uabin:server_uri','string','content','urn:example:local:server'),field('endpoint','uabin:endpoint','string','content','opc.tcp://127.0.0.1:4840')]
            nodes=[leaf('server_uri','String'),leaf('endpoint_url','String')]
        else:
            opn=typ=='OPN';offset=79 if opn else 24;seq_offset=71 if opn else 16;handle=1 if opn else 3 if typ=='CLO' else 2
            channel=0 if mid=='open_channel' else 1
            fs += [fixed('channel','abs:8',0,'uint32','little') if not channel else field('channel','abs:8','uint32',default=1,endian='little',mutable='runtime_bound' if not opn else 'fuzzable'),
                field('sequence',f'abs:{seq_offset}','uint32',default=int.from_bytes(raw[seq_offset:seq_offset+4],'little'),endian='little'),
                field('request_id',f'abs:{seq_offset+4}','uint32',default=handle,endian='little'),
                field('service_nodeid',f'abs:{offset}','nodeid','content',raw[offset:offset+4].hex()),
                field('request_handle','uabin:header.request_handle','uint32',default=handle,endian='little')]
            if opn:
                fs += [field('policy_uri','uabin:policy_uri','string','content','http://opcfoundation.org/UA/SecurityPolicy#None'),
                    field('sender_certificate','uabin:sender_certificate','bytes','content','',structure='Int32 length -1 means null in None profile.'),
                    field('receiver_thumbprint','uabin:receiver_thumbprint','bytes','content','',structure='Int32 length -1 means null in None profile.')]
                if is_response:
                    fs += [field('token','uabin:token.token_id','uint32',default=1,endian='little'),field('token_channel','uabin:token.channel_id','uint32',default=1,endian='little'),
                        field('created_at','uabin:token.created_at','uint64',default=134373600000000000,endian='little'),field('revised_lifetime','uabin:token.lifetime','uint32',default=600000,endian='little')]
                    deps += [dep('request_id','request_id','correlate_request_response',message='open_channel',scope='transaction'),dep('request_handle','request_handle','copy_from_message',message='open_channel',scope='transaction')]
                else:
                    fs += [fixed('protocol_version','uabin:open.protocol_version',0,'uint32','little'),fixed('request_type','uabin:open.request_type',0,'uint32','little'),
                        fixed('security_mode','uabin:open.security_mode',1,'uint32','little'),field('requested_lifetime','uabin:open.lifetime','uint32',default=600000,endian='little')]
            else:
                fs.append(field('token','abs:12','uint32',default=1,endian='little',mutable='runtime_bound'))
                deps += [dep('channel','channel','bind_from_response',message='open_channel_response',scope='connection'),dep('token','token','bind_from_response',message='open_channel_response',scope='connection')]
                if is_response:deps += [dep('request_id','request_id','correlate_request_response',message='message',scope='transaction'),dep('request_handle','request_handle','copy_from_message',message='message',scope='transaction')]
            deps.append(dep('sequence','$message','sequence_number',scope='connection'))
            header=container('response_header' if is_response else 'request_header','sequence',[
                *([] if is_response else [leaf('authentication_token','NodeId-null-for-discovery')]),leaf('timestamp','DateTime-Int64'),leaf('request_handle','UInt32'),
                *([leaf('service_result','StatusCode'),leaf('service_diagnostics','DiagnosticInfo'),container('string_table','repeat',[leaf('string','String')],min=0,max=64)] if is_response else [
                    leaf('return_diagnostics','UInt32'),leaf('audit_entry_id','String'),leaf('timeout_hint','UInt32')]),leaf('additional_header','ExtensionObject')])
            nodes=[leaf('secure_channel_id','UInt32'),leaf('security_header','AsymmetricAlgorithmHeader-3-Strings' if opn else 'SymmetricAlgorithmHeader-TokenId'),
                leaf('sequence_number','UInt32'),leaf('request_id','UInt32'),leaf('encoding_id','NodeId'),header]
            if opn:
                nodes += [leaf('server_protocol_version' if is_response else 'client_protocol_version','UInt32'),
                    *([container('security_token','sequence',[leaf('channel_id','UInt32'),leaf('token_id','UInt32'),leaf('created_at','DateTime'),leaf('revised_lifetime','UInt32')])] if is_response else [
                        leaf('request_type','SecurityTokenRequestType-Issue'),leaf('security_mode','MessageSecurityMode-None-1')]),
                    leaf('nonce','ByteString-null-for-None'),*([] if is_response else [leaf('requested_lifetime','UInt32')])]
            elif mid=='message':
                nodes += [leaf('endpoint_url','String'),container('locale_ids','repeat',[leaf('locale','String')],min=0,max=64),container('profile_uris','repeat',[leaf('uri','String')],min=0,max=64)]
                fs.append(field('endpoint','uabin:endpoint','string','content','opc.tcp://127.0.0.1:4840'))
            elif mid=='message_response':
                application=container('server','sequence',[leaf('application_uri','String'),leaf('product_uri','String'),leaf('application_name','LocalizedText'),leaf('application_type','UInt32'),leaf('gateway_uri','String'),leaf('discovery_profile_uri','String'),container('discovery_urls','repeat',[leaf('url','String')],min=0,max=64)])
                token=container('user_token_policy','sequence',[leaf('policy_id','String'),leaf('token_type','UInt32'),leaf('issued_token_type','String'),leaf('issuer_endpoint_url','String'),leaf('security_policy_uri','String')])
                nodes.append(container('endpoints','repeat',[container('endpoint','sequence',[leaf('endpoint_url','String'),application,leaf('certificate','ByteString'),leaf('security_mode','UInt32'),leaf('security_policy_uri','String'),container('user_tokens','repeat',[token],min=0,max=64),leaf('transport_profile_uri','String'),leaf('security_level','Byte')])],min=0,max=64,encoding='Int32-count-then-EndpointDescription'))
            if is_response:fs.append(field('service_result','uabin:header.service_result','uint32',default=0x800b0000 if mid=='service_fault' else 0,endian='little'))
        fs[3]['structure_model']=container('ua_binary_body','sequence',nodes,encoding='UA-Binary-little-endian; String/ByteString/array use signed-Int32 count; -1 null')
        for f in fs:f['evidence']='wire' if typ=='CLO' else 'official';f['confidence']='implementation' if typ=='CLO' else 'normative'
        notes='Complete single final chunk in None profile. Assigned channel/token values are examples and must be replaced from a fresh OpenSecureChannel response.'
        if mid=='message':notes+=' MSG carries complete GetEndpoints Discovery request; this service does not require CreateSession/ActivateSession.'
        if mid=='reverse_hello':notes+=' RHE is sent by the server in reverse-connect mode; it does not itself negotiate a SecureChannel.'
        if mid=='close_channel':notes+=' Implementation profile includes binary encoding NodeId 452 plus RequestHeader; Part6 7.1.4 says empty body. This wording difference is unresolved, so CLO is implementation evidence, not asserted full normative conformance. No response is sent.'
        messages.append(message(mid,raw.hex(),fs,deps,'response' if is_response else 'request',notes=notes))
    states=[('tcp','TCP connected'),('hello_sent','HEL sent; ACK pending'),('acknowledged','ACK buffers negotiated'),('channel_pending','OpenSecureChannel Issue sent'),('channel','Successful OpenSecureChannel response; unexpired token bound, no Session'),('closed','Transport/channel closed')]
    transitions=[('tcp','hello_sent','hello','ack','',[]),('hello_sent','acknowledged','ack','','negotiation accepted',[]),
        ('acknowledged','channel_pending','open_channel','open_channel_response','SecurityPolicy None; request type Issue',[]),
        ('channel_pending','channel','open_channel_response','','service_result Good; channel/token assigned',['bind channel and token; track expiry']),
        ('channel','channel','message','message_response','token valid; GetEndpoints requires no Session',['advance per-direction sequence; cache request ID/handle']),
        ('channel','channel','message_response','','matching request ID/handle',['clear request context']),('channel','channel','service_fault','','matching request ID/handle; Bad status',['clear request context']),
        ('channel','closed','close_channel','','no response expected',['clear token/channel']),('tcp','tcp','reverse_hello','','reverse-connect role only',[]),
        *[(state,'closed','error','','transport error closes connection',[]) for state in ['tcp','hello_sent','acknowledged','channel_pending','channel']]]
    emit('opcua_tcp','OPC UA TCP','OPC10000 Part4/6 v1.05 / asyncua interoperability profile',
        'Complete HEL/ACK/ERR/RHE and single-final-chunk UASC SecurityPolicy None Issue OpenSecureChannel request/response, GetEndpoints Discovery request/response, ServiceFault, implementation-profile CloseSecureChannel. Complete UA Binary headers and nested endpoint/token arrays; no Session services or runtime encoder.',
        'opcua',messages,states,transitions,'https://github.com/FreeOpcUa/opcua-asyncio/tree/c321a240e53d083fd6e167c67f795915d8f236fd/asyncua/ua',
        'ua_binary.py and generated uaprotocol_auto.py: all service fixtures decoded completely and re-encoded byte-for-byte; no network exchange',
        ['signing/encryption and certificates','OpenSecureChannel Renew and token-overlap behavior','CreateSession/ActivateSession and authenticated/session services','intermediate/abort chunks and runtime reassembly','whole-standard conformance; CLO normative wording difference unresolved'],
        extra_sources=[dict(id='services',url='https://reference.opcfoundation.org/specs/OPC-10000-4/5.5.1',basis='normative',sections='Discovery service set; Session not required'),dict(id='nodeids',url='https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/NodeIds.csv',basis='normative',sections='namespace0 binary encoding IDs: 397,428,431,446,449,452')])
