"""Static structure and provenance annotations for the scoped ICP-IR models.

These trees describe nested wire semantics. They are not arbitrary executable
expressions or a claim that a static-only model has a C runtime codec.
"""
import copy


def leaf(name, typ, **kw):
    return dict(id=name, kind='field', type=typ, **kw)


def container(name, kind, children, **kw):
    return dict(id=name, kind=kind, children=children, **kw)


OFFICIAL = {
    'bacnet': ('https://www.ashrae.org/technical-resources/standards-and-guidelines/titles-purposes-and-scopes',
               'ASHRAE 135 catalogue identity only; wire semantics verified against local BACnet Stack 1.5.0'),
    'modbus': ('https://www.modbus.org/file/secure/modbusprotocolspecification.pdf',
               'Application Protocol V1.1b3 sections 4 and 6; current PDF linked by official specifications index'),
    'iec104': ('https://webstore.iec.ch/en/publication/25035',
               'IEC 60870-5-104:2006+AMD1:2016 catalogue; full paid text not consulted'),
    'mms': ('https://www.rfc-editor.org/rfc/rfc1006',
            'RFC 1006 section 6 TPKT; MMS/ACSE semantics from libIEC61850 implementation'),
    'enip': ('https://www.odva.org/subscriptions-services/specifications/',
             'ODVA specification catalogue and subscription boundaries; wire details from OpENer'),
    'opcua': ('https://reference.opcfoundation.org/specs/OPC-10000-6',
              'Part 6 sections 5.2 UA Binary, 6.7 UASC, 7.1 UACP; SecurityPolicy None scope'),
}


def enrich(p, st, field, fixed, length, dep, message):
    codec = p['codec']
    url, sections = OFFICIAL[codec]
    p['sources'].append(dict(id='official', url=url,
                             basis='normative' if codec in {'modbus', 'opcua', 'mms'} else 'implementation',
                             sections=sections))
    if codec == 'mms':
        p['sources'].append(dict(id='iec_scope', url='https://webstore.iec.ch/en/publication/6021',
            basis='inferred', sections='IEC 61850-8-1 catalogue; paid normative text not consulted'))
    msgs = {m['id']: m for m in p['messages']}
    if codec == 'bacnet':
        for m in p['messages']:
            ctl = next(f for f in m['fields'] if f['id'] == 'npdu_control')
            ctl['structure_model'] = container('npdu_addresses', 'sequence', [
                leaf('dnet', 'uint16-big', condition='control bit5 set'),
                leaf('dlen', 'uint8', condition='control bit5 set'),
                container('dadr', 'repeat', [leaf('address_octet', 'uint8')], min=0, max=255, condition='DLEN octets when control bit5 set'),
                leaf('snet', 'uint16-big', condition='control bit3 set'),
                leaf('slen', 'uint8', condition='control bit3 set'),
                container('sadr', 'repeat', [leaf('address_octet', 'uint8')], min=1, max=255, condition='SLEN octets when control bit3 set'),
                leaf('hop_count', 'uint8', condition='control bit5 set')], encoding='BACnet-NPDU')
        next(f for f in msgs['who_is']['fields'] if f['id']=='limits')['structure_model'] = container('device_limits', 'choice', [
            leaf('absent', 'empty', condition='both limits absent'),
            container('range', 'sequence', [leaf('low', 'context-unsigned', tag=0, min=0, max=4194303),
                leaf('high', 'context-unsigned', tag=1, min=0, max=4194303)], condition='both present; low <= high <= 4194303')], encoding='BACnet-LVT')
        next(f for f in msgs['read_property_ack']['fields'] if f['id']=='value')['structure_model'] = container('read_property_ack', 'sequence', [
            leaf('object_identifier', 'context-object-id', tag=0), leaf('property_identifier', 'context-unsigned', tag=1),
            leaf('array_index', 'context-unsigned', tag=2, condition='optional array index'),
            container('property_value', 'tlv', [leaf('application_value', 'BACnet-application-tags')], tag=3)], encoding='BACnet-opening-closing-tags')
    elif codec == 'modbus':
        for m in p['messages']:
            for f in m['fields']:
                f['evidence']='official'; f['confidence']='normative'
        wc=msgs['write_coils']; wr=msgs['write_registers']
        for m in (wc,wr):
            q=next(f for f in m['fields'] if f['id']=='quantity')
            q['min']=1; q['max']=1968 if m is wc else 123
            q['default']=8 if m is wc else 1
            data=next(f for f in m['fields'] if f['id']=='data')
            data['repeat']={'count':'quantity','min':1,'max':246 if m is wc else 123,'element_width':1 if m is wc else 2}
            data['min']=1 if m is wc else 2
            data['structure_model']=container('values','repeat',[leaf('value','packed-8-coils' if m is wc else 'uint16-big')],min=1,max=246 if m is wc else 123,encoding='ceil(quantity/8)-bytes' if m is wc else 'quantity*2-bytes')
            for d in m['dependencies']:
                if d['target']=='quantity' and m is wc: d['multiply']=8
            m['notes'] += ' FC0F count_of uses full-byte coil groups; non-multiple-of-eight quantities need explicit padding semantics and are outside this fixture generator.' if m is wc else ''
        base=copy.deepcopy(msgs['read_response']['fields'][:4])
        for code,request,mid in [(1,'read_coils','read_coils_response'),(2,'read_discrete','read_discrete_response'),(4,'read_input','read_input_response')]:
            payload='01' if code<3 else '0001'
            hx=f'00010000{(3+len(bytes.fromhex(payload))):04x}01{code:02x}{len(bytes.fromhex(payload)):02x}'+payload
            p['messages'].append(message(mid,hx,copy.deepcopy(base)+[fixed('function','abs:7',code),length('byte_count','abs:8','uint8'),field('data','abs:9','bytes','content',payload)],
                [dep('length',add=-6),dep('byte_count','data'),dep('transaction','transaction','correlate_request_response',message=request,scope='transaction')],'response'))
        for code,request in [(5,'write_coil'),(6,'write_register'),(15,'write_coils'),(16,'write_registers')]:
            req=msgs[request]; qty='quantity' if code>=15 else 'value'
            fs=copy.deepcopy(req['fields'][:7])
            if code>=15:
                f=next(x for x in fs if x['id']==qty);f.update(role='content',block='CONTENT',mutability='runtime_bound')
            response=bytearray.fromhex(req['example'][:24]);response[4:6]=(6).to_bytes(2,'big')
            p['messages'].append(message(request+'_response',response.hex(),fs,
                [dep('length',add=-6),dep('transaction','transaction','correlate_request_response',message=request,scope='transaction'),
                 dep(qty,qty,'copy_from_message',message=request,scope='transaction')],'response'))
        st['transitions']=[dict(**{'from':'connected','to':'connected'},message=m['id'],response='',guard='MBAP transaction context',actions=[]) for m in p['messages']]
    elif codec == 'iec104':
        m=msgs['interrogation']
        for f in m['fields']:
            if f['id']=='vsq': f.update(min=1,max=1,default=1,values=[1],structure='C_IC_NA_1 contains exactly one information object; SQ=0 in this profile.')
            if f['id']=='ioa': f.update(min=0,max=0,default=0,values=[0])
            if f['id']=='send_seq' or f['id']=='receive_seq':
                f.update(max=65534,structure='Wire UInt16 = logical sequence number 0..32767 shifted left one; low bit zero. Increment logical N(S) modulo 32768 only on I frames. N(R) acknowledges next expected peer I frame.')
        # These controls are connection keepalive checks in either transfer phase.
        st['transitions'] += [dict(**{'from':'stopped','to':'stopped'},message=x,response='test_con' if x=='test_act' else '',guard='TESTFR is independent of data-transfer activation',actions=[]) for x in ['test_act','test_con']]
        qoi=next(f for f in m['fields'] if f['id']=='qoi')
        qoi['structure_model']=container('information_object','sequence',[leaf('ioa','uint24-little',min=0,max=0),leaf('qoi','uint8',min=20,max=36)],encoding='single-C_IC_NA_1')
    elif codec == 'mms':
        for m in p['messages']:
            if m['id']=='cotp_cr': continue
            f=next(x for x in m['fields'] if x['id']=='pdu')
            if m['id'] in {'get_name_list','read','write'}:
                service={'get_name_list':1,'read':4,'write':5}[m['id']]
                content={'get_name_list':[leaf('object_class','context-object-class',tag=0),leaf('object_scope','context-scope-choice',tag=1),leaf('continue_after','identifier',tag=2,condition='optional')],
                         'read':[leaf('specification_with_result','boolean',tag=0,condition='optional'),leaf('variable_access','VariableAccessSpecification',tag=1)],
                         'write':[leaf('variable_access','VariableAccessSpecification',tag=0),container('list_of_data','repeat',[leaf('data','MMS-Data-choice')],min=1,max=64)]}[m['id']]
                f['structure_model']=container('confirmed_request','tlv',[leaf('invoke_id','BER-Unsigned32',tag=2),container('service','tlv',content,tag=service)],tag=0,encoding='BER-context-constructed')
                m['fields'].append(field('invoke_id','ber:confirmed.invoke','uint32',default=1,structure='BER INTEGER payload location is determined by TLV tree, never absolute byte offset.'))
            elif m['id']=='initiate':
                f['structure_model']=container('initiate_request','tlv',[leaf('local_detail','Unsigned32',tag=0),leaf('outstanding_calling','Unsigned16',tag=1),leaf('outstanding_called','Unsigned16',tag=2),leaf('nesting','Unsigned8',tag=3),container('detail','tlv',[leaf('version','Integer',tag=0),leaf('parameter_cbb','BIT STRING',tag=1),leaf('services_supported','BIT STRING',tag=2)],tag=4)],tag=8,encoding='BER-context-constructed')
            else:
                f['structure_model']=container('acse','tlv',[leaf('association_fields','ACSE-AARQ' if m['id']=='associate' else 'ACSE-RLRQ')],tag=0 if m['id']=='associate' else 2,encoding='BER-application-constructed')
        req=msgs['read']; response=copy.deepcopy(req);response['id']='confirmed_response';response['direction']='response'
        raw=bytearray.fromhex(response['example']);raw[7]=0xa1;response['example']=raw.hex()
        response['dependencies'].append(dep('invoke_id','invoke_id','correlate_request_response',message='read',scope='transaction'))
        response['notes']='Structural ConfirmedResponse envelope with matching invoke field; service-specific result payload still needs a complete BER codec.'
        p['messages'].append(response)
        st['transitions'].append(dict(**{'from':'associated','to':'associated'},message='confirmed_response',response='',guard='pending invoke ID must match',actions=['clear invoke context']))
    elif codec == 'enip':
        # Correct CPF item lengths in the reference fixtures and expose actual CIP fields.
        for mid,cip_off,itemlen_off in [('send_rr',40,38),('send_unit',46,42)]:
            m=msgs[mid];raw=bytearray.fromhex(m['example']);raw[itemlen_off:itemlen_off+2]=(len(raw)-(itemlen_off+2)).to_bytes(2,'little');m['example']=raw.hex()
            m['fields'] += [field('cip_service',f'abs:{cip_off}',default=14,values=[1,14,16],structure='Request service; response has bit 7 set.'),
                length('path_words',f'abs:{cip_off+1}','uint8'),field('epath',f'abs:{cip_off+2}','epath','content','200124013001',structure='Logical segments class 0x20, instance 0x24, attribute 0x30; one-byte segment values. Word count includes segments and padding.')]
            m['dependencies'].append(dep('path_words','epath','count_of',unit=2))
            next(f for f in m['fields'] if f['id']=='epath')['structure_model']=container('epath','repeat',[container('segment','choice',[leaf('class','logical-segment-0x20'),leaf('instance','logical-segment-0x24'),leaf('attribute','logical-segment-0x30')])],min=0,max=64,encoding='16-bit-words')
            for f in m['fields']:
                if f['id']=='session': m['dependencies'].append(dep('session','session','bind_from_response',message='register_response',scope='connection'))
        reg=copy.deepcopy(msgs['register']);reg['id']='register_response';reg['direction']='response'
        raw=bytearray.fromhex(reg['example']);raw[4:8]=(1).to_bytes(4,'little');reg['example']=raw.hex()
        reg['dependencies'].append(dep('context','context','correlate_request_response',message='register',scope='transaction'))
        p['messages'].append(reg)
        msgs['unregister']['dependencies'].append(dep('session','session','bind_from_response',message='register_response',scope='connection'))
        for tr in st['transitions']:
            if tr['message']=='register':tr['response']='register_response'
        st['transitions'].append(dict(**{'from':'registered','to':'registered'},message='register_response',response='',guard='register success',actions=['cache assigned session handle']))
    elif codec == 'opcua':
        for m in p['messages']:
            raw=bytes.fromhex(m['example']);typ=raw[:3].decode()
            f=m['fields'][0];f['type']='uint24';f['width']=3;f['endian']='little';f['default']=f['min']=f['max']=int.from_bytes(raw[:3],'little');f['values']=[f['default']]
            for f in m['fields']:
                f['evidence']='official';f['confidence']='normative'
            if typ in {'HEL','ACK'}:
                for i,key in enumerate(['protocol_version','receive_buffer','send_buffer','max_message_size','max_chunk_count']):
                    m['fields'].append(field(key,f'abs:{8+i*4}','uint32',default=int.from_bytes(raw[8+i*4:12+i*4],'little'),endian='little'))
                if typ=='HEL':
                    m['fields'].append(field('endpoint','uabin:endpoint','string','content','',structure='Int32 byte length followed by UTF-8 endpoint URL. -1 means null, zero empty.'))
            next(f for f in m['fields'] if f['id']=='body')['structure_model']=container('ua_body','sequence',[
                leaf('transport_fields','UACP-negotiation' if typ in {'HEL','ACK','ERR','RHE'} else 'UASC-security-header'),
                leaf('sequence_header','UInt32-sequence-and-request-id',condition='OPN/MSG/CLO'),
                container('service','choice',[leaf('numeric_nodeid','TwoByte-FourByte-Numeric'),leaf('string_nodeid','Namespace-String'),leaf('guid_nodeid','Namespace-Guid'),leaf('bytes_nodeid','Namespace-ByteString')],condition='OPN/MSG/CLO service encoding ID; body follows')],encoding='UA-Binary-little-endian')
            if typ=='OPN':
                m['fields'] += [field('channel','abs:8','uint32',default=0,endian='little'),field('policy_uri','uabin:policy','string','content','http://opcfoundation.org/UA/SecurityPolicy#None'),field('sequence','uabin:sequence','uint32',default=1,endian='little'),field('request_id','uabin:request','uint32',default=1,endian='little')]
        # Do not imply that transport success alone activates an OPC UA session.
        p['support']['excluded'] += ['CreateSession/ActivateSession request bodies and authentication are not generated']
    # Keep block membership exact after adding semantic fields. Static nested
    # models use parent blocks to express Request -> Block -> Primitive.
    for m in p['messages']:
        for b in m['blocks']:
            b['fields']=[f['id'] for f in m['fields'] if f['block']==b['id']]
        if not p['support']['runtime']:
            m['blocks'].append(dict(id='REQUEST',fields=[]))
            for b in m['blocks']:
                if b['id']!='REQUEST': b['parent']='REQUEST'
