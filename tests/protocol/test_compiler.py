#!/usr/bin/env python3
"""Contract tests for declarative loading, typed graphs and all six models."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from proto_spec_compiler import SpecError, compile_spec, load, serialize_ir, validate


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.p=load(ROOT/'protocols/bacnet_ip/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/bacnet_ip/state_transition.yaml')
        self.msg=next(m for m in self.p['messages'] if m['id']=='read_property')
        self.field=self.msg['fields'][0]

    def make_static(self):
        self.p["support"]["runtime"]=False
        for message in self.p["messages"]:
            if "runtime_encode" in message: message["runtime_encode"]=False

    def reject(self, text=None):
        with self.assertRaises(SpecError) as error: validate(self.p,self.s)
        if text: self.assertIn(text,str(error.exception))

    def test_six_models_validate_and_ir_is_reproducible(self):
        models=sorted((ROOT/'protocols').glob('*/protocol_spec.yaml'))
        self.assertEqual(len(models),6)
        for path in models:
            with self.subTest(protocol=path.parent.name), tempfile.TemporaryDirectory() as d:
                p=load(path);s=load(path.with_name('state_transition.yaml'))
                result=compile_spec(p,s,d)
                self.assertTrue(result['validated'])
                self.assertTrue(result['runtime'])
                for fname in ['protocol_ir.json','state_ir.json','validation.json']:
                    self.assertEqual((Path(d)/fname).read_bytes(),(path.parent/fname).read_bytes())

    def test_field_type(self): self.field['type']='int128';self.reject()
    def test_duplicate_message(self): self.p['messages'].append(copy.deepcopy(self.msg));self.reject('duplicate')
    def test_duplicate_field(self): self.msg['fields'].append(copy.deepcopy(self.field));self.reject('duplicate')
    def test_missing_dependency_message(self): self.msg['dependencies'].append(dict(op='copy_from_message',target='invoke_id',source='invoke_id',message='missing'));self.reject('message')
    def test_missing_dependency_target(self): self.msg['dependencies'][0]['target']='missing';self.reject('target')
    def test_missing_dependency_source(self): self.msg['dependencies'][0]['source']='missing';self.reject('source')
    def test_unknown_encoder(self): self.p['codec']='shell';self.reject('codec')
    def test_runtime_unknown_codec(self): self.p['codec']='unavailable';self.reject('codec')
    def test_runtime_codec_transport_mismatch(self): self.p['codec']='mms';self.reject('transport mismatch')
    def test_dependency_cycle(self):
        self.msg['dependencies'] += [dict(op='copy_from_message',target='invoke_id',source='property_id'),dict(op='copy_from_message',target='property_id',source='invoke_id')]
        self.reject('cycle')
    def test_incompatible_copy(self): self.msg['dependencies'].append(dict(op='copy_from_message',target='object_id',source='invoke_id'));self.reject('types')
    def test_multiple_writers(self): self.msg['dependencies'].append(copy.deepcopy(self.msg['dependencies'][0]));self.reject('writers')
    def test_type_width(self): self.field['width']=2;self.reject('width')
    def test_overflow(self): self.field['max']=256;self.reject('integer')
    def test_negative_minimum(self): self.field['min']=-1;self.reject('integer')
    def test_illegal_enum(self): self.field['values']=[256];self.reject('integer')
    def test_strategy(self): self.field['strategies']=['exec'];self.reject('strategies')
    def test_missing_transition_message(self): self.s['transitions'][0]['message']='missing';self.reject('message')
    def test_missing_transition_response(self): self.s['transitions'][0]['response']='missing';self.reject('response')
    def test_request_as_response(self): self.s['transitions'][0]['response']='who_is';self.reject('direction')
    def test_missing_state(self): self.s['transitions'][0]['from']='missing';self.reject('state')
    def test_unreachable_state(self): self.s['states'].append(dict(id='unreachable',meaning='negative fixture'));self.reject('unreachable')
    def test_state_namespace(self): self.s['protocol_id']='other';self.reject('mismatch')
    def test_invalid_offset(self): self.field['locator']='abs:-1';self.reject('locator')
    def test_oversized_offset(self): self.field['locator']='abs:65507';self.reject('locator')
    def test_locator(self): self.field['locator']='unknown.dynamic';self.reject('locator')
    def test_stale_wire_length(self): self.msg['example']=self.msg['example'][:4]+'ffff'+self.msg['example'][8:];self.reject('length')
    def test_bad_hex(self): self.msg['example']='nonsense';self.reject('hexadecimal')
    def test_empty_example(self): self.msg['example']='';self.reject('size')
    def test_unknown_source(self): self.field['evidence']='missing';self.reject('source')
    def test_source_protocol(self): self.p['sources'][0]['url']='file:///etc/passwd';self.reject('HTTP')
    def test_block_membership(self): self.msg['blocks'][0]['fields'].remove(self.field['id']);self.reject('membership')
    def test_block_missing(self): self.field['block']='missing';self.reject('block')
    def test_parent_cycle(self): self.msg['blocks'][0]['parent']='CONTENT';self.msg['blocks'][1]['parent']='HEAD';self.reject('cycle')
    def test_missing_parent(self): self.msg['blocks'][0]['parent']='missing';self.reject('parent')
    def test_fixed_range(self): self.field['min']=0;self.reject('fixed')
    def test_unknown_dependency(self): self.msg['dependencies'][0]['op']='eval';self.reject('dependencies')
    def test_unsupported_runtime_op(self): self.msg['dependencies'][0]['op']='conditional_presence';self.reject('runtime')
    def test_unsupported_runtime_when(self): self.field['when']=dict(field='invoke_id',mask=1,equals=1);self.reject('static-only')
    def test_unsupported_runtime_repeat(self): self.field['repeat']=dict(count='invoke_id',max=4);self.reject('static-only')
    def test_invalid_checksum(self): self.msg['dependencies'][0].update(op='checksum_of',algorithm='eval');self.reject('algorithm')
    def test_zero_unit(self): self.msg['dependencies'][0]['unit']=0;self.reject('integer')
    def test_zero_limit(self): self.s['limits']['max_messages']=0;self.reject()
    def test_tiny_byte_limit(self): self.s['limits']['max_bytes']=1;self.reject('limit')
    def test_structure_requires_children(self): self.field['structure_model']=dict(id='x',kind='tlv');self.reject('children')
    def test_structure_bounded_repeat(self): self.field['structure_model']=dict(id='x',kind='repeat',children=[dict(id='v',kind='field',type='uint8')]);self.reject('bounded')
    def test_static_when_missing_field(self):
        self.make_static();self.field['when']=dict(field='missing',mask=1,equals=1);self.reject('conditional')
    def test_static_repeat_missing_count(self):
        self.make_static();self.field['repeat']=dict(count='missing',max=4);self.reject('count')
    def test_variable_default_type(self): self.p['messages'][0]['fields'][-1]['default']=1;self.reject('string')
    def test_variable_width(self): self.p['messages'][0]['fields'][-1]['width']=1;self.reject('variable')

    def test_fixed_role_requires_fixed_mutability(self): self.field['mutability']='fuzzable';self.reject('fixed role')
    def test_derived_mutability_requires_derived_role(self): self.field.update(role='head',mutability='derived');self.reject('derived role')
    def test_derived_field_requires_writer(self): self.msg['dependencies']=[];self.reject('requires a dependency writer')
    def test_bound_field_requires_writer(self):
        ack=next(m for m in self.p['messages'] if m['id']=='read_property_ack')
        ack['dependencies']=[d for d in ack['dependencies'] if d['target']!='invoke_id']
        self.reject('runtime_bound field requires')
    def test_fixed_field_cannot_be_dependency_target(self): self.msg['dependencies'].append(dict(op='length_of',target=self.field['id'],source='$message'));self.reject('fixed field')
    def test_runtime_direction_both_is_rejected(self): self.msg['direction']='both';self.reject('runtime direction')
    def test_runtime_fragment_is_rejected(self): self.msg['fixture_status']='fragment';self.reject('complete fixture')
    def test_runtime_encode_is_not_an_opt_out(self): self.msg['runtime_encode']=False;self.reject('capability assertion')
    def test_runtime_encode_cannot_enable_a_static_profile(self): self.make_static();self.msg['runtime_encode']=True;self.reject('capability assertion')
    def test_runtime_unavailable_type_is_rejected(self): self.msg['fields'][-1].update(type='nodeid',width=0,default='',values=[]);self.reject('runtime field type')
    def test_runtime_head_cannot_use_variable_bytes(self):
        self.msg['fields'].append(dict(self.field,id='variable_head',locator='abs:6',type='bytes',width=0,role='head',mutability='fuzzable',default='',min=0,max=100,values=[]))
        self.msg['blocks'][0]['fields'].append('variable_head')
        self.reject('HEAD mutation requires an integer')
    def test_runtime_head_requires_scalar_strategy(self):
        next(f for f in self.msg['fields'] if f['id']=='invoke_id')['strategies']=['afl','resize']
        self.reject('scalar strategy')
    def test_runtime_locator_type_must_match(self): self.field.update(type='uint16',width=2,max=65535);self.reject('octet locator')
    def test_runtime_example_range_is_checked(self):
        next(f for f in self.msg['fields'] if f['id']=='invoke_id').update(default=0,max=0)
        self.reject('example value')
    def test_runtime_fixed_value_must_match_example(self): self.field.update(default=128,min=128,max=128,values=[128]);self.reject('example value')
    def test_runtime_reserved_npdu_rejected(self):
        seed=bytearray.fromhex(self.msg['example']);seed[5]=0x80;self.msg['example']=seed.hex();self.reject('NPDU')
    def test_runtime_truncated_tags_rejected(self):
        seed=bytearray.fromhex(self.msg['example']);seed.pop();seed[2:4]=len(seed).to_bytes(2,'big');self.msg['example']=seed.hex();self.reject('tag')
    def test_runtime_unmatched_closing_tag_rejected(self):
        seed=bytearray.fromhex(self.msg['example']);seed.extend(b'\x3f');seed[2:4]=len(seed).to_bytes(2,'big');self.msg['example']=seed.hex();self.reject('closing tag')
    def test_runtime_wrong_who_is_limits_rejected(self):
        msg=self.p['messages'][0];seed=bytearray.fromhex(msg['example']);seed.extend(bytes.fromhex('09021901'));seed[2:4]=len(seed).to_bytes(2,'big');msg['example']=seed.hex();self.reject('Who-Is limits')
    def test_example_whitespace_is_not_loadable_by_c(self): self.msg['example']=' '.join(self.msg['example'][i:i+2] for i in range(0,len(self.msg['example']),2));self.reject('octet pairs')
    def test_example_odd_hex_rejected(self): self.msg['example']+='0';self.reject('octet pairs')
    def test_variable_default_requires_hex(self): self.p['messages'][0]['fields'][-1]['default']='not hex';self.reject('hexadecimal')
    def test_variable_default_byte_bounds(self): self.p['messages'][0]['fields'][-1].update(default='0001',max=1);self.reject('default byte length')
    def test_static_fixed_bytes_use_byte_length_bounds(self):
        self.make_static()
        self.p['messages'][0]['fields'][-1].update(type='bytes',role='fixed',mutability='fixed',default='0001',min=2,max=2,strategies=[])
        validate(self.p,self.s)
    def test_runtime_fixed_bytes_cannot_be_used_as_a_matcher(self):
        self.p['messages'][0]['fields'][-1].update(type='bytes',role='fixed',mutability='fixed',min=0,max=0,strategies=[])
        self.reject('fixed variable bytes are static-only')
    def test_string_default_uses_utf8_byte_bounds(self):
        self.make_static()
        self.p['messages'][0]['fields'][-1].update(type='string',default='界',max=2)
        self.reject('default byte length')
    def test_runtime_ambiguous_edges_ignore_guard(self):
        edge=copy.deepcopy(self.s['transitions'][0]);edge['guard']='a different human condition';self.s['transitions'].append(edge);self.reject('ambiguous runtime')
    def test_runtime_message_annotations_cannot_disambiguate_fixed_signatures(self):
        duplicate=copy.deepcopy(self.msg);duplicate.update(id='same_wire_other_name',match='new explanatory label')
        self.p['messages'].append(duplicate)
        self.reject('ambiguous runtime message matching')
    def test_runtime_response_requires_an_actual_edge(self):
        self.s['transitions']=[t for t in self.s['transitions'] if t['message']!='read_property_ack'];self.reject('outgoing response edge')
    def test_runtime_ignored_dependency_add_rejected(self):
        self.msg['dependencies'].append(dict(op='copy_from_message',target='invoke_id',source='property_id',add=1));self.reject('add is not executed')
    def test_runtime_sequence_uses_own_previous_value(self):
        self.msg['dependencies'].append(dict(op='sequence_number',target='invoke_id',source='property_id'));self.reject("target's own previous")

    def test_unsigned64_limits_are_supported_and_overflow_is_rejected(self):
        self.p=load(ROOT/'protocols/ethernet_ip_cip_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/ethernet_ip_cip_tcp/state_transition.yaml')
        context=next(f for f in self.p['messages'][0]['fields'] if f['id']=='context')
        context.update(default=2**64-1,values=[2**64-1])
        validate(self.p,self.s)
        context['max']=2**64
        self.reject('integer')

    def test_modbus_aliases_require_equal_runtime_constraints(self):
        self.p=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/modbus_tcp/state_transition.yaml')
        with tempfile.TemporaryDirectory() as directory:
            result=compile_spec(self.p,self.s,directory)
        self.assertEqual(result['message_aliases'],dict(write_coils_partial='write_coils',
                        write_coils_partial_response='write_coils_response'))
        partial=next(m for m in self.p['messages'] if m['id']=='write_coils_partial')
        next(f for f in partial['fields'] if f['id']=='quantity')['max']=1967
        self.reject('ambiguous runtime message matching')

    def test_modbus_aliases_require_equal_runtime_weights(self):
        self.p=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/modbus_tcp/state_transition.yaml')
        partial=next(m for m in self.p['messages'] if m['id']=='write_coils_partial')
        partial['weight'] += 1
        self.reject('ambiguous runtime message matching')

    def test_modbus_repeat_is_limited_to_exact_codec_data_descriptor(self):
        self.p=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/modbus_tcp/state_transition.yaml')
        request=next(m for m in self.p['messages'] if m['id']=='write_coils')
        next(f for f in request['fields'] if f['id']=='data')['repeat']['element_width']=2
        self.reject('exact codec-managed Modbus')

    def test_native_runtime_rejects_corrupt_inner_count(self):
        self.p=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/modbus_tcp/state_transition.yaml')
        request=next(m for m in self.p['messages'] if m['id']=='write_coils')
        wire=bytearray.fromhex(request['example']);wire[12]=2;request['example']=wire.hex()
        self.reject('byte count mismatch')

    def test_mms_tagged_length_requires_codec_managed_presentation(self):
        self.p=load(ROOT/'protocols/iec61850_mms_tcp/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/iec61850_mms_tcp/state_transition.yaml')
        request=next(m for m in self.p['messages'] if m['id']=='read')
        request['dependencies'][1]['source']='domain_id'
        self.reject('tagged_length requires codec-managed MMS')

    def test_length_multiplier_is_supported_but_copy_multiplier_is_rejected(self):
        self.msg['dependencies'].append(dict(op='length_of',target='invoke_id',source='object_id',multiply=2))
        validate(self.p,self.s)
        self.msg['dependencies'][-1]['op']='copy_from_message'
        self.msg['dependencies'][-1]['source']='property_id'
        self.reject('multiply is not executed')

    def test_metadata_is_explicit_and_defaults_do_not_rewrite_examples(self):
        original=self.msg['example']
        next(f for f in self.msg['fields'] if f['id']=='invoke_id')['default']=42
        self.msg['dependencies'][0].update(when='false; annotation only',scope='transaction')
        self.s['transitions'][0]['actions']=['documentation only']
        with tempfile.TemporaryDirectory() as d:
            result=compile_spec(self.p,self.s,d)
            contract=result['execution_contract']
            self.assertFalse(contract['static_only'])
            self.assertIn('when',contract['static_metadata']['dependency'])
            self.assertIn('structure_model',contract['static_metadata']['field'])
            ir=json.loads((Path(d)/'protocol_ir.json').read_text())
            request=next(m for m in ir['messages'] if m['id']=='read_property')
            self.assertEqual(request['example'],original)
            self.assertEqual(next(f for f in request['fields'] if f['id']=='invoke_id')['default'],42)

    def test_exact_serialized_ir_budget_is_checked_before_existing_outputs_change(self):
        self.make_static()
        for i in range(90):
            message=copy.deepcopy(self.msg);message.update(id=f'large_{i}',notes='n'*4096)
            self.p['messages'].append(message)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'protocol_ir.json';path.write_text('previous verified IR')
            with self.assertRaisesRegex(SpecError,'serialized IR'):
                compile_spec(self.p,self.s,d)
            self.assertEqual(path.read_text(),'previous verified IR')
            self.assertFalse((Path(d)/'state_ir.json').exists())

    def test_serialized_ir_counts_json_keys_and_container_tokens(self):
        with self.assertRaisesRegex(SpecError,'JSON token budget'):
            serialize_ir({f'key_{i}':0 for i in range(32768)})

    def test_long_cross_message_dependency_chain_and_cycle_are_bounded_without_python_recursion(self):
        self.make_static()
        prototype=self.p['messages'][0]
        self.p['messages']=[]
        for mi in range(20):
            message=copy.deepcopy(prototype)
            message.update(id=f'm{mi}',runtime_encode=False,dependencies=[],fields=[],
                           blocks=[dict(id='HEAD',fields=[]),dict(id='CONTENT',fields=[])])
            for fi in range(60):
                field=dict(self.field,id=f'f{fi}',locator='abs:0',role='head',mutability='fuzzable',default=0,min=0,max=255,values=[])
                message['fields'].append(field);message['blocks'][0]['fields'].append(field['id'])
                if mi!=19 or fi!=59:
                    message['dependencies'].append(dict(op='copy_from_message',target=f'f{fi}',
                        source=f'f{fi+1}' if fi<59 else 'f0',message=f'm{mi}' if fi<59 else f'm{mi+1}'))
            self.p['messages'].append(message)
        self.s.update(initial='ready',states=[dict(id='ready',meaning='independent static fixture')],
                      transitions=[dict(self.s['transitions'][0],message='m0',response='',to='ready')])
        validate(self.p,self.s)
        self.p['messages'][-1]['dependencies'].append(dict(op='copy_from_message',target='f59',source='f0',message='m0'))
        self.reject('dependency cycle')

    def test_yaml_rejections_and_cli(self):
        fixtures=['a: [','{\"a\": 1,}','!!python/object/apply:os.system [echo BAD]', 'a: 1\na: 2\n', 'a: &a [*a]\n','a: 0.5\n']
        with tempfile.TemporaryDirectory() as d:
            for i,body in enumerate(fixtures):
                with self.subTest(body=body):
                    path=Path(d)/f'invalid{i}.yaml';path.write_text(body)
                    # YAML accepts JSON trailing commas; schema still rejects it.
                    try: obj=load(path)
                    except SpecError: pass
                    else:
                        with self.assertRaises(SpecError):validate(obj,self.s)
                    r=subprocess.run([sys.executable,str(ROOT/'tools/proto_spec_compiler.py'),'--protocol',str(path),'--state',str(ROOT/'protocols/bacnet_ip/state_transition.yaml'),'--output-dir',str(Path(d)/'out')],capture_output=True,text=True)
                    self.assertEqual(r.returncode,1)
                    self.assertIn('protocol specification error:',r.stderr)
                    self.assertNotIn('Traceback',r.stderr)


if __name__=='__main__':unittest.main(verbosity=2)
