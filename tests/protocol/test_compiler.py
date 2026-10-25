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
from proto_spec_compiler import SpecError, compile_spec, load, validate


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.p=load(ROOT/'protocols/bacnet_ip/protocol_spec.yaml')
        self.s=load(ROOT/'protocols/bacnet_ip/state_transition.yaml')
        self.msg=self.p['messages'][1]
        self.field=self.msg['fields'][0]

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
                self.assertEqual(result['runtime'],path.parent.name=='bacnet_ip')
                for fname in ['protocol_ir.json','state_ir.json','validation.json']:
                    self.assertEqual((Path(d)/fname).read_bytes(),(path.parent/fname).read_bytes())

    def test_field_type(self): self.field['type']='int128';self.reject()
    def test_duplicate_message(self): self.p['messages'].append(copy.deepcopy(self.msg));self.reject('duplicate')
    def test_duplicate_field(self): self.msg['fields'].append(copy.deepcopy(self.field));self.reject('duplicate')
    def test_missing_dependency_message(self): self.msg['dependencies'].append(dict(op='copy_from_message',target='invoke_id',source='invoke_id',message='missing'));self.reject('message')
    def test_missing_dependency_target(self): self.msg['dependencies'][0]['target']='missing';self.reject('target')
    def test_missing_dependency_source(self): self.msg['dependencies'][0]['source']='missing';self.reject('source')
    def test_unknown_encoder(self): self.p['codec']='shell';self.reject('encoder')
    def test_runtime_unavailable_codec(self): self.p['codec']='mms';self.reject('runtime')
    def test_dependency_cycle(self):
        self.msg['dependencies'] += [dict(op='copy_from_message',target='invoke_id',source='property_id'),dict(op='copy_from_message',target='property_id',source='invoke_id')]
        self.reject('cycle')
    def test_incompatible_copy(self): self.msg['dependencies'].append(dict(op='copy_from_message',target='object_id',source='invoke_id'));self.reject('types')
    def test_multiple_writers(self): self.msg['dependencies'].append(copy.deepcopy(self.msg['dependencies'][0]));self.reject('writers')
    def test_type_width(self): self.field['width']=2;self.reject('width')
    def test_overflow(self): self.field['max']=256;self.reject('integer')
    def test_negative_minimum(self): self.field['min']=-1;self.reject('integer')
    def test_illegal_enum(self): self.field['values']=[256];self.reject('integer')
    def test_strategy(self): self.field['strategies']=['exec'];self.reject('strategy')
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
    def test_unknown_dependency(self): self.msg['dependencies'][0]['op']='eval';self.reject('dependency')
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
        self.p['support']['runtime']=False;self.field['when']=dict(field='missing',mask=1,equals=1);self.reject('conditional')
    def test_static_repeat_missing_count(self):
        self.p['support']['runtime']=False;self.field['repeat']=dict(count='missing',max=4);self.reject('count')
    def test_variable_default_type(self): self.msg['fields'][-1].update(type='bytes',width=0,default=1);self.reject('string')
    def test_variable_width(self): self.msg['fields'][-1].update(type='bytes',width=1,default='');self.reject('width')

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
