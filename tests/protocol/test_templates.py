#!/usr/bin/env python3
"""Template -> concrete YAML -> validated IR -> real C field mutation contract."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import yaml
ROOT=Path(__file__).resolve().parents[2]
CODEC_SOURCES=[str(ROOT/f'protocol_codec_{codec}.c')
               for codec in ('modbus','iec104','mms','enip','opcua')]
sys.path.insert(0,str(ROOT/'tools'))
from init_protocol_spec import PROFILES, instantiate
from proto_spec_compiler import SpecError, compile_spec, load, validate
from run_protocol_campaign import prepare

HARNESS=r'''
#include "protocol_runtime.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t choose(uint32_t n){assert(n);return 0;}
static uint32_t choose_last(uint32_t n){assert(n);return n-1;}
int main(int argc,char **argv){
  assert(argc==5);char error[512];
  proto_engine *engine=proto_load(argv[1],argv[2],error,sizeof(error));
  if(!engine){fprintf(stderr,"%s\n",error);return 2;}
  FILE *file=fopen(argv[3],"rb");assert(file);
  unsigned char input[1024];size_t size=fread(input,1,sizeof(input),file);fclose(file);
  assert(size>4);
  if(!strcmp(argv[4],"whois")){
    unsigned char candidate[1024];memcpy(candidate,input+4,size-4);
    const unsigned char limits[8]={0x0b,0,0,1,0x1b,0,0,2};
    memcpy(candidate+size-4,limits,sizeof(limits));
    const unsigned char *output;size_t length;
    int result=proto_mutate(engine,input,size,candidate,size-4+8,PROTO_VALID,PROTO_CONTENT,choose_last,&output,&length,error,sizeof(error));
    if(result){fprintf(stderr,"%s\n",error);proto_free(engine);return 4;}
    assert(length==size+8 && output[0]==size+4 && output[6]==0 && output[7]==size+4);
    assert(!memcmp(output+size,limits,sizeof(limits)));
    proto_free(engine);puts("PASS: renamed Who-Is request uses parsed service codec and CONTENT limits");return 0;
  }
  unsigned expected=atoi(argv[4]);
  size_t offset,width;assert(proto_bacnet_field(input+4,size-4,"apdu.invoke",&offset,&width,error,sizeof(error))==1);
  assert(width==1);
  for(unsigned i=0;i<20;i++){
    const unsigned char *output;size_t length;
    int result=proto_mutate(engine,input,size,input+4,size-4,PROTO_VALID,PROTO_HEAD,choose,&output,&length,error,sizeof(error));
    if(result){fprintf(stderr,"%s\n",error);proto_free(engine);return 3;}
    assert(length==size && output[4+offset]==expected);
    for(size_t j=0;j<size;j++)if(j!=4+offset)assert(output[j]==input[j]);
  }
  proto_free(engine);printf("PASS: description selects invoke_id=%u; all other wire and framing bytes preserved\n",expected);
  return 0;
}
'''

class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilation=tempfile.TemporaryDirectory(prefix='protocol-template-runtime-')
        root=Path(cls.compilation.name)
        source=root/'check.c';source.write_text(HARNESS)
        cls.binary=root/'check'
        subprocess.run(['clang','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(ROOT),str(source),str(ROOT/'protocol_runtime.c'),*CODEC_SOURCES,'-o',str(cls.binary)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):cls.compilation.cleanup()

    def test_all_six_profiles_instantiate_and_compile(self):
        for base in PROFILES:
            with self.subTest(base=base),tempfile.TemporaryDirectory() as folder:
                output=Path(folder)/'configured'
                result=instantiate(base,output,'local_'+base,runtime_required=True)
                self.assertTrue(result['runtime'])
                p=load(output/'protocol_spec.yaml');s=load(output/'state_transition.yaml')
                self.assertEqual(p['protocol_id'],s['protocol_id'])
                self.assertEqual(p['protocol_id'],'local_'+base)
                validate(p,s)
                self.assertEqual(json.loads((output/'protocol_ir.json').read_text())['protocol_id'],p['protocol_id'])
                self.assertTrue(list((output/'seeds').glob('*.replay')))
                text=(output/'protocol_spec.yaml').read_text()
                self.assertNotIn('{{',text)
                self.assertNotIn('&id',text)
                self.assertNotIn('*id',text)

    def test_description_changes_real_runtime_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'custom'
            instantiate('bacnet_ip',output,'local_bacnet',runtime_required=True)
            p=load(output/'protocol_spec.yaml');s=load(output/'state_transition.yaml')
            request=next(m for m in p['messages'] if m['id']=='read_property')
            control=next(f for f in request['fields'] if f['id']=='npdu_control')
            wire=bytes.fromhex(request['example'])
            control.update(role='fixed',mutability='fixed',default=wire[5],min=wire[5],max=wire[5],values=[wire[5]])
            target=next(f for f in request['fields'] if f['id']=='invoke_id')
            for value in (33,77):
                with self.subTest(invoke=value):
                    target.update(values=[value],strategies=['enum'])
                    # Simulate a user's saved YAML, then compile exactly those files.
                    (output/'protocol_spec.yaml').write_text(yaml.safe_dump(p,sort_keys=False))
                    compile_spec(load(output/'protocol_spec.yaml'),s,output)
                    result=subprocess.run([str(self.binary),str(output/'protocol_ir.json'),str(output/'state_ir.json'),str(output/'seeds/read_property.replay'),str(value)],capture_output=True,text=True,check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
                    self.assertIn(f'invoke_id={value}',result.stdout)
                    print(result.stdout.strip())

    def test_message_id_rename_does_not_change_content_codec(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'custom';instantiate('bacnet_ip',path)
            p=load(path/'protocol_spec.yaml');s=load(path/'state_transition.yaml')
            p['messages'][0]['id']='my_who_is_request'
            for transition in s['transitions']:
                if transition['message']=='who_is':transition['message']='my_who_is_request'
            compile_spec(p,s,path)
            result=subprocess.run([str(self.binary),str(path/'protocol_ir.json'),str(path/'state_ir.json'),str(path/'seeds/who_is.replay'),'whois'],capture_output=True,text=True,check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
            self.assertIn('renamed Who-Is',result.stdout)
            print(result.stdout.strip())

    def test_blank_template_requires_filling(self):
        p=load(ROOT/'protocols/templates/protocol_spec.template.yaml')
        s=load(ROOT/'protocols/templates/state_transition.template.yaml')
        with self.assertRaises(SpecError):validate(p,s)

    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'existing';path.mkdir();(path/'keep').write_text('original')
            with self.assertRaisesRegex(SpecError,'overwrite'):instantiate('bacnet_ip',path)
            self.assertEqual((path/'keep').read_text(),'original')
            self.assertEqual(sorted(f.name for f in path.iterdir()),['keep'])

    def test_broken_symlink_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'existing';path.symlink_to('missing-target')
            with self.assertRaisesRegex(SpecError,'overwrite'):instantiate('bacnet_ip',path)
            self.assertTrue(path.is_symlink())
            self.assertEqual(os.readlink(path),'missing-target')

    def test_fragment_examples_are_not_packaged_as_replay_seeds(self):
        profile=load(ROOT/'protocols/modbus_tcp/protocol_spec.yaml')
        state=load(ROOT/'protocols/modbus_tcp/state_transition.yaml')
        profile['support']['runtime']=False
        for message in profile['messages']:message['runtime_encode']=False
        request=next(m for m in profile['messages'] if m['direction']=='request')
        request['fixture_status']='fragment'
        original_load=load
        def selected(path):
            path=Path(path)
            if path.parent.name=='modbus_tcp':
                return profile if path.name=='protocol_spec.yaml' else state
            return original_load(path)
        with tempfile.TemporaryDirectory() as folder, mock.patch('init_protocol_spec.load',side_effect=selected):
            path=Path(folder)/'configured';instantiate('modbus_tcp',path)
            self.assertFalse((path/'seeds'/f"{request['id']}.replay").exists())
            self.assertEqual(load(path/'evidence.yaml')['skipped_fragment_seeds'],[request['id']])

    def test_static_profile_cannot_become_runtime_by_copying(self):
        original_load=load
        def static_profile(path):
            document=original_load(path)
            if Path(path).name=='protocol_spec.yaml':
                document['support']['runtime']=False
                for message in document['messages']:message['runtime_encode']=False
            return document
        with tempfile.TemporaryDirectory() as folder, mock.patch('init_protocol_spec.load',side_effect=static_profile):
            path=Path(folder)/'not-created'
            with self.assertRaisesRegex(SpecError,'runtime encoder unavailable'):
                instantiate('modbus_tcp',path,runtime_required=True)
            self.assertFalse(path.exists())

    def test_bad_id_rejected_without_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'not-created'
            for identifier in ('../bad', ''):
                with self.subTest(identifier=identifier), self.assertRaisesRegex(SpecError,'identifier'):
                    instantiate('bacnet_ip',path,identifier)
            self.assertFalse(path.exists())

    def test_runner_recompiles_edited_yaml_and_selects_both_models(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'configured'
            instantiate('bacnet_ip',path,'configured_bacnet')
            p=load(path/'protocol_spec.yaml')
            field=next(f for f in p['messages'][1]['fields'] if f['id']=='invoke_id')
            field.update(values=[93],strategies=['enum'])
            (path/'protocol_spec.yaml').write_text(yaml.safe_dump(p,sort_keys=False))
            result,command=prepare(path,['-i','in','-o','out','--','target','--protocol-spec'])
            self.assertEqual(result['protocol'],'configured_bacnet')
            self.assertEqual(command[1:5],['--protocol-spec',str(path/'protocol_ir.json'),'--state-spec',str(path/'state_ir.json')])
            ir=json.loads((path/'protocol_ir.json').read_text())
            self.assertEqual(next(f for f in ir['messages'][1]['fields'] if f['id']=='invoke_id')['values'],[93])
            self.assertEqual(command[-2:],['target','--protocol-spec'])

    def test_runner_rejects_static_runtime_and_allows_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'configured'
            instantiate('modbus_tcp',path)
            profile=load(path/'protocol_spec.yaml');profile['support']['runtime']=False
            for message in profile['messages']:message['runtime_encode']=False
            (path/'protocol_spec.yaml').write_text(yaml.safe_dump(profile,sort_keys=False))
            with self.assertRaisesRegex(SpecError,'static validation only'):prepare(path,[])
            result,command=prepare(path,[],validate_only=True)
            self.assertFalse(result['runtime']);self.assertIsNone(command)

    def test_runner_rejects_conflicting_model_options(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'configured';instantiate('bacnet_ip',path)
            for flag in ('--protocol-spec','--state-spec=other.json'):
                with self.subTest(flag=flag),self.assertRaisesRegex(SpecError,'do not also pass'):
                    prepare(path,[flag,'--','target'])

    def test_runner_invalid_edit_is_not_run_or_written_to_ir(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'configured';instantiate('bacnet_ip',path)
            before=(path/'protocol_ir.json').read_bytes()
            p=load(path/'protocol_spec.yaml');p['messages'][0]['fields'][0]['type']='bad'
            (path/'protocol_spec.yaml').write_text(yaml.safe_dump(p,sort_keys=False))
            with self.assertRaises(SpecError):prepare(path,['--','target'])
            self.assertEqual((path/'protocol_ir.json').read_bytes(),before)

    def test_cli_lists_support(self):
        result=subprocess.run([sys.executable,str(ROOT/'tools/init_protocol_spec.py'),'--list'],capture_output=True,text=True,check=True)
        for profile in PROFILES:self.assertIn(profile+': runtime',result.stdout)
        self.assertNotIn('static-only',result.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
