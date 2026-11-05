#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from export_protocol_bundle import build_bundle, check_generic_profile_current
from proto_spec_compiler import SpecError
from build_generic_wire_profiles import render as render_generic_profile

class BundleTests(unittest.TestCase):
    def test_generic_subset_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            name = 'iec60870_5_104'
            profile = Path(directory)/'protocols'/name
            profile.mkdir(parents=True)
            path = profile/'generic_wire.json'
            path.write_bytes(render_generic_profile(name))
            check_generic_profile_current(profile, name)
            changed = json.loads(path.read_text())
            changed['messages'][0]['weight'] += 1
            path.write_text(json.dumps(changed, indent=2) + '\n')
            with self.assertRaisesRegex(SpecError, 'stale generic_wire.json'):
                check_generic_profile_current(profile, name)

    def test_complete_packages_manifest_and_reproducible_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            first=Path(directory)/'first.zip';second=Path(directory)/'second.zip'
            result=build_bundle(first);build_bundle(second)
            self.assertEqual(first.read_bytes(),second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertIn('protocols/README.md',archive.namelist())
                manifest=json.loads(archive.read('MANIFEST.json'))
                self.assertEqual(len(manifest['profiles']),6)
                self.assertTrue(all(p['runtime'] for p in manifest['profiles']))
                self.assertTrue(all(p['all_fixtures_complete'] for p in manifest['profiles']))
                for filename in ('tools/native_protocol_codecs.py','protocol_codecs.h',
                                 'tools/protocol_seed_planner.py',
                                 'tools/protocol_template_contract.py','tools/protocol_corpus_contract.py',
                                 'tools/generic_template_catalog.py','protocols/schema/generic_wire.schema.json',
                                 'protocols/templates/generic_wire.template.json',
                                 'protocols/templates/legacy_contract/capabilities.json',
                                 'protocols/templates/minimal_runnable_example/fixture_server.c',
                                 'docs/template-unification-review-20261104.zh-CN.md',
                                 'docs/template-system-repair-20261104.zh-CN.md',
                                 'tools/check_reviewed_protocol_descriptions.py',
                                 'tools/check_protocol_descriptions.py',
                                 'protocols/reviewed/manifest.json',
                                 'protocols/reviewed/modbus_tcp/protocol_spec.yaml',
                                 'protocols/schema/reviewed_description.schema.json',
                                 'tools/build_generic_wire_profiles.py','tools/check_generic_wire_profiles.py',
                                 'generic_wire.c','generic_wire.h','generic_runtime.c','generic_runtime.h',
                                 'protocol_runtime.h','config.h','types.h',
                                 'protocol_session_constraints.c','protocol_session_constraints.h',
                                 'protocol_iec104_session.c','protocol_iec104_session.h',
                                 'tests/generic-wire/full_modbus.json','tests/generic-wire/test_full_modbus.c',
                                 'tests/protocol/test_session_constraints.c','tests/protocol/test_iec104_session.c',
                                 'docs/executor-extension-20261104.zh-CN.md',
                                 'native_json.c','native_json.h','docs/generic-wire-profile-scope.md',
                                 *(f'protocol_codec_{codec}.c' for codec in ('modbus','iec104','mms','enip','opcua'))):
                    self.assertIn(filename,archive.namelist())
                for name,digest in manifest['files'].items():
                    self.assertNotIn('..',Path(name).parts)
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),digest)
                for profile in manifest['profiles']:
                    for filename in ('protocol_spec.yaml','state_transition.yaml','protocol_ir.json','state_ir.json','evidence.yaml','validation.json','seed_manifest.json'):
                        self.assertIn('protocols/'+profile['protocol_id']+'/'+filename,archive.namelist())
            self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(),result['sha256'])
            extracted=Path(directory)/'extracted'
            with zipfile.ZipFile(first) as archive:archive.extractall(extracted)
            completed=subprocess.run([sys.executable,'tests/protocol/test_model_completeness.py'],cwd=extracted,capture_output=True,text=True,timeout=90)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            # Compile from the extracted archive only: source-list assertions
            # cannot detect an accidentally omitted transitive header.
            standalone = {
                'full_modbus': ['tests/generic-wire/test_full_modbus.c', 'generic_runtime.c',
                                'generic_wire.c', 'native_json.c'],
                'session_constraints': ['tests/protocol/test_session_constraints.c',
                                        'protocol_session_constraints.c', 'native_json.c',
                                        'protocol_codec_modbus.c', 'protocol_codec_opcua.c'],
                'iec104_session': ['tests/protocol/test_iec104_session.c',
                                   'protocol_iec104_session.c', 'protocol_codec_iec104.c'],
            }
            for name, sources in standalone.items():
                executable = extracted / name
                completed = subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1',
                                            '-I.', *sources, '-o', str(executable)],
                                           cwd=extracted, capture_output=True, text=True, timeout=90)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                completed = subprocess.run([str(executable)], cwd=extracted,
                                           capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
