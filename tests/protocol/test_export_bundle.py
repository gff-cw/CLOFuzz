#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from export_protocol_bundle import build_bundle

class BundleTests(unittest.TestCase):
    def test_complete_packages_manifest_and_reproducible_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            first=Path(directory)/'first.zip';second=Path(directory)/'second.zip'
            result=build_bundle(first);build_bundle(second)
            self.assertEqual(first.read_bytes(),second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                manifest=json.loads(archive.read('MANIFEST.json'))
                self.assertEqual(len(manifest['profiles']),6)
                self.assertTrue(all(p['all_fixtures_complete'] for p in manifest['profiles']))
                for name,digest in manifest['files'].items():
                    self.assertNotIn('..',Path(name).parts)
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(),digest)
                for profile in manifest['profiles']:
                    for filename in ('protocol_spec.yaml','state_transition.yaml','protocol_ir.json','state_ir.json','evidence.yaml','validation.json'):
                        self.assertIn('protocols/'+profile['protocol_id']+'/'+filename,archive.namelist())
            self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(),result['sha256'])

if __name__=='__main__':unittest.main(verbosity=2)
