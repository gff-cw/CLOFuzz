#!/usr/bin/env python3
"""Fail-fast CLI checks; never launch a target or create an output directory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
class CLITests(unittest.TestCase):
    def rejected(self, flags, expected, transport="udp"):
        command=[str(ROOT/'afl-fuzz'), '-i', '/not-used', '-o', '/not-used-output', '-N', f'{transport}://127.0.0.1/47818']+flags+['--','/not-a-target']
        r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(r.returncode,0)
        self.assertIn(expected.lower(),(r.stdout+r.stderr).lower())
    def test_pair(self):self.rejected(['--protocol-spec','x'],'requires both')
    def test_missing_models(self):self.rejected(['--mutation-mode','valid'],'requires both')
    def test_unknown_mode(self):self.rejected(['--mutation-mode','other'],'Unknown --mutation-mode')
    def test_bad_layers(self):self.rejected(['--mutation-layers','content'],'Invalid --mutation-layers')
    def test_bad_ratio(self):
        for value in ('-1','101','NaN','1.5',''):
            with self.subTest(value=value):self.rejected(['--protocol-ratio',value],'integer in 0..100')
    def test_explicit_static_only(self):
        with tempfile.TemporaryDirectory() as directory:
            protocol=json.loads((ROOT/'protocols/modbus_tcp/protocol_ir.json').read_text())
            protocol['support']['runtime']=False
            for message in protocol['messages']:message['runtime_encode']=False
            path=Path(directory)/'static.json';path.write_text(json.dumps(protocol))
            self.rejected(['--protocol-spec',str(path),'--state-spec','protocols/modbus_tcp/state_ir.json'],'not enabled for runtime',transport='tcp')
    def test_no_silent_fallback_of_bad_models(self):
        self.rejected(['--protocol-spec','/missing-protocol','--state-spec','/missing-state','--protocol-fallback'],'cannot open IR')
    def test_transport(self):
        self.rejected(['--protocol-spec','protocols/bacnet_ip/protocol_ir.json','--state-spec','protocols/bacnet_ip/state_ir.json'],'requires UDP transport', transport='tcp')
    def test_tcp_codecs_require_tcp_transport(self):
        for profile in ('modbus_tcp','iec60870_5_104','iec61850_mms_tcp','ethernet_ip_cip_tcp','opcua_tcp'):
            with self.subTest(profile=profile):
                self.rejected(['--protocol-spec',f'protocols/{profile}/protocol_ir.json','--state-spec',f'protocols/{profile}/state_ir.json'],'requires TCP transport')
    def test_invalid_experiment_seed(self):
        for value in ('-1','4294967296','1.5','bad',''):
            with self.subTest(value=value):self.rejected(['--random-seed',value],'uint32 integer')
    def test_duplicate_experiment_seed(self):
        self.rejected(['--random-seed','0','--random-seed','1'],'uint32 integer')
    def test_invalid_candidate_budget(self):
        for value in ('-1','1000001','1.5','bad',''):
            with self.subTest(value=value):self.rejected(['--protocol-save-candidates',value],'integer in 0..1000000')
if __name__=='__main__':unittest.main()
