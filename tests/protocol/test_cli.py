#!/usr/bin/env python3
"""Fail-fast CLI checks; never launch a target or create an output directory."""
import json
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parents[2]
class CLITests(unittest.TestCase):
    def rejected(self, flags, expected, transport="udp"):
        command=[str(ROOT/'afl-fuzz'), '-i', '/not-used', '-o', '/not-used-output', '-N', f'{transport}://127.0.0.1/47818']+flags+['--','/not-a-target']
        r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(r.returncode,0)
        self.assertIn(expected,r.stdout+r.stderr)
    def test_pair(self):self.rejected(['--protocol-spec','x'],'requires both')
    def test_missing_models(self):self.rejected(['--mutation-mode','valid'],'requires both')
    def test_unknown_mode(self):self.rejected(['--mutation-mode','other'],'Unknown --mutation-mode')
    def test_bad_layers(self):self.rejected(['--mutation-layers','content'],'Invalid --mutation-layers')
    def test_bad_ratio(self):
        for value in ('-1','101','NaN','1.5',''):
            with self.subTest(value=value):self.rejected(['--protocol-ratio',value],'integer in 0..100')
    def test_explicit_static_only(self):
        self.rejected(['--protocol-spec','protocols/modbus_tcp/protocol_ir.json','--state-spec','protocols/modbus_tcp/state_ir.json'],'unavailable (static description only)')
    def test_no_silent_fallback_of_bad_models(self):
        self.rejected(['--protocol-spec','/missing-protocol','--state-spec','/missing-state','--protocol-fallback'],'cannot open IR')
    def test_transport(self):
        self.rejected(['--protocol-spec','protocols/bacnet_ip/protocol_ir.json','--state-spec','protocols/bacnet_ip/state_ir.json'],'requires UDP transport', transport='tcp')
if __name__=='__main__':unittest.main()
