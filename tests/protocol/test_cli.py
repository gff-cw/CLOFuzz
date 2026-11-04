#!/usr/bin/env python3
"""Fail-fast CLI checks; never launch a target or create an output directory."""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from proto_spec_compiler import SpecError
from run_protocol_campaign import (LONG_FLAG_OPTIONS, LONG_VALUE_OPTIONS, MODEL_OPTIONS,
                                   SHORT_FLAG_OPTIONS, SHORT_VALUE_OPTIONS, parse_afl_input)


class CorpusArgumentTests(unittest.TestCase):
    def test_wrapper_option_consumption_tracks_production_getopt_contract(self):
        source = (ROOT / 'afl-fuzz.c').read_text()
        match = re.search(r'getopt_long\(argc, argv, "([^"]+)"', source)
        self.assertIsNotNone(match)
        options = match.group(1).lstrip('+')
        values, flags = set(), set()
        index = 0
        while index < len(options):
            option = options[index]
            if index + 1 < len(options) and options[index + 1] == ':':
                values.add(option); index += 2
            else:
                flags.add(option); index += 1
        self.assertEqual(SHORT_VALUE_OPTIONS, values)
        self.assertEqual(SHORT_FLAG_OPTIONS, flags)
        table = source.split('static const struct option protocol_options[] = {', 1)[1].split('};', 1)[0]
        long_options = re.findall(r'\{"([a-z-]+)",\s*(required_argument|no_argument)', table)
        self.assertEqual(LONG_VALUE_OPTIONS | MODEL_OPTIONS,
                         {'--' + name for name, kind in long_options if kind == 'required_argument'})
        self.assertEqual(LONG_FLAG_OPTIONS,
                         {'--' + name for name, kind in long_options if kind == 'no_argument'})

    def test_attached_separate_cluster_and_resume_input(self):
        for arguments, expected in ((['-i', 'seeds'], 'seeds'), (['-iseeds'], 'seeds'),
                                    (['-diseeds'], 'seeds'), (['-i-'], '-'), (['-i', '-'], '-')):
            with self.subTest(arguments=arguments):
                self.assertEqual(parse_afl_input(arguments), expected)

    def test_option_values_and_target_arguments_are_not_input_options(self):
        self.assertEqual(parse_afl_input(['-T', '-i-banner', '--mutation-mode', 'valid',
                                         '-ireal', '--', 'target', '-i', 'not-input']), 'real')
        self.assertEqual(parse_afl_input(['-ireal', 'target', '--generic-spec', '-iother']), 'real')
        with self.assertRaisesRegex(SpecError, '-i is required'):
            parse_afl_input(['--', 'target', '-i', 'not-input'])

    def test_missing_duplicate_and_conflicting_input_options(self):
        for arguments in ([], ['-i'], ['-i', ''], ['-i', '--', 'target'], ['-ia', '-ib']):
            with self.subTest(arguments=arguments), self.assertRaises(SpecError):
                parse_afl_input(arguments)
        for option in ('--protocol-spec', '--state-spec=x', '--generic-spec=x'):
            with self.subTest(option=option), self.assertRaisesRegex(SpecError, 'do not also pass'):
                parse_afl_input([option, '-iseeds', '--', 'target'])
        for arguments in (None, ['-T', 3, '-iseeds'], ['-iseeds', '--', object()]):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(SpecError, 'strings'):
                parse_afl_input(arguments)

class CLITests(unittest.TestCase):
    def rejected(self, flags, expected, transport="udp"):
        command=[str(ROOT/'afl-fuzz'), '-i', '/not-used', '-o', '/not-used-output', '-N', f'{transport}://127.0.0.1/47818']+flags+['--','/not-a-target']
        r=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(r.returncode,0)
        self.assertIn(expected.lower(),(r.stdout+r.stderr).lower())
    def test_pair(self):self.rejected(['--protocol-spec','x'],'requires both')
    def test_missing_models(self):self.rejected(['--mutation-mode','valid'],'requires both')
    def test_unknown_mode(self):self.rejected(['--mutation-mode','other'],'Unknown --mutation-mode')
    def test_generic_spec_conflicts_with_legacy_models(self):
        self.rejected(['--generic-spec','tests/generic-wire/fictional_protocol.json',
                       '--protocol-spec','unused'],'Use --generic-spec alone')
    def test_generic_spec_rejects_unimplemented_modes(self):
        for mode in ('near_valid','invalid'):
            with self.subTest(mode=mode):
                self.rejected(['--generic-spec','tests/generic-wire/fictional_protocol.json',
                               '--mutation-mode',mode],'supports valid, hybrid and raw')
    def test_generic_transport(self):
        self.rejected(['--generic-spec','tests/generic-wire/fictional_protocol.json'],
                      'requires udp transport',transport='tcp')
    def test_generic_offline_descriptions_fail_before_target_start(self):
        for profile in ('bacnet_ip','iec60870_5_104','iec61850_mms_tcp','ethernet_ip_cip_tcp','opcua_tcp'):
            with self.subTest(profile=profile):
                self.rejected(['--generic-spec',f'protocols/{profile}/generic_wire.json'],
                              'offline-only',transport='udp' if profile=='bacnet_ip' else 'tcp')
    def test_bad_layers(self):self.rejected(['--mutation-layers','content'],'Invalid --mutation-layers')
    def test_schedule_requires_models(self):
        self.rejected(['--protocol-schedule','adaptive'],'requires both')
    def test_bad_schedule(self):
        for value in ('random','', 'ADAPTIVE'):
            with self.subTest(value=value):
                self.rejected(['--protocol-schedule',value],'uniform or adaptive')
    def test_raw_schedule_is_rejected(self):
        self.rejected(['--protocol-spec','protocols/bacnet_ip/protocol_ir.json',
                       '--state-spec','protocols/bacnet_ip/state_ir.json',
                       '--mutation-mode','raw','--protocol-schedule','adaptive'],
                      'requires a structured mutation mode')
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
