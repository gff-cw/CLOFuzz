#!/usr/bin/env python3
"""Compile reviewed BACnet inputs and run controlled ASan/UBSan C API tests."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def main():
    with tempfile.TemporaryDirectory(prefix='stateafl-bacnet-dynamic-') as temporary:
        directory = Path(temporary)
        subprocess.run(['python3', 'tools/proto_spec_compiler.py', '--protocol',
                        'protocols/reviewed/bacnet_ip/protocol_spec.yaml', '--state',
                        'protocols/reviewed/bacnet_ip/state_transition.yaml',
                        '--output-dir', str(directory)], cwd=ROOT, check=True)
        binary = directory / 'test-bacnet-dynamic'
        sources = ['protocol_runtime.c', 'protocol_session_constraints.c',
                   'protocol_iec104_session.c', 'generic_runtime.c', 'generic_wire.c',
                   'native_json.c', 'tests/protocol/test_bacnet_dynamic.c']
        sources += [str(p.relative_to(ROOT)) for p in sorted(ROOT.glob('protocol_codec_*.c'))]
        subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-g',
                        '-Wall', '-Wextra', '-Wno-unused-parameter',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I.', *sources, '-o', str(binary)], cwd=ROOT, check=True)
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        subprocess.run([str(binary), str(directory/'protocol_ir.json'),
                        str(directory/'state_ir.json')], cwd=ROOT,
                       env=environment, check=True)

if __name__ == '__main__':
    main()
