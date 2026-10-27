#!/usr/bin/env python3
"""Compile the standalone runtime harness and record reproducible sanitizer evidence."""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
CODECS = ('modbus', 'iec104', 'mms', 'enip', 'opcua')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=25000)
    parser.add_argument('--random-models', type=int, default=250)
    parser.add_argument('--compiler', default='clang')
    args = parser.parse_args()
    if args.iterations < 1 or args.random_models < 0:
        parser.error('iterations must be positive and random-models nonnegative')
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    protocol = json.loads((ROOT/'protocols/bacnet_ip/protocol_ir.json').read_text())
    state = json.loads((ROOT/'protocols/bacnet_ip/state_ir.json').read_text())
    result = {'status': 'running', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sanitizers': ['address', 'undefined', 'leak'], 'seed': 0x51a7,
              'random_wire_iterations': args.iterations, 'loader_cases': [], 'failures': [],
              'run_command': ['python3', 'tests/protocol/run_runtime_tests.py', '--iterations', str(args.iterations), '--random-models', str(args.random_models), '--compiler', args.compiler]}
    with tempfile.TemporaryDirectory(prefix='stateafl-runtime-') as directory:
        directory = Path(directory)
        binary = directory/'runtime-tests'
        command = [args.compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-fsanitize=address,undefined',
                   '-fno-omit-frame-pointer', '-g', '-I.', 'protocol_runtime.c',
                   *(f'protocol_codec_{codec}.c' for codec in CODECS),
                   'tests/protocol/test_runtime.c', '-o', str(binary)]
        subprocess.run(command, cwd=ROOT, env=env, check=True)
        result['compiler'] = subprocess.check_output([args.compiler, '--version'], text=True).splitlines()[0]
        result['build_command'] = command[:-1] + ['<temporary-binary>']
        pp, sp = directory/'protocol.json', directory/'state.json'

        def check_case(name, p=None, s=None, raw=None, accepted=False):
            pp.write_bytes(raw if raw is not None else json.dumps(p if p is not None else protocol).encode())
            sp.write_text(json.dumps(s if s is not None else state))
            completed = subprocess.run([str(binary), 'load', str(pp), str(sp)], env=env,
                                       text=True, capture_output=True, timeout=20)
            expected = 0 if accepted else 2
            passed = completed.returncode == expected and (accepted or bool(completed.stderr.strip()))
            item = {'name': name, 'expected': 'accept' if accepted else 'reject', 'passed': passed}
            if not passed:
                item.update(returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
                result['failures'].append(item)
            result['loader_cases'].append(item)

        check_case('compiled BACnet runtime', accepted=True)
        mutations = []
        def change(name, fn, state_change=False):
            p, s = copy.deepcopy(protocol), copy.deepcopy(state)
            fn(s if state_change else p)
            mutations.append((name, p, s))
        change('invalid message type', lambda p: p['messages'].__setitem__(0, False))
        change('invalid direction', lambda p: p['messages'][0].update(direction='shell'))
        change('duplicate message ID', lambda p: p['messages'].append(copy.deepcopy(p['messages'][0])))
        change('duplicate field ID', lambda p: p['messages'][0]['fields'].append(copy.deepcopy(p['messages'][0]['fields'][0])))
        change('empty identifier', lambda p: p['messages'][0].update(id=''))
        change('unknown codec', lambda p: p.update(codec='shell'))
        change('runtime false', lambda p: p['support'].update(runtime=False))
        change('runtime wrong type', lambda p: p['support'].update(runtime=1))
        change('messages wrong type', lambda p: p.update(messages={}))
        change('fields wrong type', lambda p: p['messages'][0].update(fields={}))
        change('unknown field type', lambda p: p['messages'][0]['fields'][0].update(type='int128'))
        change('wrong field width', lambda p: p['messages'][0]['fields'][0].update(width=2))
        change('overflow scalar max', lambda p: p['messages'][0]['fields'][0].update(max=256))
        change('negative scalar min', lambda p: p['messages'][0]['fields'][0].update(min=-1))
        change('overflow unsigned64', lambda p: p['messages'][0]['fields'][0].update(max=2**64))
        change('oversize variable field', lambda p: p['messages'][0]['fields'][-1].update(max=65508))
        change('wrong integer type', lambda p: p['messages'][0].update(weight=True))
        change('invalid enumeration', lambda p: p['messages'][0]['fields'][0].update(values=[0]))
        change('invalid endian', lambda p: p['messages'][0]['fields'][0].update(endian='native'))
        change('unknown runtime strategy', lambda p: p['messages'][0]['fields'][0].update(strategies=['unknown']))
        change('head without scalar strategy', lambda p: p['messages'][0]['fields'][4].update(strategies=['afl']))
        change('invalid role', lambda p: p['messages'][0]['fields'][0].update(role='shell'))
        change('invalid mutability', lambda p: p['messages'][0]['fields'][0].update(mutability='eval'))
        change('nonfixed fixed range', lambda p: p['messages'][0]['fields'][0].update(min=0))
        change('stale BVLC example', lambda p: p['messages'][0].update(example='810affff01001008'))
        change('invalid example hex', lambda p: p['messages'][0].update(example='GG'))
        change('invalid fixed example', lambda p: p['messages'][0]['fields'][0].update(min=128,max=128,values=[128]))
        change('unknown locator', lambda p: p['messages'][0]['fields'][0].update(locator='unknown'))
        change('empty absolute locator', lambda p: p['messages'][0]['fields'][0].update(locator='abs:'))
        change('negative absolute locator', lambda p: p['messages'][0]['fields'][0].update(locator='abs:-1'))
        change('overflow absolute locator', lambda p: p['messages'][0]['fields'][0].update(locator='abs:9999999999999999999999999999999'))
        change('missing required field', lambda p: p['messages'][0]['fields'][0].update(locator='apdu.invoke'))
        change('static-only conditional', lambda p: p['messages'][0]['fields'][0].update(when={}))
        change('static-only repeat', lambda p: p['messages'][0]['fields'][0].update(repeat={}))
        change('missing dependency target', lambda p: p['messages'][0]['dependencies'][0].update(target='missing'))
        change('missing dependency source', lambda p: p['messages'][0]['dependencies'][0].update(source='missing'))
        change('missing dependency message', lambda p: p['messages'][0]['dependencies'][0].update(message='missing'))
        change('cross-message structural dependency', lambda p: p['messages'][0]['dependencies'][0].update(message='read_property'))
        change('unknown dependency', lambda p: p['messages'][0]['dependencies'][0].update(op='eval'))
        change('static-only conditional dependency', lambda p: p['messages'][0]['dependencies'][0].update(op='conditional_presence'))
        change('static-only tagged dependency', lambda p: p['messages'][0]['dependencies'][0].update(op='tagged_length'))
        change('multiple dependency writers', lambda p: p['messages'][0]['dependencies'].append(copy.deepcopy(p['messages'][0]['dependencies'][0])))
        change('unsupported checksum multiply', lambda p: p['messages'][0]['dependencies'][0].update(op='checksum_of',algorithm='sum8',multiply=2))
        change('zero dependency unit', lambda p: p['messages'][0]['dependencies'][0].update(unit=0))
        change('invalid checksum', lambda p: p['messages'][0]['dependencies'][0].update(op='checksum_of',algorithm='shell'))
        change('nonscalar dependency target', lambda p: p['messages'][0]['dependencies'][0].update(target='limits'))
        change('incompatible copy types', lambda p: p['messages'][1]['dependencies'].append(dict(op='copy_from_message',target='object_id',source='invoke_id')))
        change('dependency cycle', lambda p: p['messages'][1]['dependencies'].extend([dict(op='copy_from_message',target='invoke_id',source='property_id'),dict(op='copy_from_message',target='property_id',source='invoke_id')]))
        change('response bind from request', lambda p: p['messages'][1]['dependencies'].append(dict(op='bind_from_response',target='invoke_id',source='invoke_id',message='read_property')))
        change('namespace mismatch', lambda s: s.update(protocol_id='other'), True)
        change('duplicate state ID', lambda s: s['states'].append(copy.deepcopy(s['states'][0])), True)
        change('missing initial state', lambda s: s.update(initial='missing'), True)
        change('missing transition state', lambda s: s['transitions'][0].update(to='missing'), True)
        change('missing transition message', lambda s: s['transitions'][0].update(message='missing'), True)
        change('missing transition response', lambda s: s['transitions'][0].update(response='missing'), True)
        change('request as response', lambda s: s['transitions'][0].update(response='who_is'), True)
        change('ambiguous transition', lambda s: s['transitions'].append(copy.deepcopy(s['transitions'][0])), True)
        change('unreachable state', lambda s: s['states'].append(dict(id='unreachable')), True)
        change('max messages overflow', lambda s: s['limits'].update(max_messages=65), True)
        change('zero max repeat', lambda s: s['limits'].update(max_repeat=0), True)
        change('tiny byte limit', lambda s: s['limits'].update(max_bytes=1), True)
        change('byte limit overflow', lambda s: s['limits'].update(max_bytes=1048577), True)
        for name, p, s in mutations:
            check_case(name, p, s)
        payload = json.dumps(protocol).encode()
        malformed = [b'', b'[]', b'{', b'{"x":1,}', b'{"x":1,"x":2}', b'{"x":01}',
                     b'{"x":1.5}', b'{"x":NaN}', payload+b'\0', payload+b' false',
                     b'{"x":"\xc0\x80"}', b'{"x":"\xed\xa0\x80"}',
                     b'{"x":"\xf4\x90\x80\x80"}', b'{"x":"\\z"}', b'['*26+b']'*26]
        for index, raw in enumerate(malformed):
            check_case(f'malformed JSON {index}', raw=raw)
        for model in sorted((ROOT/'protocols').glob('*/protocol_ir.json')):
            if model.parent.name != 'bacnet_ip':
                compiled=json.loads(model.read_text())
                compiled_state=json.loads(model.with_name('state_ir.json').read_text())
                check_case(f'compiled runtime {model.parent.name}',p=compiled,s=compiled_state,accepted=True)
                if model.parent.name == 'ethernet_ip_cip_tcp':
                    context=next(f for f in compiled['messages'][0]['fields'] if f['id']=='context')
                    context['max']=2**64
                    check_case('overflow uint64 context',p=compiled,s=compiled_state)
        # Random byte mutations also exercise valid JSON with damaged schema.
        # Either success or a diagnosed rejection is acceptable; sanitizers must remain clean.
        rng = random.Random(0x51a7)
        for index in range(args.random_models):
            raw = bytearray(payload)
            for _ in range(rng.randint(1, 12)):
                at = rng.randrange(len(raw))
                raw[at] = rng.randrange(256)
            pp.write_bytes(raw);sp.write_text(json.dumps(state))
            completed = subprocess.run([str(binary), 'load', str(pp), str(sp)], env=env, capture_output=True, timeout=20)
            if completed.returncode not in (0, 2) or (completed.returncode == 2 and not completed.stderr.strip()):
                result['failures'].append({'name': f'random model {index}', 'returncode': completed.returncode,
                                           'stderr': completed.stderr.decode(errors='replace')})
        result['random_model_iterations'] = args.random_models
        completed = subprocess.run([str(binary), 'selftest', str(ROOT/'protocols/bacnet_ip/protocol_ir.json'),
                                    str(ROOT/'protocols/bacnet_ip/state_ir.json'), str(args.iterations)],
                                   env=env, capture_output=True, text=True, timeout=180)
        if completed.returncode:
            result['failures'].append({'name': 'runtime harness', 'returncode': completed.returncode,
                                       'stdout': completed.stdout, 'stderr': completed.stderr})
        else:
            result['runtime_harness'] = json.loads(completed.stdout)
        # Live session binding must not leak between engines, executions, or simulated mutation.
        bound = copy.deepcopy(protocol)
        bound['messages'][1]['dependencies'].append(dict(op='bind_from_response',target='invoke_id',source='invoke_id',message='read_property_ack'))
        # This synthetic bootstrap tests cache isolation only. It explicitly
        # declares an uncorrelated reply; real pending-request correlation and
        # handle binding are covered by test_multicodec_runtime.py.
        bound['messages'][2]['dependencies'] = [d for d in bound['messages'][2]['dependencies']
                                               if d['op'] != 'correlate_request_response']
        pp.write_text(json.dumps(bound));sp.write_text(json.dumps(state))
        completed = subprocess.run([str(binary), 'session', str(pp), str(sp)], env=env, capture_output=True, text=True, timeout=20)
        if completed.returncode:
            result['failures'].append({'name': 'session isolation', 'returncode': completed.returncode,
                                       'stdout': completed.stdout, 'stderr': completed.stderr})
        else:
            result['session_harness'] = json.loads(completed.stdout)
        transactional = copy.deepcopy(bound)
        transactional['messages'][1]['dependencies'] = [
            d for d in transactional['messages'][1]['dependencies']
            if d['op'] != 'bind_from_response']
        next(field for field in transactional['messages'][1]['fields']
             if field['id'] == 'property_id')['mutability'] = 'runtime_bound'
        transactional['messages'][1]['dependencies'].extend([
            dict(op='sequence_number', target='invoke_id', source='$message'),
            dict(op='bind_from_response', target='property_id', source='invoke_id',
                 message='read_property_ack'),
        ])
        transactional['messages'][2]['dependencies'] = [
            d for d in transactional['messages'][2]['dependencies']
            if d['op'] != 'correlate_request_response']
        pp.write_text(json.dumps(transactional))
        completed = subprocess.run([str(binary), 'binding_transaction', str(pp), str(sp)],
                                   env=env, capture_output=True, text=True, timeout=20)
        if completed.returncode:
            result['failures'].append({'name': 'atomic live binding',
                                       'returncode': completed.returncode,
                                       'stdout': completed.stdout, 'stderr': completed.stderr})
        else:
            result['binding_transaction_harness'] = json.loads(completed.stdout)
        result['dependency_harnesses'] = []
        execution_cases = [
            ('local copy', dict(op='copy_from_message', target='invoke_id', source='property_id'), 'apdu.invoke', 77),
            ('local length', dict(op='length_of', target='invoke_id', source='object_id'), 'apdu.invoke', 4),
            ('local count', dict(op='count_of', target='invoke_id', source='object_id',unit=2), 'apdu.invoke', 2),
            ('multiplied local length', dict(op='length_of', target='invoke_id', source='object_id',multiply=3), 'apdu.invoke', 12),
            ('multiplied local count', dict(op='count_of', target='invoke_id', source='object_id',unit=2,multiply=3), 'apdu.invoke', 6),
            ('local offset', dict(op='offset_of', target='invoke_id', source='property_id'), 'apdu.invoke', 16),
            ('sum8 checksum', dict(op='checksum_of', target='invoke_id', source='object_id',algorithm='sum8'), 'apdu.invoke', 125),
            ('crc32 checksum', dict(op='checksum_of', target='object_id', source='property_id',algorithm='crc32'), 'bacnet.object', zlib.crc32(bytes([77]))),
        ]
        for name, dependency, locator, expected in execution_cases:
            model = copy.deepcopy(protocol)
            model['messages'][1]['dependencies'].append(dependency)
            pp.write_text(json.dumps(model));sp.write_text(json.dumps(state))
            completed = subprocess.run([str(binary), 'dependency', str(pp), str(sp), locator, str(expected)], env=env, capture_output=True, text=True, timeout=20)
            if completed.returncode:
                result['failures'].append({'name':name,'returncode':completed.returncode,'stderr':completed.stderr})
            else:
                result['dependency_harnesses'].append({'name': name, **json.loads(completed.stdout)})
        for name, command in [('serialized byte limit', 'limits'), ('session sequence number', 'sequence_number')]:
            model, limits = copy.deepcopy(protocol), copy.deepcopy(state)
            if command == 'limits':
                limits['limits']['max_bytes'] = 21
            else:
                model['messages'][1]['dependencies'].append(dict(op='sequence_number',target='invoke_id',source='$message'))
            pp.write_text(json.dumps(model));sp.write_text(json.dumps(limits))
            completed = subprocess.run([str(binary), command, str(pp), str(sp)], env=env, capture_output=True, text=True, timeout=20)
            if completed.returncode:
                result['failures'].append({'name':name,'returncode':completed.returncode,'stderr':completed.stderr})
            else:
                result['dependency_harnesses'].append({'name': name, **json.loads(completed.stdout)})
    result['source_sha256'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in [ROOT/'protocol_runtime.c', ROOT/'protocol_runtime.h', ROOT/'protocol_codecs.h',
                                            *(ROOT/f'protocol_codec_{codec}.c' for codec in CODECS),
                                            ROOT/'tests/protocol/test_runtime.c']}
    result['supported_scope'] = {
        'runtime_codecs_loaded': ['bacnet', *CODECS],
        'wire_mutation_harness': 'BACnet/IP UDP Original-Unicast/Broadcast-NPDU, unsegmented APDUs; dedicated multi-codec tests cover the other runtime profiles',
        'content_encoders': ['Who-Is optional paired device limits', 'ReadProperty object/property/present optional array index scalar projection'],
        'parser': 'dynamic destination/source NPDU addresses, BACnet LVT including extended lengths and balanced context tags',
        'integers': 'IR unsigned-64-bit scalar bounds; uint8/16/24/32/64 field types',
        'sequence': 'request replay insert/delete/repeat/reorder; declared response transition simulated between requests; bounded counts/repetitions/serialized bytes',
        'dependencies': ['local length_of/count_of with unit and multiply; offset_of', 'local sum8/crc32 checksum_of', 'scalar copy_from_message/bind_from_response', 'invoke response correlation', 'field-width sequence_number', 'codec-managed MMS tagged_length'],
        'static_only_codecs': [],
        'excluded': ['segmented APDUs', 'network-layer NPDUs', 'BACnet/SC', 'BBMD/foreign-device lifecycle', 'generic conditional_presence/tagged_length runtime dependencies', 'generic when/repeat executable field controls', 'response payload mutation encoder', 'absent ReadProperty array-index insertion'],
        'invalid_modes': 'near_valid and invalid both intentionally change one BVLC length constraint after repair; before_send preserves these bytes',
        'metadata': 'guards/actions/structure descriptions are documentation; dependencies drive runtime binding',
        'evidence_limits': 'Standalone local tests only; randomized runs do not prove protocol conformance or replace live target integration.'}
    result['status'] = 'passed' if not result['failures'] else 'failed'
    evidence = ROOT/'tests/protocol/evidence/runtime-results.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps({'status': result['status'], 'loader_cases': len(result['loader_cases']),
                      'random_models': args.random_models, 'random_wire_iterations': args.iterations,
                      'runtime_checks': result.get('runtime_harness',{}).get('checks'),
                      'failures': result['failures'], 'evidence': str(evidence)}, indent=2))
    return bool(result['failures'])


if __name__ == '__main__':
    raise SystemExit(main())
