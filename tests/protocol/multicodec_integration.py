#!/usr/bin/env python3
"""Run five real StateAFL TCP campaigns against an instrumented fixture double.

This verifies the fuzzer/runtime/socket path and live handle binding. It makes
no claim of conformance or interoperability with an industrial server.
"""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PROFILES = {
    'modbus': ('modbus_tcp', ['read_holding', 'write_coil', 'write_register', 'write_coils_partial', 'write_registers']),
    'iec104': ('iec60870_5_104', ['start_act', 'test_act', 'interrogation']),
    'mms': ('iec61850_mms_tcp', ['cotp_cr', 'associate', 'get_name_list', 'read', 'write', 'conclude', 'release']),
    'enip': ('ethernet_ip_cip_tcp', ['register', 'send_rr', 'unregister']),
    'opcua': ('opcua_tcp', ['hello', 'open_channel', 'message', 'close_channel']),
}
TYPES = {name: n for n, name in enumerate(('uint8', 'uint16', 'uint24', 'uint32', 'uint64',
                                         'bytes', 'string', 'bacnet_tags', 'ber_tlv', 'epath', 'nodeid'))}
# Assigned by the local double, deliberately different from captured defaults.
HANDLES = {'enip': {'session': 0x6A514233}, 'opcua': {'channel': 0x6132, 'token': 0x7543}}


def c_string(value):
    return json.dumps(value, ensure_ascii=True)


def c_field(field):
    return '{%s,%d,%d,%d}' % (c_string(field['locator']), TYPES[field['type']],
                              field['width'], field['endian'] == 'little')


def c_assignment(field, value):
    return '{%s,UINT64_C(%d)}' % (c_field(field), value)


def write_header(path, models, states):
    lines = ['/* Generated from the current protocol IR, for a local test double. */']
    lists, counts = [], []
    for codec in PROFILES:
        model, state = models[codec], states[codec]
        messages = {m['id']: m for m in model['messages']}
        pairs = {t['message']: t['response'] for t in state['transitions'] if t.get('response')}
        fixture_entries = []
        for index, message in enumerate(m for m in model['messages'] if m['direction'] == 'request'):
            stem = f'{codec}_{index}'
            response = messages.get(pairs.get(message['id']))
            response_raw = bytes.fromhex(response['example']) if response else b''
            request_raw = bytes.fromhex(message['example'])
            request_fields = {f['id']: f for f in message['fields']}
            response_fields = {f['id']: f for f in response['fields']} if response else {}
            lines.append(f'static const uint8_t {stem}_request[] = {{{",".join(str(b) for b in request_raw)}}};')
            lines.append(f'static const uint8_t {stem}_response[] = {{{",".join(str(b) for b in response_raw) or "0"}}};')
            copies, bindings, assignments = [], [], []
            if response:
                for dependency in response.get('dependencies', []):
                    if (dependency['op'] in ('correlate_request_response', 'copy_from_message')
                            and dependency.get('message') == message['id']):
                        copies.append('{%s,%s}' % (c_field(request_fields[dependency['source']]),
                                                  c_field(response_fields[dependency['target']])))
                for field_id, value in HANDLES.get(codec, {}).items():
                    if field_id in response_fields:
                        assignments.append(c_assignment(response_fields[field_id], value))
                if codec == 'opcua' and response['id'] == 'open_channel_response':
                    # The ChannelSecurityToken repeats the SecureConversation ID.
                    assignments.append(c_assignment(dict(locator='uabin:token.channel_id', type='uint32',
                                                         width=4, endian='little'), HANDLES[codec]['channel']))
            for dependency in message.get('dependencies', []):
                if dependency['op'] == 'bind_from_response':
                    expected = HANDLES[codec][dependency['source']]
                    bindings.append(c_assignment(request_fields[dependency['target']], expected))
            for label, ctype, entries in [('copies', 'fixture_copy', copies),
                                          ('bindings', 'fixture_assignment', bindings),
                                          ('assignments', 'fixture_assignment', assignments)]:
                lines.append(f'static const {ctype} {stem}_{label}[] = {{{",".join(entries) or "{0}"}}};')
            fixture_entries.append('{%s,%s_request,%s_response,%d,%d,%s_copies,%d,%s_bindings,%s_assignments,%d,%d}' %
                                   (c_string(message['id']), stem, stem, len(request_raw), len(response_raw),
                                    stem, len(copies), stem, stem, len(bindings), len(assignments)))
        lines.append(f'static const fixture {codec}_fixtures[] = {{{",".join(fixture_entries)}}};')
        lists.append(f'{codec}_fixtures'); counts.append(str(len(fixture_entries)))
    lines.append(f'static const fixture *fixture_lists[] = {{{",".join(lists)}}};')
    lines.append(f'static const size_t fixture_counts[] = {{{",".join(counts)}}};')
    path.write_text('\n'.join(lines) + '\n')


def read_stats(path):
    if not path.exists():
        return {}
    return {key.strip(): value.strip() for key, value in
            (line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def build(work, env, models, states):
    write_header(work / 'multicodec_fixtures.h', models, states)
    target = work / 'fixture-server'
    sources = [f'protocol_codec_{codec}.c' for codec in PROFILES]
    command = [str(ROOT / 'afl-clang-fast'), '-O1', '-g', '-I.', '-I' + str(work),
               'tests/protocol/fixtures/multicodec_server.c', *sources, '-o', str(target)]
    with (work / 'build.log').open('w') as log:
        subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    library = work / 'codecs.so'
    with (work / 'codec-build.log').open('w') as log:
        subprocess.run(['cc', '-std=c11', '-O2', '-fPIC', '-shared', '-I.', *sources,
                        '-o', str(library)], cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
    (work / 'build-command.json').write_text(json.dumps(command, indent=2) + '\n')
    return target, C.CDLL(str(library))


def inspect_trace(path, codec, model, library):
    validate = getattr(library, f'pc_{codec}_validate')
    field = getattr(library, f'pc_{codec}_field')
    validate.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    field.argtypes = [C.c_void_p, C.c_size_t, C.c_char_p, C.c_int, C.c_size_t,
                     C.POINTER(C.c_size_t), C.POINTER(C.c_size_t), C.c_void_p, C.c_size_t]
    messages = {m['id']: m for m in model['messages']}
    report = dict(records=0, structural_requests=0, changed_mutable_requests=0,
                  bound_requests=0, incorrect_bound_requests=0, response_records=0,
                  correct_bound_requests=0, incorrect_bound_mutable_requests=0,
                  invalid_json=0, models={}, changed_fields={}, examples=[])
    model_counts, changed_fields = Counter(), Counter()
    if not path.exists():
        return report
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            report['invalid_json'] += 1
            continue
        report['records'] += 1
        raw = bytes.fromhex(record['request'])
        if not validate(raw, len(raw), None, 0):
            report['structural_requests'] += 1
        if record['response']:
            report['response_records'] += 1
        message = messages.get(record['model'])
        if not message:
            continue
        model_counts[message['id']] += 1
        binding_targets = {d['target'] for d in message.get('dependencies', [])
                           if d['op'] == 'bind_from_response'}
        if binding_targets:
            report['bound_requests'] += 1
            report['incorrect_bound_requests'] += not record['bound']
            report['correct_bound_requests'] += record['bound']
        example = bytes.fromhex(message['example'])
        changed = []
        for f in message['fields']:
            if f['id'] in binding_targets or f['mutability'] not in ('fuzzable', 'optional'):
                continue
            at, count, example_at, example_count = (C.c_size_t() for _ in range(4))
            args = (f['locator'].encode(), TYPES[f['type']], f['width'])
            if (field(raw, len(raw), *args, C.byref(at), C.byref(count), None, 0) == 1
                    and field(example, len(example), *args, C.byref(example_at), C.byref(example_count), None, 0) == 1
                    and raw[at.value:at.value + count.value] != example[example_at.value:example_at.value + example_count.value]):
                changed.append(f['id']); changed_fields[f['id']] += 1
        if changed:
            report['changed_mutable_requests'] += 1
            if binding_targets and not record['bound']:
                report['incorrect_bound_mutable_requests'] += 1
            if len(report['examples']) < 8:
                report['examples'].append(dict(model=message['id'], fields=changed, request=record['request']))
    report['models'], report['changed_fields'] = dict(model_counts), dict(changed_fields)
    return report


def run_campaign(args, work, codec, target, library, env, model):
    folder = work / codec; folder.mkdir(); corpus = folder / 'in'; corpus.mkdir()
    messages = {m['id']: m for m in model['messages']}
    sequence = [bytes.fromhex(messages[mid]['example']) for mid in PROFILES[codec][1]]
    seed = b''.join(len(raw).to_bytes(4, 'little') + raw for raw in sequence)
    (corpus / 'session.replay').write_bytes(seed)
    port = free_port(); trace_path = folder / 'wire.jsonl'; log_path = folder / 'fuzz.log'
    spec = ROOT / 'protocols' / PROFILES[codec][0]
    command = ['setarch', os.uname().machine, '-R', str(ROOT / 'afl-fuzz'), '-d',
               '-i', str(corpus), '-o', str(folder / 'out'), '-N', f'tcp://127.0.0.1/{port}',
               '-D', str(args.startup_usecs), '-W', '5', '-w', '1000', '-r', '5',
               '-K', '-m', 'none', '-t', '1000',
               '--protocol-spec', str(spec / 'protocol_ir.json'), '--state-spec', str(spec / 'state_ir.json'),
               '--mutation-mode', 'valid', '--mutation-layers', args.layers,
               '--random-seed', '20261025', '--protocol-save-candidates', '24',
               '--', str(target), codec, str(port), str(trace_path)]
    (folder / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    started, ready = time.monotonic(), None
    print(f'START {codec}: TCP {port}', flush=True)
    with log_path.open('w') as log:
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while child.poll() is None:
                now = time.monotonic()
                if ready is None and 'All set and ready to roll!' in log_path.read_text(errors='replace'):
                    ready = now
                    print(f'READY {codec}: {now - started:.2f}s startup', flush=True)
                if ready is not None and now - ready >= args.seconds:
                    break
                if ready is None and now - started >= args.ready_timeout:
                    break
                time.sleep(.1)
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
            status = child.wait(timeout=20)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL); child.wait()
    output = folder / 'out'; stats = read_stats(output / 'fuzzer_stats')
    protocol_path = output / 'protocol_stats.json'
    protocol = json.loads(protocol_path.read_text()) if protocol_path.exists() else {}
    wire = inspect_trace(trace_path, codec, model, library)
    events, layers = Counter(), Counter()
    mutation_log = output / 'protocol_mutations.jsonl'
    if mutation_log.exists():
        for line in mutation_log.read_text().splitlines():
            event = json.loads(line); events[event['event']] += 1
            if event['event'] == 'mutation': layers[event['layer']] += 1
    checks = dict(ready=ready is not None, clean_stop=status == 0,
                  executions_continue=int(stats.get('execs_done', 0)) > 4,
                  structured_mutations=int(stats.get('protocol_structured', 0)) > 0,
                  wire_records=wire['records'] > 0,
                  wire_mutable_candidates=wire['changed_mutable_requests'] > 0,
                  complete_responses=wire['response_records'] > 0,
                  correlated_responses=protocol.get('correlated_responses', 0) > 0 if codec in ('modbus', 'mms', 'enip', 'opcua') else True,
                  no_trace_errors=wire['invalid_json'] == 0,
                  no_crashes=int(stats.get('unique_crashes', 0)) == 0,
                  no_hangs=int(stats.get('unique_hangs', 0)) == 0)
    if codec in HANDLES:
        checks['live_bindings_sent'] = wire['correct_bound_requests'] > 0
        # Raw calibration uses the captured handle1; structured executions
        # must use the newly assigned response handles, including mutations.
        checks['live_mutated_bindings_correct'] = wire['incorrect_bound_mutable_requests'] == 0
    result = dict(codec=codec, passed=all(checks.values()), checks=checks, command=command,
                  exit_code=status, seconds=round(time.monotonic() - started, 3),
                  stats=stats, protocol_stats=protocol, wire=wire,
                  events=dict(events), layers=dict(layers))
    (folder / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'END {codec}: passed={result["passed"]} execs={stats.get("execs_done")} structured={stats.get("protocol_structured")} wire_changed={wire["changed_mutable_requests"]}', flush=True)
    if not result['passed']:
        print('FAILED: ' + ', '.join(k for k, v in checks.items() if not v), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=8)
    parser.add_argument('--ready-timeout', type=float, default=120)
    parser.add_argument('--startup-usecs', type=int, default=20000)
    parser.add_argument('--codecs', default=','.join(PROFILES))
    parser.add_argument('--layers', default='head,content,sequence')
    args = parser.parse_args()
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    selected = args.codecs.split(',')
    if not selected or any(codec not in PROFILES for codec in selected):
        parser.error('unknown codec')
    env = dict(os.environ, AFL_PATH=str(ROOT), AFL_NO_UI='1', AFL_NO_AFFINITY='1',
               AFL_SKIP_CPUFREQ='1', AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1')
    for key in list(env):
        if key.startswith('__AFL_') or key in ('STATE_SHM_ID', 'MVP_CALIBRATION_SHM_ID', 'MVP_RADIUS', 'AFL_OUTDIR'):
            del env[key]
    models, states = {}, {}
    for codec, (pid, _) in PROFILES.items():
        models[codec] = json.loads((ROOT / 'protocols' / pid / 'protocol_ir.json').read_text())
        states[codec] = json.loads((ROOT / 'protocols' / pid / 'state_ir.json').read_text())
    target, library = build(work, env, models, states)
    metadata = dict(fixture='captured-record local test double; not an industrial server',
                    afl_fuzz_sha256=hashlib.sha256((ROOT / 'afl-fuzz').read_bytes()).hexdigest(),
                    target_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                    live_handles=HANDLES)
    (work / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    results = [run_campaign(args, work, codec, target, library, env, models[codec]) for codec in selected]
    result = dict(passed=all(r['passed'] for r in results), scope=metadata['fixture'], campaigns=results)
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
