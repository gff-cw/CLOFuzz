#!/usr/bin/env python3
"""Loopback acceptance controller only; all online mutation executes in C."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
LEGACY_SOURCES = ('afl-fuzz.c', 'generic_wire.c', 'generic_runtime.c',
                  'tests/generic-wire/fixture_udp_server.c',
                  'tests/generic-wire/fictional_protocol.json')
LOCAL_BINARIES = ('afl-fuzz', 'afl-clang-fast', 'afl-llvm-pass.so',
                  'afl-llvm-rt.o', 'afl-llvm-rt-state-tracer.o')


def file_snapshot(path):
    """Read provenance only; absence or an unreadable file is not a test result."""
    result = {'path': str(path), 'present': False}
    try:
        result['present'] = path.is_file()
        if not result['present']:
            return result
        result['resolved_path'] = str(path.resolve())
        before = path.stat()
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        after = path.stat()
        result.update(size=after.st_size,
                      sha256=digest.hexdigest(), mtime_ns=after.st_mtime_ns,
                      stable_during_read=(before.st_dev, before.st_ino, before.st_size,
                                          before.st_mtime_ns, before.st_ctime_ns) ==
                                         (after.st_dev, after.st_ino, after.st_size,
                                          after.st_mtime_ns, after.st_ctime_ns))
    except OSError as error:
        result['read_error'] = str(error)
    return result


def source_inventory():
    """An explicit local inventory, not a compiler-derived dependency closure."""
    names = set(LEGACY_SOURCES) | {'Makefile', 'tests/generic-wire/run_live.py'}
    for pattern in ('*.c', '*.h'):
        names.update(str(path.relative_to(ROOT)) for path in ROOT.glob(pattern))
    for path in (ROOT / 'llvm_mode').rglob('*'):
        relative = path.relative_to(ROOT)
        if any(part.startswith('.') for part in relative.parts):
            continue
        if path.suffix in {'.c', '.cc', '.cpp', '.h', '.patch', '.cmake'} or path.name in {
                'Makefile', 'CMakeLists.txt'}:
            names.add(str(relative))
    return {name: file_snapshot(ROOT / name) for name in sorted(names)}


def changed_files(before, after):
    """Include additions, removals and unreadable snapshots in the change list."""
    def identity(item):
        return (item.get('present'), item.get('sha256'), item.get('resolved_path'))

    return [name for name in sorted(before.keys() | after.keys())
            if name not in before or name not in after
            or identity(before[name]) != identity(after[name])
            or (before[name].get('present') and not before[name].get('stable_during_read', False))
            or (after[name].get('present') and not after[name].get('stable_during_read', False))]


def unverified_files(snapshot):
    return [name for name, item in snapshot.items()
            if not item.get('present') or not item.get('sha256')
            or not item.get('stable_during_read', False)]


def artifact_inventory(work, candidates):
    """Report existing files beside the report without copying or creating them."""
    names = {'build.log', 'command.json', 'fuzz.log', 'wire.jsonl', 'fixture-server',
             'in/pulse.replay', 'out/experiment_baseline.json', 'out/fuzzer_stats',
             'out/protocol_stats.json', 'out/protocol_schedule.json',
             'out/protocol_mutations.jsonl', 'out/run_manifest.json'}
    for stem in candidates:
        names.update(f'out/protocol-candidates/{stem}{suffix}'
                     for suffix in ('.json', '.replay'))
    result = {}
    for name in sorted(names):
        item = file_snapshot(work / name)
        item['path'] = name
        item['present_beside_report'] = False
        if item['present'] and 'resolved_path' in item:
            try:
                Path(item['resolved_path']).relative_to(work.resolve())
            except ValueError:
                pass
            else:
                item['present_beside_report'] = True
        result[name] = item
    return result


def response_metric_definitions(stats):
    """Keep legacy completion counts distinct from v2 field correlation."""
    version = stats.get('stats_version', 1)
    if type(version) is int and version == 2:
        return {
            'completed_responses': 'Pending requests completed by the expected response.',
            'correlated_responses': ('Completed pending responses for which at least one '
                                     'applicable field equality rule was checked and all '
                                     'applicable rules passed; not a count of comparisons.'),
        }
    if type(version) is int and version == 1:
        return {
            'correlated_responses': ('Legacy v1 completion count: includes expected responses '
                                     'with no field equality rules. It cannot establish '
                                     'that field correlation was checked.'),
        }
    return {
        'completed_responses': 'Unknown statistics version; count semantics are unverified.',
        'correlated_responses': 'Unknown statistics version; count semantics are unverified.',
    }


def read_stats(path):
    return {key.strip(): value.strip() for line in path.read_text().splitlines()
            if ':' in line for key, value in [line.split(':', 1)]}


def records(path):
    data = path.read_bytes()
    result, at = [], 0
    while at < len(data):
        if len(data) - at < 4:
            raise ValueError(f'truncated record prefix: {path}')
        size = int.from_bytes(data[at:at + 4], 'little')
        at += 4
        if size < 7 or size > 14 or size > len(data) - at:
            raise ValueError(f'invalid record size: {path}')
        packet = data[at:at + size]
        if (packet[0] != 0xa7 or packet[3] != 1 or
                int.from_bytes(packet[1:3], 'big') != size - 3 or
                int.from_bytes(packet[4:6], 'big') == 0):
            raise ValueError(f'invalid fictional wire message: {path}')
        result.append(packet)
        at += size
    if not result:
        raise ValueError(f'empty replay: {path}')
    return result


LAYER_IDS = {'HEAD': 1, 'CONTENT': 2, 'SEQUENCE': 4}
PURPOSES = {'coverage', 'confirmation', 'calibration', 'sync', 'state_analysis',
            'hang_check', 'unknown'}


def identity_key(item):
    """A recorded execution identity; labels alone never establish a join."""
    if not isinstance(item, dict) or not isinstance(item.get('run_id'), str) or not item['run_id']:
        raise ValueError('missing run identity')
    for name, minimum in (('segment_id', 0), ('candidate_id', 1), ('exec_id', 1)):
        if type(item.get(name)) is not int or item[name] < minimum:
            raise ValueError(f'invalid {name}')
    return tuple(item[name] for name in ('run_id', 'segment_id', 'candidate_id', 'exec_id'))


def candidate_evidence(directory, example, feedback):
    """Qualify existing v3 captures only; never run a target or manufacture IDs.

    Capture budgets can omit later executions. Unjoined feedback is reported and
    excluded from evidence; it cannot be promoted to a successful sampled edit.
    """
    eligible, errors, excluded, seen = {}, [], [], set()
    all_stems = []
    for metadata in sorted(directory.glob('*.json')):
        all_stems.append(metadata.stem)
        try:
            sidecar = json.loads(metadata.read_text())
            if (not isinstance(sidecar, dict) or type(sidecar.get('format_version')) is not int or
                    sidecar['format_version'] != 3):
                raise ValueError('capture format_version must be 3')
            purpose = sidecar.get('purpose')
            if purpose not in PURPOSES:
                raise ValueError('missing or unknown explicit execution purpose')
            if purpose != 'coverage':
                excluded.append({'capture': metadata.stem, 'reason': 'not coverage'})
                continue
            key = identity_key(sidecar)
            if key in seen:
                eligible.pop(key, None)
                raise ValueError('duplicate coverage execution identity')
            seen.add(key)
            if type(sidecar.get('structured')) is not bool:
                raise ValueError('structured must be an explicit boolean')
            if not sidecar['structured']:
                excluded.append({'capture': metadata.stem, 'reason': 'raw execution'})
                continue
            for name in ('planned_messages', 'attempted_messages', 'sent_messages',
                         'submitted_records', 'total_bytes_sent', 'partial_bytes_tail',
                         'parent_seed_id', 'target_state'):
                if type(sidecar.get(name)) is not int or sidecar[name] < 0:
                    raise ValueError(f'missing or invalid {name}')
            for name in ('is_transmission_complete', 'is_response_complete',
                         'response_budget_exceeded'):
                if type(sidecar.get(name)) is not bool:
                    raise ValueError(f'missing or invalid {name}')
            if (not sidecar['is_transmission_complete'] or
                    not sidecar['is_response_complete'] or sidecar['response_budget_exceeded']):
                excluded.append({'capture': metadata.stem, 'reason': 'incomplete execution'})
                continue
            count = sidecar['planned_messages']
            if (count == 0 or sidecar['attempted_messages'] != count or
                    sidecar['sent_messages'] != count or sidecar['submitted_records'] != count or
                    sidecar['partial_bytes_tail'] != 0):
                raise ValueError('complete flag disagrees with submitted/planned counts')
            packets = records(metadata.with_suffix('.replay'))
            if len(packets) != count or sum(map(len, packets)) != sidecar['total_bytes_sent']:
                raise ValueError('replay records disagree with capture metadata')
            if sidecar.get('layer') not in LAYER_IDS:
                raise ValueError('structured capture has no actual mutation layer')
            if sidecar.get('forkserver') != 'coverage':
                raise ValueError('coverage purpose requires coverage forkserver')
            eligible[key] = (metadata.stem, sidecar, packets)
        except (OSError, ValueError, TypeError) as error:
            errors.append({'capture': metadata.stem, 'reason': str(error)})

    joined, feedback_keys = {}, set()
    unjoined = 0
    for item in feedback:
        if not isinstance(item, dict):
            errors.append({'feedback': item, 'reason': 'feedback record must be an object'})
            continue
        if item.get('event') != 'layer_feedback':
            continue
        try:
            for name in ('discoveries', 'new_tuples', 'new_buckets'):
                if type(item.get(name)) is not int or item[name] < 0:
                    raise ValueError(f'invalid feedback {name}')
            if (type(item.get('layer_id')) is not int or item['layer_id'] not in LAYER_IDS.values() or
                    type(item.get('memory_state_id')) is not int or item['memory_state_id'] < 0):
                raise ValueError('invalid feedback layer/state')
            if item.get('exec_id') == 0:
                if item['discoveries'] or item['new_tuples'] or item['new_buckets']:
                    raise ValueError('unexecuted candidate received discovery credit')
                unjoined += 1
                continue
            key = identity_key(item)
            if key in feedback_keys:
                joined.pop(key, None)
                raise ValueError('duplicate layer_feedback execution identity')
            feedback_keys.add(key)
            if key not in eligible:
                unjoined += 1
                continue
            sidecar = eligible[key][1]
            if (item.get('layer_id') != LAYER_IDS[sidecar['layer']] or
                    item.get('memory_state_id') != sidecar['target_state']):
                raise ValueError('feedback layer/state does not match captured execution')
            joined[key] = item
        except (ValueError, TypeError) as error:
            errors.append({'feedback': item, 'reason': str(error)})

    edits = {layer: [] for layer in LAYER_IDS}
    nonzero = []
    for key, (stem, sidecar, packets) in eligible.items():
        if key not in joined:
            continue
        if sidecar['target_state'] > 0:
            nonzero.append(stem)
        # Only the initial queue seed has the known one-record baseline. Later
        # parent seeds require their own immutable baseline before claiming edits.
        if sidecar['parent_seed_id'] != 0:
            continue
        layer = sidecar['layer']
        if layer == 'HEAD':
            changed = (len(packets) == 1 and packets[0][4:6] != example[4:6] and
                       packets[0][6:] == example[6:])
        elif layer == 'CONTENT':
            changed = (len(packets) == 1 and packets[0][4:6] == example[4:6] and
                       packets[0][6:] != example[6:])
        else:
            changed = len(packets) != 1
        if changed:
            edits[layer].append(stem)
    missing = [value[0] for key, value in eligible.items() if key not in joined]
    return {
        'candidates': [value[0] for value in eligible.values()],
        'all_capture_stems': all_stems,
        'errors': errors,
        'excluded_captures': excluded,
        'matched_feedback_count': len(joined),
        'unjoined_feedback_count': unjoined,
        'samples_without_matching_feedback': missing,
        'edit_samples': edits,
        'nonzero_target_samples': nonzero,
        'coverage_discovery_samples': [eligible[key][0] for key, item in joined.items()
                                       if item['discoveries'] & 16 and
                                       item['new_tuples'] + item['new_buckets'] > 0],
        'memory_discovery_samples': [eligible[key][0] for key, item in joined.items()
                                     if item['discoveries'] & 2],
        'scope': ('Exact v3 captured bytes joined to a unique coverage execution and '
                  'its feedback. Nonzero target samples establish observed directed entry; '
                  'they do not establish comparative effectiveness or complete build identity.'),
    }


def run(args):
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    source_before = source_inventory()
    build_inputs_before = {name: file_snapshot(ROOT / name) for name in LOCAL_BINARIES}
    env = dict(os.environ, AFL_PATH=str(ROOT), AFL_NO_UI='1', AFL_NO_AFFINITY='1',
               AFL_SKIP_CPUFREQ='1', AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1')
    target = work / 'fixture-server'
    build = [str(ROOT / 'afl-clang-fast'), '-O1', '-g', '-Wall', '-Wextra',
             'tests/generic-wire/fixture_udp_server.c', '-o', str(target)]
    with (work / 'build.log').open('w') as log:
        subprocess.run(build, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    spec = ROOT / 'tests/generic-wire/fictional_protocol.json'
    example = bytes.fromhex(json.loads(spec.read_text())['messages'][0]['example_hex'])
    corpus = work / 'in'
    corpus.mkdir()
    (corpus / 'pulse.replay').write_bytes(len(example).to_bytes(4, 'little') + example)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    output = work / 'out'
    trace = work / 'wire.jsonl'
    command = ['setarch', os.uname().machine, '-R', str(ROOT / 'afl-fuzz'), '-d',
               '-i', str(corpus), '-o', str(output), '-N', f'udp://127.0.0.1/{port}',
               '-D', '50000', '-W', '10', '-w', '1000', '-r', '10', '-K',
               '-m', 'none', '-t', '1000', '--random-seed', str(args.seed),
               '--generic-spec', str(spec), '--mutation-mode', 'valid',
               '--mutation-layers', 'head,content,sequence', '--protocol-schedule', 'adaptive',
               '--protocol-save-candidates', '128']
    if args.state_aware:
        command += ['-E', '-q', '3', '-s', '3']
    command += ['--', str(target), str(port), str(trace)]
    (work / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    binary_paths = {name: ROOT / name for name in LOCAL_BINARIES}
    binary_paths['fixture-server'] = target
    binaries_before = {name: file_snapshot(path) for name, path in binary_paths.items()}
    started, ready = time.monotonic(), None
    log_path = work / 'fuzz.log'
    with log_path.open('w') as log:
        child = subprocess.Popen(command, cwd=work, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while child.poll() is None:
                now = time.monotonic()
                if ready is None and (output / 'experiment_baseline.json').exists():
                    ready = now
                if ready is not None and now - ready >= args.seconds:
                    child.send_signal(signal.SIGINT)
                    break
                if ready is None and now - started > 60:
                    raise TimeoutError('target startup/calibration exceeded 60 seconds')
                time.sleep(0.1)
            child.wait(timeout=20)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    if child.returncode != 0 or ready is None:
        raise RuntimeError(f'StateAFL failed ({child.returncode}); see {log_path}')
    stats = json.loads((output / 'protocol_stats.json').read_text())
    schedule = json.loads((output / 'protocol_schedule.json').read_text())
    feedback = [json.loads(line) for line in (output / 'protocol_mutations.jsonl').read_text().splitlines()]
    traffic = [json.loads(line) for line in trace.read_text().splitlines()]
    evidence = candidate_evidence(output / 'protocol-candidates', example, feedback)
    candidates = evidence['candidates']
    baseline = json.loads((output / 'experiment_baseline.json').read_text())
    final = read_stats(output / 'fuzzer_stats')
    checks = {
        'generic_engine': stats.get('engine') == 'generic-wire',
        'candidate_metadata_valid': not evidence['errors'],
        'saved_candidates_show_all_three_edits': all(evidence['edit_samples'].values()),
        'all_received_packets_valid': bool(traffic) and all(
            isinstance(item, dict) and item.get('valid') is True for item in traffic),
        'no_raw_mutation': int(final['protocol_raw']) == 0,
        'coverage_feedback_received': bool(evidence['coverage_discovery_samples']),
        'captured_feedback_identity_valid': bool(candidates) and
                                            not evidence['samples_without_matching_feedback'],
        'feedback_attribution_matches': schedule['observations'] == sum(
            isinstance(item, dict) and item.get('event') == 'layer_feedback' for item in feedback),
        'memory_feedback_received': not args.state_aware or bool(evidence['memory_discovery_samples']),
        'natural_nonzero_target_m2_executed': not args.state_aware or
                                             bool(evidence['nonzero_target_samples']),
        'candidate_identity_boundary_maintained': all(
            json.loads(meta.read_text()).get('execution_identity_verified') is False
            for meta in (output / 'protocol-candidates').glob('*.json')
        ) if list((output / 'protocol-candidates').glob('*.json')) else True,
    }
    binaries_after = {name: file_snapshot(path) for name, path in binary_paths.items()}
    source_after = source_inventory()
    provenance = {
        'format_version': 1,
        'source_inventory_scope': ('Root C sources and headers, LLVM-mode non-hidden '
                                   'source/build-description files, fixture description '
                                   'and acceptance controller; an overinclusive local '
                                   'inventory, not a compiler dependency trace.'),
        'source_before_build': source_before,
        'source_after_execution': source_after,
        'source_changes': changed_files(source_before, source_after),
        'unverified_source_inputs': sorted(set(unverified_files(source_before)) |
                                           set(unverified_files(source_after))),
        'local_binaries_before_build': build_inputs_before,
        'binaries_before_execution': binaries_before,
        'binaries_after_execution': binaries_after,
        'binary_changes': changed_files(binaries_before, binaries_after),
        'unverified_binary_inputs': sorted(set(unverified_files(binaries_before)) |
                                           set(unverified_files(binaries_after)) |
                                           set(unverified_files(build_inputs_before))),
        'build_input_changes': changed_files(
            build_inputs_before, {name: binaries_before[name] for name in LOCAL_BINARIES}),
        'artifacts': artifact_inventory(work, evidence['all_capture_stems']),
        'packaging': ('Files marked present_beside_report existed in the output '
                      'directory when this report was assembled. They are not embedded '
                      'in this JSON or automatically copied by it; copying report.json '
                      'alone does not preserve them. The report excludes its own hash.'),
        'complete_build_attestation': False,
        'execution_identity_verified': False,
        'binary_snapshot_scope': ('Disk paths observed before and after execution; '
                                  'no attestation of the running process images.'),
        'limitations': ('Snapshots identify observed file contents and changes. They '
                        'do not establish that the fuzzer was built from these sources, '
                        'trace the downstream compiler, identify external libraries, '
                        'or certify that later copies of this report retain its artifacts. '
                        'Missing, unreadable or changing inputs remain unverified; '
                        'provenance does not alter the acceptance checks.'),
    }
    metric_definitions = {
        'structured_success': 'Candidates constructed by the engine, not successful sends.',
        'responses': 'Frames matching a declared response grammar, including unsolicited responses.',
        'memory_events': ('New memory states observed during coverage-qualified analysis; '
                          'this does not show that nonzero states were selected for mutation.'),
        'nonzero_target_samples': ('Captured complete structured coverage executions with target_state > 0 '
                                   'and uniquely matching layer feedback; no injected IDs are used. '
                                   'These demonstrate directed entry only within the declared provider scope.'),
    }
    metric_definitions.update(response_metric_definitions(stats))
    report = dict(checks=checks, passed=all(checks.values()), state_aware=args.state_aware,
                  seed=args.seed, seconds=args.seconds, received_packets=len(traffic),
                  structured_samples=len(candidates), candidate_evidence=evidence, baseline=baseline, protocol=stats,
                  schedule=schedule, build=build, command=command,
                  source_sha256={name: source_after[name].get('sha256') for name in LEGACY_SOURCES},
                  provenance=provenance, metric_definitions=metric_definitions,
                  statistics_schema_version=stats.get('stats_version', 1),
                  feedback_memory_state_ids=sorted({item['memory_state_id'] for item in feedback
                                                    if isinstance(item, dict) and
                                                    item.get('event') == 'layer_feedback' and
                                                    type(item.get('memory_state_id')) is int}),
                  limitation='Loopback fictional protocol integration acceptance; no industrial conformance or comparative coverage claim.')
    (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--seconds', type=float, default=12, help='fuzz time after calibration')
    parser.add_argument('--seed', type=int, default=20261027)
    parser.add_argument('--state-aware', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600 or not 0 <= args.seed <= 0xffffffff:
        parser.error('seconds must be 1..600 and seed must be uint32')
    raise SystemExit(run(args))
