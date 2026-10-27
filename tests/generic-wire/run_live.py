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


def run(args):
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
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
    candidates = []
    head = content = sequence = False
    for metadata in sorted((output / 'protocol-candidates').glob('*.json')):
        if not json.loads(metadata.read_text())['structured']:
            continue
        packets = records(metadata.with_suffix('.replay'))
        candidates.append(metadata.stem)
        head |= any(packet[4:6] != example[4:6] for packet in packets)
        content |= any(packet[6:] != example[6:] for packet in packets)
        sequence |= len(packets) != 1
    baseline = json.loads((output / 'experiment_baseline.json').read_text())
    final = read_stats(output / 'fuzzer_stats')
    checks = {
        'generic_engine': stats.get('engine') == 'generic-wire',
        'all_three_layers_executed': all(stats[layer] > 0 for layer in ('HEAD', 'CONTENT', 'SEQUENCE')),
        'saved_candidates_show_all_three_edits': head and content and sequence,
        'all_received_packets_valid': bool(traffic) and all(item['valid'] for item in traffic),
        'no_raw_mutation': int(final['protocol_raw']) == 0,
        'coverage_feedback_received': schedule['coverage_events'] > 0 and
                                      schedule['new_tuples'] + schedule['new_buckets'] > 0,
        'feedback_attribution_matches': schedule['observations'] == sum(item['event'] == 'layer_feedback' for item in feedback),
        'memory_feedback_received': not args.state_aware or schedule['memory_events'] > 0,
    }
    report = dict(checks=checks, passed=all(checks.values()), state_aware=args.state_aware,
                  seed=args.seed, seconds=args.seconds, received_packets=len(traffic),
                  structured_samples=len(candidates), baseline=baseline, protocol=stats,
                  schedule=schedule, build=build, command=command,
                  source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                 for name in ('afl-fuzz.c', 'generic_wire.c', 'generic_runtime.c',
                                              'tests/generic-wire/fixture_udp_server.c',
                                              'tests/generic-wire/fictional_protocol.json')},
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
