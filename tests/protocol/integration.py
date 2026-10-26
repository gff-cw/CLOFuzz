#!/usr/bin/env python3
"""Bounded, loopback-only BACnet campaigns for five StateAFL configurations."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

from validate_bacnet import decode_packet, replay_records


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
MODES = {"legacy": None, "head": ("valid", "head"),
         "head_content": ("valid", "head,content"),
         "all": ("valid", "head,content,sequence"),
         "hybrid": ("hybrid", "head,content,sequence")}
SEEDS = ("seed01_whois.replay", "seed03_read_objectname.replay",
         "seed04_read_vendorname.replay", "seed05_read_objectlist.replay")


def read_stats(path):
    result = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                result[key.strip()] = value.strip()
    return result


def valid_request(packet):
    parsed = decode_packet(packet)
    assert parsed["bvlc_function"] in (10, 11), parsed
    values = parsed.get("tags", [])
    assert all(tag["context"] and "kind" not in tag for tag in values), parsed
    if parsed["apdu_type"] == 1 and parsed["service"] == 8:
        assert not values or ([tag["tag"] for tag in values] == [0, 1]
                              and 0 <= values[0]["value"] <= values[1]["value"] <= 4194303), parsed
    elif parsed["apdu_type"] == 0 and parsed["service"] == 12:
        assert [tag["tag"] for tag in values] in ([0, 1], [0, 1, 2]), parsed
        assert len(bytes.fromhex(values[0]["bytes"])) == 4, parsed
    else:
        raise ValueError("outside supported Who-Is / ReadProperty request grammar")
    return parsed


def inspect_replays(directory):
    files = sorted(directory.glob("id*"))
    result = {"files": len(files), "framing_valid": 0, "all_messages_structural": 0,
              "messages": 0, "structural_messages": 0, "examples": [], "errors": []}
    for path in files:
        item = {"file": path.name, "bytes": path.stat().st_size}
        try:
            records, framing = replay_records(path.read_bytes())
            assert framing == "LE32-length-prefixed", framing
            result["framing_valid"] += 1
            result["messages"] += len(records)
            item.update(framing=framing, message_count=len(records), lengths=[len(record) for record in records])
            valid = 0
            for record in records:
                try:
                    valid_request(record)
                    valid += 1
                except (AssertionError, ValueError, IndexError, KeyError):
                    pass
            result["structural_messages"] += valid
            if valid == len(records):
                result["all_messages_structural"] += 1
            item["structural_messages"] = valid
        except (AssertionError, ValueError, IndexError) as error:
            if len(result["errors"]) < 10:
                result["errors"].append({"file": path.name, "error": str(error)})
        if len(result["examples"]) < 10:
            result["examples"].append(item)
    result["structural_file_ratio"] = result["all_messages_structural"] / len(files) if files else None
    result["structural_message_ratio"] = result["structural_messages"] / result["messages"] if result["messages"] else None
    return result


def report_campaign(work, name, command, status, timing):
    output = work / name / "out"
    stats = read_stats(output / "fuzzer_stats")
    protocol_path = output / "protocol_stats.json"
    protocol = json.loads(protocol_path.read_text()) if protocol_path.exists() else None
    events, layers, violations, log_errors = Counter(), Counter(), Counter(), []
    log_path = output / "protocol_mutations.jsonl"
    if log_path.exists():
        for index, line in enumerate(log_path.read_text().splitlines(), 1):
            try:
                event = json.loads(line)
                events[event.get("event", "unknown")] += 1
                if event.get("event") == "mutation":
                    layers[event.get("layer", "unknown")] += 1
                    violations[str(event.get("intentional_violation"))] += 1
            except json.JSONDecodeError:
                log_errors.append(index)
    paths = sorted((output / "replayable-new-ipsm-paths").glob("id*"))
    sequences = []
    for path in paths:
        encoded = path.name.split(":", 2)[1].removesuffix("-")
        if re.fullmatch(r"[0-9]+(?:-[0-9]+)*", encoded):
            sequences.append([int(value) for value in encoded.split("-")])
    state_ids = sorted({value for sequence in sequences for value in sequence})
    dot_path = output / "ipsm.dot"
    dot_text = dot_path.read_text() if dot_path.exists() else ""
    graph_edges = {(int(source), int(target)) for source, target in re.findall(r"(?m)^\s*(\d+)\s*->\s*(\d+)\b", dot_text)}
    sequence_edges = {(source, target) for sequence in sequences for source, target in zip(sequence, sequence[1:])}
    tlsh_path = output / "tlsh.log"
    radii = tlsh_path.read_text().splitlines() if tlsh_path.exists() else []
    queue_count = len(list((output / "queue").glob("id*")))
    replays = inspect_replays(output / "replayable-queue")
    fuzz_log = (work / name / "fuzz.log").read_text(errors="replace")
    structured, raw = int(stats.get("protocol_structured", "0")), int(stats.get("protocol_raw", "0"))
    attempts = protocol.get("attempts", 0) if protocol else 0
    rejects = protocol.get("rejected", 0) if protocol else 0
    checks = {"ready_reached": "All set and ready to roll!" in fuzz_log,
              "clean_sigint_stop": timing["sigint_sent"] and status == 0,
              "fuzzer_aslr_disabled": "ASLR disabled for this process (ADDR_NO_RANDOMIZE)." in fuzz_log,
              "executions_continue": int(stats.get("execs_done", "0")) > 4,
              "coverage_nonzero": float(stats.get("bitmap_cvg", "0").rstrip("%")) > 0,
              "queue_matches_stats": queue_count == int(stats.get("paths_total", "0")),
              "replays_present_and_framed": replays["files"] >= 4 and replays["framing_valid"] == replays["files"],
              "memory_states_present": len(state_ids) > 1 and 0 in state_ids,
              "memory_graph_matches_paths": bool(sequence_edges) and sequence_edges <= graph_edges,
              "calibration_present": bool(radii) and all(line.isdigit() and int(line) > 0 for line in radii),
              "no_crashes": int(stats.get("unique_crashes", "0")) == 0,
              "no_hangs": int(stats.get("unique_hangs", "0")) == 0}
    if name != "legacy":
        checks.update(protocol_stats_present=protocol is not None,
                      structured_mutations_run=structured > 0,
                      mutation_log_valid=log_path.exists() and not log_errors,
                      attempts_accounted=bool(protocol) and attempts == protocol["structured_success"] + rejects,
                      enabled_layers_only=set(layers) <= set(MODES[name][1].upper().split(",")))
    else:
        checks["legacy_has_no_protocol_outputs"] = protocol is None and not log_path.exists()
    result = {"mode": name, "passed": all(checks.values()), "checks": checks,
              "command": command, "exit_code": status, "timing": timing, "stats": stats,
              "queue_count": queue_count, "replayable_queue": replays,
              "protocol_stats": protocol,
              "protocol_log": {"path": str(log_path), "events": dict(events), "layers": dict(layers),
                               "intentional_violations": dict(violations), "invalid_json_lines": log_errors},
              "ratios": {"structured_run_share": structured / (structured + raw) if structured + raw else None,
                         "rejection_share_of_attempts": rejects / attempts if attempts else None,
                         "mutation_share_of_log_candidates": events["mutation"] / (events["mutation"] + events["rejected"]) if events["mutation"] + events["rejected"] else None},
              "memory_state_feedback": {"inferred_state_ids": state_ids, "state_sequences": sequences,
                                        "state_paths": [path.name for path in paths], "graph_edges": sorted(graph_edges),
                                        "calibrated_radii": radii}}
    (work / name / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_campaign(args, work, corpus, name, env):
    folder = work / name
    folder.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    active = env.copy()
    active.update(BACNET_IFACE="lo", BACNET_IP_PORT=str(port))
    command = ["setarch", os.uname().machine, "-R", str(ROOT / "afl-fuzz"), "-d",
               "-i", str(corpus), "-o", str(folder / "out"),
               "-N", f"udp://127.0.0.1/{port}", "-D", str(args.startup_usecs), "-W", "10", "-w", "1000",
               "-r", "10", "-E", "-K", "-q", "3", "-s", "3", "-m", "none", "-t", "1000"]
    if MODES[name]:
        mode, layers = MODES[name]
        command = command[:3] + [sys.executable, str(ROOT / "tools/run_protocol_campaign.py"),
                    "--spec-dir", str(args.spec_dir), "--"] + command[4:]
        command += ["--mutation-mode", mode, "--mutation-layers", layers]
    command += ["--", str(args.server), "123"]
    (folder / "command.json").write_text(json.dumps({"argv": command,
        "environment": {key: active[key] for key in ("AFL_PATH", "AFL_NO_UI", "AFL_NO_AFFINITY", "AFL_SKIP_CPUFREQ", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "BACNET_IFACE", "BACNET_IP_PORT")}}, indent=2) + "\n")
    started, ready = time.monotonic(), None
    timing = {"ready_elapsed_seconds": None, "sigint_sent": False}
    log_path = folder / "fuzz.log"
    print(f"START {name}: UDP {port}", flush=True)
    with log_path.open("w") as log:
        process = subprocess.Popen(command, env=active, cwd=folder, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                now = time.monotonic()
                if ready is None:
                    if "All set and ready to roll!" in log_path.read_text(errors="replace"):
                        ready = now
                        timing["ready_elapsed_seconds"] = round(now - started, 3)
                        print(f"READY {name}: calibration={now-started:.2f}s; running {args.seconds}s", flush=True)
                    elif now - started > args.ready_timeout:
                        timing["startup_timeout"] = True
                        break
                elif now - ready >= args.seconds:
                    break
                time.sleep(.1)
            if process.poll() is None:
                timing["sigint_sent"] = True
                process.send_signal(signal.SIGINT)
            try:
                status = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                timing["forced_kill"] = True
                os.killpg(process.pid, signal.SIGKILL)
                status = process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    timing["total_elapsed_seconds"] = round(time.monotonic() - started, 3)
    timing["seconds_after_ready"] = round(time.monotonic() - ready, 3) if ready is not None else None
    result = report_campaign(work, name, command, status, timing)
    print(f"END {name}: passed={result['passed']} execs={result['stats'].get('execs_done')} queue={result['queue_count']} coverage={result['stats'].get('bitmap_cvg')} states={result['memory_state_feedback']['inferred_state_ids']}", flush=True)
    if not result["passed"]:
        print("FAILED CHECKS " + ", ".join(key for key, value in result["checks"].items() if not value), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=15)
    parser.add_argument("--startup-usecs", type=int, default=200000)
    parser.add_argument("--ready-timeout", type=float, default=300)
    parser.add_argument("--server", type=Path, default=WORKSPACE / "bacnet-stack/build-protocol-integration/server")
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--spec-dir", type=Path, default=ROOT / "protocols/bacnet_ip")
    args = parser.parse_args()
    args.server = args.server.resolve()
    args.spec_dir = args.spec_dir.resolve()
    work = args.output.resolve()
    modes = args.modes.split(",")
    assert all(name in MODES for name in modes), modes
    if work.exists():
        raise SystemExit(f"Refusing to overwrite evidence directory: {work}")
    work.mkdir(parents=True)
    corpus = work / "in"
    corpus.mkdir()
    corpus_metadata = []
    for name in SEEDS:
        source = WORKSPACE / "bacnet-stack/inputs" / name
        data = source.read_bytes()
        records, framing = replay_records(data)
        assert len(records) == 1 and framing == "LE32-length-prefixed", name
        valid_request(records[0])
        (corpus / name).write_bytes(data)
        corpus_metadata.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    env = os.environ.copy()
    env.update(AFL_PATH=str(ROOT), AFL_NO_UI="1", AFL_NO_AFFINITY="1",
               AFL_SKIP_CPUFREQ="1", AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1")
    for key in list(env):
        if key.startswith("__AFL_") or key in ("STATE_SHM_ID", "MVP_CALIBRATION_SHM_ID", "MVP_RADIUS", "AFL_OUTDIR"):
            del env[key]
    metadata = {"server": str(args.server), "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
                "afl_fuzz_sha256": hashlib.sha256((ROOT / "afl-fuzz").read_bytes()).hexdigest(),
                "protocol_ir_sha256": hashlib.sha256((args.spec_dir / "protocol_ir.json").read_bytes()).hexdigest(),
                "state_ir_sha256": hashlib.sha256((args.spec_dir / "state_ir.json").read_bytes()).hexdigest(),
                "corpus": corpus_metadata, "seconds_after_ready": args.seconds, "modes": modes}
    (work / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = []
    for name in modes:
        result = run_campaign(args, work, corpus, name, env)
        results.append(result)
        (work / "summary.json").write_text(json.dumps({"passed": all(item["passed"] for item in results), "runs": results}, indent=2) + "\n")
        if not result["passed"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
