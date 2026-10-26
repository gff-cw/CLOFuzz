#!/usr/bin/env python3
"""Repeated loopback BACnet comparisons and separate YAML wire controls.

The unit tests import the analysis helpers without launching a target. Live runs
require the BACnet integration target and the two reproducibility CLI options.
"""

import argparse
from collections import Counter
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

from integration import MODES, ROOT, SEEDS, WORKSPACE, read_stats, report_campaign, valid_request
from validate_bacnet import replay_records


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(directory, names=None):
    paths = sorted(directory.rglob("*")) if names is None else [directory / name for name in sorted(names)]
    files = {str(path.relative_to(directory)): sha256(path) for path in paths if path.is_file()}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"sha256": digest, "files": files}


def source_manifest():
    tracked = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT, check=True,
                             capture_output=True).stdout.decode().split("\0")
    names = [name for name in tracked if name and not name.startswith("tests/protocol/evidence/")]
    for name in ("tests/protocol/controlled_experiments.py", "tests/protocol/test_experiment_analysis.py",
                 "docs/controlled-experiment-design.md"):
        if name not in names and (ROOT / name).exists():
            names.append(name)
    return manifest(ROOT, names)


def run_order(modes, repeat):
    """Latin-style rotation; the seed is paired across modes within each round."""
    offset = repeat % len(modes)
    return list(modes[offset:]) + list(modes[:offset])


def quantiles(values):
    """Linear interpolation (the common R-7 convention), with no invented zeros."""
    ordered = sorted(float(value) for value in values if value is not None and math.isfinite(value))
    if not ordered:
        return {"n": 0, "min": None, "p25": None, "median": None, "p75": None, "max": None}

    def at(fraction):
        position = (len(ordered) - 1) * fraction
        low = math.floor(position)
        high = math.ceil(position)
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)

    return {"n": len(ordered), "min": ordered[0], "p25": at(.25), "median": at(.5),
            "p75": at(.75), "max": ordered[-1]}


def bitmap_metrics(path):
    if not path.exists():
        return {"bytes": None, "nonvirgin_bytes": None, "cleared_bits": None, "sha256": None}
    data = path.read_bytes()
    return {"bytes": len(data), "nonvirgin_bytes": sum(value != 255 for value in data),
            "cleared_bits": sum(8 - value.bit_count() for value in data),
            "sha256": hashlib.sha256(data).hexdigest()}


def number(stats, name):
    value = stats.get(name)
    return int(value) if value is not None else None


def delta(final, initial, name):
    end, begin = number(final, name), number(initial, name)
    return end - begin if end is not None and begin is not None else None


def ratio(numerator, denominator):
    return numerator / denominator if numerator is not None and denominator else None


def analyze_run(result, baseline, bitmap):
    stats, protocol = result["stats"], result["protocol_stats"] or {}
    initial = baseline.get("stats", {})
    initial_protocol = baseline.get("protocol_stats") or {}
    executions = delta(stats, initial, "execs_done")
    structured = delta(stats, initial, "protocol_structured")
    raw = delta(stats, initial, "protocol_raw")
    attempts = delta(protocol, initial_protocol, "attempts")
    rejected = delta(protocol, initial_protocol, "rejected")
    initial_bitmap = baseline.get("bitmap", {}).get("nonvirgin_bytes")
    seconds = result["timing"].get("measured_fuzz_seconds")
    return {"fuzz_executions": executions,
            "fuzz_executions_per_second": ratio(executions, seconds),
            "total_executions_including_calibration": number(stats, "execs_done"),
            "calibration_baseline_executions": number(initial, "execs_done"),
            "bitmap_nonvirgin_bytes": bitmap["nonvirgin_bytes"],
            "bitmap_cleared_bits": bitmap["cleared_bits"],
            "bitmap_nonvirgin_byte_gain": bitmap["nonvirgin_bytes"] - initial_bitmap
                if bitmap["nonvirgin_bytes"] is not None and initial_bitmap is not None else None,
            "memory_state_count": len(result["memory_state_feedback"]["inferred_state_ids"]),
            "memory_edge_count": len(result["memory_state_feedback"]["graph_edges"]),
            "queue_count": result["queue_count"], "queue_growth": delta(stats, initial, "paths_total"),
            "structured_runs": structured, "raw_runs": raw,
            "structured_run_share": ratio(structured, structured + raw)
                if structured is not None and raw is not None else None,
            "raw_run_share": ratio(raw, structured + raw)
                if structured is not None and raw is not None else None,
            "structured_attempts": attempts, "rejected_attempts": rejected,
            "rejection_share_of_attempts": ratio(rejected, attempts),
            "responses": delta(protocol, initial_protocol, "responses"),
            "correlated_responses": delta(protocol, initial_protocol, "correlated_responses"),
            "unique_crashes": number(stats, "unique_crashes"),
            "unique_hangs": number(stats, "unique_hangs")}


def summarize(runs):
    groups = {}
    for mode in MODES:
        selected = [run for run in runs if run["mode"] == mode]
        if not selected:
            continue
        keys = sorted({key for run in selected for key in run["metrics"]})
        groups[mode] = {"runs": len(selected), "passed_runs": sum(run["passed"] for run in selected),
                        "metrics": {key: quantiles([run["metrics"].get(key) for run in selected]) for key in keys}}
    paired = {}
    legacy = {run["repeat"]: run for run in runs if run["mode"] == "legacy"}
    for mode in MODES:
        if mode == "legacy":
            continue
        differences = {}
        for run in runs:
            if run["mode"] != mode or run["repeat"] not in legacy:
                continue
            reference = legacy[run["repeat"]]
            for key, value in run["metrics"].items():
                other = reference["metrics"].get(key)
                if value is not None and other is not None:
                    differences.setdefault(key, []).append(value - other)
        paired[mode] = {key: quantiles(values) for key, values in differences.items()}
    return {"by_mode": groups, "paired_differences_from_legacy": paired,
            "interpretation": "Descriptive short-run results only; no statistical-significance or bug-finding benefit claim. "
                              "Zero crashes/hangs means zero observed in this budget, not proof of absence."}


def environment():
    env = os.environ.copy()
    env.update(AFL_PATH=str(ROOT), AFL_NO_UI="1", AFL_NO_AFFINITY="1", AFL_SKIP_CPUFREQ="1",
               AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1")
    for key in list(env):
        if key.startswith("__AFL_") or key in ("STATE_SHM_ID", "MVP_CALIBRATION_SHM_ID", "MVP_RADIUS", "AFL_OUTDIR"):
            del env[key]
    return env


def snapshot(output, destination, protocol_enabled):
    stats = read_stats(output / "fuzzer_stats")
    # write_stats_file truncates before writing, so never accept a partial file.
    if not all(key in stats for key in ("execs_done", "paths_total", "command_line", "slowest_exec_ms")):
        return None
    try:
        protocol = json.loads((output / "protocol_stats.json").read_text()) if protocol_enabled else None
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    exact_path = output / "experiment_baseline.json"
    try:
        exact = json.loads(exact_path.read_text()) if exact_path.exists() else None
        exact_protocol_path = output / "experiment_protocol_baseline.json"
        exact_protocol = json.loads(exact_protocol_path.read_text()) if exact_protocol_path.exists() else None
    except json.JSONDecodeError:
        return None
    if exact is not None:
        stats.update({key: str(exact[key]) for key in ("execs_done", "paths_total", "protocol_structured",
                      "protocol_raw", "protocol_rejected") if key in exact})
        if protocol is not None:
            protocol.update({key: exact[key] for key in ("responses", "correlated_responses") if key in exact})
    if exact_protocol is not None:
        protocol = exact_protocol
    bitmap = bitmap_metrics(output / "fuzz_bitmap")
    if exact is not None and "coverage_edges" in exact:
        bitmap["nonvirgin_bytes"] = exact["coverage_edges"]
        bitmap["count_source"] = "synchronous experiment_baseline.json (virgin_bits byte != 255)"
    saved = {"stats": stats, "protocol_stats": protocol, "bitmap": bitmap,
             "synchronous_baseline": exact, "synchronous_protocol_baseline": exact_protocol}
    destination.mkdir(exist_ok=True)
    for name in ("fuzzer_stats", "protocol_stats.json", "fuzz_bitmap", "ipsm.dot", "experiment_baseline.json",
                 "experiment_protocol_baseline.json"):
        if (output / name).is_file():
            shutil.copy2(output / name, destination / name)
    write_json(destination / "snapshot.json", saved)
    return saved


def run_campaign(args, work, corpus, name, model, random_seed, env, *, mutation_mode=None,
                 seconds=None, save_candidates=0):
    folder = work / name
    folder.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    active = env.copy()
    active.update(BACNET_IFACE="lo", BACNET_IP_PORT=str(port))
    fuzz = ["-d", "-i", str(corpus), "-o", str(folder / "out"), "-N", f"udp://127.0.0.1/{port}",
            "-D", str(args.startup_usecs), "-W", "10", "-w", "1000", "-r", "10", "-E", "-K",
            "-q", "3", "-s", "3", "-m", "none", "-t", "1000", "--random-seed", str(random_seed)]
    command = ["setarch", os.uname().machine, "-R"]
    if MODES[name]:
        mode, layers = MODES[name]
        command += [sys.executable, str(ROOT / "tools/run_protocol_campaign.py"), "--spec-dir", str(model), "--"]
        fuzz += ["--mutation-mode", mutation_mode or mode, "--mutation-layers", layers]
    else:
        command += [str(ROOT / "afl-fuzz")]
    fuzz += ["--protocol-save-candidates", str(save_candidates)]
    command += fuzz + ["--", str(args.server), "123"]
    run_metadata = {"argv": command, "random_seed": random_seed, "source": source_manifest(),
                    "afl_fuzz_sha256": sha256(ROOT / "afl-fuzz"), "server_sha256": sha256(args.server),
                    "model_before_wrapper": manifest(model), "seeds": manifest(corpus),
                    "environment": {key: active[key] for key in ("AFL_PATH", "AFL_NO_UI", "AFL_NO_AFFINITY",
                        "AFL_SKIP_CPUFREQ", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "BACNET_IFACE", "BACNET_IP_PORT")}}
    write_json(folder / "command.json", run_metadata)
    budget = args.seconds if seconds is None else seconds
    started, started_wall = time.monotonic(), time.time()
    ready, measured_start, stopped = None, None, None
    baseline = {}
    timing = {"ready_elapsed_seconds": None, "sigint_sent": False}
    log_path = folder / "fuzz.log"
    print(f"START {work.name}/{name}: seed={random_seed} seconds={budget} UDP={port}", flush=True)
    with log_path.open("w") as log:
        process = subprocess.Popen(command, env=active, cwd=folder, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                now = time.monotonic()
                if ready is None:
                    if "All set and ready to roll!" in log_path.read_text(errors="replace"):
                        ready = now
                        timing["ready_elapsed_seconds"] = now - started
                    elif now - started > args.ready_timeout:
                        timing["startup_timeout"] = True
                        break
                if ready is not None and measured_start is None:
                    candidate = snapshot(folder / "out", folder / "ready", bool(MODES[name]))
                    if candidate is not None:
                        baseline, measured_start = candidate, now
                        timing["baseline_delay_after_ready_seconds"] = now - ready
                if ready is not None and now - ready >= budget:
                    break
                time.sleep(.05)
            stopped = time.monotonic()
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
    baseline_timestamp = baseline.get("synchronous_baseline", {}).get("timestamp_ms") if baseline.get("synchronous_baseline") else None
    measured_seconds = stopped - measured_start if measured_start is not None else None
    if baseline_timestamp is not None:
        # Convert the synchronous wall-clock baseline into this process's
        # monotonic time frame, rather than dropping the ready polling delay.
        measured_seconds = stopped - started - (baseline_timestamp / 1000 - started_wall)
    timing.update(total_elapsed_seconds=time.monotonic() - started,
                  seconds_after_ready=stopped - ready if ready is not None else None,
                  measured_fuzz_seconds=measured_seconds,
                  requested_seconds_after_ready=budget,
                  execution_baseline="synchronous experiment_baseline.json before ready" if baseline.get("synchronous_baseline")
                      else "first complete fuzzer_stats observed after ready; sampling delay recorded")
    result = report_campaign(work, name, command, status, timing)
    # integration.py's campaign uses four seeds; the independent wire control
    # intentionally has one. Keep the framing assertion tied to the real input.
    replays = result["replayable_queue"]
    seed_count = sum(path.is_file() for path in corpus.iterdir())
    result["checks"]["replays_present_and_framed"] = (replays["files"] >= seed_count
        and replays["framing_valid"] == replays["files"])
    result["metrics"] = analyze_run(result, baseline, bitmap_metrics(folder / "out/fuzz_bitmap"))
    result["candidate_sample"] = sample_candidate_metrics(folder / "out")
    result["metrics"].update({"candidate_sample_size": result["candidate_sample"]["sequences"],
        "candidate_sample_structural_share": result["candidate_sample"]["structural_sequence_share"],
        "candidate_sample_structured_share": result["candidate_sample"]["structured_sequence_share"]})
    result["baseline"] = baseline
    result["random_seed"] = random_seed
    result["model_after_wrapper"] = manifest(model)
    result["checks"]["calibration_baseline_recorded"] = bool(baseline)
    result["checks"]["actual_fuzz_bitmap_recorded"] = result["metrics"]["bitmap_nonvirgin_bytes"] is not None
    result["checks"]["post_calibration_executions_present"] = (result["metrics"]["fuzz_executions"] or 0) > 0
    result["passed"] = all(result["checks"].values())
    write_json(folder / "result.json", result)
    print(f"END {work.name}/{name}: passed={result['passed']} fuzz_execs={result['metrics']['fuzz_executions']} "
          f"bitmap_bytes={result['metrics']['bitmap_nonvirgin_bytes']} states={result['metrics']['memory_state_count']}", flush=True)
    return result


def candidate_packets(output, structured_only=False):
    directory = output / "protocol-candidates"
    files = sorted(path for path in directory.glob("*.replay") if path.is_file())
    packets, errors = [], []
    for path in files:
        try:
            sidecar = json.loads(path.with_suffix(".json").read_text())
            if structured_only and sidecar.get("structured") is not True:
                continue
            records, framing = replay_records(path.read_bytes())
            if framing != "LE32-length-prefixed":
                raise ValueError(f"unexpected framing: {framing}")
            if sidecar.get("sent_messages") != len(records):
                raise ValueError("sidecar sent_messages differs from saved records")
            packets.append((path.name, records))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append({"file": path.name, "error": str(error)})
    return packets, errors


def sample_candidate_metrics(output):
    candidates, errors = candidate_packets(output)
    structural, structured, messages, structural_messages = 0, 0, 0, 0
    for filename, records in candidates:
        sidecar = json.loads((output / "protocol-candidates" / filename).with_suffix(".json").read_text())
        structured += sidecar.get("structured") is True
        valid = 0
        for packet in records:
            try:
                valid_request(packet)
                valid += 1
            except (AssertionError, ValueError, IndexError, KeyError):
                pass
        messages += len(records)
        structural_messages += valid
        structural += valid == len(records)
    return {"sequences": len(candidates), "messages": messages, "structural_sequences": structural,
            "structured_sequences": structured, "errors": errors,
            "structural_sequence_share": ratio(structural, len(candidates)),
            "structured_sequence_share": ratio(structured, len(candidates)),
            "structural_message_share": ratio(structural_messages, messages),
            "sampling": "First bounded actual network sends after ready; descriptive sample, not an unbiased full-run estimate."}


def inspect_control_candidates(output, seed_packet, invoke, length_delta=0):
    expected = bytearray(seed_packet)
    expected[8] = invoke
    expected[2:4] = (len(expected) + length_delta).to_bytes(2, "big")
    candidates, errors = candidate_packets(output, structured_only=True)
    mismatches, values, lengths = [], Counter(), Counter()
    for filename, records in candidates:
        for packet in records:
            if len(packet) > 8:
                values[packet[8]] += 1
            if len(packet) >= 4:
                lengths[int.from_bytes(packet[2:4], "big") - len(packet)] += 1
        if len(records) != 1 or records[0] != expected:
            mismatches.append(filename)
    return {"passed": bool(candidates) and not errors and not mismatches,
            "saved_candidates": len(candidates), "invalid_replay_files": errors,
            "wire_mismatches": mismatches, "invoke_values": dict(values),
            "bvlc_length_deltas": dict(lengths), "expected_wire_hex": expected.hex(),
            "claim": "Every saved actual structured candidate equals the input request except configured Invoke ID and expected BVLC length delta."}


def create_policy_model(source, destination, invoke, seed_packet=None):
    import yaml
    shutil.copytree(source, destination)
    protocol = yaml.safe_load((destination / "protocol_spec.yaml").read_text())
    for message in protocol["messages"]:
        if message["id"] == "read_property" and seed_packet is not None:
            # The normal external corpus predates the current template and
            # uses NPDU control 0 rather than template control 4. Bind the
            # frozen policy to the actual unchanged seed used in this control.
            message["example"] = seed_packet.hex()
        fields = [copy.deepcopy(field) for field in message["fields"]]
        message["fields"] = fields
        for field in fields:
            if field["id"] == "npdu_control":
                value = bytes.fromhex(message["example"])[5]
                field.update(role="fixed", mutability="fixed", default=value, min=value, max=value,
                             values=[value], strategies=["enum"])
            if message["id"] == "read_property" and field["id"] == "invoke_id":
                field.update(default=invoke, values=[invoke], strategies=["enum"])
    (destination / "protocol_spec.yaml").write_text(yaml.safe_dump(protocol, sort_keys=False))


def negative_dependency_control(args, work, model, env):
    import yaml
    folder = work / "negative-dependency"
    folder.mkdir()
    shutil.copytree(model, folder / "model")
    spec_path = folder / "model/protocol_spec.yaml"
    protocol = yaml.safe_load(spec_path.read_text())
    message = next(message for message in protocol["messages"] if message["id"] == "read_property")
    message["dependencies"][0]["source"] = "missing_dependency_source"
    spec_path.write_text(yaml.safe_dump(protocol, sort_keys=False))
    marker = folder / "target-started"
    launcher = folder / "target_probe.py"
    launcher.write_text("import os, pathlib, sys\npathlib.Path(sys.argv[1]).write_text('started')\nos.execv(sys.argv[2], [sys.argv[2], '123'])\n")
    command = [sys.executable, str(ROOT / "tools/run_protocol_campaign.py"), "--spec-dir", str(folder / "model"),
               "--", "--random-seed", str(args.seed_base), "--", sys.executable, str(launcher), str(marker), str(args.server)]
    completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    log = completed.stdout + completed.stderr
    (folder / "validation.log").write_text(log)
    result = {"passed": completed.returncode != 0 and not marker.exists()
                        and "missing dependency source" in log,
              "exit_code": completed.returncode, "target_started": marker.exists(),
              "command": command, "model": manifest(folder / "model"), "log": log}
    write_json(folder / "result.json", result)
    return result


def functional_controls(args, work, model, env):
    work.mkdir()
    corpus = work / "in-read-property"
    corpus.mkdir()
    source = WORKSPACE / "bacnet-stack/inputs/seed03_read_objectname.replay"
    shutil.copy2(source, corpus / source.name)
    packets, framing = replay_records(source.read_bytes())
    assert framing == "LE32-length-prefixed" and len(packets) == 1
    valid_request(packets[0])
    models = {}
    for invoke in (33, 77):
        models[invoke] = work / f"model-invoke-{invoke}"
        create_policy_model(model, models[invoke], invoke, packets[0])
    results = {}
    for label, invoke, mutation_mode, length_delta in (("invoke-33-valid", 33, "valid", 0),
                                                      ("invoke-77-valid", 77, "valid", 0),
                                                      ("invoke-33-near-valid", 33, "near_valid", 1)):
        parent = work / label
        parent.mkdir()
        result = run_campaign(args, parent, corpus, "head", models[invoke], args.seed_base, env,
                              mutation_mode=mutation_mode, seconds=args.control_seconds,
                              save_candidates=args.candidate_limit)
        wire = inspect_control_candidates(parent / "head/out", packets[0], invoke, length_delta)
        lifecycle = {key: result["checks"][key] for key in ("ready_reached", "clean_sigint_stop", "post_calibration_executions_present")}
        results[label] = {"passed": wire["passed"] and all(lifecycle.values()), "wire": wire,
                          "lifecycle": lifecycle, "campaign_result": str(parent / "head/result.json")}
    results["negative-dependency"] = negative_dependency_control(args, work, models[33], env)
    result = {"passed": all(item["passed"] for item in results.values()), "controls": results,
              "scope": "Functional YAML-to-wire and dependency/repair assertions; excluded from performance comparison."}
    write_json(work / "summary.json", result)
    return result


def preflight(args):
    if not args.server.is_file():
        raise SystemExit(f"BACnet target not found: {args.server}")
    completed = subprocess.run([str(ROOT / "afl-fuzz"), "-h"], capture_output=True, text=True, timeout=10)
    help_text = completed.stdout + completed.stderr
    missing = [option for option in ("--random-seed", "--protocol-save-candidates") if option not in help_text]
    if missing:
        raise SystemExit("Rebuild afl-fuzz with required reproducibility options: " + ", ".join(missing))
    return {"required_options_confirmed": ["--random-seed", "--protocol-save-candidates"],
            "afl_fuzz_sha256": sha256(ROOT / "afl-fuzz"), "server_sha256": sha256(args.server)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=15)
    parser.add_argument("--seed-base", type=int, default=20261025)
    parser.add_argument("--startup-usecs", type=int, default=200000)
    parser.add_argument("--ready-timeout", type=float, default=300)
    parser.add_argument("--control-seconds", type=float, default=8)
    parser.add_argument("--candidate-limit", type=int, default=24)
    parser.add_argument("--performance-candidates", type=int, default=24,
                        help="same bounded actual-send sample per performance run; 0 disables sampling")
    parser.add_argument("--server", type=Path, default=WORKSPACE / "bacnet-stack/build-protocol-integration/server")
    parser.add_argument("--spec-dir", type=Path, default=ROOT / "protocols/bacnet_ip")
    parser.add_argument("--modes", default=",".join(MODES))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--skip-controls", action="store_true")
    group.add_argument("--controls-only", action="store_true")
    args = parser.parse_args()
    modes = args.modes.split(",")
    if not modes or len(modes) != len(set(modes)) or any(mode not in MODES for mode in modes):
        parser.error("--modes must contain distinct supported mode names")
    if args.repeats < 3 or any(not math.isfinite(value) or value <= 0
                               for value in (args.seconds, args.control_seconds, args.ready_timeout)):
        parser.error("use at least 3 repeats and positive finite durations")
    if not 1 <= args.candidate_limit <= 0xffffffff or not 0 <= args.performance_candidates <= 0xffffffff or args.startup_usecs < 0:
        parser.error("use at least 3 repeats, positive durations, and a positive candidate limit")
    if not 0 <= args.seed_base <= 0xffffffff or args.seed_base + args.repeats - 1 > 0xffffffff:
        parser.error("paired random seeds must fit uint32")
    args.server, args.spec_dir = args.server.resolve(), args.spec_dir.resolve()
    confirmation = preflight(args)
    work = args.output.resolve()
    if work.exists():
        raise SystemExit(f"Refusing to overwrite evidence directory: {work}")
    work.mkdir(parents=True)
    corpus = work / "in"
    corpus.mkdir()
    for name in SEEDS:
        source = WORKSPACE / "bacnet-stack/inputs" / name
        records, framing = replay_records(source.read_bytes())
        assert len(records) == 1 and framing == "LE32-length-prefixed", name
        valid_request(records[0])
        shutil.copy2(source, corpus / name)
    model = work / "model"
    shutil.copytree(args.spec_dir, model)
    metadata = {"preflight": confirmation, "source": source_manifest(), "model": manifest(model),
                "seeds": manifest(corpus), "repeats": args.repeats, "seconds_after_ready": args.seconds,
                "seed_base": args.seed_base, "modes": modes, "sequential_execution": True,
                "performance_candidate_limit": args.performance_candidates,
                "schedule": [{"repeat": repeat + 1, "random_seed": args.seed_base + repeat,
                              "modes": run_order(modes, repeat)} for repeat in range(args.repeats)]}
    write_json(work / "metadata.json", metadata)
    env, runs, controls = environment(), [], None
    if not args.controls_only:
        for repeat in range(args.repeats):
            round_dir = work / f"repeat-{repeat + 1:02d}"
            round_dir.mkdir()
            for mode in run_order(modes, repeat):
                result = run_campaign(args, round_dir, corpus, mode, model, args.seed_base + repeat, env,
                                      save_candidates=args.performance_candidates)
                result["repeat"] = repeat + 1
                runs.append(result)
                write_json(work / "summary.json", {"passed": all(run["passed"] for run in runs),
                           "runs": runs, "analysis": summarize(runs), "functional_controls": controls})
    if not args.skip_controls:
        controls = functional_controls(args, work / "functional-controls", model, env)
    passed = all(run["passed"] for run in runs) and (controls is None or controls["passed"])
    write_json(work / "summary.json", {"passed": passed, "runs": runs,
               "analysis": summarize(runs), "functional_controls": controls})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
