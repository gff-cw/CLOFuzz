#!/usr/bin/env python3
"""Read existing result artifacts without building, launching, or replaying targets."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TCP_PROFILES = ("modbus", "iec104", "mms", "enip", "opcua")
BACNET_MODES = ("legacy", "head", "head_content", "all", "hybrid")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        reject_constant(value)
    return result


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def read_json(path):
    try:
        data = parse_json(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data, None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        return None, str(error)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(root, path):
    return {"path": str(path.relative_to(root)), "sha256": digest(path)}


def unavailable(root, path, error):
    return dict(path=str(path.relative_to(root)),
                evidence_state="missing" if error == "missing" else "invalid",
                recorded_outcome="unverified", acceptance="unverified", error=error)


def audit_result(root, path):
    """Keep runner termination, target counters, and candidate events separate."""
    data, error = read_json(path)
    if error:
        return unavailable(root, path, error)
    checks, exit_code = data.get("checks"), data.get("exit_code")
    known_failure = (data.get("passed") is False
                     or (type(exit_code) is int and exit_code != 0)
                     or (isinstance(checks, dict) and any(value is False for value in checks.values())))

    def invalid(error):
        result = unavailable(root, path, error)
        if known_failure:
            result.update(recorded_outcome="failed", acceptance="failed")
        if type(exit_code) is int:
            result.update(runner_exit_code=exit_code,
                          runner_signal=-exit_code if exit_code < 0 else None)
        return result

    stats = data.get("stats", {})
    snapshot = data.get("protocol_stats")
    events = data.get("events", {})
    if (type(data.get("passed")) is not bool or type(exit_code) is not int
            or not isinstance(checks, dict) or not checks
            or any(type(value) is not bool for value in checks.values())
            or not isinstance(stats, dict)
            or (snapshot is not None and not isinstance(snapshot, dict))
            or not isinstance(events, dict)):
        return invalid("missing or invalid passed/checks/exit_code/counters")
    snapshot = snapshot or {}
    counts = [snapshot.get("structured_success"), events.get("mutation"), events.get("rejected")]
    if any(value is not None and (type(value) is not int or value < 0) for value in counts):
        return invalid("counters must be nonnegative integers")
    failed = [name for name, value in checks.items() if not value]
    passed = data["passed"] and exit_code == 0 and not failed
    result = dict(artifact(root, path), evidence_state="present",
                  recorded_outcome="passed" if passed else "failed",
                  acceptance="unverified" if passed else "failed",
                  source_provenance="unverified", runner_exit_code=exit_code,
                  runner_signal=-exit_code if exit_code < 0 else None,
                  failed_checks=failed,
                  target_unique_crashes=stats.get("unique_crashes"),
                  target_unique_hangs=stats.get("unique_hangs"))
    result["snapshot_structured_success"] = snapshot.get("structured_success")
    event_path = path.parent / "out/protocol_mutations.jsonl"
    result["event_source"] = "result_only"
    result["event_count_complete"] = None
    if event_path.exists():
        events = Counter()
        number = 0
        try:
            with event_path.open(encoding="utf-8") as stream:
                for number, line in enumerate(stream, 1):
                    event = parse_json(line)
                    if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                        raise ValueError("expected an event object with a string event")
                    events[event["event"]] += 1
            result["event_artifact"] = artifact(root, event_path)
            result["event_source"] = "jsonl"
            result["event_count_complete"] = True
        except (OSError, UnicodeError, ValueError, RecursionError) as error:
            result.update(evidence_state="invalid", event_error=f"line {number}: {error}",
                          event_source="invalid_jsonl", event_count_complete=False,
                          partial_event_counts=dict(events))
            if passed:
                result["acceptance"] = "unverified"
    for event, key in (("mutation", "mutation_event_count"), ("rejected", "rejected_event_count")):
        if result["event_count_complete"] is False:
            result[key] = None
        elif result["event_count_complete"]:
            result[key] = events.get(event, 0)
        else:
            result[key] = events.get(event)
    count, structured = result["mutation_event_count"], result["snapshot_structured_success"]
    result["counter_consistency"] = ("unverified" if count is None or structured is None
                                     else "match" if count == structured else "mismatch")
    result["counter_note"] = ("Candidate construction events do not count successful sends. "
                              "A mismatch does not establish its cause.")
    return result


def audit_runtime(root, path):
    data, error = read_json(path)
    if error:
        return unavailable(root, path, error)
    hashes = data.get("source_sha256")
    if (data.get("status") not in ("passed", "failed")
            or not isinstance(data.get("failures"), list)
            or not isinstance(hashes, dict) or not hashes):
        return unavailable(root, path, "missing or invalid status/failures/source_sha256")
    recorded_pass = data["status"] == "passed" and not data["failures"]
    nested_failures = []
    for key in ("loader_cases", "dependency_harnesses"):
        if key not in data:
            continue
        cases = data[key]
        if not isinstance(cases, list):
            return unavailable(root, path, f"invalid {key} list")
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                return unavailable(root, path, f"invalid {key} entry")
            if key == "loader_cases":
                if type(case.get("passed")) is not bool:
                    return unavailable(root, path, "invalid loader verdict")
                passed = case["passed"]
            else:
                if case.get("status") not in ("passed", "failed"):
                    return unavailable(root, path, "invalid dependency verdict")
                passed = case["status"] == "passed"
            if not passed:
                nested_failures.append(f"{key}[{index}]")
    for key in ("runtime_harness", "session_harness"):
        if key not in data:
            continue
        harness = data[key]
        if not isinstance(harness, dict) or harness.get("status") not in ("passed", "failed"):
            return unavailable(root, path, f"invalid {key} status")
        if harness["status"] != "passed":
            nested_failures.append(key)
    recorded_pass = recorded_pass and not nested_failures
    sources = []
    for name, expected in sorted(hashes.items()):
        try:
            source = (root / name).resolve()
        except (OSError, ValueError, RuntimeError):
            sources.append(dict(path=name, status="invalid_path"))
            continue
        if (Path(name).is_absolute() or ".." in Path(name).parts
                or not source.is_relative_to(root.resolve())):
            sources.append(dict(path=name, status="invalid_path"))
            continue
        if (not isinstance(expected, str) or len(expected) != 64
                or any(c not in "0123456789abcdef" for c in expected)):
            sources.append(dict(path=name, status="invalid_digest"))
            continue
        try:
            actual = digest(source)
            sources.append(dict(path=name, status="match" if actual == expected else "stale",
                                expected_sha256=expected, actual_sha256=actual))
        except OSError as error:
            sources.append(dict(path=name, status="unavailable", error=str(error)))
    matched = all(source["status"] == "match" for source in sources)
    return dict(artifact(root, path), evidence_state="present",
                recorded_outcome="passed" if recorded_pass else "failed",
                acceptance=("failed" if not recorded_pass else "passed" if matched else "unverified"),
                source_provenance="listed_sources_match" if matched else "stale_or_unavailable",
                sources=sources, nested_failures=nested_failures,
                scope_note="Only the listed source files are bound to this offline result; "
                           "this does not certify afl-fuzz, its binary, or integration runs.")


def audit(root):
    root = Path(root).resolve()
    out = root / "tests/protocol/out"
    tcp = {name: audit_result(root, out / "multicodec-tcp-final" / name / "result.json")
           for name in TCP_PROFILES}
    bacnet = {mode: audit_result(root, out / "multicodec-bacnet-regression" / mode / "result.json")
              for mode in BACNET_MODES}
    runtime = audit_runtime(root, root / "tests/protocol/evidence/runtime-results.json")
    entries = [runtime, *tcp.values(), *bacnet.values()]
    acceptance = ("failed" if any(item["acceptance"] == "failed" for item in entries)
                  else "passed" if all(item["acceptance"] == "passed" for item in entries)
                  else "unverified")
    return dict(format_version=1, acceptance=acceptance,
                observed_at_utc=datetime.now(timezone.utc).isoformat(),
                auditor_sha256=digest(Path(__file__)),
                method="Read-only audit of existing artifacts; no tests were executed.",
                runtime=runtime, tcp_fixtures=tcp, bacnet=bacnet,
                limits=["Successful integration records lack source/binary hashes and remain unverified "
                        "for the current complete worktree.",
                        "Missing modes are unverified, even when an earlier matrix passed.",
                        "Fixture results do not establish industrial-server interoperability."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    report = audit(args.root)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {"passed": 0, "failed": 1, "unverified": 2}[report["acceptance"]]


if __name__ == "__main__":
    raise SystemExit(main())
