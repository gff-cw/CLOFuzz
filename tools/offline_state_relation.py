#!/usr/bin/env python3
"""Summarize explicitly aligned protocol/memory observations from an offline JSON file.

Input markers are declarations by the trace producer, not independently verified
facts. This tool neither runs a protocol state machine nor changes StateAFL IDs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES, MAX_EVENTS, MAX_RELATIONS = 1 << 20, 10000, 65536
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ObservationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ObservationError(message)


def keys(value, required, optional, where):
    require(type(value) is dict, f"{where}: expected object")
    require(required <= value.keys() <= required | optional, f"{where}: missing or unsupported keys")


def text(value, where):
    require(type(value) is str and 0 < len(value) <= 256 and not any(ord(c) < 32 for c in value),
            f"{where}: expected nonempty text of at most 256 characters")
    return value


def number(value, where, maximum=(1 << 63) - 1):
    require(type(value) is int and 0 <= value <= maximum, f"{where}: expected bounded nonnegative integer")
    return value


def digest(value, where):
    require(isinstance(value, str) and HEX_DIGEST.fullmatch(value), f"{where}: expected lowercase SHA256")
    return value


def validate_protocol(protocol):
    keys(protocol, {"status", "states", "source", "correlation", "complete"}, {"evidence_ref"}, "protocol")
    status, states = protocol["status"], protocol["states"]
    require(status in ("observed", "ambiguous", "predicted", "unknown", "unobserved", "inconsistent"), "unsupported protocol status")
    require(type(states) is list and len(states) <= 64, "protocol.states must be a list of at most 64 names")
    for state in states:
        text(state, "protocol state")
    require(len(set(states)) == len(states), "duplicate protocol state")
    require(protocol["source"] in ("matched_response", "local_observation", "prediction", "none"), "unsupported protocol source")
    require(protocol["correlation"] in ("confirmed", "ambiguous", "missing"), "unsupported correlation status")
    require(type(protocol["complete"]) is bool, "protocol.complete must be boolean")
    if status == "observed":
        require(len(states) == 1, "observed state requires exactly one state")
    elif status == "ambiguous":
        require(len(states) >= 2, "ambiguous state requires at least two states")
    elif status == "predicted":
        require(bool(states) and protocol["source"] == "prediction", "predicted state requires prediction source and candidates")
    elif status == "inconsistent":
        require(not states and protocol["source"] in ("matched_response", "local_observation"),
                "inconsistent observations require an empty candidate set and observation provenance")
        require(protocol["complete"] and protocol["correlation"] == "confirmed",
                "inconsistent assertions require complete, correlated evidence")
    else:
        require(not states and protocol["source"] == "none", "unknown/unobserved cannot carry state assertions")
    if status in ("observed", "ambiguous"):
        require(protocol["source"] in ("matched_response", "local_observation"), "observed states require observation provenance")
    if status not in ("unknown", "unobserved"):
        text(protocol.get("evidence_ref"), "protocol.evidence_ref")
    elif "evidence_ref" in protocol:
        text(protocol["evidence_ref"], "protocol.evidence_ref")


def analyze(document):
    keys(document, {"format", "version", "events"}, set(), "observations")
    require(document["format"] == "stateafl.offline-observations", "unsupported observation format")
    require(type(document["version"]) is int and document["version"] == 1, "unsupported observation version")
    events = document["events"]
    require(type(events) is list and len(events) <= MAX_EVENTS, "event budget exceeded")
    sessions, epochs, markers, relations, skipped = {}, {}, set(), Counter(), Counter()
    relation_evidence = {}
    unpaired = []
    def skip(reason, event):
        skipped[reason] += 1
        # Keep the original declarations; missing alignment must not erase either observation.
        unpaired.append({"reason": reason, "event": event})
    for event in events:
        keys(event, {"run_id", "session_id", "session_epoch", "event_index", "model_sha256", "kind"},
             {"protocol", "memory", "boundary", "reset_evidence"}, "event")
        run_id, session_id = text(event["run_id"], "run_id"), text(event["session_id"], "session_id")
        epoch = number(event["session_epoch"], "session_epoch")
        index = number(event["event_index"], "event_index")
        model = digest(event["model_sha256"], "model_sha256")
        kind = event["kind"]
        require(kind in ("session_start", "reset", "observation", "timeout", "partial", "unmatched"), "unsupported event kind")
        session_key = run_id, session_id, epoch
        stream_key = run_id, session_id
        if stream_key in epochs:
            require(epoch >= epochs[stream_key], "stale session epoch or out-of-order stream")
        if session_key not in sessions:
            require(kind in ("session_start", "reset"), "new session epoch requires explicit start/reset marker")
            sessions[session_key] = {"model_sha256": model, "last_event_index": -1,
                                     "last_confirmed": None, "last_prediction": None,
                                     "current_status": "unknown", "current_candidates": []}
        else:
            require(kind not in ("session_start", "reset"), "start/reset must create a fresh session epoch")
        epochs[stream_key] = epoch
        session = sessions[session_key]
        require(session["model_sha256"] == model, "model changed inside a session epoch")
        require(index > session["last_event_index"], "event_index must increase strictly within each session epoch")
        session["last_event_index"] = index
        if kind == "reset":
            require(event.get("reset_evidence") == "confirmed", "reset requires explicitly confirmed reset evidence")
        else:
            require("reset_evidence" not in event, "reset_evidence only belongs to reset events")
        protocol = event.get("protocol")
        if protocol is not None:
            validate_protocol(protocol)
        memory = event.get("memory")
        if memory is not None:
            keys(memory, {"namespace", "calibration_epoch", "library_revision", "state_id", "source", "status"}, set(), "memory")
            text(memory["namespace"], "memory.namespace")
            text(memory["source"], "memory.source")
            text(memory["library_revision"], "memory.library_revision")
            require(memory["status"] in ("snapshot_label", "synthetic"), "unsupported memory status")
            number(memory["calibration_epoch"], "memory.calibration_epoch")
            number(memory["state_id"], "memory.state_id", (1 << 32) - 1)
        boundary = event.get("boundary")
        if boundary is not None:
            keys(boundary, {"observation_id", "alignment", "phase", "synchronization", "source"}, set(), "boundary")
            observation_id = text(boundary["observation_id"], "observation_id")
            text(boundary["source"], "boundary.source")
            require(boundary["alignment"] in ("shared_marker", "unaligned"), "unsupported alignment")
            require(boundary["phase"] in ("completed", "quiescent", "pending"), "unsupported observation phase")
            require(boundary["synchronization"] in ("quiescent", "atomic_snapshot", "unknown"), "unsupported synchronization evidence")
            marker = session_key + (observation_id,)
            require(marker not in markers, "observation_id reused within a session epoch")
            markers.add(marker)
        if kind in ("timeout", "partial", "unmatched"):
            # A timeout neither proves an initial state nor erases the historical observation.
            session["current_status"] = "unknown"
            session["current_candidates"] = []
            skip(kind, event)
            continue
        if protocol is None:
            session["current_status"] = "unknown"
            session["current_candidates"] = []
            skip("no_protocol_observation", event)
            continue
        status = protocol["status"]
        if status in ("predicted", "unknown", "unobserved", "inconsistent"):
            session["current_status"] = status if status != "predicted" else "unknown"
            session["current_candidates"] = []
            if status == "predicted":
                session["last_prediction"] = {"states": protocol["states"], "event_index": index}
            skip(status, event)
            continue
        if not protocol["complete"] or protocol["correlation"] != "confirmed":
            session["current_status"] = "unknown"
            session["current_candidates"] = []
            skip("incomplete_or_uncorrelated", event)
            continue
        session["current_status"] = status
        session["current_candidates"] = protocol["states"]
        if status == "observed":
            session["last_confirmed"] = {"state": protocol["states"][0], "event_index": index,
                                          "source": protocol["source"]}
        if memory is None or boundary is None:
            skip("missing_memory_or_shared_boundary", event)
            continue
        if memory["status"] != "snapshot_label" or memory["state_id"] == 0:
            skip("non_snapshot_memory", event)
            continue
        if (boundary["alignment"] != "shared_marker" or boundary["phase"] not in ("completed", "quiescent") or
                boundary["synchronization"] == "unknown"):
            skip("unaligned_pending_or_unsynchronized", event)
            continue
        partition = (model, memory["namespace"], memory["calibration_epoch"], memory["library_revision"], *session_key)
        # Keep an ambiguous set together: its members are not separate observations.
        relation = partition + (tuple(sorted(protocol["states"])), memory["state_id"], status)
        relations[relation] += 1
        require(len(relations) <= MAX_RELATIONS, "relation budget exceeded")
        relation_evidence.setdefault(relation, []).append({
            "event_index": index, "observation_id": boundary["observation_id"],
            "protocol_evidence_ref": protocol["evidence_ref"], "memory_source": memory["source"],
            "boundary_source": boundary["source"], "synchronization": boundary["synchronization"]})
    rows = []
    for relation, count in sorted(relations.items()):
        model, namespace, calibration, library_revision, run_id, session_id, epoch, states, memory_id, certainty = relation
        rows.append({"model_sha256": model, "memory_namespace": namespace, "calibration_epoch": calibration,
                     "memory_library_revision": library_revision,
                     "run_id": run_id, "session_id": session_id, "session_epoch": epoch,
                     "protocol_states": list(states), "memory_state_id": memory_id,
                     "certainty": certainty, "observation_count": count, "evidence": relation_evidence[relation]})
    session_rows = [dict(run_id=key[0], session_id=key[1], session_epoch=key[2], **value)
                    for key, value in sorted(sessions.items())]
    return {"format": "stateafl.offline-state-relation", "version": 1, "events": len(events),
            "relations": rows, "sessions": session_rows, "skipped": dict(sorted(skipped.items())),
            "unpaired_observations": unpaired,
            "limits": ["Shared markers and provenance are producer declarations, not independently verified facts.",
                       "No transitions are inferred, and no protocol or memory state IDs are merged.",
                       "Counts for ambiguous candidates are not confirmed transitions or probabilities.",
                       "Legacy trace arrays cannot establish shared observation boundaries."]}


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"duplicate JSON key {name!r}")
        result[name] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.input.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "observation file exceeds 1 MiB")
        def constant(value):
            raise ObservationError(f"invalid JSON constant {value}")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=constant)
        report = analyze(document)
        report["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except (ObservationError, OSError, ValueError, TypeError, RecursionError) as error:
        print(json.dumps({"status": "invalid_observations", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
