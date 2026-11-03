#!/usr/bin/env python3
"""Plan request-only replay corpora from the legacy runtime's state projection.

This module never invokes a codec, compiler, target or network. The caller must
provide the compiler's validation result and canonical message aliases. A proof
here concerns the declared model and replay limits, never an actual exchange.
"""
from collections import deque
import hashlib
import json
from pathlib import Path
import re

MAX_FILE = 1048576
MAX_WIRE = 65507
DEFAULT_SEARCH_NODES = 16384


def _digest(document):
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def plan_model_corpus(protocol, state, validation, *,
                      validation_source="compiler result", max_search_nodes=DEFAULT_SEARCH_NODES):
    """Return (manifest, single-message fixtures, model-reachable replay seeds).

    BFS uses nondominated resource labels per semantic state. A label with no
    more canonical repeats or bytes can replace another at that state: guards,
    actions and transaction caches do not participate in semantic_step(). This
    keeps cycles bounded without incorrectly merging distinct repeat budgets.
    """
    if not isinstance(max_search_nodes, int) or isinstance(max_search_nodes, bool) or max_search_nodes < 1:
        raise ValueError("max_search_nodes must be a positive integer")
    messages = {message["id"]: message for message in protocol["messages"]}
    if protocol["protocol_id"] != state["protocol_id"]:
        raise ValueError("protocol/state ID mismatch in corpus model")
    if len(messages) != len(protocol["messages"]):
        raise ValueError("duplicate message ID in corpus model")
    for mid in messages:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", mid):
            raise ValueError("unsafe message ID in corpus model")
    states = {item["id"] for item in state["states"]}
    initial = state["initial"]
    if initial not in states or len(states) != len(state["states"]):
        raise ValueError("invalid initial state or duplicate state ID")
    aliases = validation.get("message_aliases", {})
    if not isinstance(aliases, dict) or set(aliases) - set(messages):
        raise ValueError("invalid compiler message aliases")
    canonical = {}
    for mid in messages:
        target, visited = mid, set()
        while target in aliases:
            if target in visited or aliases[target] not in messages:
                raise ValueError("cyclic or missing compiler message alias")
            visited.add(target)
            target = aliases[target]
        if messages[mid]["direction"] != messages[target]["direction"]:
            raise ValueError("compiler alias changes message direction")
        canonical[mid] = target
    limits = state["limits"]
    for key, ceiling in (("max_messages", 64), ("max_repeat", 8), ("max_bytes", MAX_FILE)):
        value = limits[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
            raise ValueError(f"{key} is outside runtime capacity")
    validated = (validation.get("validated") is True and validation.get("runtime") is True
                 and protocol.get("support", {}).get("runtime") is True
                 and validation.get("protocol") == protocol["protocol_id"])
    edges = {}
    for edge in state["transitions"]:
        if edge["from"] not in states or edge["to"] not in states or edge["message"] not in messages:
            raise ValueError("transition references missing state or message")
        response = edge.get("response", "")
        if response and response not in messages:
            raise ValueError("transition references missing response")
        key = (edge["from"], canonical[edge["message"]])
        projection = (edge["to"], canonical[response] if response else None)
        if key in edges and edges[key][0] != projection:
            if validated:
                raise ValueError("ambiguous canonical transition in corpus model")
            # A static model may legally use guards to distinguish edges. No
            # seed will be emitted without runtime validation, so retain only
            # its fixtures instead of claiming an executable projection.
            continue
        # Runtime retains the first equivalent edge after alias normalization.
        edges.setdefault(key, (projection, edge))
    # An alias is usable only when both outgoing and expected-response roles
    # agree. Do not let a compiler field alias hide different state semantics.
    for mid, target in canonical.items():
        if mid == target:
            continue
        def roles(message):
            outgoing, expected = set(), set()
            for edge in state["transitions"]:
                response = edge.get("response", "")
                if edge["message"] == message:
                    outgoing.add((edge["from"], edge["to"], canonical[response] if response else None))
                if response == message:
                    expected.add((edge["from"], edge["to"], canonical[edge["message"]]))
            return outgoing, expected
        if validated and roles(mid) != roles(target):
            raise ValueError("compiler alias has differing state transition semantics")

    wire = {}
    for mid, message in messages.items():
        example = message["example"]
        if not isinstance(example, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", example):
            raise ValueError(f"{mid}: invalid fixture hex")
        wire[mid] = bytes.fromhex(example)
        if len(wire[mid]) > MAX_WIRE:
            raise ValueError(f"{mid}: fixture exceeds runtime wire capacity")
    requests = [mid for mid, message in messages.items() if message["direction"] in {"request", "both"}]
    fixtures = {mid + ".replay": len(wire[mid]).to_bytes(4, "little") + wire[mid] for mid in requests}
    entries = {mid: dict(fixture="fixtures/requests/" + mid + ".replay",
                        fixture_status=messages[mid].get("fixture_status", "complete"),
                        notes=messages[mid].get("notes", ""), status="fixture_only") for mid in requests}
    eligible = []
    for mid in requests:
        if entries[mid]["fixture_status"] != "complete":
            entries[mid]["reason"] = "fragment_fixture"
        elif messages[mid]["direction"] != "request":
            entries[mid]["reason"] = "ambiguous_request_direction"
        elif not validated:
            entries[mid]["reason"] = "runtime_examples_not_validated"
        else:
            eligible.append(mid)

    def step(current, mid):
        found = edges.get((current, canonical[mid]))
        if found is None:
            return None, "no_request_edge"
        (request_state, response), edge = found
        final = request_state
        if response is not None:
            model = messages[response]
            if model["direction"] != "response" or model.get("fixture_status", "complete") != "complete":
                return None, "expected_response_not_complete_parseable_model"
            answer = edges.get((request_state, response))
            if answer is None:
                return None, "missing_expected_response_edge"
            # Like semantic_step(), project exactly one matching response edge;
            # do not recursively follow its own response or unrelated events.
            final = answer[0][0]
        return dict(from_state=current, request=mid, canonical_request=canonical[mid],
                    request_state=request_state, expected_response=edge.get("response") or None,
                    canonical_response=response, to_state=final), None

    kinds = tuple(dict.fromkeys(canonical[mid] for mid in eligible))
    positions = {mid: index for index, mid in enumerate(kinds)}
    empty_counts = (0,) * len(kinds)
    queue = deque([(initial, (), (), empty_counts, 0)]) if eligible else deque()
    labels = {initial: [(empty_counts, 0)]}
    accepted, seeds, failures = {}, {}, {mid: set() for mid in eligible}
    expanded = 0
    scheduled = 1 if queue else 0
    truncated = False
    while queue and len(accepted) < len(eligible):
        if expanded >= max_search_nodes:
            truncated = True
            break
        current, path, trace, counts, size = queue.popleft()
        expanded += 1
        for mid in eligible:
            transition, error = step(current, mid)
            if error:
                failures[mid].add(error)
                continue
            next_counts = list(counts)
            next_counts[positions[canonical[mid]]] += 1
            next_counts = tuple(next_counts)
            next_size = size + 4 + len(wire[mid])
            violations = []
            if len(path) + 1 > limits["max_messages"]:
                violations.append("max_messages")
            if next_counts[positions[canonical[mid]]] > limits["max_repeat"]:
                violations.append("max_repeat")
            if next_size > limits["max_bytes"]:
                violations.append("max_bytes_including_le32")
            if next_size > MAX_FILE:
                violations.append("MAX_FILE")
            if violations:
                failures[mid].update(violations)
                continue
            next_path, next_trace = path + (mid,), trace + (transition,)
            if mid not in accepted:
                accepted[mid] = dict(status="model_reachable", seed="seeds/" + mid + ".replay",
                    request_ids=list(next_path), model_states=[initial] + [item["to_state"] for item in next_trace],
                    transitions=list(next_trace), request_count=len(next_path), serialized_bytes=next_size,
                    canonical_repeats={kind: next_counts[index] for kind, index in positions.items() if next_counts[index]})
                seeds[mid + ".replay"] = b"".join(fixtures[item + ".replay"] for item in next_path)
            destination = transition["to_state"]
            frontier = labels.setdefault(destination, [])
            if any(old_size <= next_size and all(old <= new for old, new in zip(old_counts, next_counts))
                   for old_counts, old_size in frontier):
                continue
            if scheduled >= max_search_nodes:
                truncated = True
                continue
            frontier[:] = [(old_counts, old_size) for old_counts, old_size in frontier
                           if not (next_size <= old_size and all(new <= old for new, old in zip(next_counts, old_counts)))]
            frontier.append((next_counts, next_size))
            queue.append((destination, next_path, next_trace, next_counts, next_size))
            scheduled += 1
    for mid in eligible:
        if mid in accepted:
            entries[mid].update(accepted[mid])
        else:
            entries[mid].update(reason="search_budget_exhausted" if truncated else "no_model_path_within_limits",
                                observed_blockers=sorted(failures[mid]))
    manifest = dict(format="stateafl.model-corpus", version=1, protocol_id=protocol["protocol_id"],
        proof_scope="Declared legacy codec model reachability from initial, with one expected-response projection per request; no actual target session was observed or proven.",
        actual_target_session_verified=False, responses_written_to_seeds=False,
        validation_source=validation_source, runtime_examples_validated=validated,
        model_sha256=dict(protocol=_digest(protocol), state=_digest(state)),
        initial_state=initial, canonical_aliases={mid: target for mid, target in canonical.items() if mid != target},
        limits=dict(limits, MAX_FILE=MAX_FILE, MAX_WIRE=MAX_WIRE),
        resource_scope="Request records only; max_bytes includes every 4-byte LE32 replay header; repeat counts use canonical request identity.",
        static_annotations_not_executed=["guard", "actions", "dependency.scope", "dependency.when"],
        external_prerequisites=protocol.get("support", {}).get("excluded", []),
        search=dict(algorithm="breadth-first with resource dominance", max_nodes=max_search_nodes,
                    expanded_nodes=expanded, scheduled_nodes=scheduled, budget_exhausted=truncated),
        seeds=len(seeds), fixtures=len(fixtures), requests=entries)
    return manifest, fixtures, seeds


def write_model_corpus(directory, protocol, state, validation, **options):
    """Publish static corpus assets inside the caller's package staging area.

    Plan completely before touching files. init_protocol_spec owns the outer
    same-parent atomic package rename. Existing historical evidence is untouched.
    """
    manifest, fixtures, seeds = plan_model_corpus(protocol, state, validation, **options)
    directory = Path(directory)
    for relative, contents in (("fixtures/requests", fixtures), ("seeds", seeds)):
        destination = directory / relative
        destination.mkdir(parents=True, exist_ok=True)
        for name, data in contents.items():
            temporary = destination / ("." + name + ".tmp")
            temporary.write_bytes(data)
            temporary.replace(destination / name)
        for previous in destination.glob("*.replay"):
            if previous.name not in contents:
                previous.unlink()
    (directory / "seed_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def refresh_saved_model_corpus(directory, **options):
    """Convert saved, source-consistent assets without compiling or probing.

    This trusts the saved compiler validation snapshot; it does not repeat codec
    validation. Refuse YAML edits that have not been recompiled into the IR pair.
    """
    import yaml
    directory = Path(directory)
    try:
        protocol = yaml.safe_load((directory / "protocol_spec.yaml").read_text(encoding="utf-8"))
        state = yaml.safe_load((directory / "state_transition.yaml").read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"invalid corpus source YAML: {error}") from error
    validation = json.loads((directory / "validation.json").read_text(encoding="utf-8"))
    ir_pair = []
    for kind, source in (("protocol", protocol), ("state", state)):
        ir = json.loads((directory / (kind + "_ir.json")).read_text(encoding="utf-8"))
        if (ir.get("format") != "stateafl." + kind + "-ir" or ir.get("ir_version") != 1
                or set(ir) != set(source) | {"format", "ir_version", "bundle_digest"}
                or any(ir.get(key) != value for key, value in source.items())):
            raise ValueError(f"{kind}: saved IR differs from YAML; recompile the pair first")
        ir_pair.append(ir)
    bundle = json.loads((directory / "spec_bundle.json").read_text(encoding="utf-8"))
    raw_pair = []
    for ir in ir_pair:
        raw = dict(ir)
        raw.pop("bundle_digest")
        raw_pair.append(json.dumps(raw, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
    digest = hashlib.sha256("".join(raw_pair).encode("utf-8")).hexdigest()
    if (any(ir.get("bundle_digest") != digest for ir in ir_pair)
            or bundle.get("bundle_digest") != digest
            or bundle.get("protocol_id") != protocol["protocol_id"]
            or state["protocol_id"] != protocol["protocol_id"]):
        raise ValueError("saved protocol/state bundle identity mismatch")
    return write_model_corpus(directory, protocol, state, validation,
        validation_source="stored validation.json snapshot; source/IR consistency checked; compiler and target not re-executed",
        **options)


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Refresh model-only corpus assets from a saved, source-consistent IR pair; never compiles or contacts a target. Replaces generated *.replay files in seeds/ and fixtures/requests/.")
    parser.add_argument("--spec-dir", type=Path, required=True)
    parser.add_argument("--max-search-nodes", type=int, default=DEFAULT_SEARCH_NODES)
    args = parser.parse_args()
    try:
        result = refresh_saved_model_corpus(args.spec_dir, max_search_nodes=args.max_search_nodes)
        print(json.dumps(dict(protocol_id=result["protocol_id"], model_seeds=result["seeds"],
                              request_fixtures=result["fixtures"], search=result["search"])))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"model corpus error: {error}", file=sys.stderr)
        sys.exit(1)
