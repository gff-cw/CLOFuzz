#!/usr/bin/env python3
"""Read-only consistency contracts for legacy model-generated request corpora.

The caller supplies a current compiler result. This module never compiles a
model, writes a corpus, starts StateAFL or observes a target. Managed files are
compared with the planner's current output. External inputs receive independent
framing/resource checks and are explicitly not certified by the package proof.
"""
import hashlib
import json
from pathlib import Path
import stat

from protocol_seed_planner import MAX_FILE, MAX_WIRE, plan_model_corpus


class CorpusContractError(ValueError):
    pass


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _read_bytes(path, *, limit=MAX_FILE):
    path = Path(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise CorpusContractError(f"{path}: expected a regular file, not a symlink or special entry")
        if info.st_size > limit:
            raise CorpusContractError(f"{path}: file exceeds {limit} bytes")
        data = path.read_bytes()
        if len(data) > limit:
            raise CorpusContractError(f"{path}: file exceeds {limit} bytes")
        return data
    except OSError as error:
        raise CorpusContractError(f"{path}: cannot read file: {error}") from error


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorpusContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _not_integer(value):
    raise CorpusContractError(f"non-integer JSON numeric value: {value}")


def _read_json(path):
    try:
        return json.loads(_read_bytes(path).decode("utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_float=_not_integer, parse_constant=_not_integer)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusContractError(f"{path}: invalid JSON: {error}") from error


def _check_inventory(directory, expected):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise CorpusContractError(f"{directory}: missing managed corpus directory")
    try:
        actual = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise CorpusContractError(f"{directory}: cannot inspect inventory: {error}") from error
    if actual != set(expected):
        raise CorpusContractError(f"{directory}: stale managed inventory; "
                                  f"missing={sorted(set(expected) - actual)}, "
                                  f"unexpected={sorted(actual - set(expected))}")
    identity = []
    for name, expected_bytes in sorted(expected.items()):
        data = _read_bytes(directory / name)
        if data != expected_bytes:
            raise CorpusContractError(f"{directory / name}: stale managed bytes")
        identity.append((name, hashlib.sha256(data).hexdigest()))
    return identity


def check_model_corpus(directory, protocol, state, validation, *, require_seed=True):
    """Verify all managed assets against the current model/compiler result.

    Only the human-readable validation_source may differ from a fresh planner
    result. Manifest paths are never trusted as file paths: expected filenames
    are independently derived from the validated model. A stored non-default
    search budget is reproduced instead of silently changing planner policy.
    """
    directory = Path(directory)
    try:
        stored_validation = _read_json(directory / "validation.json")
        if _canonical(stored_validation) != _canonical(validation):
            raise CorpusContractError("validation.json differs from the current compiler result")
        recorded = _read_json(directory / "seed_manifest.json")
        if not isinstance(recorded, dict):
            raise CorpusContractError("seed_manifest.json must contain an object")
        source = recorded.get("validation_source")
        if not isinstance(source, str) or not source:
            raise CorpusContractError("seed manifest requires validation_source text")
        search = recorded.get("search")
        budget = search.get("max_nodes") if isinstance(search, dict) else None
        if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
            raise CorpusContractError("seed manifest search budget must be a positive integer")
        expected, fixtures, seeds = plan_model_corpus(protocol, state, validation,
                                                     max_search_nodes=budget)
        proof = {key: value for key, value in recorded.items() if key != "validation_source"}
        wanted = {key: value for key, value in expected.items() if key != "validation_source"}
        if _canonical(proof) != _canonical(wanted):
            raise CorpusContractError("seed_manifest.json is stale for the current model")
        fixture_identity = _check_inventory(directory / "fixtures/requests", fixtures)
        seed_identity = _check_inventory(directory / "seeds", seeds)
        if require_seed and not seeds:
            raise CorpusContractError("no model-reachable request seeds are available")
        return dict(status="current", scope="managed_model_corpus",
                    model_binding_verified=True, actual_target_session_verified=False,
                    model_sha256=expected["model_sha256"], fixtures=len(fixtures), seeds=len(seeds),
                    inventory_sha256=hashlib.sha256(_canonical(
                        {"fixtures": fixture_identity, "seeds": seed_identity}).encode("utf-8")).hexdigest())
    except (CorpusContractError, OSError, KeyError, TypeError, ValueError) as error:
        raise CorpusContractError(
            f"managed corpus is stale or invalid in {directory}: {error}; "
            "recompile both YAML files with tools/proto_spec_compiler.py, then run "
            f"tools/protocol_seed_planner.py --spec-dir {directory}; "
            "the campaign wrapper never overwrites seeds or custom inputs") from error


def _replay_records(data, state, path):
    limits = state["limits"]
    if not data or len(data) > min(MAX_FILE, limits["max_bytes"]):
        raise CorpusContractError(f"{path}: empty input or serialized byte budget exceeded")
    position = count = 0
    records = []
    while position < len(data):
        if len(data) - position < 4:
            raise CorpusContractError(f"{path}: truncated LE32 record length")
        length = int.from_bytes(data[position:position + 4], "little")
        position += 4
        if not length or length > MAX_WIRE or length > len(data) - position:
            raise CorpusContractError(f"{path}: invalid LE32 record length")
        records.append(data[position:position + length])
        position += length
        count += 1
        if count > min(64, limits["max_messages"]):
            raise CorpusContractError(f"{path}: message count budget exceeded")
    return records


def check_input_corpus(input_directory, directory, state, managed):
    """Check the selected -i independently and state its actual proof scope.

    -i - remains the host's locked authoritative-snapshot restore contract.
    Custom corpora are checked for framing and measurable resource budgets.
    Neither preparation nor ordinary raw/initial execution establishes their
    codec semantics or canonical per-model repeats.
    """
    if input_directory == "-":
        return dict(scope="runtime_resume", status="deferred_to_host",
                    model_binding_verified=False,
                    verification="StateAFL checks authoritative snapshots under its output lock")
    selected = Path(input_directory).resolve()
    package_seeds = (Path(directory) / "seeds").resolve()
    if selected == package_seeds:
        return dict(managed, input_directory=str(selected))
    if not selected.is_dir():
        raise CorpusContractError(f"external input directory does not exist: {selected}")

    raw_queue = None
    # The host selects old-output mode by marker existence before opening the
    # directory. A file or broken link named queue/.state must not fall through
    # to an otherwise valid custom replay corpus here.
    queue_marker, state_marker = selected / "queue", selected / ".state"
    if queue_marker.exists() or queue_marker.is_symlink():
        if not queue_marker.is_dir():
            raise CorpusContractError(f"{queue_marker}: raw queue marker must be a directory")
        raw_queue = queue_marker
    elif state_marker.exists() or state_marker.is_symlink():
        if not state_marker.is_dir():
            raise CorpusContractError(f"{state_marker}: raw queue marker must be a directory")
        raw_queue = selected
    inputs = raw_queue / ".state/replay" if raw_queue else selected
    if not inputs.is_dir() or inputs.is_symlink():
        raise CorpusContractError(f"{selected}: raw queue requires authoritative .state/replay snapshots")
    identities = []
    try:
        entries = sorted(inputs.iterdir(), key=lambda path: path.name)
        for path in entries:
            if raw_queue:
                if path.name.startswith("."):
                    continue
                if not path.name.startswith(("id:", "id_")):
                    raise CorpusContractError(f"{path}: unexpected authoritative replay snapshot")
            elif path.is_dir() or path.name.startswith("README.txt"):
                continue
            data = _read_bytes(path)
            if not data:
                continue  # Same empty-file exclusion as the host input scan.
            records = _replay_records(data, state, path)
            if raw_queue:
                raw = _read_bytes(raw_queue / path.name)
                if raw != b"".join(records):
                    raise CorpusContractError(f"{path}: authoritative replay differs from its raw queue input")
            identities.append((path.name, hashlib.sha256(data).hexdigest(), len(records), len(data)))
        if raw_queue:
            raw_names = {path.name for path in raw_queue.iterdir()
                         if path.name.startswith(("id:", "id_"))}
            if raw_names != {name for name, *_ in identities}:
                raise CorpusContractError(f"{raw_queue}: raw/replay inventory mismatch")
    except OSError as error:
        raise CorpusContractError(f"cannot inspect external corpus {selected}: {error}") from error
    if not identities:
        raise CorpusContractError(f"{selected}: no nonempty replay inputs are available")
    return dict(scope="external_unmanaged", status="framing_and_resource_checked",
                input_directory=str(selected), files_checked=len(identities),
                inventory_sha256=hashlib.sha256(_canonical(identities).encode("utf-8")).hexdigest(),
                model_binding_verified=False, actual_target_session_verified=False,
                semantic_and_per_model_repeat_validation="not_verified_by_preparation")
