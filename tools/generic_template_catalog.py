#!/usr/bin/env python3
"""Copy/check generic-wire authoring examples without compiling or starting targets.

Schema validation and exact artifact checks are static authoring checks. The
native loader is still authoritative for wire parsing and execution semantics.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile

import jsonschema

from check_generic_wire_profiles import load as load_bounded_json

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ("udp_oneway", "udp_request_response", "tcp_request_response")
MAX_FILE = 1048576
MAX_FRAME = 65507


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _record(wire):
    return len(wire).to_bytes(4, "little") + wire


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _regular_bytes(path, limit):
    path = Path(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_size <= limit,
             f"non-regular, symlink or oversized managed file: {path}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    _require(len(data) <= limit, f"managed file exceeds budget: {path}")
    return data


def _json_file(path):
    _regular_bytes(path, MAX_FILE)
    return load_bounded_json(Path(path))


def _safe_artifact(relative, fixture=False):
    _require(type(relative) is str, "managed artifact path must be text")
    parts = Path(relative).parts
    _require(relative == Path(relative).as_posix() and not Path(relative).is_absolute(),
             "unsafe managed artifact path")
    if fixture:
        valid = (len(parts) == 3 and parts[0] == "fixtures"
                 and parts[1] in {"requests", "responses"} and Path(relative).suffix == ".wire")
    else:
        valid = len(parts) == 2 and parts[0] == "seeds" and Path(relative).suffix == ".replay"
    _require(valid and parts[-1] not in {".", ".."} and not parts[-1].startswith("."),
             "unsafe managed artifact path")


def _inventory(directory, allow_missing=False):
    """List every managed entry; glob filtering must not hide fuzzer inputs."""
    directory = Path(directory)
    _require(stat.S_ISDIR(directory.lstat().st_mode), "managed package must be a regular directory")
    found = set()
    for top in ("seeds", "fixtures"):
        folder = directory / top
        if allow_missing and not folder.exists() and not folder.is_symlink():
            continue
        _require(stat.S_ISDIR(folder.lstat().st_mode), f"non-directory or symlink managed directory: {folder}")
        subfolders = [folder]
        if top == "fixtures":
            subfolders = list(folder.iterdir())
            for child in subfolders:
                _require(child.name in {"requests", "responses"}
                         and stat.S_ISDIR(child.lstat().st_mode),
                         f"unexpected or symlink fixture directory: {child}")
        for subfolder in subfolders:
            for path in subfolder.iterdir():
                relative = path.relative_to(directory).as_posix()
                _safe_artifact(relative, top == "fixtures")
                _regular_bytes(path, MAX_FRAME if top == "fixtures" else MAX_FILE)
                found.add(relative)
    return found


def _manifest_paths(manifest):
    _require(type(manifest) is dict and manifest.get("format") == "stateafl.generic-template-corpus"
             and type(manifest.get("version")) is int and manifest["version"] == 1,
             "unknown managed corpus manifest")
    _require(type(manifest.get("seeds")) is dict and manifest["seeds"],
             "managed corpus needs at least one declared request path")
    _require(type(manifest.get("fixtures")) is dict, "invalid managed fixture manifest")
    for relative in manifest["seeds"]:
        _safe_artifact(relative)
    for relative in manifest["fixtures"]:
        _safe_artifact(relative, True)
    return {relative: entry["request_ids"] for relative, entry in manifest["seeds"].items()}


def schema_check(document, root=ROOT):
    """Check structure only; no claim of native loader equivalence or execution."""
    schema = load_bounded_json(Path(root) / "protocols/schema/generic_wire.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(document)


def _expected_manifest(directory, document, paths):
    messages = {message["id"]: message for message in document["messages"]}
    _require(len(messages) == len(document["messages"]), "duplicate message identity")
    # Resolve every edge before planning writes, including alternatives on
    # edges absent from the managed request paths. Schema validation checks
    # shape; it cannot establish message identity or direction.
    for edge in document["states"]["transitions"]:
        _require(edge["message"] in messages
                 and messages[edge["message"]]["direction"] == "request",
                 "transition contains unknown request model")
        responses = edge.get("responses", [edge["response"]] if "response" in edge else [])
        _require(all(response in messages and messages[response]["direction"] == "response"
                     for response in responses), "missing response model")
    fixtures = {}
    for mid, message in messages.items():
        _require("/" not in mid and "\\" not in mid and mid not in {".", ".."},
                 "template artifact message ID is not a safe filename")
        wire = bytes.fromhex(message["example_hex"])
        relative = f"fixtures/{message['direction']}s/{mid}.wire"
        _safe_artifact(relative, True)
        fixtures[relative] = dict(message_id=mid, direction=message["direction"],
                                  wire_bytes=len(wire), sha256=_sha(wire))
    seeds = {}
    limits = document["limits"]
    _require(type(paths) is dict and paths, "managed corpus needs at least one declared request path")
    covered = set()
    for relative, ids in paths.items():
        _safe_artifact(relative)
        _require(type(ids) is list and ids and all(type(mid) is str for mid in ids)
                 and len(ids) <= limits["max_messages"], "request count exceeds template budget")
        current = document["states"]["initial"]
        states = [current]
        repeats = {}
        records = []
        for mid in ids:
            _require(mid in messages and messages[mid]["direction"] == "request",
                     "seed contains unknown message or response bytes")
            repeats[mid] = repeats.get(mid, 0) + 1
            covered.add(mid)
            _require(repeats[mid] <= limits["max_repeat"], "template seed exceeds repeat budget")
            edges = [edge for edge in document["states"]["transitions"]
                     if edge["from"] == current and edge["message"] == mid]
            _require(len(edges) == 1, "template seed has no unique request transition")
            current = edges[0]["to"]
            states.append(current)
            records.append(_record(bytes.fromhex(messages[mid]["example_hex"])))
        data = b"".join(records)
        _require(len(data) <= limits["max_bytes"], "template seed exceeds replay byte budget")
        seeds[relative] = dict(request_ids=list(ids), request_count=len(ids),
                               serialized_bytes=len(data), sha256=_sha(data), projected_states=states)
    _require(covered == {mid for mid, message in messages.items() if message["direction"] == "request"},
             "a declared request has no managed seed path")
    return dict(format="stateafl.generic-template-corpus", version=1,
        protocol_id=document["protocol_id"],
        description_sha256=_sha(_regular_bytes(directory / "generic_wire.json", MAX_FILE)),
        proof_scope="Static fixture/replay composition and declared request state projection; no C loader, response, network or target verification is asserted.",
        actual_target_session_verified=False, responses_written_to_seeds=False,
        fixtures=fixtures, seeds=seeds)


def check_package(directory, root=ROOT):
    """Verify one managed example's structure, source identity and exact corpus.

    This does not parse packets through their grammars or execute a C program.
    A successful result cannot certify arbitrary user input directories.
    """
    directory = Path(directory)
    document = _json_file(directory / "generic_wire.json")
    schema_check(document, root)
    manifest = _json_file(directory / "seed_manifest.json")
    paths = _manifest_paths(manifest)
    expected = _expected_manifest(directory, document, paths)
    _require(json.dumps(manifest, sort_keys=True, separators=(",", ":"))
             == json.dumps(expected, sort_keys=True, separators=(",", ":")),
             "stale template description/corpus manifest")
    inventory = _inventory(directory)
    _require(inventory == set(expected["fixtures"]) | set(expected["seeds"]),
             "template artifact inventory mismatch")
    messages = {message["id"]: message for message in document["messages"]}
    for relative, entry in expected["fixtures"].items():
        data = _regular_bytes(directory / relative, MAX_FRAME)
        _require(data == bytes.fromhex(messages[entry["message_id"]]["example_hex"]),
                 f"stale fixture: {relative}")
    for relative, entry in expected["seeds"].items():
        data = b"".join(_record(bytes.fromhex(messages[mid]["example_hex"]))
                        for mid in entry["request_ids"])
        _require(_regular_bytes(directory / relative, document["limits"]["max_bytes"]) == data,
                 f"stale seed: {relative}")
    return dict(protocol_id=document["protocol_id"], fixtures=len(expected["fixtures"]),
        seeds=len(expected["seeds"]), schema_scope="generic-wire v1 online structural contract",
        semantic_scope="declared request path and exact fixture/replay composition only",
        native_loader_executed=False, target_session_verified=False)


def check_catalog(root=ROOT):
    root = Path(root)
    base = root / "protocols/templates/generic_wire_examples"
    results = [check_package(base / name, root) for name in EXAMPLES]
    starter = root / "protocols/templates/generic_wire.template.json"
    _require(_regular_bytes(starter, MAX_FILE) == _regular_bytes(base / "udp_oneway/generic_wire.json", MAX_FILE),
             "generic-wire starter and catalog example drifted")
    return dict(templates=results, native_loader_executed=False, targets_executed=False)


def refresh_package_corpus(directory, root=ROOT):
    """Explicitly regenerate managed assets along manifest-declared paths.

    All paths and projected transitions are checked before publication. This
    preserves author-chosen request sequences rather than guessing a new graph
    path or changing an unrelated -i corpus. A state edit invalidating a path
    requires the author to update its request_ids first. Publication is atomic
    per file; a failed partial refresh is detected by the old manifest.
    """
    directory = Path(directory)
    document = _json_file(directory / "generic_wire.json")
    schema_check(document, root)
    old = _json_file(directory / "seed_manifest.json")
    paths = _manifest_paths(old)
    manifest = _expected_manifest(directory, document, paths)
    messages = {message["id"]: message for message in document["messages"]}
    planned = {}
    for relative, entry in manifest["fixtures"].items():
        planned[relative] = bytes.fromhex(messages[entry["message_id"]]["example_hex"])
    for relative, entry in manifest["seeds"].items():
        planned[relative] = b"".join(_record(bytes.fromhex(messages[mid]["example_hex"]))
                                     for mid in entry["request_ids"])
    existing = _inventory(directory, allow_missing=True)
    _require(existing <= set(old["fixtures"]) | set(old["seeds"]) | set(planned),
             "unknown managed artifact; refresh refuses to overwrite or delete it")
    # Staging lives outside seeds/fixtures: interrupted writes must never add
    # a hidden temporary file to a directory the real fuzzer enumerates.
    with tempfile.TemporaryDirectory(prefix=".generic-corpus-", dir=directory) as temporary:
        staging = Path(temporary)
        for relative, data in planned.items():
            staged = staging / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(data)
        staged_manifest = staging / "seed_manifest.json"
        staged_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        for relative in planned:
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            (staging / relative).replace(path)
        for previous in existing - set(planned):
            (directory / previous).unlink()
        staged_manifest.replace(directory / "seed_manifest.json")
    return check_package(directory, root)


def instantiate_generic(base, output, protocol_id=None, root=ROOT):
    """Copy a complete bounded example; supported primitives remain editable.

    This uses no codec allowlist and does not create a new protocol parser.
    Choosing an example selects UDP/TCP authoring scaffolding only.
    """
    _require(base in EXAMPLES, "unknown generic template example")
    root, output = Path(root), Path(output)
    _require(not output.exists() and not output.is_symlink(), "refusing to overwrite output")
    source = root / "protocols/templates/generic_wire_examples" / base
    check_package(source, root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".generic-draft-", dir=output.parent) as temporary:
        draft = Path(temporary) / "package"
        shutil.copytree(source, draft)
        if protocol_id is not None:
            _require(type(protocol_id) is str and 1 <= len(protocol_id.encode("utf-8")) <= 63
                     and "\0" not in protocol_id, "invalid generic protocol ID")
            path = draft / "generic_wire.json"
            document = load_bounded_json(path)
            document["protocol_id"] = protocol_id
            path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            old = load_bounded_json(draft / "seed_manifest.json")
            paths = {relative: entry["request_ids"] for relative, entry in old["seeds"].items()}
            manifest = _expected_manifest(draft, document, paths)
            (draft / "seed_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        result = check_package(draft, root)
        _require(not output.exists() and not output.is_symlink(), "refusing to overwrite output")
        draft.rename(output)
    return dict(output=str(output), **result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check bundled template catalog")
    parser.add_argument("--check-package", type=Path, help="check one managed copied example")
    parser.add_argument("--refresh-corpus", type=Path,
                        help="explicitly replace one package's generated fixtures/seeds along declared request_ids")
    parser.add_argument("--base", choices=EXAMPLES, help="copy one generic authoring scaffold")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--protocol-id")
    args = parser.parse_args()
    try:
        selected = (int(args.check) + int(args.check_package is not None)
                    + int(args.refresh_corpus is not None) + int(args.base is not None))
        _require(selected == 1, "choose exactly one of --check, --check-package, --refresh-corpus or --base")
        if args.check:
            result = check_catalog()
        elif args.check_package:
            result = check_package(args.check_package)
        elif args.refresh_corpus:
            result = refresh_package_corpus(args.refresh_corpus)
        else:
            _require(args.output_dir is not None, "--base requires --output-dir")
            result = instantiate_generic(args.base, args.output_dir, args.protocol_id)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, jsonschema.ValidationError,
            jsonschema.SchemaError) as error:
        parser.exit(1, f"generic template error: {error}\n")


if __name__ == "__main__":
    main()
