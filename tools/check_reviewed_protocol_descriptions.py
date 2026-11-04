#!/usr/bin/env python3
"""Read-only checks for reviewed source descriptions; never invoke native code.

These are editable inputs for init_protocol_spec.py --source-dir, not compiled
packages. A successful check establishes schema, references and saved source
identity only. It does not certify codec acceptance or target interoperability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

import jsonschema
import yaml

from check_protocol_descriptions import DescriptionError, index, read_document, require

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("bacnet_ip", "modbus_tcp", "iec60870_5_104", "iec61850_mms_tcp",
            "ethernet_ip_cip_tcp", "opcua_tcp")
SOURCE_FILES = ("protocol_spec.yaml", "state_transition.yaml", "constraints.json", "README.md")
BASE_FILES = ("protocol_spec.yaml", "state_transition.yaml", "generic_wire.json")
NON_SOURCE_FILES = frozenset(("validation.json", "protocol_ir.json", "state_ir.json",
                              "spec_bundle.json", "seed_manifest.json", "seeds"))


def _sha(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 2**20,
            f"{path}: expected a regular source file of at most 1 MiB")
    with path.open("rb") as stream:
        data = stream.read(2**20 + 1)
    require(len(data) <= 2**20, f"{path}: source exceeds 1 MiB")
    return hashlib.sha256(data).hexdigest()


def _same(left, right):
    return json.dumps(left, sort_keys=True, ensure_ascii=False) == json.dumps(right, sort_keys=True, ensure_ascii=False)


def _schema(root, document, name):
    schema, _ = read_document(root / "protocols/schema" / (name + ".schema.json"))
    jsonschema.Draft202012Validator.check_schema(schema)
    error = next(jsonschema.Draft202012Validator(schema).iter_errors(document), None)
    if error is not None:
        raise DescriptionError(f"{name}.{'.'.join(map(str, error.absolute_path))}: {error.message}")


def check_source(root, name):
    """Check one complete YAML pair and its declaration/codec boundary list."""
    root = Path(root)
    require(name in PROFILES, "unknown reviewed profile")
    directory = root / "protocols/reviewed" / name
    require(stat.S_ISDIR(directory.lstat().st_mode), f"{directory}: expected a regular source directory")
    inventory = {path.name for path in directory.iterdir()}
    require(not inventory & NON_SOURCE_FILES, "reviewed source must not contain native validation or compiled outputs")
    require(inventory == set(SOURCE_FILES), f"{directory}: unexpected or missing source files")
    hashes = {filename: _sha(directory / filename) for filename in SOURCE_FILES}
    protocol, _ = read_document(directory / "protocol_spec.yaml")
    state, _ = read_document(directory / "state_transition.yaml")
    constraints, _ = read_document(directory / "constraints.json")
    _schema(root, protocol, "protocol_spec")
    _schema(root, state, "state_transition")
    _schema(root, constraints, "reviewed_description")
    require(protocol["protocol_id"] == state["protocol_id"] == constraints["protocol_id"] == name,
            "reviewed protocol/state/constraint identity mismatch")
    messages = index(protocol["messages"], "id", "messages")
    states = index(state["states"], "id", "states")
    sources = index(protocol["sources"], "id", "sources")
    require(state["initial"] in states, "unknown initial state")
    examples = {}
    for mid, message in messages.items():
        require(message.get("fixture_status") == "complete", f"{mid}: source fixture is incomplete")
        require(message.get("runtime_encode") is (protocol["support"]["runtime"] and message["direction"] == "request"),
                f"{mid}: inconsistent runtime capability assertion")
        require(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", message["example"]) is not None,
                f"{mid}: invalid example hex")
        examples[mid] = bytes.fromhex(message["example"])
        require(len(examples[mid]) <= 65507, f"{mid}: oversized example")
        fields = index(message["fields"], "id", mid + ".fields")
        blocks = index(message["blocks"], "id", mid + ".blocks")
        members = [fid for block in blocks.values() for fid in block["fields"]]
        require(len(members) == len(set(members)) and set(members) == set(fields), f"{mid}: incomplete block field inventory")
        for fid, field in fields.items():
            require(field["evidence"] in sources, f"{mid}.{fid}: unknown source")
            require(field["block"] in blocks and fid in blocks[field["block"]]["fields"], f"{mid}.{fid}: mismatched block")
            require(field["min"] <= field["max"], f"{mid}.{fid}: reversed bounds")
            if field["width"]:
                require(field["max"] < 1 << (8 * field["width"]), f"{mid}.{fid}: bounds exceed width")
                if field["mutability"] == "fixed":
                    require(field["min"] == field["max"] == field["default"], f"{mid}.{fid}: inconsistent fixed scalar")
                # These positions have a direct static meaning. Dynamic
                # codec locators still require native parsing, not a guessed
                # offset inferred from a field's display name.
                location = None
                if re.fullmatch(r"abs:[0-9]+", field["locator"]):
                    location = int(field["locator"][4:])
                elif protocol["codec"] == "bacnet":
                    location = {"bvlc.type": 0, "bvlc.function": 1, "bvlc.length": 2,
                                "npdu.version": 4, "npdu.control": 5}.get(field["locator"])
                if location is not None:
                    width = field["width"]
                    require(location + width <= len(examples[mid]), f"{mid}.{fid}: truncated scalar example")
                    actual = int.from_bytes(examples[mid][location:location + width], field["endian"])
                    require(field["min"] <= actual <= field["max"], f"{mid}.{fid}: example scalar violates bounds")
        writers = set()
        for dependency in message["dependencies"]:
            target = dependency["target"]
            require(target in fields and target not in writers, f"{mid}: unknown or multiply written dependency target")
            writers.add(target)
            source_message = dependency.get("message", mid)
            require(source_message in messages, f"{mid}: missing dependency message")
            source_fields = {field["id"]: field for field in messages[source_message]["fields"]}
            source = dependency.get("source", "$message")
            require(source == "$message" or source in source_fields, f"{mid}: missing dependency source")
            if dependency["op"] in {"copy_from_message", "bind_from_response", "correlate_request_response"}:
                require(source != "$message" and fields[target]["width"] > 0
                        and (fields[target]["type"], fields[target]["width"]) ==
                            (source_fields[source]["type"], source_fields[source]["width"]),
                        f"{mid}: incompatible scalar dependency")
            if dependency["op"] == "correlate_request_response":
                require(message["direction"] == "response" and messages[source_message]["direction"] == "request",
                        f"{mid}: correlation direction mismatch")
        require(all(field["id"] in writers for field in fields.values()
                    if field["mutability"] in {"derived", "runtime_bound"}), f"{mid}: missing dependency writer")
    edge_keys, used = set(), set()
    for edge in state["transitions"]:
        require(edge["from"] in states and edge["to"] in states and edge["message"] in messages,
                "unknown transition endpoint or message")
        key = edge["from"], edge["message"]
        require(key not in edge_keys, "duplicate executable state edge; guards do not disambiguate")
        edge_keys.add(key)
        used.add(edge["message"])
        response = edge.get("response")
        if response:
            require(response in messages and messages[response]["direction"] == "response", "unknown or non-response expectation")
            require(any(other["from"] == edge["to"] and other["message"] == response
                        for other in state["transitions"]), "expected response lacks an outgoing edge")
    require(used == set(messages), "a declared message has no state edge")
    reached = {state["initial"]}
    for _ in states:
        reached |= {edge["to"] for edge in state["transitions"] if edge["from"] in reached}
    require(reached == set(states), "unreachable declared state")
    covered = set()
    for section in ("changes", "codec_constraints"):
        index(constraints[section], "id", section)
        for entry in constraints[section]:
            require(set(entry["messages"]) <= set(messages), f"{section}: unknown message reference")
            if section == "codec_constraints":
                covered.update(entry["messages"])
    require(covered == set(messages), "codec constraint inventory does not cover every message")
    index(constraints["remaining_gaps"], "id", "remaining_gaps")
    baseline = root / "protocols" / name
    generic, _ = read_document(baseline / "generic_wire.json")
    generic_ids = [message["id"] for message in generic["messages"]]
    coverage = constraints["generic_coverage"]
    require(coverage["online"] is generic["online"], "generic online eligibility drift")
    require(set(coverage["implemented_messages"]) == set(generic_ids), "generic implemented-message inventory drift")
    require(set(generic_ids) <= set(messages), "reviewed source removed a generic message")
    require(set(coverage["missing_messages"]) == set(messages) - set(generic_ids),
            "generic missing-message inventory drift")
    return dict(protocol_id=name, files_sha256=hashes,
                published_source_sha256={filename: _sha(baseline / filename) for filename in BASE_FILES},
                messages=len(messages), requests=sum(m["direction"] == "request" for m in messages.values()),
                responses=sum(m["direction"] == "response" for m in messages.values()),
                fields=sum(len(m["fields"]) for m in messages.values()),
                states=len(states), transitions=len(state["transitions"]),
                generic_messages=len(generic_ids), generic_online=generic["online"])


def check_catalog(root=ROOT):
    root = Path(root)
    directory = root / "protocols/reviewed"
    require(stat.S_ISDIR(directory.lstat().st_mode), "reviewed catalog must be a regular directory")
    require({path.name for path in directory.iterdir()} == set(PROFILES) | {"README.md", "manifest.json"},
            "unexpected or missing reviewed catalog entries")
    manifest, _ = read_document(root / "protocols/reviewed/manifest.json")
    require(set(manifest) == {"format", "version", "source_commit", "proof_scope", "native_validator_executed",
                              "runtime_tests_executed", "whole_standard_complete", "profiles"}, "unknown reviewed catalog format")
    require(manifest["format"] == "stateafl.reviewed-description-catalog" and type(manifest["version"]) is int
            and manifest["version"] == 1, "unsupported reviewed catalog version")
    require(isinstance(manifest["source_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]),
            "invalid source baseline commit")
    require(isinstance(manifest["proof_scope"], str) and bool(manifest["proof_scope"]), "missing static proof scope")
    require(all(manifest[key] is False for key in ("native_validator_executed", "runtime_tests_executed", "whole_standard_complete")),
            "source catalog cannot claim native/runtime/whole-standard acceptance")
    expected = [check_source(root, name) for name in PROFILES]
    require(_same(manifest["profiles"], expected), "reviewed source catalog is stale; review and refresh its identity explicitly")
    return dict(scope="reviewed_source_static_contract", profiles=expected,
                native_validator_executed=False, runtime_tests_executed=False,
                whole_standard_complete=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(check_catalog(), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, yaml.YAMLError, jsonschema.ValidationError,
            jsonschema.SchemaError) as error:
        parser.exit(1, f"reviewed description error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
