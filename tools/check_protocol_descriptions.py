#!/usr/bin/env python3
"""Check YAML schemas, references and evidence metadata without native codecs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("modbus_tcp", "iec60870_5_104", "iec61850_mms_tcp",
            "ethernet_ip_cip_tcp", "opcua_tcp")


class DescriptionError(ValueError):
    pass


class DocumentLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key, deep=deep)
        if not isinstance(key, str) or key in result:
            raise DescriptionError(f"duplicate or non-string mapping key: {key!r}")
        result[key] = loader.construct_object(value, deep=deep)
    return result


DocumentLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def read_document(path):
    raw = path.read_bytes()
    if len(raw) > 2**20:
        raise DescriptionError(f"{path.name}: exceeds 1 MiB")
    data = yaml.load(raw.decode("utf-8"), Loader=DocumentLoader)
    budget = [65536]

    def walk(value, depth=0):
        budget[0] -= 1
        if depth > 24 or budget[0] < 0:
            raise DescriptionError("description exceeds nesting or node budget")
        if isinstance(value, dict):
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)
        elif value is not None and type(value) not in (str, int, bool):
            raise DescriptionError("expected JSON-compatible string/integer/boolean values")

    walk(data)
    if not isinstance(data, dict):
        raise DescriptionError(f"{path.name}: expected a mapping")
    return data, hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise DescriptionError(message)


def index(items, key, label):
    require(isinstance(items, list), f"{label}: expected a list")
    result = {}
    for item in items:
        require(isinstance(item, dict) and isinstance(item.get(key), str), f"{label}: missing {key}")
        name = item[key]
        require(name not in result, f"{label}: duplicate {name}")
        result[name] = item
    return result


def check_package(directory):
    directory = Path(directory)
    report = dict(path=str(directory), status="failed", input_sha256={})
    try:
        documents = {}
        for filename in ("protocol_spec.yaml", "state_transition.yaml", "evidence.yaml", "validation.json"):
            documents[filename], report["input_sha256"][filename] = read_document(directory / filename)
        protocol, state = documents["protocol_spec.yaml"], documents["state_transition.yaml"]
        evidence, validation = documents["evidence.yaml"], documents["validation.json"]
        for document, name in ((protocol, "protocol_spec"), (state, "state_transition")):
            schema = json.loads((ROOT / "protocols/schema" / (name + ".schema.json")).read_text())
            errors = list(jsonschema.Draft202012Validator(schema).iter_errors(document))
            if errors:
                error = errors[0]
                raise DescriptionError(f"{name}.{'.'.join(map(str, error.absolute_path))}: {error.message}")
        require(protocol["protocol_id"] == state["protocol_id"], "protocol/state ID mismatch")
        messages = index(protocol["messages"], "id", "messages")
        sources = index(protocol["sources"], "id", "sources")
        states = index(state["states"], "id", "states")
        require(state["initial"] in states, "unknown initial state")
        expected = {}
        for mid, message in messages.items():
            for fid, field in index(message["fields"], "id", mid + ".fields").items():
                require(field["evidence"] in sources, f"{mid}.{fid}: unknown source")
                expected[(mid, fid)] = (field["evidence"], field["confidence"])
        for edge in state["transitions"]:
            require(edge["from"] in states and edge["to"] in states, "unknown transition state")
            require(edge["message"] in messages, "unknown transition message")
            require(not edge.get("response") or edge["response"] in messages, "unknown transition response")
        require(index(evidence.get("sources"), "id", "evidence.sources") == sources,
                "evidence source definitions differ from protocol")
        actual = {}
        entries = evidence.get("field_sources")
        require(isinstance(entries, list), "missing evidence.field_sources")
        for entry in entries:
            require(isinstance(entry, dict), "invalid field source entry")
            require(all(isinstance(entry.get(key), str) for key in ("message", "field", "source", "confidence")),
                    "field source entry requires message/field/source/confidence strings")
            pair = (entry["message"], entry["field"])
            require(pair not in actual, f"duplicate field source: {pair}")
            actual[pair] = (entry["source"], entry["confidence"])
        require(actual == expected, "field_sources must exactly cover and match declared fields")
        require(evidence.get("scope") == protocol["scope"] == validation.get("scope"), "scope mismatch")
        require(evidence.get("validation") == validation, "evidence validation snapshot differs from validation.json")
        counts = Counter(message.get("fixture_status", "complete") for message in messages.values())
        fixture_counts = evidence.get("fixture_counts")
        require(isinstance(fixture_counts, dict)
                and all(type(fixture_counts.get(key)) is int for key in ("complete", "fragment"))
                and fixture_counts == {key: counts[key] for key in ("complete", "fragment")},
                "fixture counts mismatch")
        for key, expected_value in (("protocol", protocol["protocol_id"]), ("messages", len(messages)),
                                    ("fields", len(expected)), ("semantic_states", len(states))):
            actual_value = validation.get(key)
            require(type(actual_value) is type(expected_value) and actual_value == expected_value,
                    f"validation.{key} mismatch")
        warnings = []
        if any(any(part in source["url"] for part in ("/master/", "/main/", "/latest/"))
               for source in sources.values()):
            warnings.append("Some source URLs name moving branches; their historical contents are not pinned.")
        if "source_sha256" not in validation:
            warnings.append("The saved validation record does not bind all YAML inputs by hash; this check is new static evidence.")
        report.update(status="passed", protocol_id=protocol["protocol_id"], scope=protocol["scope"],
                      messages=len(messages), fields=len(expected), semantic_states=len(states),
                      transitions=len(state["transitions"]), complete_fixtures=counts["complete"],
                      warnings=warnings)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError) as error:
        report["error"] = str(error)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-dir", type=Path, action="append", help="May be repeated; defaults to the five TCP profiles.")
    args = parser.parse_args()
    directories = args.spec_dir or [ROOT / "protocols" / name for name in PROFILES]
    packages = [check_package(directory) for directory in directories]
    passed = all(package["status"] == "passed" for package in packages)
    print(json.dumps(dict(status="passed" if passed else "failed", packages=packages,
                          checked=["YAML schema", "message/state/source references", "field-source coverage", "evidence metadata"],
                          not_checked=["wire decoding", "native compilation", "mutation execution", "network integration",
                                       "dependency execution semantics", "source URL contents", "whole-standard conformance"]), ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
