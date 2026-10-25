#!/usr/bin/env python3
"""Instantiate the shared description templates using one verified protocol profile."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import yaml
from proto_spec_compiler import SpecError, compile_spec, ident, load, validate

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("bacnet_ip", "modbus_tcp", "iec60870_5_104", "iec61850_mms_tcp",
            "ethernet_ip_cip_tcp", "opcua_tcp")
TEMPLATES = ROOT / "protocols/templates"


class EditableDumper(yaml.SafeDumper):
    """Write independent fields, so editing one message never edits a YAML alias."""
    def ignore_aliases(self, data):
        return True


def instantiate(base, output, protocol_id=None, runtime_required=False):
    if base not in PROFILES:
        raise SpecError(f"unknown protocol profile: {base}")
    output = Path(output)
    if output.exists():
        raise SpecError(f"refusing to overwrite existing path: {output}")
    source = ROOT / "protocols" / base
    protocol = load(source / "protocol_spec.yaml")
    state = load(source / "state_transition.yaml")
    protocol_id = protocol["protocol_id"] if protocol_id is None else protocol_id
    ident(protocol_id, "protocol_id")
    if runtime_required and not protocol["support"]["runtime"]:
        raise SpecError(f"{base}: runtime encoder unavailable; profile is static-only")
    # Apply exactly the common top-level template structure. Nested message,
    # field and state objects come from the selected real protocol, not toy offsets.
    documents = []
    for name, profile in (("protocol_spec", protocol), ("state_transition", state)):
        skeleton = load(TEMPLATES / (name + ".template.yaml"))
        missing = set(skeleton) - set(profile)
        if missing:
            raise SpecError(f"{base}: profile lacks template sections: {sorted(missing)}")
        document = {key: copy.deepcopy(profile[key]) for key in skeleton}
        document["protocol_id"] = protocol_id
        documents.append(document)
    protocol, state = documents
    validate(protocol, state)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".protocol-draft-", dir=output.parent) as temporary:
        draft = Path(temporary) / "package"
        result = compile_spec(protocol, state, draft)
        for name, document in (("protocol_spec.yaml", protocol), ("state_transition.yaml", state)):
            (draft / name).write_text(
                f"# Instantiated from protocols/templates using {base}.\n"
                "# Edit this YAML, then recompile both files; do not hand-edit IR.\n"
                + yaml.dump(document, Dumper=EditableDumper, sort_keys=False), encoding="utf-8")
        seed_directory = draft / "seeds"
        seed_directory.mkdir()
        for message in protocol["messages"]:
            if message["direction"] == "request":
                wire = bytes.fromhex(message["example"])
                (seed_directory / (message["id"] + ".replay")).write_bytes(
                    len(wire).to_bytes(4, "little") + wire)
        evidence = dict(base_profile=base, protocol_id=protocol_id,
                        source_files={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                                      for name in ("protocol_spec.yaml", "state_transition.yaml")},
                        sources=protocol["sources"], scope=protocol["scope"],
                        support=protocol["support"], validation=result)
        (draft / "evidence.yaml").write_text(yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8")
        (draft / "README.md").write_text(
            f"# {protocol['name']} description package\n\n"
            f"Base profile: `{base}`. Protocol ID: `{protocol_id}`.\n\n"
            f"Scope: {protocol['scope']}\n\n"
            f"Runtime encoder available: {str(result['runtime']).lower()}. "
            "This flag does not claim this copied package has passed a live target test.\n\n"
            "Edit protocol_spec.yaml and state_transition.yaml, then run:\n\n"
            "```bash\npython3 /path/to/stateafl/tools/proto_spec_compiler.py "
            "--protocol protocol_spec.yaml --state state_transition.yaml --output-dir .\n```\n\n"
            "For a runtime-enabled package, load protocol_ir.json and state_ir.json "
            "using afl-fuzz --protocol-spec and --state-spec.\n", encoding="utf-8")
        # Same-parent move publishes a complete package; validation failures
        # never leave half-written YAML or IR at the requested destination.
        if output.exists():
            raise SpecError(f"refusing to overwrite existing path: {output}")
        draft.rename(output)
    return dict(output=str(output), base_profile=base, protocol_id=protocol_id,
                validated=True, runtime=result["runtime"], messages=result["messages"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", choices=PROFILES)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--protocol-id")
    parser.add_argument("--require-runtime", action="store_true")
    parser.add_argument("--list", action="store_true", help="list profiles and actual runtime availability")
    args = parser.parse_args()
    if args.list:
        for base in PROFILES:
            profile = load(ROOT / "protocols" / base / "protocol_spec.yaml")
            print(f"{base}: {'runtime' if profile['support']['runtime'] else 'static-only'}")
        return 0
    if not args.base or not args.output_dir:
        parser.error("--base and --output-dir are required unless --list is used")
    try:
        print(json.dumps(instantiate(args.base, args.output_dir, args.protocol_id, args.require_runtime), ensure_ascii=False))
        return 0
    except (SpecError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol template error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
