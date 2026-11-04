#!/usr/bin/env python3
"""Copy a concrete legacy profile under the common schema/template contract."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import yaml
from proto_spec_compiler import SpecError, compile_spec, ident, load, validate
from protocol_seed_planner import write_model_corpus
from protocol_template_contract import TemplateContractError, checked_profile_copy, contract_metadata

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("bacnet_ip", "modbus_tcp", "iec60870_5_104", "iec61850_mms_tcp",
            "ethernet_ip_cip_tcp", "opcua_tcp")
TEMPLATES = ROOT / "protocols/templates"


class EditableDumper(yaml.SafeDumper):
    """Write independent fields, so editing one message never edits a YAML alias."""
    def ignore_aliases(self, data):
        return True


def _source_hashes(directory):
    result = {}
    for name in ("protocol_spec.yaml", "state_transition.yaml"):
        with (directory / name).open("rb") as source:
            data = source.read(2**20 + 1)
        if len(data) > 2**20:
            raise SpecError(f"{name}: source description exceeds 1 MiB")
        result[name] = hashlib.sha256(data).hexdigest()
    return result


def instantiate(base, output, protocol_id=None, runtime_required=False, *, source_directory=None):
    if source_directory is not None and base is not None:
        raise SpecError("choose either a base profile or an explicit source directory")
    if source_directory is None and base not in PROFILES:
        raise SpecError(f"unknown protocol profile: {base}")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise SpecError(f"refusing to overwrite existing path: {output}")
    source = Path(source_directory).resolve() if source_directory is not None else ROOT / "protocols" / base
    source_files = _source_hashes(source)
    protocol = load(source / "protocol_spec.yaml")
    state = load(source / "state_transition.yaml")
    try:
        protocol, state = checked_profile_copy(protocol, state, template_directory=TEMPLATES)
        template_contract = contract_metadata(template_directory=TEMPLATES)
    except TemplateContractError as error:
        raise SpecError(f"template contract: {error}") from error
    protocol_id = protocol["protocol_id"] if protocol_id is None else protocol_id
    ident(protocol_id, "protocol_id")
    if protocol["protocol_id"] != state["protocol_id"]:
        raise SpecError("source protocol/state ID mismatch; fix both source files before instantiation")
    if runtime_required and not protocol["support"]["runtime"]:
        raise SpecError(f"{base or source}: runtime encoder unavailable; profile is static-only")
    protocol["protocol_id"] = state["protocol_id"] = protocol_id
    validate(protocol, state)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".protocol-draft-", dir=output.parent) as temporary:
        draft = Path(temporary) / "package"
        result = compile_spec(protocol, state, draft)
        for name, document in (("protocol_spec.yaml", protocol), ("state_transition.yaml", state)):
            (draft / name).write_text(
                "# Concrete values copied under the common schema/template contract.\n"
                "# Source identity and exact contract hashes: template_contract.json.\n"
                "# Edit this YAML, then recompile both files; do not hand-edit IR.\n"
                + yaml.dump(document, Dumper=EditableDumper, sort_keys=False), encoding="utf-8")
        corpus = write_model_corpus(draft, protocol, state, result)
        if source_files != _source_hashes(source):
            raise SpecError("source YAML changed during package generation; retry from a stable source pair")
        template_contract["source"] = dict(kind="base_profile" if base is not None else "explicit_directory",
                                            base_profile=base, directory=str(source.resolve()),
                                            files_sha256=source_files)
        template_contract["output_protocol_id"] = protocol_id
        (draft / "template_contract.json").write_text(
            json.dumps(template_contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        skipped_fragments = [message["id"] for message in protocol["messages"]
                             if message["direction"] == "request"
                             and message.get("fixture_status", "complete") == "fragment"]
        evidence = dict(base_profile=base, protocol_id=protocol_id,
                        source_files=source_files,
                        sources=protocol["sources"], scope=protocol["scope"],
                        support=protocol["support"], validation=result,
                        skipped_fragment_seeds=skipped_fragments,
                        model_corpus_manifest="seed_manifest.json", template_contract="template_contract.json",
                        model_reachable_seeds=corpus["seeds"])
        (draft / "evidence.yaml").write_text(yaml.safe_dump(evidence, sort_keys=False), encoding="utf-8")
        (draft / "README.md").write_text(
            f"# {protocol['name']} description package\n\n"
            f"Concrete source: `{base or str(source)}`. Protocol ID: `{protocol_id}`.\n\n"
            f"Scope: {protocol['scope']}\n\n"
            f"Runtime encoder available: {str(result['runtime']).lower()}. "
            "This flag does not claim this copied package has passed a live target test.\n\n"
            "The schemas own structure; this source profile owns every concrete nested value. "
            "template_contract.json records source, schema, skeleton and capability hashes. "
            "Changing a skeleton example does not override real protocol fields or generate a new codec.\n\n"
            "fixtures/requests retains single-message request examples, including static fragments. "
            "seeds contains only request sequences reachable from the declared initial state: "
            "each request projects its declared expected response once, without writing response bytes. "
            "seed_manifest.json records request IDs, projected states, limits and reasons for withholding a seed. "
            "This is a model-level proof; no actual target session, guard, external prerequisite or live response binding is proven.\n\n"
            "Field default, structure_model, state guard/actions and dependency scope/when are annotations; "
            "read validation.json execution_contract for the fields actually interpreted by the runtime.\n\n"
            "Edit protocol_spec.yaml and state_transition.yaml, then run:\n\n"
            "```bash\npython3 /path/to/stateafl/tools/proto_spec_compiler.py "
            "--protocol protocol_spec.yaml --state state_transition.yaml --output-dir .\n"
            "python3 /path/to/stateafl/tools/protocol_seed_planner.py --spec-dir .\n```\n\n"
            "For a runtime-enabled package, load protocol_ir.json and state_ir.json "
            "using afl-fuzz --protocol-spec and --state-spec.\n", encoding="utf-8")
        # Same-parent move publishes a complete package; validation failures
        # never leave half-written YAML or IR at the requested destination.
        if output.exists() or output.is_symlink():
            raise SpecError(f"refusing to overwrite existing path: {output}")
        draft.rename(output)
    return dict(output=str(output), base_profile=base, protocol_id=protocol_id,
                source_directory=str(source.resolve()), template_contract="template_contract.json",
                validated=True, runtime=result["runtime"], messages=result["messages"],
                model_reachable_seeds=corpus["seeds"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument("--base", choices=PROFILES)
    sources.add_argument("--source-dir", type=Path,
                         help="copy an explicit concrete YAML input pair using an already supported codec")
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
    if (not args.base and args.source_dir is None) or not args.output_dir:
        parser.error("choose --base or --source-dir and provide --output-dir unless --list is used")
    try:
        print(json.dumps(instantiate(args.base, args.output_dir, args.protocol_id, args.require_runtime,
                                     source_directory=args.source_dir), ensure_ascii=False))
        return 0
    except (SpecError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol template error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
