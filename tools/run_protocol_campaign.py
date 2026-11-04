#!/usr/bin/env python3
"""Validate and compile a selected YAML description package before running StateAFL."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from proto_spec_compiler import SpecError, compile_spec, load, validate
from protocol_corpus_contract import CorpusContractError, check_input_corpus, check_model_corpus

ROOT = Path(__file__).resolve().parents[1]
COMPILED_FILES = ("protocol_ir.json", "state_ir.json", "spec_bundle.json", "validation.json")
# Matches the current host's getopt string and protocol_options table. Values
# must be consumed before looking for -i, and target argv is never scanned.
SHORT_VALUE_OPTIONS = frozenset("iofmtTBSMxNDWrwePqscluU")
SHORT_FLAG_OPTIONS = frozenset("dnCQKERF")
LONG_VALUE_OPTIONS = frozenset(("--mutation-mode", "--mutation-layers", "--protocol-ratio",
                                "--protocol-schedule", "--random-seed", "--protocol-save-candidates"))
LONG_FLAG_OPTIONS = frozenset(("--protocol-fallback",))
MODEL_OPTIONS = frozenset(("--protocol-spec", "--state-spec", "--generic-spec"))
SOURCE_FILES = ("protocol_spec.yaml", "state_transition.yaml")


def _source_identity(directory):
    """Bound the source snapshot used to detect edits during preparation.

    This is a before/after stability check, not a lock against arbitrary edits
    after the final check or while the host starts.
    """
    identity = {}
    for name in SOURCE_FILES:
        with (directory / name).open("rb") as source:
            contents = source.read(2**20 + 1)
        if len(contents) > 2**20:
            raise SpecError(f"{name}: source description exceeds 1 MiB")
        identity[name] = hashlib.sha256(contents).hexdigest()
    return identity


def _require_stable_sources(directory, identity):
    if _source_identity(directory) != identity:
        raise SpecError("source YAML changed during preparation; retry from a stable source pair")


def parse_afl_input(arguments, *, required=True):
    """Find one complete -i option, respecting short clusters and target argv."""
    if not isinstance(arguments, (list, tuple)) or any(not isinstance(argument, str) for argument in arguments):
        raise SpecError("afl-fuzz arguments must be a list or tuple of strings")
    selected = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if not isinstance(argument, str):
            raise SpecError("afl-fuzz arguments must be strings")
        if argument == "--" or not argument.startswith("-") or argument == "-":
            break
        if argument.startswith("--"):
            option, equal, value = argument.partition("=")
            if option in MODEL_OPTIONS:
                raise SpecError("--spec-dir selects both models; do not also pass "
                                "--protocol-spec, --state-spec or --generic-spec")
            if option in LONG_FLAG_OPTIONS and not equal:
                index += 1
                continue
            if option not in LONG_VALUE_OPTIONS:
                raise SpecError(f"unsupported afl-fuzz option: {option}")
            if not equal:
                index += 1
                if index >= len(arguments) or arguments[index] == "--":
                    raise SpecError(f"missing value for {option}")
            index += 1
            continue
        cluster = argument[1:]
        offset = 0
        while offset < len(cluster):
            option = cluster[offset]
            if option in SHORT_FLAG_OPTIONS:
                offset += 1
                continue
            if option not in SHORT_VALUE_OPTIONS:
                raise SpecError(f"unsupported afl-fuzz option: -{option}")
            value = cluster[offset + 1:]
            if not value:
                index += 1
                if index >= len(arguments) or arguments[index] == "--":
                    raise SpecError(f"missing value for -{option}")
                value = arguments[index]
            if option == "i":
                if selected is not None:
                    raise SpecError("multiple -i options are not supported")
                if not isinstance(value, str) or not value:
                    raise SpecError("-i requires a nonempty input directory or '-' for resume")
                selected = value
            break  # A value consumes the rest of its short-option cluster.
        index += 1
    if required and selected is None:
        raise SpecError("-i is required: select the package seeds, a custom replay directory, or '-' for resume")
    return selected


def _publish_compiled(stage, directory):
    """Prepare all replacement files before publishing any of them.

    Per-file replacement is atomic; this is not a whole-directory transaction.
    Readers retain the existing paired bundle-digest consistency checks.
    """
    contents = [(name, (stage / name).read_bytes()) for name in COMPILED_FILES]
    prepared = []
    try:
        for name, data in contents:
            descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.campaign.", dir=directory)
            prepared.append((Path(temporary), directory / name))
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
        for temporary, destination in prepared:
            temporary.replace(destination)
    finally:
        for temporary, _ in prepared:
            temporary.unlink(missing_ok=True)


def prepare(spec_directory, afl_arguments, afl_binary=None, validate_only=False):
    spec_directory = Path(spec_directory).resolve()
    source_identity = _source_identity(spec_directory)
    protocol = load(spec_directory / "protocol_spec.yaml")
    state = load(spec_directory / "state_transition.yaml")
    _require_stable_sources(spec_directory, source_identity)
    validate(protocol, state)
    if not validate_only and not protocol["support"]["runtime"]:
        raise SpecError(f"{protocol['protocol_id']}: runtime encoder unavailable; "
                        "this package supports static validation only (use --validate-only)")
    selected_input = parse_afl_input(afl_arguments, required=not validate_only)
    binary = None
    if not validate_only:
        binary = Path(afl_binary or ROOT / "afl-fuzz").resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SpecError(f"afl-fuzz is not an executable file: {binary}; build StateAFL first")
    # A rejected edit/corpus must not overwrite the previously published IR.
    # Native compiler checks run in staging; all corpus checks are read-only.
    with tempfile.TemporaryDirectory(prefix=".campaign-check-", dir=spec_directory) as temporary:
        stage = Path(temporary)
        result = compile_spec(protocol, state, stage)
        if validate_only:
            preparation = dict(scope="model_only", corpus_check="not_requested",
                               input_check="not_requested", target_started=False)
        else:
            try:
                managed = check_model_corpus(spec_directory, protocol, state, result)
                selected = check_input_corpus(selected_input, spec_directory, state, managed)
            except CorpusContractError as error:
                raise SpecError(str(error)) from error
            preparation = dict(scope="model_and_selected_input", managed_corpus=managed,
                               selected_input=selected, target_started=False)
        _require_stable_sources(spec_directory, source_identity)
        preparation["source_sha256"] = source_identity
        _publish_compiled(stage, spec_directory)
    result = dict(result, preparation=preparation)
    if validate_only:
        return result, None
    command = [str(binary), "--protocol-spec", str(spec_directory / "protocol_ir.json"),
               "--state-spec", str(spec_directory / "state_ir.json"), *afl_arguments]
    return result, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-dir", required=True, type=Path)
    parser.add_argument("--afl-fuzz", type=Path, default=ROOT / "afl-fuzz")
    parser.add_argument("--validate-only", action="store_true",
                        help="validate and compile models only; no corpus/target claim; supports static packages")
    parser.add_argument("--print-command", action="store_true",
                        help="check models and selected -i corpus, then print argv without starting a target")
    parser.add_argument("afl_arguments", nargs=argparse.REMAINDER,
                        help="after --: original afl-fuzz options, then -- target arguments")
    args = parser.parse_args()
    arguments = args.afl_arguments
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    try:
        result, command = prepare(args.spec_dir, arguments, args.afl_fuzz, args.validate_only)
        if args.validate_only or args.print_command:
            print(json.dumps(dict(validation=result, command=command), ensure_ascii=False, indent=2))
            return 0
        selected = result["preparation"]["selected_input"]
        if selected["scope"] == "external_unmanaged":
            input_scope = "custom input framing/resource checks; protocol semantics not verified by preparation"
        elif selected["scope"] == "runtime_resume":
            input_scope = "resume input requires the host's locked snapshot verification"
        else:
            input_scope = "package request corpus matches the current declared model"
        print(f"Loading {result['protocol']} from {args.spec_dir.resolve()} "
              f"(models and managed corpus current; {input_scope}).", flush=True)
        # Replace this wrapper so the fuzzer retains its normal signal and
        # shutdown behavior. No shell evaluation or extra long-lived process.
        os.execv(command[0], command)
    except (SpecError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol campaign error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
