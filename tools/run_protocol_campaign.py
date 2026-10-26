#!/usr/bin/env python3
"""Validate and compile a selected YAML description package before running StateAFL."""
import argparse
import json
import os
from pathlib import Path
import sys
from proto_spec_compiler import SpecError, compile_spec, load, validate

ROOT = Path(__file__).resolve().parents[1]


def prepare(spec_directory, afl_arguments, afl_binary=None, validate_only=False):
    spec_directory = Path(spec_directory).resolve()
    protocol = load(spec_directory / "protocol_spec.yaml")
    state = load(spec_directory / "state_transition.yaml")
    validate(protocol, state)
    if not validate_only and not protocol["support"]["runtime"]:
        raise SpecError(f"{protocol['protocol_id']}: runtime encoder unavailable; "
                        "this package supports static validation only (use --validate-only)")
    target_boundary = afl_arguments.index("--") if "--" in afl_arguments else len(afl_arguments)
    for argument in afl_arguments[:target_boundary]:
        if argument.split("=", 1)[0] in {"--protocol-spec", "--state-spec"}:
            raise SpecError("--spec-dir selects both models; do not also pass --protocol-spec or --state-spec")
    result = compile_spec(protocol, state, spec_directory)
    if validate_only:
        return result, None
    binary = Path(afl_binary or ROOT / "afl-fuzz").resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SpecError(f"afl-fuzz is not an executable file: {binary}; build StateAFL first")
    command = [str(binary), "--protocol-spec", str(spec_directory / "protocol_ir.json"),
               "--state-spec", str(spec_directory / "state_ir.json"), *afl_arguments]
    return result, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-dir", required=True, type=Path)
    parser.add_argument("--afl-fuzz", type=Path, default=ROOT / "afl-fuzz")
    parser.add_argument("--validate-only", action="store_true", help="compile only; works for static-only packages")
    parser.add_argument("--print-command", action="store_true", help="compile and print argv without starting a target")
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
        if not arguments:
            raise SpecError("supply afl-fuzz arguments after --, or use --print-command/--validate-only")
        print(f"Loading {result['protocol']} from {args.spec_dir.resolve()} "
              "(YAML validated and IR rebuilt).", flush=True)
        # Replace this wrapper so the fuzzer retains its normal signal and
        # shutdown behavior. No shell evaluation or extra long-lived process.
        os.execv(command[0], command)
    except (SpecError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol campaign error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
