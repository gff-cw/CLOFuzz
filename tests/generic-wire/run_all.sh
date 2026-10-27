#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
generic_test_output="${1:-tests/generic-wire/out/checks}"
mkdir -p "$generic_test_output"
generic_test_output="$(realpath "$generic_test_output")"
generic_test_cc="${CC:-clang}"
generic_test_flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -I.)
generic_test_sources=(protocol_runtime.c generic_runtime.c generic_wire.c native_json.c protocol_codec_*.c)
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
python3 tools/check_generic_wire_profiles.py > "$generic_test_output/descriptions.json"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_generic_wire.c generic_wire.c native_json.c -o "$generic_test_output/wire"
"$generic_test_output/wire" tests/generic-wire/fictional_protocol.json > "$generic_test_output/wire.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_generic_profiles.c generic_wire.c native_json.c -o "$generic_test_output/profiles"
"$generic_test_output/profiles" protocols/*/generic_wire.json > "$generic_test_output/profiles.log"
for generic_test_name in runtime modbus; do
  "$generic_test_cc" "${generic_test_flags[@]}" "tests/generic-wire/test_generic_${generic_test_name}.c" "${generic_test_sources[@]}" -o "$generic_test_output/$generic_test_name"
done
"$generic_test_output/runtime" tests/generic-wire/fictional_protocol.json > "$generic_test_output/runtime.log"
"$generic_test_output/modbus" protocols/modbus_tcp/generic_wire.json > "$generic_test_output/modbus.log"
printf 'Generic C grammar/runtime checks passed. Logs: %s\n' "$generic_test_output"
