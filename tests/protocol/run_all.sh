#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
protocol_test_output="${1:-tests/protocol/out/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$protocol_test_output"
protocol_test_output="$(realpath "$protocol_test_output")"
make -j2 afl-fuzz aflnet-replay > "$protocol_test_output/build.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_compiler.py -v > "$protocol_test_output/compiler.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_cli.py -v > "$protocol_test_output/cli.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_templates.py -v > "$protocol_test_output/templates.log" 2>&1
python3 tests/protocol/test_model_completeness.py > "$protocol_test_output/model-completeness.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_experiment_analysis.py -v > "$protocol_test_output/experiment-analysis.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_export_bundle.py -v > "$protocol_test_output/export-bundle.log" 2>&1
python3 tests/protocol/run_runtime_tests.py > "$protocol_test_output/runtime.log" 2>&1
clang -O1 -g -Wno-pointer-sign -fsanitize=address,undefined -fno-omit-frame-pointer -I. \
  tests/protocol/test_network.c aflnet.c -o "$protocol_test_output/network-test" > "$protocol_test_output/network-build.log" 2>&1
"$protocol_test_output/network-test" > "$protocol_test_output/network.log" 2>&1
printf 'Protocol tests passed. Logs: %s\n' "$protocol_test_output"
