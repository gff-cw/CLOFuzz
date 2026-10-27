#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
protocol_test_output="${1:-tests/protocol/out/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$protocol_test_output"
protocol_test_output="$(realpath "$protocol_test_output")"
make -j2 afl-fuzz aflnet-replay > "$protocol_test_output/build.log" 2>&1
clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I. tests/protocol/test_schedule.c protocol_schedule.c \
  -o "$protocol_test_output/schedule-test" > "$protocol_test_output/schedule-build.log" 2>&1
"$protocol_test_output/schedule-test" > "$protocol_test_output/schedule.log" 2>&1
clang -std=gnu11 -O1 -g -Wno-pointer-sign -Wno-unused-result \
  -DAFL_PATH='"."' -DBIN_PATH='"/usr/bin"' -DDOC_PATH='"docs"' \
  -fsanitize=address,undefined -fno-omit-frame-pointer -I. \
  tests/protocol/test_feedback.c protocol_runtime.c protocol_schedule.c \
  protocol_codec_*.c native_json.c native_layout.c native_observation.c native_inspect.c \
  aflnet.c -ldl -lgvc -lcgraph -lm -o "$protocol_test_output/feedback-test" \
  > "$protocol_test_output/feedback-build.log" 2>&1
"$protocol_test_output/feedback-test" > "$protocol_test_output/feedback.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_compiler.py -v > "$protocol_test_output/compiler.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_cli.py -v > "$protocol_test_output/cli.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_templates.py -v > "$protocol_test_output/templates.log" 2>&1
python3 tests/protocol/test_model_completeness.py > "$protocol_test_output/model-completeness.log" 2>&1
python3 tests/protocol/test_codec_modbus_iec.py > "$protocol_test_output/modbus-iec-codecs.log" 2>&1
python3 tests/protocol/test_mms_codec.py > "$protocol_test_output/mms-codec.log" 2>&1
python3 tests/protocol/test_enip_opcua_codecs.py > "$protocol_test_output/enip-opcua-codecs.log" 2>&1
python3 tests/protocol/test_multicodec_runtime.py > "$protocol_test_output/multicodec-runtime.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_experiment_analysis.py -v > "$protocol_test_output/experiment-analysis.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_campaign_budget.py -v > "$protocol_test_output/campaign-budget.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_evidence_audit.py -v > "$protocol_test_output/evidence-audit.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_description_checks.py -v > "$protocol_test_output/description-checks.log" 2>&1
python3 -m unittest discover -s tests/protocol -p test_export_bundle.py -v > "$protocol_test_output/export-bundle.log" 2>&1
python3 tests/protocol/run_runtime_tests.py > "$protocol_test_output/runtime.log" 2>&1
clang -O1 -g -Wno-pointer-sign -fsanitize=address,undefined -fno-omit-frame-pointer -I. \
  tests/protocol/test_network.c aflnet.c -o "$protocol_test_output/network-test" > "$protocol_test_output/network-build.log" 2>&1
"$protocol_test_output/network-test" > "$protocol_test_output/network.log" 2>&1
printf 'Protocol tests passed. Logs: %s\n' "$protocol_test_output"
