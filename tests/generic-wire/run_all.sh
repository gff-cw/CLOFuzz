#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
generic_build_only=0
if [[ "${1:-}" == --build-only ]]; then
  generic_build_only=1
  shift
fi
generic_test_run() {
  if [[ "$generic_build_only" == 0 ]]; then "$@"; fi
}
generic_test_output="${1:-tests/generic-wire/out/checks}"
mkdir -p "$generic_test_output"
generic_test_output="$(realpath "$generic_test_output")"
generic_test_cc="${CC:-clang}"
generic_test_flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -I.)
# The legacy host/network translation units predate the strict runtime flags.
# Keep their instrumentation identical without turning legacy warnings into errors.
generic_legacy_flags=(-std=gnu11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-pointer-sign -Wno-unused-result -I.)
generic_test_sources=(protocol_runtime.c generic_runtime.c generic_wire.c native_json.c run_manifest.c protocol_codec_*.c)
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
generic_test_objs=()
for src in "${generic_test_sources[@]}"; do
  obj="$generic_test_output/$(basename "${src%.c}.o")"
  # Always rebuild: header changes and compiler/sanitizer flags are dependencies.
  "$generic_test_cc" "${generic_test_flags[@]}" -c "$src" -o "$obj"
  generic_test_objs+=("$obj")
done
generic_test_run python3 tests/generic-wire/test_profile_checker.py > "$generic_test_output/profile-checker.log" 2>&1
generic_test_run python3 tests/generic-wire/test_evidence_provenance.py > "$generic_test_output/evidence-provenance.log" 2>&1
generic_test_run python3 tests/generic-wire/test_candidate_evidence_contract.py > "$generic_test_output/candidate-evidence-contract.log" 2>&1
generic_test_run python3 tools/check_generic_wire_profiles.py > "$generic_test_output/descriptions.json"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_generic_wire.c "$generic_test_output/generic_wire.o" "$generic_test_output/native_json.o" -o "$generic_test_output/wire"
generic_test_run "$generic_test_output/wire" tests/generic-wire/fictional_protocol.json > "$generic_test_output/wire.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_generic_profiles.c "$generic_test_output/generic_wire.o" "$generic_test_output/native_json.o" -o "$generic_test_output/profiles"
generic_test_run "$generic_test_output/profiles" protocols/*/generic_wire.json > "$generic_test_output/profiles.log"
for generic_test_name in runtime modbus; do
  "$generic_test_cc" "${generic_test_flags[@]}" "tests/generic-wire/test_generic_${generic_test_name}.c" "${generic_test_objs[@]}" -o "$generic_test_output/$generic_test_name"
done
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_generic_load.c "${generic_test_objs[@]}" -o "$generic_test_output/load"
generic_test_run "$generic_test_output/load" > "$generic_test_output/load.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_state_shared_bounds.c -o "$generic_test_output/state_bounds"
generic_test_run "$generic_test_output/state_bounds" > "$generic_test_output/state_bounds.log"
"$generic_test_cc" "${generic_legacy_flags[@]}" -c aflnet.c -o "$generic_test_output/aflnet.o"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_message_context_lifecycle.c "$generic_test_output/aflnet.o" -o "$generic_test_output/lifecycle"
generic_test_run "$generic_test_output/lifecycle" > "$generic_test_output/lifecycle.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_observation_isolation.c -o "$generic_test_output/observation_isolation"
generic_test_run "$generic_test_output/observation_isolation" > "$generic_test_output/observation_isolation.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_execution_wire_contract.c -o "$generic_test_output/execution_wire_contract"
generic_test_run "$generic_test_output/execution_wire_contract" > "$generic_test_output/execution_wire_contract.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_transmission_ledger.c "$generic_test_output/aflnet.o" -o "$generic_test_output/ledger"
generic_test_run "$generic_test_output/ledger" > "$generic_test_output/ledger.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_state_observation_provider.c -o "$generic_test_output/state_observation_provider"
generic_test_run "$generic_test_output/state_observation_provider" > "$generic_test_output/state_observation_provider.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_candidate_metadata_identity.c -o "$generic_test_output/candidate_metadata"
generic_test_run "$generic_test_output/candidate_metadata" > "$generic_test_output/candidate_metadata.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_novelty_admission_decoupling.c -o "$generic_test_output/novelty_admission"
generic_test_run "$generic_test_output/novelty_admission" > "$generic_test_output/novelty_admission.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_reachability_deduplication.c -o "$generic_test_output/reachability_dedup"
generic_test_run "$generic_test_output/reachability_dedup" > "$generic_test_output/reachability_dedup.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_no_response_observation.c -o "$generic_test_output/no_response_obs"
generic_test_run "$generic_test_output/no_response_obs" > "$generic_test_output/no_response_obs.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_message_snapshot_boundary_mapping.c -o "$generic_test_output/boundary_mapping"
generic_test_run "$generic_test_output/boundary_mapping" > "$generic_test_output/boundary_mapping.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_target_state_m2_selection.c -o "$generic_test_output/target_state_m2"
generic_test_run "$generic_test_output/target_state_m2" > "$generic_test_output/target_state_m2.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_alias_canonical_identity.c "${generic_test_objs[@]}" -o "$generic_test_output/alias_canonical"
generic_test_run "$generic_test_output/alias_canonical" > "$generic_test_output/alias_canonical.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_ir_loader_contract.c "${generic_test_objs[@]}" -o "$generic_test_output/ir_contract"
generic_test_run "$generic_test_output/ir_contract" > "$generic_test_output/ir_contract.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_sequence_full_validation.c "${generic_test_objs[@]}" -o "$generic_test_output/sequence_validation"
generic_test_run "$generic_test_output/sequence_validation" > "$generic_test_output/sequence_validation.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_state_graph_strict_execution.c "${generic_test_objs[@]}" -o "$generic_test_output/state_graph_strict"
generic_test_run "$generic_test_output/state_graph_strict" > "$generic_test_output/state_graph_strict.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_session_runtime_binding_isolation.c "$generic_test_output/aflnet.o" "${generic_test_objs[@]}" -o "$generic_test_output/session_isolation"
generic_test_run "$generic_test_output/session_isolation" > "$generic_test_output/session_isolation.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_tcp_framing_verification.c "${generic_test_objs[@]}" -o "$generic_test_output/tcp_framing"
generic_test_run "$generic_test_output/tcp_framing" > "$generic_test_output/tcp_framing.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_bacnet_field_validation.c "${generic_test_objs[@]}" -o "$generic_test_output/bacnet_field_validation"
generic_test_run "$generic_test_output/bacnet_field_validation" > "$generic_test_output/bacnet_field_validation.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_zero_length_message.c "${generic_test_objs[@]}" -o "$generic_test_output/zero_length_message"
generic_test_run "$generic_test_output/zero_length_message" > "$generic_test_output/zero_length_message.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_udp_datagram_boundaries.c "$generic_test_output/aflnet.o" "${generic_test_objs[@]}" -o "$generic_test_output/udp_datagram_boundaries"
generic_test_run "$generic_test_output/udp_datagram_boundaries" > "$generic_test_output/udp_datagram_boundaries.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_tcp_response_buffer_bounds.c "$generic_test_output/aflnet.o" -o "$generic_test_output/tcp_response_bounds"
generic_test_run "$generic_test_output/tcp_response_bounds" > "$generic_test_output/tcp_response_bounds.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_timeout_budget_consistency.c "$generic_test_output/aflnet.o" -o "$generic_test_output/timeout_budget"
generic_test_run "$generic_test_output/timeout_budget" > "$generic_test_output/timeout_budget.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_stage_gating_attribution.c -o "$generic_test_output/stage_gating"
generic_test_run "$generic_test_output/stage_gating" > "$generic_test_output/stage_gating.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_layer_operability_accounting.c "${generic_test_objs[@]}" -o "$generic_test_output/layer_operability"
generic_test_run "$generic_test_output/layer_operability" > "$generic_test_output/layer_operability.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_versioned_metrics_dictionary.c "${generic_test_objs[@]}" -o "$generic_test_output/versioned_metrics"
generic_test_run "$generic_test_output/versioned_metrics" > "$generic_test_output/versioned_metrics.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_cold_start_segment_manifest.c "${generic_test_objs[@]}" -o "$generic_test_output/cold_start_manifest"
generic_test_run "$generic_test_output/cold_start_manifest" > "$generic_test_output/cold_start_manifest.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_dual_file_publish_consistency.c "${generic_test_objs[@]}" -o "$generic_test_output/dual_file_publish"
generic_test_run "$generic_test_output/dual_file_publish" > "$generic_test_output/dual_file_publish.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_format_boundaries.c "${generic_test_objs[@]}" -o "$generic_test_output/format_boundaries"
generic_test_run "$generic_test_output/format_boundaries" > "$generic_test_output/format_boundaries.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_unsupported_rejection.c "${generic_test_objs[@]}" -o "$generic_test_output/unsupported_rejection"
generic_test_run "$generic_test_output/unsupported_rejection" > "$generic_test_output/unsupported_rejection.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_protocol_capability_gaps.c "${generic_test_objs[@]}" -o "$generic_test_output/protocol_capability_gaps"
generic_test_run "$generic_test_output/protocol_capability_gaps" > "$generic_test_output/protocol_capability_gaps.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_template_misconfiguration_guard.c "${generic_test_objs[@]}" -o "$generic_test_output/template_misconfiguration_guard"
generic_test_run "$generic_test_output/template_misconfiguration_guard" > "$generic_test_output/template_misconfiguration_guard.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_early_receive_error_cleanup.c -o "$generic_test_output/early_receive_cleanup"
generic_test_run "$generic_test_output/early_receive_cleanup" > "$generic_test_output/early_receive_cleanup.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_calibration_bounds.c -o "$generic_test_output/calibration_bounds"
generic_test_run "$generic_test_output/calibration_bounds" > "$generic_test_output/calibration_bounds.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_novelty_status_admission.c -o "$generic_test_output/novelty_status_admission"
generic_test_run "$generic_test_output/novelty_status_admission" > "$generic_test_output/novelty_status_admission.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_update_fuzzs.c -o "$generic_test_output/update_fuzzs"
generic_test_run "$generic_test_output/update_fuzzs" > "$generic_test_output/update_fuzzs.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_feedback_layer_purpose_identity.c "${generic_test_objs[@]}" -o "$generic_test_output/feedback_identity"
generic_test_run "$generic_test_output/feedback_identity" > "$generic_test_output/feedback_identity.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_intentionally_invalid_mode.c "${generic_test_objs[@]}" -o "$generic_test_output/intentionally_invalid_mode"
generic_test_run "$generic_test_output/intentionally_invalid_mode" > "$generic_test_output/intentionally_invalid_mode.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_monotonic_deadline_budget.c "$generic_test_output/aflnet.o" -o "$generic_test_output/monotonic_deadline_budget"
generic_test_run "$generic_test_output/monotonic_deadline_budget" > "$generic_test_output/monotonic_deadline_budget.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_manifest_attribution_continuity.c "${generic_test_objs[@]}" -o "$generic_test_output/manifest_attribution_continuity"
generic_test_run "$generic_test_output/manifest_attribution_continuity" > "$generic_test_output/manifest_attribution_continuity.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_manifest_configuration_contract.c "${generic_test_objs[@]}" -o "$generic_test_output/manifest_configuration_contract"
generic_test_run "$generic_test_output/manifest_configuration_contract" > "$generic_test_output/manifest_configuration_contract.log"
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_response_completion_transaction.c "${generic_test_objs[@]}" -o "$generic_test_output/response_completion_transaction"
generic_test_run "$generic_test_output/response_completion_transaction" > "$generic_test_output/response_completion_transaction.log"
# This regression includes the production aflnet.c with syscall injection, so
# linking aflnet.o as well would duplicate the implementation.
"$generic_test_cc" "${generic_legacy_flags[@]}" tests/generic-wire/test_transport_error_contract.c -o "$generic_test_output/transport_error_contract"
generic_test_run "$generic_test_output/transport_error_contract" > "$generic_test_output/transport_error_contract.log"
"$generic_test_cc" "${generic_legacy_flags[@]}" \
  -DAFL_PATH='"."' -DBIN_PATH='"/usr/bin"' -DDOC_PATH='"docs"' \
  tests/generic-wire/test_production_execution_contract.c "${generic_test_objs[@]}" \
  protocol_schedule.c native_inspect.c native_layout.c native_observation.c \
  "$generic_test_output/aflnet.o" -ldl -lgvc -lcgraph -lm \
  -o "$generic_test_output/production_execution_contract"
generic_test_run "$generic_test_output/production_execution_contract" > "$generic_test_output/production_execution_contract.log"
for generic_host_contract in calibration_queue child_wait startup_selection resume_input; do
  "$generic_test_cc" "${generic_legacy_flags[@]}" \
    -DAFL_PATH='"."' -DBIN_PATH='"/usr/bin"' -DDOC_PATH='"docs"' \
    "tests/generic-wire/test_${generic_host_contract}_contract.c" "${generic_test_objs[@]}" \
    protocol_schedule.c native_inspect.c native_layout.c native_observation.c \
    "$generic_test_output/aflnet.o" -ldl -lgvc -lcgraph -lm \
    -o "$generic_test_output/${generic_host_contract}_contract"
  generic_test_run "$generic_test_output/${generic_host_contract}_contract" > "$generic_test_output/${generic_host_contract}_contract.log"
done
"$generic_test_cc" "${generic_test_flags[@]}" tests/generic-wire/test_transmission_ledger_rejection.c "$generic_test_output/aflnet.o" -o "$generic_test_output/transmission_ledger_rejection"
generic_test_run "$generic_test_output/transmission_ledger_rejection" > "$generic_test_output/transmission_ledger_rejection.log"
generic_test_run "$generic_test_output/runtime" tests/generic-wire/fictional_protocol.json > "$generic_test_output/runtime.log"
generic_test_run "$generic_test_output/modbus" protocols/modbus_tcp/generic_wire.json > "$generic_test_output/modbus.log"
if [[ "$generic_build_only" == 1 ]]; then
  printf 'Generic regression sources compiled; no tests executed. Objects: %s\n' "$generic_test_output"
else
  printf 'Generic C grammar/runtime checks passed. Logs: %s\n' "$generic_test_output"
fi
