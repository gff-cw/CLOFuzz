#!/usr/bin/env python3
"""Exercise the evidence reader with synthetic artifacts; never launch targets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[2] / "tools/audit_protocol_evidence.py"
SPEC = importlib.util.spec_from_file_location("evidence_audit", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class EvidenceAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "workspace"
        self.root.mkdir()
        self.result_path = self.root / "tests/protocol/out/multicodec-tcp-final/iec104/result.json"
        self.runtime_path = self.root / "tests/protocol/evidence/runtime-results.json"

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def integration_result(self, **changes):
        result = {
            "passed": True,
            "exit_code": 0,
            "checks": {"ready": True, "clean_stop": True, "no_crashes": True},
            "stats": {"unique_crashes": "0", "unique_hangs": "0"},
            "protocol_stats": {"structured_success": 2},
            "events": {"mutation": 2, "rejected": 1},
        }
        result.update(changes)
        return result

    def runtime_result(self):
        source = self.root / "sample.c"
        source.write_text("synthetic source artifact\n", encoding="utf-8")
        result = {
            "status": "passed",
            "failures": [],
            "source_sha256": {"sample.c": hashlib.sha256(source.read_bytes()).hexdigest()},
        }
        self.write_json(self.runtime_path, result)
        return result

    def cli(self):
        return subprocess.run(
            [sys.executable, str(TOOL), "--root", str(self.root)],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_missing_result_is_unverified(self):
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["evidence_state"], "missing")
        self.assertEqual(result["acceptance"], "unverified")

    def test_truncated_or_nonobject_json_is_invalid(self):
        self.result_path.parent.mkdir(parents=True)
        for text in ('{"passed":', "[]", "null"):
            with self.subTest(text=text):
                self.result_path.write_text(text, encoding="utf-8")
                result = AUDIT.audit_result(self.root, self.result_path)
                self.assertEqual(result["evidence_state"], "invalid")
                self.assertEqual(result["acceptance"], "unverified")

    def test_empty_or_nonboolean_checks_are_invalid(self):
        for checks in ({}, {"ready": 1}, {"ready": "true"}, {"ready": None}, []):
            with self.subTest(checks=checks):
                self.write_json(self.result_path, self.integration_result(checks=checks))
                result = AUDIT.audit_result(self.root, self.result_path)
                self.assertEqual(result["evidence_state"], "invalid")
                self.assertEqual(result["acceptance"], "unverified")

    def test_runner_signal_overrides_target_zero_and_reported_pass(self):
        self.write_json(self.result_path, self.integration_result(exit_code=-11))
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["recorded_outcome"], "failed")
        self.assertEqual(result["acceptance"], "failed")
        self.assertEqual(result["runner_exit_code"], -11)
        self.assertEqual(result["runner_signal"], 11)
        self.assertEqual(result["target_unique_crashes"], "0")

    def test_duplicate_keys_and_nonfinite_numbers_are_invalid(self):
        self.result_path.parent.mkdir(parents=True)
        for text in ('{"passed": false, "passed": true}', '{"seconds": NaN}',
                     '{"seconds": Infinity}', '{"seconds": -Infinity}',
                     '{"stats": {"seconds": 1e999}}'):
            with self.subTest(text=text):
                self.result_path.write_text(text, encoding="utf-8")
                result = AUDIT.audit_result(self.root, self.result_path)
                self.assertEqual(result["evidence_state"], "invalid")
                self.assertEqual(result["acceptance"], "unverified")

    def test_malformed_counter_objects_are_invalid(self):
        for changes in ({"stats": []}, {"protocol_stats": True}, {"events": []},
                        {"events": {"mutation": True}},
                        {"protocol_stats": {"structured_success": -1}}):
            with self.subTest(changes=changes):
                self.write_json(self.result_path, self.integration_result(**changes))
                result = AUDIT.audit_result(self.root, self.result_path)
                self.assertEqual(result["evidence_state"], "invalid")

    def test_invalid_counters_do_not_hide_known_runner_failure(self):
        self.write_json(self.result_path, self.integration_result(
            exit_code=-11, protocol_stats={"structured_success": "broken"}))
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["evidence_state"], "invalid")
        self.assertEqual(result["acceptance"], "failed")
        self.assertEqual(result["runner_signal"], 11)
        completed = self.cli()
        self.assertEqual(completed.returncode, 1, completed.stderr)

    def test_empty_complete_event_log_records_zero(self):
        self.write_json(self.result_path, self.integration_result(
            protocol_stats={"structured_success": 0}))
        events = self.result_path.parent / "out/protocol_mutations.jsonl"
        events.parent.mkdir()
        events.write_text("", encoding="utf-8")
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertTrue(result["event_count_complete"])
        self.assertEqual(result["mutation_event_count"], 0)
        self.assertEqual(result["counter_consistency"], "match")

    def test_failed_check_overrides_reported_pass(self):
        self.write_json(self.result_path, self.integration_result(checks={"ready": False}))
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["acceptance"], "failed")
        self.assertEqual(result["failed_checks"], ["ready"])

    def test_successful_unhashed_integration_remains_unverified(self):
        self.write_json(self.result_path, self.integration_result())
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["recorded_outcome"], "passed")
        self.assertEqual(result["source_provenance"], "unverified")
        self.assertEqual(result["acceptance"], "unverified")

    def test_events_and_zero_snapshot_preserved_without_inventing_cause(self):
        self.write_json(self.result_path, self.integration_result(
            passed=False, exit_code=-11, protocol_stats={"structured_success": 0},
            events={"mutation": 0, "rejected": 0},
        ))
        events = self.result_path.parent / "out/protocol_mutations.jsonl"
        events.parent.mkdir()
        events.write_text("\n".join(json.dumps({"event": "mutation"}) for _ in range(47)) + "\n",
                          encoding="utf-8")
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["mutation_event_count"], 47)
        self.assertEqual(result["snapshot_structured_success"], 0)
        self.assertEqual(result["event_source"], "jsonl")
        self.assertEqual(result["counter_consistency"], "mismatch")
        self.assertIsNone(result.get("inferred_cause"))
        self.assertIn("does not establish its cause", result["counter_note"])
        self.assertEqual(result["acceptance"], "failed")

    def test_truncated_event_marks_evidence_invalid_with_line(self):
        self.write_json(self.result_path, self.integration_result())
        events = self.result_path.parent / "out/protocol_mutations.jsonl"
        events.parent.mkdir()
        events.write_text('{"event":"mutation"}\n{"event":', encoding="utf-8")
        result = AUDIT.audit_result(self.root, self.result_path)
        self.assertEqual(result["evidence_state"], "invalid")
        self.assertEqual(result["acceptance"], "unverified")
        self.assertIn("line 2:", result["event_error"])
        self.assertFalse(result["event_count_complete"])
        self.assertEqual(result["event_source"], "invalid_jsonl")
        self.assertIsNone(result["mutation_event_count"])
        self.assertEqual(result["partial_event_counts"], {"mutation": 1})
        self.assertEqual(result["counter_consistency"], "unverified")

    def test_matching_hash_only_certifies_listed_runtime_sources(self):
        self.runtime_result()
        result = AUDIT.audit_runtime(self.root, self.runtime_path)
        self.assertEqual(result["recorded_outcome"], "passed")
        self.assertEqual(result["acceptance"], "passed")
        self.assertEqual(result["source_provenance"], "listed_sources_match")
        self.assertEqual(result["sources"][0]["status"], "match")
        self.assertIn("does not certify", result["scope_note"])

    def test_changed_source_retains_historical_pass_but_current_unverified(self):
        self.runtime_result()
        (self.root / "sample.c").write_text("changed source\n", encoding="utf-8")
        result = AUDIT.audit_runtime(self.root, self.runtime_path)
        self.assertEqual(result["recorded_outcome"], "passed")
        self.assertEqual(result["acceptance"], "unverified")
        self.assertEqual(result["sources"][0]["status"], "stale")

    def test_source_paths_cannot_escape_workspace(self):
        outside = self.directory / "outside.txt"
        outside.write_text("ordinary external text\n", encoding="utf-8")
        expected = hashlib.sha256(outside.read_bytes()).hexdigest()
        for name in ("../outside.txt", str(outside)):
            with self.subTest(name=name):
                self.write_json(self.runtime_path, {
                    "status": "passed", "failures": [], "source_sha256": {name: expected},
                })
                result = AUDIT.audit_runtime(self.root, self.runtime_path)
                self.assertEqual(result["acceptance"], "unverified")
                self.assertEqual(result["sources"][0]["status"], "invalid_path")
                self.assertNotIn("actual_sha256", result["sources"][0])

    def test_failed_nested_runtime_verdict_overrides_passed_summary(self):
        for key, value in (("loader_cases", [{"passed": False}]),
                           ("dependency_harnesses", [{"status": "failed"}]),
                           ("runtime_harness", {"status": "failed"}),
                           ("session_harness", {"status": "failed"})):
            with self.subTest(key=key):
                data = self.runtime_result()
                data[key] = value
                self.write_json(self.runtime_path, data)
                result = AUDIT.audit_runtime(self.root, self.runtime_path)
                self.assertEqual(result["acceptance"], "failed")
                self.assertTrue(result["nested_failures"])

    def test_malformed_nested_runtime_verdict_is_invalid(self):
        data = self.runtime_result()
        data["loader_cases"] = [{"passed": "true"}]
        self.write_json(self.runtime_path, data)
        result = AUDIT.audit_runtime(self.root, self.runtime_path)
        self.assertEqual(result["evidence_state"], "invalid")
        self.assertEqual(result["acceptance"], "unverified")

    def test_nul_and_circular_source_paths_are_invalid(self):
        (self.root / "loop.c").symlink_to("loop.c")
        for name in ("bad\0name", "loop.c"):
            with self.subTest(name=name):
                self.write_json(self.runtime_path, {
                    "status": "passed", "failures": [], "source_sha256": {name: "a" * 64},
                })
                result = AUDIT.audit_runtime(self.root, self.runtime_path)
                self.assertEqual(result["acceptance"], "unverified")
                self.assertEqual(result["sources"][0]["status"], "invalid_path")

    def test_source_symlink_cannot_escape_workspace(self):
        outside = self.directory / "outside.txt"
        outside.write_text("ordinary external text\n", encoding="utf-8")
        (self.root / "linked.c").symlink_to(outside)
        self.write_json(self.runtime_path, {
            "status": "passed", "failures": [],
            "source_sha256": {"linked.c": hashlib.sha256(outside.read_bytes()).hexdigest()},
        })
        result = AUDIT.audit_runtime(self.root, self.runtime_path)
        self.assertEqual(result["acceptance"], "unverified")
        self.assertEqual(result["sources"][0]["status"], "invalid_path")

    def test_missing_bacnet_modes_cannot_produce_pass(self):
        self.runtime_result()
        for name in AUDIT.TCP_PROFILES:
            path = self.root / "tests/protocol/out/multicodec-tcp-final" / name / "result.json"
            self.write_json(path, self.integration_result())
        legacy = self.root / "tests/protocol/out/multicodec-bacnet-regression/legacy/result.json"
        self.write_json(legacy, self.integration_result())
        result = AUDIT.audit(self.root)
        self.assertEqual(result["acceptance"], "unverified")
        self.assertEqual(set(result["bacnet"]), set(AUDIT.BACNET_MODES))
        for mode in AUDIT.BACNET_MODES:
            if mode != "legacy":
                self.assertEqual(result["bacnet"][mode]["evidence_state"], "missing")
                self.assertEqual(result["bacnet"][mode]["acceptance"], "unverified")

    def test_cli_returns_one_when_any_artifact_records_failure(self):
        self.write_json(self.result_path, self.integration_result(exit_code=-11))
        result = self.cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["acceptance"], "failed")

    def test_cli_returns_two_for_missing_evidence(self):
        result = self.cli()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["acceptance"], "unverified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
