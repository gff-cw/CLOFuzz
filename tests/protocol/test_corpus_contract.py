#!/usr/bin/env python3
"""Production corpus gate contracts; compiler calls are mocked, never a target.

These sources are not executed by the current compile/static review. When run
later, file/model checks use the real planner and real read-only gate; campaign
publication checks inject a compiler result to isolate refusal side effects.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from protocol_corpus_contract import CorpusContractError, check_input_corpus, check_model_corpus
from protocol_seed_planner import write_model_corpus
import run_protocol_campaign as campaign
from proto_spec_compiler import SpecError


def model():
    protocol = dict(protocol_id="fixture", support=dict(runtime=True, excluded=[]),
                    messages=[dict(id="request", direction="request", example="10", fixture_status="complete"),
                              dict(id="response", direction="response", example="11", fixture_status="complete")])
    state = dict(protocol_id="fixture", initial="ready", states=[dict(id="ready")],
                 limits=dict(max_messages=4, max_repeat=4, max_bytes=128))
    state["transitions"] = [dict(zip(("from", "to", "message", "response"), values)) for values in
                            (("ready", "ready", "request", "response"),
                             ("ready", "ready", "response", ""))]
    validation = dict(protocol="fixture", validated=True, runtime=True, message_aliases={},
                      messages=2, fields=0, semantic_states=1,
                      execution_contract=dict(scope="compiler-result-fixture"))
    return protocol, state, validation


class CorpusContractTests(unittest.TestCase):
    def package(self, parent):
        directory = Path(parent) / "package"
        directory.mkdir()
        protocol, state, validation = model()
        (directory / "protocol_spec.yaml").write_text(yaml.safe_dump(protocol), encoding="utf-8")
        (directory / "state_transition.yaml").write_text(yaml.safe_dump(state), encoding="utf-8")
        (directory / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
        write_model_corpus(directory, protocol, state, validation)
        for name in campaign.COMPILED_FILES[:-1]:
            (directory / name).write_text(json.dumps(dict(previous=name)), encoding="utf-8")
        return directory, protocol, state, validation

    def files(self, directory):
        return {str(path.relative_to(directory)): path.read_bytes()
                for path in directory.rglob("*") if path.is_file()}

    def compiler(self, validation):
        def compile_fixture(protocol, state, destination):
            destination = Path(destination)
            destination.mkdir(parents=True, exist_ok=True)
            for name in campaign.COMPILED_FILES[:-1]:
                (destination / name).write_text(json.dumps(dict(compiled=name)), encoding="utf-8")
            (destination / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
            return copy.deepcopy(validation)
        return compile_fixture

    def test_managed_inventory_is_current_and_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            before = self.files(directory)
            checked = check_model_corpus(directory, protocol, state, validation)
            self.assertEqual(checked["status"], "current")
            self.assertTrue(checked["model_binding_verified"])
            self.assertFalse(checked["actual_target_session_verified"])
            self.assertEqual(checked["seeds"], 1)
            self.assertEqual(before, self.files(directory))

    def test_provenance_text_may_differ_but_proof_may_not(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            path = directory / "seed_manifest.json"
            manifest = json.loads(path.read_text())
            manifest["validation_source"] = "saved compiler snapshot; no new target observation"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            check_model_corpus(directory, protocol, state, validation)
            manifest["actual_target_session_verified"] = True
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(CorpusContractError, "stale"):
                check_model_corpus(directory, protocol, state, validation)

    def test_changed_model_compiler_result_and_bytes_are_rejected(self):
        for change in ("model", "validation", "fixture", "seed", "extra"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                directory, protocol, state, validation = self.package(folder)
                if change == "model":
                    protocol["messages"][0]["example"] = "20"
                elif change == "validation":
                    validation["execution_contract"]["scope"] = "new compiler contract"
                elif change == "fixture":
                    (directory / "fixtures/requests/request.replay").write_bytes(b"\x01\0\0\0\x20")
                elif change == "seed":
                    (directory / "seeds/request.replay").write_bytes(b"\x01\0\0")
                else:
                    (directory / "seeds/extra.raw").write_bytes(b"\x01\0\0\0\x10")
                before = self.files(directory)
                with self.assertRaisesRegex(CorpusContractError, "stale"):
                    check_model_corpus(directory, protocol, state, validation)
                self.assertEqual(before, self.files(directory))

    def test_missing_and_duplicate_manifest_keys_are_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as folder:
                directory, protocol, state, validation = self.package(folder)
                path = directory / "seed_manifest.json"
                if duplicate:
                    path.write_text('{"format":"first","format":"second"}', encoding="utf-8")
                else:
                    path.unlink()
                with self.assertRaisesRegex(CorpusContractError, "stale"):
                    check_model_corpus(directory, protocol, state, validation)

    def test_custom_input_has_separate_scope_and_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            managed = check_model_corpus(directory, protocol, state, validation)
            external = Path(folder) / "custom"
            external.mkdir()
            path = external / "deliberately-different.replay"
            data = b"\x01\0\0\0\x99"
            path.write_bytes(data)
            checked = check_input_corpus(str(external), directory, state, managed)
            self.assertEqual(checked["scope"], "external_unmanaged")
            self.assertFalse(checked["model_binding_verified"])
            self.assertEqual(checked["semantic_and_per_model_repeat_validation"], "not_verified_by_preparation")
            self.assertEqual(path.read_bytes(), data)
            path.write_bytes(data[:-1])
            with self.assertRaisesRegex(CorpusContractError, "record length"):
                check_input_corpus(str(external), directory, state, managed)

    def test_raw_queue_requires_matching_authoritative_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            managed = check_model_corpus(directory, protocol, state, validation)
            output = Path(folder) / "old-output"
            raw = output / "queue"
            snapshots = raw / ".state/replay"
            snapshots.mkdir(parents=True)
            (raw / "id:000000").write_bytes(b"\x10")
            (snapshots / "id:000000").write_bytes(b"\x01\0\0\0\x10")
            checked = check_input_corpus(str(output), directory, state, managed)
            self.assertEqual(checked["files_checked"], 1)
            (raw / "id:000000").write_bytes(b"\x20")
            with self.assertRaisesRegex(CorpusContractError, "differs"):
                check_input_corpus(str(raw), directory, state, managed)
            resume = check_input_corpus("-", directory, state, managed)
            self.assertEqual(resume["status"], "deferred_to_host")
            self.assertFalse(resume["model_binding_verified"])

    def test_invalid_raw_queue_markers_cannot_fall_back_to_custom_input(self):
        for marker in ("queue", ".state"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as folder:
                directory, protocol, state, validation = self.package(folder)
                managed = check_model_corpus(directory, protocol, state, validation)
                external = Path(folder) / "custom"
                external.mkdir()
                (external / "valid.replay").write_bytes(b"\x01\0\0\0\x10")
                (external / marker).write_text("not a directory", encoding="utf-8")
                with self.assertRaisesRegex(CorpusContractError, "marker must be a directory"):
                    check_input_corpus(str(external), directory, state, managed)

    def test_raw_snapshot_inventory_rejects_unexpected_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            managed = check_model_corpus(directory, protocol, state, validation)
            raw = Path(folder) / "queue"
            snapshots = raw / ".state/replay"
            snapshots.mkdir(parents=True)
            (raw / "id:000000").write_bytes(b"\x10")
            (snapshots / "id:000000").write_bytes(b"\x01\0\0\0\x10")
            (snapshots / "unexpected").mkdir()
            with self.assertRaisesRegex(CorpusContractError, "unexpected authoritative"):
                check_input_corpus(str(raw), directory, state, managed)

    def test_source_edits_during_compilation_do_not_publish_ir(self):
        for validate_only in (False, True):
            with self.subTest(validate_only=validate_only), tempfile.TemporaryDirectory() as folder:
                directory, protocol, state, validation = self.package(folder)
                before = {name: (directory / name).read_bytes() for name in campaign.COMPILED_FILES}
                compile_fixture = self.compiler(validation)

                def edit_during_compile(protocol, state, destination):
                    result = compile_fixture(protocol, state, destination)
                    source = directory / "protocol_spec.yaml"
                    source.write_text(source.read_text() + "\n# concurrent edit\n", encoding="utf-8")
                    return result

                with mock.patch.object(campaign, "validate"), \
                     mock.patch.object(campaign, "compile_spec", side_effect=edit_during_compile):
                    with self.assertRaisesRegex(SpecError, "source YAML changed during preparation"):
                        campaign.prepare(directory, ["-i", str(directory / "seeds"), "--", "target"],
                                         sys.executable, validate_only=validate_only)
                self.assertEqual(before, {name: (directory / name).read_bytes()
                                          for name in campaign.COMPILED_FILES})
                self.assertFalse(list(directory.glob(".campaign-check-*")))

    def test_stale_edit_does_not_publish_any_compiled_file(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            protocol["messages"][0]["example"] = "20"
            (directory / "protocol_spec.yaml").write_text(yaml.safe_dump(protocol), encoding="utf-8")
            before = self.files(directory)
            with mock.patch.object(campaign, "validate"), \
                 mock.patch.object(campaign, "compile_spec", side_effect=self.compiler(validation)):
                with self.assertRaisesRegex(SpecError, "managed corpus is stale"):
                    campaign.prepare(directory, ["-i", str(directory / "seeds"), "--", "target"], sys.executable)
            self.assertEqual(before, self.files(directory))
            self.assertFalse(list(directory.glob(".campaign-check-*")))

    def test_current_corpus_publishes_only_after_selected_input_check(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            before = self.files(directory)
            with mock.patch.object(campaign, "validate"), \
                 mock.patch.object(campaign, "compile_spec", side_effect=self.compiler(validation)):
                with self.assertRaisesRegex(SpecError, "does not exist"):
                    campaign.prepare(directory, ["-i", str(Path(folder) / "missing"), "--", "target"], sys.executable)
                self.assertEqual(before, self.files(directory))
                result, command = campaign.prepare(directory, ["-i", str(directory / "seeds"), "--", "target"], sys.executable)
            self.assertTrue(result["preparation"]["selected_input"]["model_binding_verified"])
            self.assertEqual(command[-2:], ["--", "target"])
            self.assertIn("compiled", json.loads((directory / "protocol_ir.json").read_text()))

    def test_validate_only_makes_no_corpus_or_selected_input_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            (directory / "seed_manifest.json").unlink()
            with mock.patch.object(campaign, "validate"), \
                 mock.patch.object(campaign, "compile_spec", side_effect=self.compiler(validation)), \
                 mock.patch.object(campaign, "check_model_corpus") as corpus_check:
                result, command = campaign.prepare(directory, [], validate_only=True)
            corpus_check.assert_not_called()
            self.assertIsNone(command)
            self.assertEqual(result["preparation"]["scope"], "model_only")

    def test_print_command_checks_the_input_and_never_executes(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, protocol, state, validation = self.package(folder)
            arguments = ["run_protocol_campaign.py", "--spec-dir", str(directory),
                         "--afl-fuzz", sys.executable, "--print-command", "--",
                         "-i", str(directory / "seeds"), "--", "target", "--generic-spec"]
            output = io.StringIO()
            with mock.patch.object(sys, "argv", arguments), \
                 mock.patch.object(campaign, "validate"), \
                 mock.patch.object(campaign, "compile_spec", side_effect=self.compiler(validation)), \
                 mock.patch.object(campaign.os, "execv") as execute, contextlib.redirect_stdout(output):
                self.assertEqual(campaign.main(), 0)
            execute.assert_not_called()
            self.assertTrue(json.loads(output.getvalue())["validation"]["preparation"]["selected_input"]["model_binding_verified"])


if __name__ == "__main__":
    unittest.main()
