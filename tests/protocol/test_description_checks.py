#!/usr/bin/env python3
"""Check description metadata using temporary copies, without native code or targets."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "description_checks", ROOT / "tools/check_protocol_descriptions.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DescriptionCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.package = Path(temporary.name) / "modbus"
        self.package.mkdir()
        for name in ("protocol_spec.yaml", "state_transition.yaml", "evidence.yaml", "validation.json"):
            shutil.copyfile(ROOT / "protocols/modbus_tcp" / name, self.package / name)

    def read(self, name):
        return CHECK.read_document(self.package / name)[0]

    def write(self, name, document):
        text = (json.dumps(document) if name.endswith(".json")
                else CHECK.yaml.safe_dump(document, sort_keys=False))
        (self.package / name).write_text(text, encoding="utf-8")

    def edit(self, name, change):
        document = self.read(name)
        change(document)
        self.write(name, document)

    def save_validation(self, validation):
        self.write("validation.json", validation)
        evidence = self.read("evidence.yaml")
        evidence["validation"] = copy.deepcopy(validation)
        self.write("evidence.yaml", evidence)

    def source_hashes(self):
        return {name: hashlib.sha256((self.package / name).read_bytes()).hexdigest()
                for name in ("protocol_spec.yaml", "state_transition.yaml")}

    def assert_failed(self, fragment=None):
        report = CHECK.check_package(self.package)
        self.assertEqual(report["status"], "failed", report)
        self.assertTrue(report.get("error"), report)
        if fragment:
            self.assertIn(fragment, report["error"])
        return report

    def test_existing_package_passes_static_checks(self):
        report = CHECK.check_package(self.package)
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(report["protocol_id"], "modbus_tcp")
        self.assertEqual(set(report["input_sha256"]), {
            "protocol_spec.yaml", "state_transition.yaml", "evidence.yaml", "validation.json"})
        self.assertGreater(report["messages"], 0)
        self.assertGreater(report["fields"], 0)

    def test_missing_file_is_a_failed_package(self):
        (self.package / "evidence.yaml").unlink()
        self.assert_failed("evidence.yaml")

    def test_read_document_requests_only_the_bounded_byte_range(self):
        self.assertEqual(CHECK.MAX_DESCRIPTION_BYTES, 1 << 20)
        raw = b"key: value\n"
        path = self.package / "bounded.yaml"
        with mock.patch.object(Path, "open") as opened:
            stream = opened.return_value.__enter__.return_value
            stream.read.return_value = raw
            document, digest = CHECK.read_document(path)
            opened.assert_called_once_with("rb")
            stream.read.assert_called_once_with(CHECK.MAX_DESCRIPTION_BYTES + 1)
            opened.return_value.__exit__.assert_called_once()
        self.assertEqual(document, {"key": "value"})
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_read_document_accepts_exactly_the_byte_limit(self):
        prefix = b"key: value\n"
        raw = prefix + b" " * (CHECK.MAX_DESCRIPTION_BYTES - len(prefix))
        path = self.package / "bounded.yaml"
        path.write_bytes(raw)
        document, digest = CHECK.read_document(path)
        self.assertEqual(document, {"key": "value"})
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_oversized_document_is_rejected_before_yaml_parsing(self):
        path = self.package / "bounded.yaml"
        path.write_bytes(b" " * (CHECK.MAX_DESCRIPTION_BYTES + 1))
        with mock.patch.object(CHECK.yaml, "load") as load:
            with self.assertRaisesRegex(CHECK.DescriptionError, "exceeds 1 MiB"):
                CHECK.read_document(path)
            load.assert_not_called()

    def test_invalid_utf8_is_a_failed_package(self):
        (self.package / "evidence.yaml").write_bytes(b"key: \xff\n")
        self.assert_failed()

    def test_non_json_scalar_types_are_rejected(self):
        path = self.package / "bounded.yaml"
        for text in ("key: 1.5\n", "key: 2026-10-27\n"):
            with self.subTest(text=text):
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(CHECK.DescriptionError, "JSON-compatible"):
                    CHECK.read_document(path)

    def test_duplicate_yaml_key_is_rejected(self):
        path = self.package / "protocol_spec.yaml"
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\nprotocol_id: duplicate\n")
        self.assert_failed("duplicate")

    def test_missing_field_sources_is_rejected(self):
        self.edit("evidence.yaml", lambda document: document.pop("field_sources"))
        self.assert_failed("field_sources")

    def test_incomplete_field_source_coverage_is_rejected(self):
        self.edit("evidence.yaml", lambda document: document["field_sources"].pop())
        self.assert_failed("field_sources")

    def test_duplicate_field_source_is_rejected(self):
        self.edit("evidence.yaml", lambda document: document["field_sources"].append(
            copy.deepcopy(document["field_sources"][0])))
        self.assert_failed("duplicate field source")

    def test_wrong_field_source_is_rejected(self):
        def change(document):
            document["field_sources"][0]["source"] = "unknown_source"
        self.edit("evidence.yaml", change)
        self.assert_failed("field_sources")

    def test_extra_field_source_is_rejected(self):
        def change(document):
            entry = copy.deepcopy(document["field_sources"][0])
            entry["field"] = "undeclared_field"
            document["field_sources"].append(entry)
        self.edit("evidence.yaml", change)
        self.assert_failed("field_sources")

    def test_evidence_source_definition_must_match(self):
        def change(document):
            document["sources"][0]["sections"] = "different source sections"
        self.edit("evidence.yaml", change)
        self.assert_failed("source definitions")

    def test_state_protocol_id_must_match(self):
        def change(document):
            document["protocol_id"] = "different_profile"
        self.edit("state_transition.yaml", change)
        self.assert_failed("ID mismatch")

    def test_unknown_transition_message_is_rejected(self):
        def change(document):
            document["transitions"][0]["message"] = "unknown_message"
        self.edit("state_transition.yaml", change)
        self.assert_failed("unknown transition message")

    def test_unknown_transition_response_is_rejected(self):
        def change(document):
            document["transitions"][0]["response"] = "unknown_response"
        self.edit("state_transition.yaml", change)
        self.assert_failed("unknown transition response")

    def test_unknown_initial_state_is_rejected(self):
        def change(document):
            document["initial"] = "unknown_state"
        self.edit("state_transition.yaml", change)
        self.assert_failed("unknown initial state")

    def test_unknown_transition_state_is_rejected(self):
        def change(document):
            document["transitions"][0]["to"] = "unknown_state"
        self.edit("state_transition.yaml", change)
        self.assert_failed("unknown transition state")

    def test_scope_mismatch_is_rejected(self):
        def change(document):
            document["scope"] = "a different bounded scope"
        self.edit("evidence.yaml", change)
        self.assert_failed("scope mismatch")

    def test_validation_snapshot_must_match_saved_record(self):
        def change(document):
            document["validation"]["messages"] += 1
        self.edit("evidence.yaml", change)
        self.assert_failed("validation snapshot")

    def test_consistent_but_incorrect_validation_counts_are_rejected(self):
        for key in ("messages", "fields", "semantic_states"):
            with self.subTest(key=key):
                validation = self.read("validation.json")
                validation[key] += 1
                self.write("validation.json", validation)
                evidence = self.read("evidence.yaml")
                evidence["validation"] = validation
                self.write("evidence.yaml", evidence)
                self.assert_failed("validation." + key)
                validation[key] -= 1
                self.write("validation.json", validation)
                evidence["validation"] = validation
                self.write("evidence.yaml", evidence)

    def test_fixture_counts_must_match_messages(self):
        def change(document):
            document["fixture_counts"]["complete"] += 1
        self.edit("evidence.yaml", change)
        self.assert_failed("fixture counts")

    def test_boolean_validation_count_is_not_an_integer_count(self):
        validation = self.read("validation.json")
        self.assertEqual(validation["semantic_states"], 1)
        validation["semantic_states"] = True
        self.write("validation.json", validation)
        evidence = self.read("evidence.yaml")
        evidence["validation"] = validation
        self.write("evidence.yaml", evidence)
        self.assert_failed("validation.semantic_states")

    def test_saved_validation_requires_a_true_boolean(self):
        original = self.read("validation.json")
        for value in (False, 1, None, "true"):
            with self.subTest(value=value):
                validation = copy.deepcopy(original)
                validation["validated"] = value
                self.save_validation(validation)
                self.assert_failed("validation.validated")
        validation = copy.deepcopy(original)
        validation.pop("validated")
        self.save_validation(validation)
        self.assert_failed("validation.validated")

    def test_saved_runtime_requires_the_matching_boolean(self):
        original = self.read("validation.json")
        self.assertIs(self.read("protocol_spec.yaml")["support"]["runtime"], True)
        for value in (False, 1, None, "true"):
            with self.subTest(value=value):
                validation = copy.deepcopy(original)
                validation["runtime"] = value
                self.save_validation(validation)
                self.assert_failed("validation.runtime")
        validation = copy.deepcopy(original)
        validation.pop("runtime")
        self.save_validation(validation)
        self.assert_failed("validation.runtime")

    def test_missing_source_hashes_remain_explicitly_unbound(self):
        validation = self.read("validation.json")
        validation.pop("source_sha256", None)
        self.save_validation(validation)
        report = CHECK.check_package(self.package)
        self.assertEqual(report["status"], "passed", report)
        self.assertEqual(report["source_hash_binding"], "absent")
        self.assertTrue(any("hash" in warning.lower() for warning in report["warnings"]))

    def test_matching_source_hashes_are_checked_case_insensitively(self):
        original = self.read("validation.json")
        hashes = self.source_hashes()
        for uppercase in (False, True):
            with self.subTest(uppercase=uppercase):
                validation = copy.deepcopy(original)
                validation["source_sha256"] = {
                    name: digest.upper() if uppercase else digest
                    for name, digest in hashes.items()}
                self.save_validation(validation)
                report = CHECK.check_package(self.package)
                self.assertEqual(report["status"], "passed", report)
                self.assertEqual(report["source_hash_binding"], "matched")
                self.assertFalse(any("does not bind" in warning for warning in report["warnings"]))

    def test_invalid_source_hash_declarations_are_rejected(self):
        original = self.read("validation.json")
        hashes = self.source_hashes()
        invalid = [None, False, [], {},
                   {"protocol_spec.yaml": hashes["protocol_spec.yaml"]},
                   {**hashes, "evidence.yaml": "a" * 64}]
        for value in (True, 1, "", "a" * 63, "g" * 64, " " + "a" * 64):
            invalid.append({**hashes, "protocol_spec.yaml": value})
        for number, declaration in enumerate(invalid):
            with self.subTest(case=number):
                validation = copy.deepcopy(original)
                validation["source_sha256"] = declaration
                self.save_validation(validation)
                report = self.assert_failed("source_sha256")
                self.assertEqual(report["source_hash_binding"], "unchecked")

    def test_stale_hash_is_rejected_when_either_source_changes(self):
        for name in ("protocol_spec.yaml", "state_transition.yaml"):
            with self.subTest(source=name):
                validation = self.read("validation.json")
                validation["source_sha256"] = self.source_hashes()
                self.save_validation(validation)
                path = self.package / name
                original = path.read_bytes()
                try:
                    # A comment changes raw bytes without changing parsed fields.
                    path.write_bytes(original + b"\n# changed source bytes\n")
                    report = self.assert_failed("source_sha256")
                    self.assertEqual(report["source_hash_binding"], "unchecked")
                finally:
                    path.write_bytes(original)

    def test_unsafe_yaml_object_tag_is_rejected(self):
        (self.package / "evidence.yaml").write_text(
            "!!python/object/apply:builtins.str ['unsupported tag']\n", encoding="utf-8")
        self.assert_failed()

    def test_recursive_yaml_alias_is_rejected(self):
        (self.package / "evidence.yaml").write_text("root: &cycle [*cycle]\n", encoding="utf-8")
        self.assert_failed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
