#!/usr/bin/env python3
"""Check description metadata using temporary copies, without native code or targets."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


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

    def test_unsafe_yaml_object_tag_is_rejected(self):
        (self.package / "evidence.yaml").write_text(
            "!!python/object/apply:builtins.str ['unsupported tag']\n", encoding="utf-8")
        self.assert_failed()

    def test_recursive_yaml_alias_is_rejected(self):
        (self.package / "evidence.yaml").write_text("root: &cycle [*cycle]\n", encoding="utf-8")
        self.assert_failed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
