"""File/schema template contracts; this suite never invokes a codec or target."""
import ast
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import re
from unittest import mock

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from protocol_template_contract import (
    TemplateContractError, checked_profile_copy, contract_metadata, load_capability_catalog,
)


def source_pair():
    directory = ROOT / "protocols/modbus_tcp"
    return tuple(yaml.safe_load((directory / name).read_text())
                 for name in ("protocol_spec.yaml", "state_transition.yaml"))


def contracts_in(directory):
    directory = Path(directory)
    templates, schemas = directory / "templates", directory / "schema"
    shutil.copytree(ROOT / "protocols/templates", templates)
    shutil.copytree(ROOT / "protocols/schema", schemas)
    return templates, schemas


class TemplateContractTests(unittest.TestCase):
    def test_all_profiles_preserve_every_concrete_value_and_optional_property(self):
        for source in sorted((ROOT / "protocols").glob("*/protocol_spec.yaml")):
            with self.subTest(profile=source.parent.name):
                pair = tuple(yaml.safe_load((source.parent / name).read_text())
                             for name in ("protocol_spec.yaml", "state_transition.yaml"))
                copied = checked_profile_copy(*pair)
                self.assertEqual(copied, pair)
                copied[0]["messages"][0]["fields"][0]["default"] = "independent copy"
                self.assertNotEqual(copied, pair)

    def test_unknown_nested_key_and_missing_required_key_are_rejected(self):
        protocol, state = source_pair()
        protocol["messages"][0]["fields"][0]["typo_locator"] = "abs:0"
        with self.assertRaisesRegex(TemplateContractError, "unknown keys.*typo_locator"):
            checked_profile_copy(protocol, state)
        protocol, state = source_pair()
        del state["transitions"][0]["message"]
        with self.assertRaisesRegex(TemplateContractError, "missing required keys.*message"):
            checked_profile_copy(protocol, state)

    def test_source_explicit_completeness_contract_is_required(self):
        for key in ("fixture_status", "runtime_encode"):
            protocol, state = source_pair()
            del protocol["messages"][0][key]
            with self.subTest(key=key), self.assertRaisesRegex(TemplateContractError, "require explicit.*" + key):
                checked_profile_copy(protocol, state)

    def test_nested_template_containers_cannot_erase_required_example_structure(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            file = templates / "protocol_spec.template.yaml"
            skeleton = yaml.safe_load(file.read_text())
            skeleton["messages"][0]["fields"] = []
            file.write_text(yaml.safe_dump(skeleton))
            with self.assertRaisesRegex(TemplateContractError, "array size outside structural"):
                checked_profile_copy(*source_pair(), template_directory=templates, schema_directory=schemas)

    def test_duplicate_template_keys_are_rejected_instead_of_overriding_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            file = templates / "protocol_spec.template.yaml"
            file.write_text(file.read_text() + "\ncodec: modbus\n")
            with self.assertRaisesRegex(TemplateContractError, "duplicate template key.*codec"):
                checked_profile_copy(*source_pair(), template_directory=templates, schema_directory=schemas)

    def test_schema_extension_is_preserved_instead_of_silently_projected_away(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            file = schemas / "protocol_spec.schema.json"
            schema = json.loads(file.read_text())
            schema["properties"]["package_note"] = {"type": "string"}
            file.write_text(json.dumps(schema))
            protocol, state = source_pair()
            protocol["package_note"] = "new schema-known property absent from the basic skeleton"
            copied, _ = checked_profile_copy(protocol, state, template_directory=templates,
                                              schema_directory=schemas)
            self.assertEqual(copied["package_note"], protocol["package_note"])

    def test_skeleton_nested_values_are_illustrations_not_silent_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            file = templates / "protocol_spec.template.yaml"
            skeleton = yaml.safe_load(file.read_text())
            skeleton["messages"][0]["fields"][0]["default"] = 42
            skeleton["messages"][0]["fields"][0]["strategies"] = ["enum"]
            file.write_text(yaml.safe_dump(skeleton))
            protocol, state = source_pair()
            copied = checked_profile_copy(protocol, state, template_directory=templates,
                                            schema_directory=schemas)
            self.assertEqual(copied, (protocol, state))
            del skeleton["messages"][0]["fields"][0]["id"]
            file.write_text(yaml.safe_dump(skeleton))
            with self.assertRaisesRegex(TemplateContractError, "template.*missing required keys.*id"):
                checked_profile_copy(protocol, state, template_directory=templates, schema_directory=schemas)

    def test_capability_catalog_rejects_schema_operation_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            file = schemas / "protocol_spec.schema.json"
            schema = json.loads(file.read_text())
            schema["properties"]["messages"]["items"]["properties"]["dependencies"]["items"]["properties"]["op"]["enum"].append("future_operation")
            file.write_text(json.dumps(schema))
            with self.assertRaisesRegex(TemplateContractError, "dependency operations differ"):
                checked_profile_copy(*source_pair(), template_directory=templates, schema_directory=schemas)

    def test_concrete_fragments_reject_invalid_enum_and_scalar_types(self):
        for change in ("enum", "type"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                templates, schemas = contracts_in(directory)
                file = templates / "legacy_contract/advanced_fragments.yaml"
                fragments = yaml.safe_load(file.read_text())
                fragment = next(item for item in fragments["fragments"] if item["id"] == "when")
                fragment["selection"]["type" if change == "enum" else "width"] = "not_a_valid_field_value"
                file.write_text(yaml.safe_dump(fragments))
                with self.assertRaisesRegex(TemplateContractError, "invalid schema component value"):
                    load_capability_catalog(template_directory=templates, schema_directory=schemas)

    def test_source_digest_selection_and_context_drift_are_rejected(self):
        for change, message in (("digest", "stale source profile SHA256"),
                                ("selection", "selection differs"), ("context", "context fields differ")):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                templates, schemas = contracts_in(directory)
                file = templates / "legacy_contract/advanced_fragments.yaml"
                fragments = yaml.safe_load(file.read_text())
                fragment = next(item for item in fragments["fragments"] if item["id"] == "length_of")
                if change == "digest":
                    fragment["source"]["source_sha256"] = "0" * 64
                elif change == "selection":
                    fragment["selection"]["add"] = -5
                else:
                    fragment["context"]["fields"]["read_coils"][0]["default"] = 1
                file.write_text(yaml.safe_dump(fragments))
                with self.assertRaisesRegex(TemplateContractError, message):
                    load_capability_catalog(template_directory=templates, schema_directory=schemas)

    def test_actual_profile_edits_invalidate_saved_fragment_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            templates, schemas = contracts_in(directory)
            source_root = Path(directory) / "source-root"
            source = source_root / "protocols/modbus_tcp/protocol_spec.yaml"
            source.parent.mkdir(parents=True)
            source.write_bytes((ROOT / "protocols/modbus_tcp/protocol_spec.yaml").read_bytes() + b"\n# changed source\n")
            with mock.patch("protocol_template_contract.ROOT", source_root):
                with self.assertRaisesRegex(TemplateContractError, "stale source profile SHA256"):
                    load_capability_catalog(template_directory=templates, schema_directory=schemas)

    def test_capability_versions_classifications_and_message_policy_cannot_silently_drift(self):
        for change in ("version", "classification", "explicit_keys", "codecs", "direction"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                templates, schemas = contracts_in(directory)
                file = templates / "legacy_contract/capabilities.json"
                catalog = json.loads(file.read_text())
                if change == "version":
                    catalog["version"] = True
                elif change == "classification":
                    catalog["dependency_operations"][0]["classification"] = "static_only"
                elif change == "explicit_keys":
                    catalog["explicit_packaging_message_keys"] = ["fixture_status"]
                elif change == "codecs":
                    catalog["supported_codecs"].append("future_codec")
                else:
                    catalog["direction"]["online"].append("both")
                file.write_text(json.dumps(catalog))
                with self.assertRaises(TemplateContractError):
                    load_capability_catalog(template_directory=templates, schema_directory=schemas)

    def test_every_catalog_component_has_valid_schema_shape_and_types(self):
        catalog = load_capability_catalog()
        fragments = yaml.safe_load((ROOT / "protocols/templates/legacy_contract/advanced_fragments.yaml").read_text())
        schemas = {name: json.loads((ROOT / "protocols/schema" / (name + ".schema.json")).read_text())
                   for name in ("protocol_spec", "state_transition")}
        for fragment in fragments["fragments"]:
            with self.subTest(fragment=fragment["id"]):
                schema = schemas[fragment.get("schema_document", "protocol_spec")]
                component = schema
                for part in fragment["schema_pointer"][2:].split("/"):
                    component = component[part]
                component = dict(component, **{"$defs": schema.get("$defs", {})})
                jsonschema.Draft202012Validator(component).validate(fragment["selection"])
        self.assertEqual(len(catalog["dependency_operations"]), 10)
        static = next(op for op in catalog["dependency_operations"] if op["op"] == "conditional_presence")
        self.assertEqual(static["classification"], "static_only")
        tagged = next(op for op in catalog["dependency_operations"] if op["op"] == "tagged_length")
        self.assertEqual(tagged["online_codecs"], ["mms"])

    def test_catalog_tracks_python_and_c_operation_whitelists(self):
        # Read source literals without importing compiler/native helper code.
        tree = ast.parse((ROOT / "tools/proto_spec_compiler.py").read_text())
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in {"OPS", "RUNTIME_OPS", "CODECS"}:
                    constants[name] = ast.literal_eval(node.value)
        catalog = load_capability_catalog()
        operations = {entry["op"] for entry in catalog["dependency_operations"]}
        runtime = {entry["op"] for entry in catalog["dependency_operations"] if entry["classification"] != "static_only"}
        self.assertEqual(operations, constants["OPS"])
        self.assertEqual(runtime, constants["RUNTIME_OPS"])
        self.assertEqual(set(catalog["supported_codecs"]), constants["CODECS"])
        source = (ROOT / "protocol_runtime.c").read_text()
        declaration = re.search(r'static const char \*ops\[\]=\{([^}]+)\}', source)
        self.assertIsNotNone(declaration)
        self.assertEqual(set(re.findall(r'"([a-z_]+)"', declaration.group(1))), operations)

    def test_real_excerpts_stay_tied_to_existing_declared_fields_and_dependencies(self):
        fragments = yaml.safe_load((ROOT / "protocols/templates/legacy_contract/advanced_fragments.yaml").read_text())
        for fragment in fragments["fragments"]:
            source = fragment["source"]
            if source["kind"] != "profile_excerpt":
                self.assertFalse(source["industrial_profile_claim"])
                continue
            with self.subTest(fragment=fragment["id"]):
                profile = yaml.safe_load((ROOT / source["source_file"]).read_text())
                self.assertEqual(hashlib.sha256((ROOT / source["source_file"]).read_bytes()).hexdigest(),
                                 source["source_sha256"])
                message = next(m for m in profile["messages"] if m["id"] == source["message"])
                if fragment["id"] == "repeat":
                    self.assertEqual(fragment["selection"], next(f for f in message["fields"] if f["id"] == source["field"]))
                elif fragment["id"] == "structure_model":
                    self.assertEqual(fragment["selection"], next(f for f in message["fields"] if f["id"] == source["field"])["structure_model"])
                else:
                    self.assertIn(fragment["selection"], message["dependencies"])

    def test_provenance_names_profile_values_and_does_not_claim_runtime_tests(self):
        metadata = contract_metadata()
        self.assertEqual(metadata["version"], 1)
        self.assertFalse(metadata["new_codec_generated"])
        self.assertFalse(metadata["runtime_tests_executed_by_instantiator"])
        self.assertIn("source profile", metadata["concrete_value_authority"])
        for record in metadata["descriptions"].values():
            self.assertEqual(len(record["schema_sha256"]), 64)
            self.assertEqual(len(record["template_sha256"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
