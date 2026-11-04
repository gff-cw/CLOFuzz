"""Reviewed source contracts; no codec, compiler, target or network is invoked."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from check_protocol_descriptions import DescriptionError
from check_reviewed_protocol_descriptions import BASE_FILES, PROFILES, check_catalog, check_source


class ReviewedDescriptionTests(unittest.TestCase):
    def copy_catalog(self, directory):
        root = Path(directory)
        shutil.copytree(ROOT / "protocols/reviewed", root / "protocols/reviewed")
        shutil.copytree(ROOT / "protocols/schema", root / "protocols/schema")
        for name in PROFILES:
            destination = root / "protocols" / name
            destination.mkdir()
            for filename in BASE_FILES:
                shutil.copyfile(ROOT / "protocols" / name / filename, destination / filename)
        return root

    def test_catalog_reports_source_checks_without_runtime_claims(self):
        result = check_catalog()
        self.assertEqual(len(result["profiles"]), 6)
        self.assertFalse(result["native_validator_executed"])
        self.assertFalse(result["runtime_tests_executed"])
        self.assertFalse(result["whole_standard_complete"])
        self.assertEqual(sum(p["generic_messages"] for p in result["profiles"]), 14)
        self.assertGreaterEqual(sum(p["requests"] for p in result["profiles"]), 31)

    def test_edited_source_is_rejected_by_saved_catalog_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_catalog(temporary)
            path = root / "protocols/reviewed/modbus_tcp/README.md"
            path.write_text(path.read_text() + "\nChanged after review.\n")
            with self.assertRaisesRegex(DescriptionError, "catalog is stale"):
                check_catalog(root)

    def test_native_acceptance_claim_cannot_be_added_to_source_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_catalog(temporary)
            path = root / "protocols/reviewed/manifest.json"
            manifest = json.loads(path.read_text())
            manifest["native_validator_executed"] = True
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(DescriptionError, "cannot claim"):
                check_catalog(root)

    def test_duplicate_state_edges_and_missing_constraints_are_rejected(self):
        for change in ("edge", "coverage"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = self.copy_catalog(temporary)
                directory = root / "protocols/reviewed/modbus_tcp"
                if change == "edge":
                    path = directory / "state_transition.yaml"
                    state = yaml.safe_load(path.read_text())
                    state["transitions"].append(dict(state["transitions"][0]))
                    path.write_text(yaml.safe_dump(state))
                    message = "duplicate executable state edge"
                else:
                    path = directory / "constraints.json"
                    constraints = json.loads(path.read_text())
                    missing = yaml.safe_load((directory / "protocol_spec.yaml").read_text())["messages"][0]["id"]
                    constraints["codec_constraints"] = [dict(entry, messages=[mid for mid in entry["messages"] if mid != missing])
                                                       for entry in constraints["codec_constraints"]]
                    constraints["codec_constraints"] = [entry for entry in constraints["codec_constraints"] if entry["messages"]]
                    path.write_text(json.dumps(constraints))
                    message = "does not cover every message"
                with self.assertRaisesRegex(DescriptionError, message):
                    check_source(root, "modbus_tcp")

    def test_bacnet_npdu_fixed_value_must_match_each_actual_example(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_catalog(temporary)
            path = root / "protocols/reviewed/bacnet_ip/protocol_spec.yaml"
            protocol = yaml.safe_load(path.read_text())
            request = next(m for m in protocol["messages"] if m["id"] == "read_property")
            control = next(f for f in request["fields"] if f["locator"] == "npdu.control")
            control.update(default=0, min=0, max=0, values=[0])
            path.write_text(yaml.safe_dump(protocol))
            with self.assertRaisesRegex(DescriptionError, "read_property.npdu_control: example scalar violates bounds"):
                check_source(root, "bacnet_ip")


if __name__ == "__main__":
    unittest.main()
