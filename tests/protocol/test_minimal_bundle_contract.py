"""Source package and generated-corpus contracts; no server is started here."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from init_protocol_spec import instantiate

SOURCE = ROOT / "protocols/templates/minimal_runnable_example"


class MinimalBundleTests(unittest.TestCase):
    def test_static_input_assets_match_declared_examples(self):
        manifest = json.loads((SOURCE / "static_input_manifest.json").read_text())
        self.assertFalse(manifest["native_validation_executed"])
        self.assertFalse(manifest["actual_target_session_verified"])
        for name, digest in manifest["source_sha256"].items():
            self.assertEqual(hashlib.sha256((SOURCE / name).read_bytes()).hexdigest(), digest)
        protocol = yaml.safe_load((SOURCE / "protocol_spec.yaml").read_text())
        request = next(message for message in protocol["messages"] if message["direction"] == "request")
        wire = bytes.fromhex(request["example"])
        record = struct.pack("<I", len(wire)) + wire
        self.assertEqual((SOURCE / "fixtures/requests/read_holding.replay").read_bytes(), record)
        self.assertEqual((SOURCE / "seeds/read_holding.replay").read_bytes(), record)
        self.assertEqual((SOURCE / "seeds/read_twice.replay").read_bytes(), record * 2)
        self.assertIn("trace_message_boundary", (SOURCE / "fixture_server.c").read_text())

    def test_source_directory_generates_complete_current_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "package"
            result = instantiate(None, package, runtime_required=True, source_directory=SOURCE)
            self.assertTrue(result["runtime"])
            for filename in ("protocol_spec.yaml", "state_transition.yaml", "protocol_ir.json",
                             "state_ir.json", "spec_bundle.json", "validation.json",
                             "seed_manifest.json", "template_contract.json", "evidence.yaml", "README.md"):
                self.assertTrue((package / filename).is_file(), filename)
            self.assertTrue((package / "fixtures/requests/read_holding.replay").is_file())
            self.assertTrue((package / "seeds/read_holding.replay").is_file())
            corpus = json.loads((package / "seed_manifest.json").read_text())
            self.assertFalse(corpus["actual_target_session_verified"])


if __name__ == "__main__":
    unittest.main()
