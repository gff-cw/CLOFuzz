#!/usr/bin/env python3
"""Pure file/model corpus contracts; no compiler, native helper or network."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from protocol_seed_planner import MAX_FILE, plan_model_corpus, refresh_saved_model_corpus, write_model_corpus


def model():
    messages = [dict(id=mid, direction=direction, example=example,
                     fixture_status="complete", notes="")
                for mid, direction, example in
                (("greeting", "request", "10"), ("ack", "response", "11"),
                 ("open", "request", "20"), ("opened", "response", "21"),
                 ("work", "request", "30"), ("result", "response", "31"))]
    protocol = dict(protocol_id="fictional", messages=messages, support=dict(runtime=True, excluded=[]))
    state = dict(protocol_id="fictional", initial="cold", states=[dict(id=mid) for mid in ("cold", "greeted", "ready", "opening", "live")],
        transitions=[dict(zip(("from", "to", "message", "response"), row)) for row in
                     (("cold", "greeted", "greeting", "ack"), ("greeted", "ready", "ack", ""),
                      ("ready", "opening", "open", "opened"), ("opening", "live", "opened", ""),
                      ("live", "live", "work", "result"), ("live", "live", "result", ""))],
        limits=dict(max_messages=8, max_repeat=4, max_bytes=MAX_FILE))
    validation = dict(protocol="fictional", validated=True, runtime=True, message_aliases={})
    return protocol, state, validation


class SeedPlannerTests(unittest.TestCase):
    def test_complete_prefix_and_no_fabricated_response_records(self):
        p, s, v = model()
        manifest, fixtures, seeds = plan_model_corpus(p, s, v)
        entry = manifest["requests"]["work"]
        self.assertEqual(entry["request_ids"], ["greeting", "open", "work"])
        self.assertEqual(entry["model_states"], ["cold", "ready", "live", "live"])
        self.assertEqual(entry["serialized_bytes"], 15)
        self.assertEqual(seeds["work.replay"], b"\x01\0\0\0\x10\x01\0\0\0\x20\x01\0\0\0\x30")
        self.assertEqual(fixtures["work.replay"], b"\x01\0\0\0\x30")
        self.assertFalse(manifest["actual_target_session_verified"])
        self.assertFalse(manifest["responses_written_to_seeds"])

    def test_missing_response_edge_withholds_affected_paths(self):
        p, s, v = model()
        s["transitions"] = [edge for edge in s["transitions"] if edge["message"] != "ack"]
        manifest, fixtures, seeds = plan_model_corpus(p, s, v)
        self.assertEqual(seeds, {})
        self.assertEqual(len(fixtures), 3)
        self.assertIn("missing_expected_response_edge", manifest["requests"]["greeting"]["observed_blockers"])

    def test_projection_follows_only_the_declared_one_response(self):
        p, s, v = model()
        # An unrelated unsolicited response cannot stand in for a request prefix.
        s["transitions"].append({"from": "cold", "to": "live", "message": "result", "response": ""})
        manifest, _, _ = plan_model_corpus(p, s, v)
        self.assertEqual(manifest["requests"]["work"]["request_ids"], ["greeting", "open", "work"])

    def test_limits_count_the_entire_prefix_and_record_headers(self):
        for limit, value, blocker in (("max_messages", 2, "max_messages"), ("max_bytes", 14, "max_bytes_including_le32")):
            with self.subTest(limit=limit):
                p, s, v = model()
                s["limits"][limit] = value
                manifest, _, seeds = plan_model_corpus(p, s, v)
                self.assertNotIn("work.replay", seeds)
                self.assertIn(blocker, manifest["requests"]["work"]["observed_blockers"])
        p, s, v = model()
        s["limits"]["max_bytes"] = MAX_FILE + 1
        with self.assertRaisesRegex(ValueError, "runtime capacity"):
            plan_model_corpus(p, s, v)

    def test_fragment_static_only_and_incomplete_response_are_fixtures(self):
        p, s, v = model()
        p["messages"][0]["fixture_status"] = "fragment"
        manifest, fixtures, seeds = plan_model_corpus(p, s, v)
        self.assertIn("greeting.replay", fixtures)
        self.assertNotIn("greeting.replay", seeds)
        self.assertEqual(manifest["requests"]["greeting"]["reason"], "fragment_fixture")
        p, s, v = model()
        p["support"]["runtime"] = False
        self.assertEqual(plan_model_corpus(p, s, v)[2], {})
        p, s, v = model()
        p["messages"][1]["fixture_status"] = "fragment"
        manifest, _, seeds = plan_model_corpus(p, s, v)
        self.assertEqual(seeds, {})
        self.assertIn("expected_response_not_complete_parseable_model",
                      manifest["requests"]["greeting"]["observed_blockers"])

    def test_aliases_share_repeat_budget_and_require_equivalent_edges(self):
        p, s, v = model()
        alias = copy.deepcopy(p["messages"][0])
        alias["id"] = "salutation"
        p["messages"].append(alias)
        s["transitions"].append(dict(s["transitions"][0], message="salutation"))
        v["message_aliases"] = {"salutation": "greeting"}
        manifest, _, _ = plan_model_corpus(p, s, v)
        self.assertEqual(manifest["requests"]["salutation"]["canonical_repeats"], {"greeting": 1})
        s["transitions"][-1]["to"] = "live"
        with self.assertRaisesRegex(ValueError, "ambiguous canonical transition"):
            plan_model_corpus(p, s, v)

    def test_cycles_cannot_bypass_canonical_repeat_limit(self):
        p, s, v = model()
        # Reusing greeting is required to progress from ready to live.
        s["transitions"] = [edge for edge in s["transitions"] if edge["message"] not in {"open", "opened"}]
        s["transitions"].append({"from": "ready", "to": "live", "message": "greeting", "response": ""})
        s["limits"]["max_repeat"] = 1
        manifest, _, seeds = plan_model_corpus(p, s, v)
        self.assertNotIn("work.replay", seeds)
        s["limits"]["max_repeat"] = 2
        manifest, _, seeds = plan_model_corpus(p, s, v)
        self.assertEqual(manifest["requests"]["work"]["request_ids"], ["greeting", "greeting", "work"])

    def test_search_cap_never_claims_an_unproven_path(self):
        p, s, v = model()
        manifest, _, seeds = plan_model_corpus(p, s, v, max_search_nodes=1)
        self.assertEqual(set(seeds), {"greeting.replay"})
        self.assertEqual(manifest["requests"]["work"]["reason"], "search_budget_exhausted")
        self.assertTrue(manifest["search"]["budget_exhausted"])
        self.assertLessEqual(manifest["search"]["scheduled_nodes"], 1)

    def test_writer_keeps_fixtures_separate_and_removes_stale_seeds(self):
        p, s, v = model()
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "seeds").mkdir()
            (directory / "seeds/stale.replay").write_bytes(b"stale")
            manifest = write_model_corpus(directory, p, s, v)
            self.assertFalse((directory / "seeds/stale.replay").exists())
            self.assertEqual((directory / "fixtures/requests/work.replay").read_bytes(), b"\x01\0\0\0\x30")
            self.assertEqual(json.loads((directory / "seed_manifest.json").read_text()), manifest)

    def test_saved_refresh_rejects_uncompiled_edits_before_writing(self):
        source = ROOT / "protocols/bacnet_ip"
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for name in ("protocol_spec.yaml", "state_transition.yaml", "protocol_ir.json",
                         "state_ir.json", "spec_bundle.json", "validation.json"):
                (directory / name).write_bytes((source / name).read_bytes())
            p = yaml.safe_load((directory / "protocol_spec.yaml").read_text())
            p["scope"] += "; uncompiled edit"
            (directory / "protocol_spec.yaml").write_text(yaml.safe_dump(p))
            with self.assertRaisesRegex(ValueError, "recompile"):
                refresh_saved_model_corpus(directory)
            self.assertFalse((directory / "seeds").exists())
            self.assertFalse((directory / "seed_manifest.json").exists())

    def test_standard_profile_prefixes_without_invoking_compiler(self):
        cases = {"bacnet_ip": ("read_property", ["read_property"]),
                 "modbus_tcp": ("read_holding", ["read_holding"]),
                 "iec60870_5_104": ("interrogation", ["start_act", "interrogation"]),
                 "iec61850_mms_tcp": ("read", ["cotp_cr", "associate", "read"]),
                 "ethernet_ip_cip_tcp": ("send_rr", ["register", "send_rr"]),
                 "opcua_tcp": ("message", ["hello", "open_channel", "message"])}
        for name, (target, expected) in cases.items():
            with self.subTest(profile=name):
                directory = ROOT / "protocols" / name
                p = yaml.safe_load((directory / "protocol_spec.yaml").read_text())
                s = yaml.safe_load((directory / "state_transition.yaml").read_text())
                v = json.loads((directory / "validation.json").read_text())
                manifest, fixtures, seeds = plan_model_corpus(p, s, v, validation_source="stored snapshot; not re-executed")
                self.assertEqual(manifest["requests"][target]["request_ids"], expected)
                self.assertEqual(seeds[target + ".replay"], b"".join(fixtures[mid + ".replay"] for mid in expected))

    def test_minimal_example_is_one_register_without_narrowing_full_profile(self):
        directory = ROOT / "protocols/templates/minimal_runnable_example"
        minimal = yaml.safe_load((directory / "protocol_spec.yaml").read_text())
        request = next(message for message in minimal["messages"] if message["id"] == "read_holding")
        quantity = next(field for field in request["fields"] if field["id"] == "quantity")
        self.assertEqual((quantity["role"], quantity["mutability"], quantity["min"], quantity["max"]),
                         ("fixed", "fixed", 1, 1))
        response = next(message for message in minimal["messages"] if message["id"] == "read_response")
        data = next(field for field in response["fields"] if field["id"] == "data")
        self.assertEqual((data["min"], data["max"]), (2, 2))
        full = yaml.safe_load((ROOT / "protocols/modbus_tcp/protocol_spec.yaml").read_text())
        request = next(message for message in full["messages"] if message["id"] == "read_holding")
        self.assertGreater(next(field for field in request["fields"] if field["id"] == "quantity")["max"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
