"""Static generic template contracts; no compiler, native helper or target."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from generic_template_catalog import (EXAMPLES, check_catalog, check_package,
                                      instantiate_generic, refresh_package_corpus, schema_check)


class GenericTemplateTests(unittest.TestCase):
    def model(self, base="udp_request_response"):
        return json.loads((ROOT / "protocols/templates/generic_wire_examples" / base / "generic_wire.json").read_text())

    def reject(self, change, base="udp_request_response"):
        model = self.model(base)
        change(model)
        with self.assertRaises(jsonschema.ValidationError):
            schema_check(model)

    def test_complete_catalog_is_source_bound(self):
        result = check_catalog()
        self.assertEqual(len(result["templates"]), 3)
        self.assertFalse(result["native_loader_executed"])
        self.assertFalse(result["targets_executed"])
        self.assertTrue(all(item["seeds"] == 2 for item in result["templates"]))

    def test_strict_keys_types_and_online_scope(self):
        self.reject(lambda m: m.update(guard="ignored?"))
        self.reject(lambda m: m.update(online=False))
        self.reject(lambda m: m.update(version=True))
        self.reject(lambda m: m["limits"].update(max_messages=65))
        self.reject(lambda m: m["limits"].update(max_repeat=65))
        self.reject(lambda m: m["limits"].update(max_bytes=7))
        self.reject(lambda m: m["messages"][0].update(example_hex="AA"))
        self.reject(lambda m: m["messages"][0].update(correlate=[]))
        self.reject(lambda m: m["states"]["transitions"][0].update(guard="true"))

    def test_field_type_and_role_shapes(self):
        def field(model): return model["messages"][0]["grammar"]["fields"][0]
        self.reject(lambda m: field(m).update(width=0))
        self.reject(lambda m: field(m).update(width=9))
        self.reject(lambda m: field(m).update(max=256))
        self.reject(lambda m: field(m).update(length=1))
        self.reject(lambda m: field(m).pop("expected"))
        self.reject(lambda m: field(m).update(derived={"op":"size_of", "target":"$message"}))
        self.reject(lambda m: m["messages"][0]["grammar"]["fields"][-1].update(role="head"))
        self.reject(lambda m: m["messages"][0]["grammar"]["fields"][-1].update(width=1))
        # Wire grammar bounds and online frame bounds are intentionally separate.
        model = self.model(); model["messages"][0]["grammar"]["fields"][-1]["max"] = 1048576
        schema_check(model)
        self.reject(lambda m: m["messages"][0]["grammar"]["fields"][-1].update(max=1048577))

    def test_tcp_branch_and_framing_budget(self):
        self.reject(lambda m: m.update(framing={"kind":"datagram"}), "tcp_request_response")
        self.reject(lambda m: m["framing"].update(width=5), "tcp_request_response")
        self.reject(lambda m: m["framing"].update(offset=65506,width=2), "tcp_request_response")
        self.reject(lambda m: m["framing"].update(add=9223372036854775808), "tcp_request_response")

    def test_lexical_patterns_reject_terminal_line_breaks(self):
        # JSON Schema searches regex patterns; '$' alone can match before a
        # final newline in the Python validator even though C consumes all text.
        for ending in ("\n", "\r\n"):
            with self.subTest(ending=repr(ending)):
                self.reject(lambda m: m["messages"][0]["grammar"]["fields"][0].update(id="magic" + ending))
                self.reject(lambda m: m["messages"][0].update(example_hex="b700050100015566" + ending))
                self.reject(lambda m: m["messages"][0]["grammar"]["fields"][-1].update(
                    role="fixed", expected_hex="5566" + ending))
                self.reject(lambda m: m["messages"][0]["grammar"]["fields"][-1]["length"].update(ref="body_length" + ending))
                self.reject(lambda m: m["messages"][0]["grammar"]["fields"][1]["derived"].update(target="payload" + ending))
                self.reject(lambda m: m["messages"][1]["correlate"][0].update(field="serial" + ending))
                self.reject(lambda m: m["messages"][1]["correlate"][0].update(source="serial" + ending))

    def test_copy_is_atomic_and_custom_identity_is_recorded(self):
        for base in EXAMPLES:
            with self.subTest(base=base), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "new-protocol"
                result = instantiate_generic(base, output, "editable_custom_protocol")
                self.assertEqual(result["protocol_id"], "editable_custom_protocol")
                self.assertEqual(check_package(output)["protocol_id"], "editable_custom_protocol")
                (output / "keep").write_text("preserve")
                with self.assertRaisesRegex(ValueError,"overwrite"):
                    instantiate_generic(base, output)
                self.assertEqual((output / "keep").read_text(), "preserve")

    def test_stale_description_and_replay_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            seed = output / "seeds/pulse.replay"
            seed.write_bytes(seed.read_bytes() + b"x")
            with self.assertRaisesRegex(ValueError,"stale seed"):
                check_package(output)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("tcp_request_response", output)
            path = output / "generic_wire.json"
            model = json.loads(path.read_text()); model["limits"]["max_repeat"] = 3
            path.write_text(json.dumps(model,indent=2)+"\n")
            with self.assertRaisesRegex(ValueError,"stale template"):
                check_package(output)

    def test_schema_cannot_prove_wire_equations(self):
        model = self.model("tcp_request_response")
        model["messages"][0]["grammar"]["fields"][1]["derived"]["add"] = -4
        schema_check(model)  # The native C contract regression covers actual loader checks.

    def test_explicit_refresh_preserves_declared_request_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            path = output / "generic_wire.json"
            model = json.loads(path.read_text()); model["messages"][0]["example_hex"] = "a700050100025566"
            path.write_text(json.dumps(model,indent=2)+"\n")
            with self.assertRaisesRegex(ValueError,"stale template"):
                check_package(output)
            result = refresh_package_corpus(output)
            self.assertEqual(result["seeds"], 2)
            self.assertEqual((output / "seeds/pulse.replay").read_bytes(), b"\x08\0\0\0" + bytes.fromhex(model["messages"][0]["example_hex"]))
            before = (output / "seed_manifest.json").read_bytes()
            model["states"]["initial"] = "not_ready"
            path.write_text(json.dumps(model,indent=2)+"\n")
            with self.assertRaisesRegex(ValueError,"unique request transition"):
                refresh_package_corpus(output)
            self.assertEqual((output / "seed_manifest.json").read_bytes(), before)

    def test_every_seed_entry_is_checked_before_refresh(self):
        for extra in ("stray.raw", ".hidden.replay", "subdirectory"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "package"
                instantiate_generic("udp_oneway", output)
                stray = output / "seeds" / extra
                if extra == "subdirectory": stray.mkdir()
                else: stray.write_bytes(b"unexpected fuzzer input")
                before = (output / "seed_manifest.json").read_bytes()
                with self.assertRaises(ValueError): check_package(output)
                with self.assertRaises(ValueError): refresh_package_corpus(output)
                self.assertTrue(stray.exists())
                self.assertEqual((output / "seed_manifest.json").read_bytes(), before)

    def test_response_alternatives_refresh_preserves_request_only_seeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_request_response", output)
            seeds = {p.name: p.read_bytes() for p in (output / "seeds").iterdir()}
            path = output / "generic_wire.json"
            model = json.loads(path.read_text())
            alternate = copy.deepcopy(model["messages"][1])
            alternate["id"] = "alternate_answer"
            alternate["grammar"]["fields"][2].update(min=130, max=130, expected=130)
            alternate["example_hex"] = "b700058200015566"
            model["messages"].append(alternate)
            edge = model["states"]["transitions"][0]
            edge["responses"] = [edge.pop("response"), alternate["id"]]
            path.write_text(json.dumps(model, indent=2) + "\n")
            refresh_package_corpus(output)
            self.assertEqual(check_package(output)["fixtures"], 3)
            self.assertEqual({p.name: p.read_bytes() for p in (output / "seeds").iterdir()}, seeds)
            self.assertEqual((output / "fixtures/responses/alternate_answer.wire").read_bytes(),
                             bytes.fromhex(alternate["example_hex"]))

    def test_invalid_response_alternative_refuses_refresh_before_writes(self):
        for invalid in ("missing_answer", "query"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "package"
                instantiate_generic("udp_request_response", output)
                path = output / "generic_wire.json"
                model = json.loads(path.read_text())
                # Keep the valid managed path unchanged: even an unvisited
                # edge must not hide a bad alternative from static authoring.
                edge = copy.deepcopy(model["states"]["transitions"][0])
                edge["from"] = "unvisited"
                edge["responses"] = [edge.pop("response"), invalid]
                model["states"]["transitions"].append(edge)
                path.write_text(json.dumps(model, indent=2) + "\n")
                before = {p.relative_to(output): p.read_bytes()
                          for p in output.rglob("*") if p.is_file()}
                with self.assertRaisesRegex(ValueError, "missing response model"):
                    refresh_package_corpus(output)
                self.assertEqual({p.relative_to(output): p.read_bytes()
                                  for p in output.rglob("*") if p.is_file()}, before)

    def test_symlinks_and_oversized_artifacts_are_not_accepted(self):
        for relative in ("seeds/pulse.replay", "fixtures/requests/pulse.wire"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "package"
                instantiate_generic("udp_oneway", output)
                target = Path(temporary) / "external"
                target.write_bytes((output / relative).read_bytes())
                (output / relative).unlink()
                (output / relative).symlink_to(target)
                before = target.read_bytes()
                with self.assertRaises(ValueError): check_package(output)
                with self.assertRaises(ValueError): refresh_package_corpus(output)
                self.assertEqual(target.read_bytes(), before)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            (output / "fixtures/requests/pulse.wire").write_bytes(b"x" * 65508)
            with self.assertRaises(ValueError): check_package(output)
            with self.assertRaises(ValueError): refresh_package_corpus(output)

    def test_fixture_directory_symlink_and_seed_fifo_are_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            original = output / "fixtures/requests"
            external = Path(temporary) / "external-requests"
            original.rename(external)
            original.symlink_to(external, target_is_directory=True)
            with self.assertRaises(ValueError): check_package(output)
            with self.assertRaises(ValueError): refresh_package_corpus(output)
            self.assertTrue((external / "pulse.wire").is_file())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            seed = output / "seeds/pulse.replay"
            seed.unlink(); os.mkfifo(seed)
            with self.assertRaises(ValueError): check_package(output)
            with self.assertRaises(ValueError): refresh_package_corpus(output)

    def test_manifest_needs_nonempty_paths_and_canonical_relative_names(self):
        for seeds in ({}, {"seeds/../escaped.replay": {"request_ids":["pulse"]}},
                      {"seeds//pulse.replay": {"request_ids":["pulse"]}}):
            with self.subTest(seeds=seeds), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "package"
                instantiate_generic("udp_oneway", output)
                path = output / "seed_manifest.json"
                manifest = json.loads(path.read_text()); manifest["seeds"] = seeds
                path.write_text(json.dumps(manifest,indent=2)+"\n")
                before = path.read_bytes()
                with self.assertRaises(ValueError): check_package(output)
                with self.assertRaises(ValueError): refresh_package_corpus(output)
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse((output / "escaped.replay").exists())

    def test_manifest_boolean_flags_remain_typed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "package"
            instantiate_generic("udp_oneway", output)
            path = output / "seed_manifest.json"
            manifest = json.loads(path.read_text()); manifest["actual_target_session_verified"] = 0
            path.write_text(json.dumps(manifest,indent=2)+"\n")
            with self.assertRaisesRegex(ValueError,"stale template"):
                check_package(output)


if __name__ == "__main__":
    unittest.main()
