#!/usr/bin/env python3
"""File-only regressions for generic profile validation; no C or target setup."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from check_generic_wire_profiles import (
    MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_WIRE, check, check_correlation_pairs,
    check_example_matches, load, parse_grammar,
)


def scalar_message(identifier, direction, example, low=0, high=255):
    return {
        "id": identifier,
        "direction": direction,
        "example_hex": f"{example:02x}",
        "grammar": {"kind": "struct", "fields": [
            {"id": "value", "kind": "uint", "width": 1, "byte_order": "big",
             "role": "content", "min": low, "max": high},
        ]},
    }


def correlation(request):
    return {"request": request, "field": "value", "source": "value"}


def transition(request, response, state="ready"):
    return {"from": state, "to": state, "message": request, "response": response}


class StrictJSONLoadingTests(unittest.TestCase):
    def load_bytes(self, raw):
        with tempfile.TemporaryDirectory(prefix="generic-json-check-") as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(raw)
            return load(path)

    def test_native_integer_limits_and_negative_zero_are_accepted(self):
        values = self.load_bytes(b'[-9223372036854775808,18446744073709551615,-0]')
        self.assertEqual(values, [-(1 << 63), (1 << 64)-1, 0])

    def test_float_and_non_json_constants_are_rejected_even_in_metadata(self):
        for token in ("0.0", "1e0", "NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, "only integer JSON numbers"):
                    self.load_bytes(('{"metadata":' + token + '}').encode("ascii"))

    def test_out_of_native_range_integers_are_rejected(self):
        for token in (str(-(1 << 63)-1), str(1 << 64), "9" * 10000):
            with self.subTest(length=len(token)):
                with self.assertRaisesRegex(ValueError, "integer"):
                    self.load_bytes(token.encode("ascii"))

    def test_only_utf8_without_bom_is_accepted(self):
        source = '{"metadata":"text"}'
        for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                with self.assertRaises(ValueError):
                    self.load_bytes(source.encode(encoding))

    def test_lone_surrogates_are_rejected_in_values_and_keys(self):
        for source in (b'{"metadata":"\\ud800"}', b'{"\\udfff":0}'):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    self.load_bytes(source)

    def test_valid_surrogate_pair_and_quoted_delimiters_are_accepted(self):
        self.assertEqual(self.load_bytes(b'{"metadata":"\\ud83d\\ude00"}'),
                         {"metadata": "\U0001f600"})
        metadata = '[{"\\' * (MAX_JSON_DEPTH + 10)
        self.assertEqual(self.load_bytes(json.dumps({"metadata": metadata}).encode("utf-8")),
                         {"metadata": metadata})

    def test_duplicate_decoded_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.load_bytes(b'{"a":1,"\\u0061":2}')

    def test_input_byte_budget_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "JSON file exceeds C input budget"):
            self.load_bytes(b" " * (MAX_WIRE + 1))

    def test_root_zero_depth_includes_empty_container_boundary(self):
        empty = self.load_bytes(b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1))
        self.assertIsInstance(empty, list)
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            self.load_bytes(b"[" * (MAX_JSON_DEPTH + 2) + b"]" * (MAX_JSON_DEPTH + 2))
        scalar = b"[" * MAX_JSON_DEPTH + b"0" + b"]" * MAX_JSON_DEPTH
        self.assertIsInstance(self.load_bytes(scalar), list)
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            self.load_bytes(b"[" * (MAX_JSON_DEPTH + 1) + b"0" + b"]" * (MAX_JSON_DEPTH + 1))

    def test_array_node_budget_counts_the_root(self):
        exact = b"[" + b",".join([b"null"] * (MAX_JSON_NODES - 1)) + b"]"
        self.assertEqual(len(self.load_bytes(exact)), MAX_JSON_NODES - 1)
        excess = b"[" + b",".join([b"null"] * MAX_JSON_NODES) + b"]"
        with self.assertRaisesRegex(ValueError, "node budget"):
            self.load_bytes(excess)

    def test_object_keys_consume_nodes_as_in_c(self):
        source = json.dumps({f"k{index}": None for index in range(MAX_JSON_NODES // 2)})
        with self.assertRaisesRegex(ValueError, "node budget"):
            self.load_bytes(source.encode("ascii"))

    def test_missing_grammar_attribute_has_value_error_contract(self):
        grammar = scalar_message("request", "request", 1)["grammar"]
        del grammar["fields"][0]["width"]
        with self.assertRaisesRegex(ValueError, "invalid grammar"):
            parse_grammar(grammar, b"\x01")


class ExampleMatchingTests(unittest.TestCase):
    def test_rejects_same_direction_example_ambiguity(self):
        messages = [scalar_message("first", "request", 1),
                    scalar_message("second", "request", 2)]
        with self.assertRaisesRegex(ValueError, "same-direction grammar"):
            check_example_matches(messages)

    def test_request_and_response_grammars_are_separate(self):
        messages = [scalar_message("request", "request", 1),
                    scalar_message("response", "response", 1)]
        check_example_matches(messages)

    def test_disjoint_examples_pass(self):
        messages = [scalar_message("first", "request", 1, 0, 9),
                    scalar_message("second", "request", 10, 10, 20)]
        check_example_matches(messages)

    def test_example_check_does_not_claim_all_grammars_disjoint(self):
        # Neither example is ambiguous, but values 5..10 match both grammars.
        messages = [scalar_message("first", "request", 0, 0, 10),
                    scalar_message("second", "request", 15, 5, 15)]
        check_example_matches(messages)


class CorrelationPairTests(unittest.TestCase):
    def test_rejects_orphan_rule(self):
        messages = [{"id": "response", "correlate": [correlation("first")]}]
        with self.assertRaisesRegex(ValueError, "has no request/response transition"):
            check_correlation_pairs(messages, [])

    def test_rejects_uncovered_shared_response_request(self):
        messages = [{"id": "response", "correlate": [correlation("first")]}]
        transitions = [transition("first", "response"), transition("second", "response")]
        with self.assertRaisesRegex(ValueError, "second lacks request correlation"):
            check_correlation_pairs(messages, transitions)

    def test_shared_response_with_both_rules_passes(self):
        messages = [{"id": "response", "correlate": [
            correlation("first"), correlation("second"),
        ]}]
        transitions = [transition("first", "response"), transition("second", "response")]
        check_correlation_pairs(messages, transitions)

    def test_same_pair_in_multiple_states_passes(self):
        messages = [{"id": "response", "correlate": [correlation("first")]}]
        transitions = [transition("first", "response", "ready"),
                       transition("first", "response", "again")]
        check_correlation_pairs(messages, transitions)

    def test_no_field_correlations_remains_allowed(self):
        for message in ({"id": "response"}, {"id": "response", "correlate": []}):
            with self.subTest(message=message):
                check_correlation_pairs([message], [transition("first", "response")])


class ProfileEntryPointTests(unittest.TestCase):
    """Exercise the public file entry point without replacing its validators."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="generic-profile-check-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "modbus_tcp"
        self.directory.mkdir()
        for filename in ("generic_wire.json", "protocol_ir.json"):
            shutil.copyfile(ROOT / "protocols" / "modbus_tcp" / filename,
                            self.directory / filename)
        self.path = self.directory / "generic_wire.json"
        self.data = json.loads(self.path.read_text(encoding="utf-8"))
        self.source_path = self.directory / "protocol_ir.json"
        self.source = json.loads(self.source_path.read_text(encoding="utf-8"))

    def check_files(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        self.source_path.write_text(json.dumps(self.source), encoding="utf-8")
        return check(self.path)

    def add_request_variant(self, distinct=False):
        request = next(m for m in self.data["messages"] if m["id"] == "read_holding")
        source = next(m for m in self.source["messages"] if m["id"] == "read_holding")
        variant, source_variant = copy.deepcopy(request), copy.deepcopy(source)
        variant["id"] = source_variant["id"] = "read_holding_variant"
        if distinct:
            # Keep all unrelated identity/framing/correlation checks valid.
            # Address is not a correlation key; exact different values make
            # the original and variant request grammars unambiguous.
            for message, original, address in ((request, source, 0),
                                               (variant, source_variant, 1)):
                field = next(f for f in message["grammar"]["fields"] if f["id"] == "address")
                field.update(role="fixed", min=address, max=address, expected=address)
                offset = 0
                for preceding in message["grammar"]["fields"]:
                    if preceding["id"] == "address":
                        break
                    offset += preceding["width"]
                wire = bytearray.fromhex(message["example_hex"])
                wire[offset:offset + field["width"]] = address.to_bytes(field["width"], "big")
                message["example_hex"] = original["example"] = wire.hex()
                original_field = next(f for f in original["fields"] if f["id"] == "address")
                original_field.update(role="fixed", mutability="fixed", min=address,
                                      max=address, default=address, values=[address], strategies=[])
        self.data["messages"].append(variant)
        self.source["messages"].append(source_variant)
        edge = copy.deepcopy(self.data["states"]["transitions"][0])
        edge["message"] = variant["id"]
        self.data["states"]["transitions"].append(edge)
        return variant["id"]

    def test_checked_in_profile_passes_public_entry_point(self):
        result = self.check_files()
        self.assertEqual(result["protocol"], "modbus_tcp")
        self.assertEqual((result["requests"], result["responses"]), (1, 1))

    def test_entry_point_rejects_ambiguous_example(self):
        variant = self.add_request_variant()
        response = next(m for m in self.data["messages"] if m["id"] == "read_response")
        rules = copy.deepcopy(response["correlate"])
        for rule in rules:
            rule["request"] = variant
        response["correlate"].extend(rules)
        with self.assertRaisesRegex(ValueError, "same-direction grammar"):
            self.check_files()

    def test_entry_point_rejects_orphan_correlation(self):
        del self.data["states"]["transitions"][0]["response"]
        with self.assertRaisesRegex(ValueError, "has no request/response transition"):
            self.check_files()

    def test_entry_point_rejects_uncovered_shared_response(self):
        variant = self.add_request_variant(distinct=True)
        with self.assertRaisesRegex(ValueError, f"{variant} lacks request correlation"):
            self.check_files()

    def test_entry_point_rejects_empty_initial_state(self):
        self.data["states"]["initial"] = ""
        with self.assertRaisesRegex(ValueError, "empty initial state"):
            self.check_files()

    def test_entry_point_rejects_empty_transition_state(self):
        original = copy.deepcopy(self.data["states"]["transitions"][0])
        for key in ("from", "to"):
            with self.subTest(key=key):
                self.data["states"]["transitions"][0] = dict(original, **{key: ""})
                with self.assertRaisesRegex(ValueError, "empty transition state"):
                    self.check_files()

    def test_entry_point_contextualizes_missing_source_file(self):
        self.source_path.unlink()
        with self.assertRaisesRegex(ValueError, "modbus_tcp:"):
            check(self.path)

    def test_entry_point_rejects_request_example_over_replay_budget(self):
        self.data["limits"]["max_bytes"] = 8
        with self.assertRaisesRegex(ValueError, "request example exceeds max_bytes"):
            self.check_files()

    def test_entry_point_accepts_exact_request_replay_budget(self):
        request = next(m for m in self.data["messages"] if m["direction"] == "request")
        self.data["limits"]["max_bytes"] = len(bytes.fromhex(request["example_hex"])) + 4
        self.assertEqual(self.check_files()["protocol"], "modbus_tcp")

    def test_entry_point_rejects_float_metadata_before_schema_checks(self):
        self.data["limitations"] = [1.0]
        with self.assertRaisesRegex(ValueError, "modbus_tcp: only integer JSON numbers"):
            self.check_files()


if __name__ == "__main__":
    unittest.main()
