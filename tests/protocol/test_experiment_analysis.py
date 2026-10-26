#!/usr/bin/env python3
"""Small deterministic tests for experiment accounting, without live fuzzing."""

import json
from pathlib import Path
import struct
import tempfile
import unittest

from controlled_experiments import (analyze_run, bitmap_metrics, inspect_control_candidates,
                                    quantiles, run_order, sample_candidate_metrics, snapshot, summarize)


class ExperimentAnalysisTests(unittest.TestCase):
    def test_rotation_avoids_always_starting_with_legacy(self):
        modes = ["legacy", "head", "head_content", "all", "hybrid"]
        orders = [run_order(modes, repeat) for repeat in range(5)]
        self.assertEqual([order[0] for order in orders], modes)
        for order in orders:
            self.assertCountEqual(order, modes)
        self.assertEqual(run_order(modes, 5), modes)

    def test_descriptive_quantiles_keep_zero_and_exclude_missing(self):
        result = quantiles([0, 10, 20, None])
        self.assertEqual(result, {"n": 3, "min": 0, "p25": 5, "median": 10, "p75": 15, "max": 20})
        self.assertEqual(quantiles([None])["n"], 0)
        self.assertIsNone(quantiles([])["median"])

    def test_fuzz_bitmap_counts_nonvirgin_bytes_and_hit_class_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fuzz_bitmap"
            path.write_bytes(bytes([255, 254, 0, 127]))
            metrics = bitmap_metrics(path)
            self.assertEqual(metrics["nonvirgin_bytes"], 3)
            self.assertEqual(metrics["cleared_bits"], 10)
            self.assertEqual(metrics["bytes"], 4)
            self.assertIsNone(bitmap_metrics(path.with_name("missing"))["nonvirgin_bytes"])

    @staticmethod
    def fixture():
        return {"mode": "head", "stats": {"execs_done": "150", "paths_total": "7", "protocol_structured": "32",
                    "protocol_raw": "8", "unique_crashes": "0", "unique_hangs": "0"},
                "protocol_stats": {"attempts": 40, "rejected": 8, "responses": 80, "correlated_responses": 55},
                "timing": {"measured_fuzz_seconds": 10}, "queue_count": 7,
                "memory_state_feedback": {"inferred_state_ids": [0, 9], "graph_edges": [[0, 9]]}}

    def test_calibration_executions_and_responses_are_subtracted(self):
        baseline = {"stats": {"execs_done": "100", "paths_total": "4", "protocol_structured": "2", "protocol_raw": "3"},
                    "protocol_stats": {"attempts": 4, "rejected": 2, "responses": 30, "correlated_responses": 20},
                    "bitmap": {"nonvirgin_bytes": 12}}
        metrics = analyze_run(self.fixture(), baseline, {"nonvirgin_bytes": 17, "cleared_bits": 20})
        self.assertEqual(metrics["fuzz_executions"], 50)
        self.assertEqual(metrics["fuzz_executions_per_second"], 5)
        self.assertEqual(metrics["responses"], 50)
        self.assertEqual(metrics["correlated_responses"], 35)
        self.assertEqual(metrics["queue_growth"], 3)
        self.assertEqual(metrics["bitmap_nonvirgin_byte_gain"], 5)
        self.assertEqual(metrics["structured_run_share"], 30 / 35)
        self.assertEqual(metrics["rejection_share_of_attempts"], 6 / 36)

    def test_missing_calibration_baseline_does_not_become_zero(self):
        metrics = analyze_run(self.fixture(), {}, {"nonvirgin_bytes": 17, "cleared_bits": 20})
        self.assertIsNone(metrics["fuzz_executions"])
        self.assertIsNone(metrics["fuzz_executions_per_second"])
        self.assertIsNone(metrics["responses"])

    def test_synchronous_baseline_takes_precedence_over_late_stats_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "fuzzer_stats").write_text("execs_done: 105\npaths_total: 5\ncommand_line: afl-fuzz\nslowest_exec_ms: 1\n")
            (output / "experiment_baseline.json").write_text(json.dumps({"execs_done": 100, "paths_total": 4,
                "coverage_edges": 12, "protocol_structured": 0, "protocol_raw": 0, "protocol_rejected": 0,
                "timestamp_ms": 123456}))
            (output / "fuzz_bitmap").write_bytes(bytes([0, 0]))
            initial = snapshot(output, output / "ready", False)
            self.assertEqual(initial["stats"]["execs_done"], "100")
            self.assertEqual(initial["stats"]["paths_total"], "4")
            self.assertEqual(initial["bitmap"]["nonvirgin_bytes"], 12)
            self.assertTrue((output / "ready/experiment_baseline.json").exists())

    def test_paired_comparison_matches_repeats_not_list_order(self):
        runs = [{"repeat": 2, "mode": "head", "passed": True, "metrics": {"fuzz_executions": 27}},
                {"repeat": 1, "mode": "legacy", "passed": True, "metrics": {"fuzz_executions": 10}},
                {"repeat": 1, "mode": "head", "passed": True, "metrics": {"fuzz_executions": 13}},
                {"repeat": 2, "mode": "legacy", "passed": True, "metrics": {"fuzz_executions": 20}}]
        differences = summarize(runs)["paired_differences_from_legacy"]["head"]["fuzz_executions"]
        self.assertEqual((differences["min"], differences["median"], differences["max"]), (3, 5, 7))

    @staticmethod
    def save_candidate(directory, number, packets, structured=True):
        folder = directory / "protocol-candidates"
        folder.mkdir(exist_ok=True)
        path = folder / f"{number:06d}.replay"
        path.write_bytes(b"".join(struct.pack("<I", len(packet)) + packet for packet in packets))
        path.with_suffix(".json").write_text(json.dumps({"structured": structured, "sent_messages": len(packets)}))

    def test_wire_controls_read_actual_candidates_and_ignore_raw_sends(self):
        packet = bytes.fromhex("810a001101040005010c0c0200007b194d")
        changed = bytearray(packet)
        changed[8] = 33
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.save_candidate(output, 0, [changed])
            self.save_candidate(output, 1, [b"raw mutation"], structured=False)
            result = inspect_control_candidates(output, packet, 33)
            self.assertTrue(result["passed"])
            self.assertEqual(result["saved_candidates"], 1)
            self.assertFalse(inspect_control_candidates(output, packet, 77)["passed"])
            sample = sample_candidate_metrics(output)
            self.assertEqual(sample["sequences"], 2)
            self.assertEqual(sample["structured_sequence_share"], .5)
            self.assertEqual(sample["structural_sequence_share"], .5)

    def test_near_valid_control_requires_exactly_bvlc_length_plus_one(self):
        packet = bytes.fromhex("810a001101040005010c0c0200007b194d")
        changed = bytearray(packet)
        changed[8] = 33
        changed[2:4] = (len(changed) + 1).to_bytes(2, "big")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.save_candidate(output, 0, [changed])
            self.assertTrue(inspect_control_candidates(output, packet, 33, 1)["passed"])
            self.assertFalse(inspect_control_candidates(output, packet, 33, 0)["passed"])
            changed[-1] ^= 1
            self.save_candidate(output, 1, [changed])
            self.assertFalse(inspect_control_candidates(output, packet, 33, 1)["passed"])

    def test_absent_samples_cannot_pass_yaml_functional_control(self):
        with tempfile.TemporaryDirectory() as directory:
            result = inspect_control_candidates(Path(directory), bytes.fromhex("810a001101040005010c0c0200007b194d"), 33)
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
