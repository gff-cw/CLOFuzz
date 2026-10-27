#!/usr/bin/env python3
"""Reject impossible campaign budgets before output or target initialization."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DRIVERS = ("integration.py", "controlled_experiments.py")


class CampaignBudgetTests(unittest.TestCase):
    def test_invalid_budgets_stop_before_initialization(self):
        cases = (
            (["--exec-timeout-ms", "0"], "must be a positive uint32 value"),
            (["--exec-timeout-ms", "-1"], "must be a positive uint32 value"),
            (["--exec-timeout-ms", "4"], "must be at least 5 ms"),
            (["--exec-timeout-ms", "4294967296"], "must be a positive uint32 value"),
            (["--startup-usecs", "-1"], "must be a nonnegative uint32 value"),
            (["--startup-usecs", "4294967296"], "must be a nonnegative uint32 value"),
            (["--startup-usecs", "5000000"], "must be less than --exec-timeout-ms * 1000"),
            (["--startup-usecs", "5000001"], "must be less than --exec-timeout-ms * 1000"),
        )
        with tempfile.TemporaryDirectory(prefix="stateafl-campaign-budget-") as directory:
            for driver in DRIVERS:
                for index, (flags, diagnostic) in enumerate(cases):
                    with self.subTest(driver=driver, flags=flags):
                        output = Path(directory) / f"{driver}-{index}"
                        result = subprocess.run(
                            [sys.executable, str(ROOT / "tests/protocol" / driver),
                             "--output", str(output), "--server", "/not-a-campaign-target",
                             *flags], cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                        self.assertIn(diagnostic, result.stderr)
                        self.assertNotIn("BACnet target not found", result.stderr)
                        self.assertFalse(output.exists())

    def test_help_exposes_both_budgets_and_defaults(self):
        for driver in DRIVERS:
            with self.subTest(driver=driver):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "tests/protocol" / driver), "--help"],
                    cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                help_text = " ".join(result.stdout.split())
                self.assertIn("--startup-usecs", help_text)
                self.assertIn("--exec-timeout-ms", help_text)
                self.assertIn("default: 1000000", help_text)
                self.assertIn("default: 5000", help_text)


if __name__ == "__main__":
    unittest.main()
