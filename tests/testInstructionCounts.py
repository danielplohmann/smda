"""Tests for the callgrind instruction-count gate (`.github/workflows/scripts/count_instructions.py`).

Measuring needs valgrind and minutes per fixture, so only the parts that decide the gate
are covered here: reading the callgrind total and the base/PR comparison.
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scripts" / "count_instructions.py"
_spec = importlib.util.spec_from_file_location("count_instructions", _SCRIPT)
count_instructions = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(count_instructions)


def _result(import_ir, **fixtures):
    return {
        "python": "3.11",
        "import": import_ir,
        "fixtures": {
            name: None if net is None else {"total": import_ir + net, "net": net} for name, net in fixtures.items()
        },
    }


class ReadTotalTest(unittest.TestCase):
    def _write(self, text):
        handle, path = tempfile.mkstemp()
        with os.fdopen(handle, "w") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_reads_summary_line(self):
        path = self._write("version: 1\ncreator: callgrind-3.22.0\nevents: Ir\nsummary: 3482682471\n\nfn=(1) main\n")
        self.assertEqual(count_instructions.read_total(path), 3482682471)

    def test_reads_totals_line(self):
        path = self._write("events: Ir\nfn=(1) main\n0 5\ntotals: 1234\n")
        self.assertEqual(count_instructions.read_total(path), 1234)

    def test_missing_summary_raises(self):
        path = self._write("events: Ir\nfn=(1) main\n0 5\n")
        with self.assertRaises(ValueError):
            count_instructions.read_total(path)


class CompareTest(unittest.TestCase):
    def _compare(self, base, pr):
        return count_instructions.compare(base, pr, threshold_warn=0.01, threshold_fail=0.02)

    def test_identical_results_pass(self):
        base = _result(1000, asprox=10_000, komplex=20_000)
        markdown, failed = self._compare(base, base)
        self.assertFalse(failed)
        self.assertNotIn("FAIL", markdown)

    def test_fixture_growth_past_threshold_fails(self):
        markdown, failed = self._compare(_result(1000, asprox=10_000), _result(1000, asprox=10_300))
        self.assertTrue(failed)
        self.assertIn("| asprox | 10,000 | 10,300 | +3.00% | FAIL |", markdown)

    def test_growth_between_thresholds_warns(self):
        markdown, failed = self._compare(_result(1000, asprox=10_000), _result(1000, asprox=10_150))
        self.assertFalse(failed)
        self.assertIn("| asprox | 10,000 | 10,150 | +1.50% | warn |", markdown)

    def test_improvement_passes(self):
        _, failed = self._compare(_result(1000, asprox=10_000), _result(1000, asprox=5_000))
        self.assertFalse(failed)

    def test_import_growth_is_its_own_row(self):
        markdown, failed = self._compare(_result(1000, asprox=10_000), _result(1100, asprox=10_000))
        self.assertTrue(failed)
        self.assertIn("| (import) | 1,000 | 1,100 | +10.00% | FAIL |", markdown)
        self.assertIn("| asprox | 10,000 | 10,000 | +0.00% | ok |", markdown)

    def test_fixture_on_one_side_is_reported_not_summed(self):
        base = _result(1000, asprox=10_000, aarch64_static=None)
        pr = _result(1000, asprox=10_000, aarch64_static=50_000)
        markdown, failed = self._compare(base, pr)
        self.assertFalse(failed)
        self.assertIn("| aarch64_static | - | 50,000 | n/a | only on one side |", markdown)
        self.assertIn("| TOTAL | 10,000 | 10,000 | +0.00% | ok |", markdown)

    def test_growth_below_the_absolute_floor_does_not_count(self):
        # pe_export in CI: identical code, +1.5M instructions from allocator state
        base = _result(1000, pe_export=45_619_183, asprox=2_355_805_669)
        pr = _result(1000, pe_export=47_159_148, asprox=2_355_805_669)
        markdown, failed = count_instructions.compare(base, pr, 0.01, 0.02, min_absolute=5_000_000)
        self.assertFalse(failed)
        self.assertIn("| pe_export | 45,619,183 | 47,159,148 | +3.38% | ok |", markdown)

    def test_growth_above_the_absolute_floor_still_fails(self):
        base = _result(1000, asprox=2_355_805_669)
        pr = _result(1000, asprox=2_450_000_000)
        _, failed = count_instructions.compare(base, pr, 0.01, 0.02, min_absolute=5_000_000)
        self.assertTrue(failed)

    def test_small_growth_on_every_fixture_fails_the_total(self):
        base = _result(1000, a=10_000, b=10_000)
        pr = _result(1000, a=10_150, b=10_150)
        markdown, _ = count_instructions.compare(base, pr, threshold_warn=0.0, threshold_fail=0.01)
        self.assertIn("| TOTAL | 20,000 | 20,300 | +1.50% | FAIL |", markdown)


if __name__ == "__main__":
    unittest.main()
