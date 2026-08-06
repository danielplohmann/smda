"""Tests for the CI perf-gate scripts (`.github/workflows/scripts/run_perf_check.py` and
`compare_perf.py`), the canonical report-identity hash they rely on, and the aggregation
behind the counterbalanced fixture benchmark passes.

The perf gate used to time base once and PR once, base first, so any slowdown that
developed over the job landed entirely on the PR measurement. The workflow now runs
the passes base/PR/PR/base and merges each side's samples, which cancels drift that
is linear in pass order while still surfacing a genuine regression.
"""

import datetime
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.common import computeReportIdentityHash

pytestmark = pytest.mark.slow

_SCRIPTS = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scripts"


def _load_module(name):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_perf_check = _load_module("run_perf_check")


def _timing_result(times):
    return {"execution_times": times, "median_time": statistics.median(times)}


class TestMergeResults(unittest.TestCase):
    def test_merge_accumulates_samples_and_recomputes_median(self):
        merged = run_perf_check.merge_results(
            {"k": _timing_result([1.0, 1.0, 1.0])}, {"k": _timing_result([3.0, 3.0, 3.0])}
        )
        self.assertEqual([1.0, 1.0, 1.0, 3.0, 3.0, 3.0], merged["k"]["execution_times"])
        self.assertAlmostEqual(2.0, merged["k"]["median_time"])

    def test_merge_adds_fixtures_absent_from_the_first_pass(self):
        merged = run_perf_check.merge_results({"a": _timing_result([1.0])}, {"b": _timing_result([2.0])})
        self.assertEqual({"a", "b"}, set(merged))

    def test_merge_carries_forward_keys_the_new_pass_did_not_produce(self):
        first = {"k": dict(_timing_result([1.0]), backend="intel", num_functions=7)}
        merged = run_perf_check.merge_results(first, {"k": _timing_result([2.0])})
        self.assertEqual("intel", merged["k"]["backend"])
        self.assertEqual(7, merged["k"]["num_functions"])

    def test_merge_does_not_mutate_its_inputs(self):
        first = {"k": _timing_result([1.0])}
        second = {"k": _timing_result([2.0])}
        run_perf_check.merge_results(first, second)
        self.assertEqual([1.0], first["k"]["execution_times"])
        self.assertEqual([2.0], second["k"]["execution_times"])


class TestCounterbalancedAggregation(unittest.TestCase):
    def test_linear_order_bias_cancels(self):
        # Four passes in base/PR/PR/base order under a drift of +0.0702s per pass:
        # base occupies pass slots 1 and 4, PR slots 2 and 3, so both sides carry the
        # same mean drift and the medians agree despite identical underlying speed.
        drift = 0.0702
        t0 = 0.1357
        base = run_perf_check.merge_results(
            {"k": _timing_result([t0] * 3)}, {"k": _timing_result([t0 + 3 * drift] * 3)}
        )
        pr = run_perf_check.merge_results(
            {"k": _timing_result([t0 + drift] * 3)}, {"k": _timing_result([t0 + 2 * drift] * 3)}
        )
        self.assertAlmostEqual(base["k"]["median_time"], pr["k"]["median_time"])

        # the single-pass comparison this replaces would have reported ~+52%
        single_pass_error = (t0 + drift) / t0 - 1
        self.assertGreater(single_pass_error, 0.5)

    def test_real_regression_still_surfaces(self):
        drift = 0.0702
        t0 = 0.1357
        base = run_perf_check.merge_results(
            {"k": _timing_result([t0] * 3)}, {"k": _timing_result([t0 + 3 * drift] * 3)}
        )
        pr = run_perf_check.merge_results(
            {"k": _timing_result([t0 + drift + 0.2] * 3)}, {"k": _timing_result([t0 + 2 * drift + 0.2] * 3)}
        )
        slowdown = pr["k"]["median_time"] / base["k"]["median_time"] - 1
        self.assertGreater(slowdown, 0.5)


def _decrypt(name):
    config = SmdaConfig()
    with open(os.path.join(config.PROJECT_ROOT, "tests", name), "rb") as f_binary:
        binary = f_binary.read()
    return bytes(bytearray(byte ^ (index % 256) for index, byte in enumerate(binary)))


def _result(**overrides):
    result = {
        "backend": "intel",
        "execution_times": [1.0],
        "median_time": 1.0,
        "num_functions": 2,
        "num_instructions": 20,
        "num_blocks": 4,
        "functions": {"0x1000": {"num_blocks": 2, "num_instructions": 10}},
        "report_hash": "a" * 64,
        "python_version": "3.11.0",
        "peak_memories": [100 * 1024 * 1024],
        "median_peak_memory": 100 * 1024 * 1024,
    }
    result.update(overrides)
    return result


class TestReportIdentityHash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_decrypt("cutwail_xored"))

    def test_hash_is_stable_for_the_same_report(self):
        self.assertEqual(computeReportIdentityHash(self.report), computeReportIdentityHash(self.report))

    def test_hash_ignores_volatile_fields(self):
        before = computeReportIdentityHash(self.report)
        self.report.execution_time = self.report.execution_time + 1.0
        self.report.timestamp = self.report.timestamp + datetime.timedelta(hours=1)
        self.assertEqual(before, computeReportIdentityHash(self.report))

    def test_hash_tracks_function_metadata(self):
        before = computeReportIdentityHash(self.report)
        function = list(self.report.getFunctions())[0]
        original = function.pic_hash
        function.pic_hash = 1234
        try:
            self.assertNotEqual(before, computeReportIdentityHash(self.report))
        finally:
            function.pic_hash = original
        self.assertEqual(before, computeReportIdentityHash(self.report))


class TestComparePerf(unittest.TestCase):
    def _run(self, pr, base, extra_args=()):
        with tempfile.TemporaryDirectory() as tmp:
            pr_path = os.path.join(tmp, "pr.json")
            base_path = os.path.join(tmp, "base.json")
            with open(pr_path, "w", encoding="utf-8") as f:
                json.dump(pr, f)
            with open(base_path, "w", encoding="utf-8") as f:
                json.dump(base, f)
            return subprocess.run(
                [sys.executable, str(_SCRIPTS / "compare_perf.py"), pr_path, base_path, *extra_args],
                capture_output=True,
                text=True,
            )

    def test_identical_results_pass(self):
        completed = self._run({"fixture": _result()}, {"fixture": _result()})
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_report_hash_mismatch_is_a_correctness_failure(self):
        completed = self._run({"fixture": _result(report_hash="b" * 64)}, {"fixture": _result()})
        self.assertEqual(1, completed.returncode)
        self.assertIn("Report identity hash mismatch", completed.stdout)

    def test_call_count_change_is_informational_by_default(self):
        completed = self._run(
            {"fixture": _result(total_calls=900, prim_calls=800)},
            {"fixture": _result(total_calls=1000, prim_calls=900)},
        )
        self.assertEqual(0, completed.returncode)
        self.assertIn("PYTHON CALL COUNTS", completed.stdout)
        self.assertIn("-100", completed.stdout)

    def test_call_count_change_can_be_made_fatal(self):
        completed = self._run(
            {"fixture": _result(total_calls=900)},
            {"fixture": _result(total_calls=1000)},
            extra_args=("--fail-on-call-count-change",),
        )
        self.assertEqual(1, completed.returncode)

    def test_short_fixture_percentage_alone_does_not_fail(self):
        # a 0.21s fixture swinging +31.7% (+0.068s) is runner variance, not work: this
        # exact shape failed the gate on PR #226 while peak memory moved +0.01%
        completed = self._run(
            {"komplex": _result(median_time=0.2829), "cutwail": _result(median_time=0.9265)},
            {"komplex": _result(median_time=0.2148), "cutwail": _result(median_time=0.9223)},
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("WARN (NOISE?)", completed.stdout)

    def test_large_absolute_regression_still_fails(self):
        completed = self._run(
            {"cutwail": _result(median_time=4.2)},
            {"cutwail": _result(median_time=3.0)},
        )
        self.assertEqual(2, completed.returncode)
        self.assertIn("FAIL (REGRESS)", completed.stdout)

    def test_peak_memory_growth_is_a_failure(self):
        completed = self._run(
            {"fixture": _result(median_peak_memory=130 * 1024 * 1024)},
            {"fixture": _result()},
        )
        self.assertEqual(3, completed.returncode)
        self.assertIn("PEAK MEMORY", completed.stdout)
        self.assertIn("peak memory grew", completed.stderr)

    def test_peak_memory_within_threshold_passes(self):
        completed = self._run(
            {"fixture": _result(median_peak_memory=105 * 1024 * 1024)},
            {"fixture": _result()},
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("+5.00%", completed.stdout)

    def test_peak_memory_skipped_when_one_side_lacks_the_channel(self):
        base = _result()
        del base["median_peak_memory"]
        completed = self._run({"fixture": _result()}, {"fixture": base})
        self.assertEqual(0, completed.returncode)
        self.assertIn("Memory comparison skipped", completed.stdout)

    def test_call_counts_skipped_across_python_versions(self):
        completed = self._run(
            {"fixture": _result(total_calls=900, python_version="3.13.0")},
            {"fixture": _result(total_calls=1000, python_version="3.11.0")},
        )
        self.assertEqual(0, completed.returncode)
        self.assertIn("Call-count comparison skipped", completed.stdout)
        self.assertNotIn("PYTHON CALL COUNTS", completed.stdout)


class TestRunPerfCheck(unittest.TestCase):
    def test_records_hash_and_python_version(self):
        module = _load_module("run_perf_check")
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "results.json")
            module.run_benchmark(2, output)
            with open(output, encoding="utf-8") as f:
                results = json.load(f)
        self.assertTrue(results)
        for name, entry in results.items():
            self.assertEqual(64, len(entry["report_hash"]), name)
            self.assertTrue(entry["python_version"], name)
            self.assertNotIn("total_calls", entry)


if __name__ == "__main__":
    unittest.main()
