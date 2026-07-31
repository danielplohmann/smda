"""Aggregation tests for the counterbalanced fixture benchmark passes.

The perf gate used to time base once and PR once, base first, so any slowdown that
developed over the job landed entirely on the PR measurement. The workflow now runs
the passes base/PR/PR/base and merges each side's samples, which cancels drift that
is linear in pass order while still surfacing a genuine regression.
"""

import importlib.util
import statistics
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scripts" / "run_perf_check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_perf_check", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_perf_check = _load_module()


def _result(times):
    return {"execution_times": times, "median_time": statistics.median(times)}


class TestMergeResults(unittest.TestCase):
    def test_merge_accumulates_samples_and_recomputes_median(self):
        merged = run_perf_check.merge_results({"k": _result([1.0, 1.0, 1.0])}, {"k": _result([3.0, 3.0, 3.0])})
        self.assertEqual([1.0, 1.0, 1.0, 3.0, 3.0, 3.0], merged["k"]["execution_times"])
        self.assertAlmostEqual(2.0, merged["k"]["median_time"])

    def test_merge_adds_fixtures_absent_from_the_first_pass(self):
        merged = run_perf_check.merge_results({"a": _result([1.0])}, {"b": _result([2.0])})
        self.assertEqual({"a", "b"}, set(merged))

    def test_merge_carries_forward_keys_the_new_pass_did_not_produce(self):
        first = {"k": dict(_result([1.0]), backend="intel", num_functions=7)}
        merged = run_perf_check.merge_results(first, {"k": _result([2.0])})
        self.assertEqual("intel", merged["k"]["backend"])
        self.assertEqual(7, merged["k"]["num_functions"])

    def test_merge_does_not_mutate_its_inputs(self):
        first = {"k": _result([1.0])}
        second = {"k": _result([2.0])}
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
        base = run_perf_check.merge_results({"k": _result([t0] * 3)}, {"k": _result([t0 + 3 * drift] * 3)})
        pr = run_perf_check.merge_results({"k": _result([t0 + drift] * 3)}, {"k": _result([t0 + 2 * drift] * 3)})
        self.assertAlmostEqual(base["k"]["median_time"], pr["k"]["median_time"])

        # the single-pass comparison this replaces would have reported ~+52%
        single_pass_error = (t0 + drift) / t0 - 1
        self.assertGreater(single_pass_error, 0.5)

    def test_real_regression_still_surfaces(self):
        drift = 0.0702
        t0 = 0.1357
        base = run_perf_check.merge_results({"k": _result([t0] * 3)}, {"k": _result([t0 + 3 * drift] * 3)})
        pr = run_perf_check.merge_results(
            {"k": _result([t0 + drift + 0.2] * 3)}, {"k": _result([t0 + 2 * drift + 0.2] * 3)}
        )
        slowdown = pr["k"]["median_time"] / base["k"]["median_time"] - 1
        self.assertGreater(slowdown, 0.5)


if __name__ == "__main__":
    unittest.main()
