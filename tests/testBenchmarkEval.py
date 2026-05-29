"""Unit + integration tests for the CI benchmark evaluation script
(`.github/workflows/scripts/evaluate_runtime.py`)."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scripts" / "evaluate_runtime.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("evaluate_runtime", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


er = _load_module()


def _write_report(folder: Path, name: str, addrs, exec_time):
    """Write a minimal .smda report with the given function addresses and time."""
    folder.mkdir(parents=True, exist_ok=True)
    data = {
        "execution_time": exec_time,
        "xcfg": {a: {"blocks": {"0": []}} for a in addrs},
    }
    with open(folder / f"{name}.smda", "w") as f:
        json.dump(data, f)


def _make_runtime(root: Path, base_runs, pr_runs):
    """base_runs / pr_runs: list of dicts {filename: (addrs, exec_time)} per run."""
    for i, run in enumerate(base_runs):
        for name, (addrs, t) in run.items():
            _write_report(root / f"base_{i}", name, addrs, t)
    for i, run in enumerate(pr_runs):
        for name, (addrs, t) in run.items():
            _write_report(root / f"pr_{i}", name, addrs, t)


class TestBootstrap(unittest.TestCase):
    def test_constant_values(self):
        self.assertEqual(er.bootstrap_ci([5.0, 5.0, 5.0], er.statistics.median), (5.0, 5.0))

    def test_single_value(self):
        self.assertEqual(er.bootstrap_ci([3.0], er.statistics.median), (3.0, 3.0))

    def test_empty(self):
        self.assertEqual(er.bootstrap_ci([], er.statistics.median), (0.0, 0.0))

    def test_within_range_and_reproducible(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        lo1, hi1 = er.bootstrap_ci(values, er.statistics.median, n_resamples=2000)
        lo2, hi2 = er.bootstrap_ci(values, er.statistics.median, n_resamples=2000)
        self.assertEqual((lo1, hi1), (lo2, hi2))  # fixed seed → reproducible
        self.assertLessEqual(min(values), lo1)
        self.assertLessEqual(hi1, max(values))
        self.assertLessEqual(lo1, hi1)


class TestWilcoxon(unittest.TestCase):
    def test_known_all_positive(self):
        base = [10, 9, 8, 7, 6, 5]
        pr = [5, 5, 5, 5, 5, 5]  # diffs 5,4,3,2,1,0 -> drop the 0
        res = er.wilcoxon_signed_rank(base, pr, min_n=1)
        self.assertEqual(res["statistic"], 15.0)  # sum of ranks 1..5
        self.assertEqual(res["n_nonzero"], 5)
        self.assertEqual(res["n_zero"], 1)
        self.assertIsNotNone(res["p_value"])
        self.assertTrue(0.04 < res["p_value"] < 0.08)  # hand-computed ~0.059

    def test_insufficient_samples(self):
        res = er.wilcoxon_signed_rank([2, 3, 4], [1, 1, 1], min_n=10)
        self.assertIsNone(res["p_value"])
        self.assertEqual(res["n_nonzero"], 3)

    def test_ties_handled(self):
        res = er.wilcoxon_signed_rank([2, 2], [1, 1], min_n=1)
        self.assertEqual(res["statistic"], 3.0)  # two tied abs-diffs -> avg rank 1.5 each


class TestAggregationAndDeterminism(unittest.TestCase):
    def _rep(self, addrs, t):
        return {"execution_time": t, "block_counts": dict.fromkeys(addrs, 1), "function_count": len(addrs)}

    def test_min_of_runs(self):
        caches = {
            "base_0": {"a.smda": self._rep(["0x1", "0x2"], 3.0)},
            "base_1": {"a.smda": self._rep(["0x1", "0x2"], 2.0)},
            "base_2": {"a.smda": self._rep(["0x1", "0x2"], 4.0)},
        }
        agg, meta = er.aggregate_runs(caches)
        self.assertEqual(agg["a.smda"]["time_min"], 2.0)
        self.assertEqual(agg["a.smda"]["function_addrs"], frozenset({"0x1", "0x2"}))
        self.assertEqual(meta["files"], 1)

    def test_determinism_pass_and_fail(self):
        ok = {
            "base_0": {"a.smda": self._rep(["0x1"], 1.0)},
            "base_1": {"a.smda": self._rep(["0x1"], 1.0)},
        }
        agg_ok, _ = er.aggregate_runs(ok)
        self.assertTrue(er.check_determinism(agg_ok)["is_deterministic"])

        bad = {
            "base_0": {"a.smda": self._rep(["0x1"], 1.0)},
            "base_1": {"a.smda": self._rep(["0x1", "0x2"], 1.0)},
        }
        agg_bad, _ = er.aggregate_runs(bad)
        det = er.check_determinism(agg_bad)
        self.assertFalse(det["is_deterministic"])
        self.assertEqual(det["files_disagreeing"][0]["file"], "a.smda")

    def test_paired_speedup_positive_when_pr_faster(self):
        base_agg = {
            f"f{i}.smda": {"time_min": 2.0, "function_addrs": frozenset({"0x1"}), "function_count": 1} for i in range(5)
        }
        pr_agg = {
            f"f{i}.smda": {"time_min": 1.0, "function_addrs": frozenset({"0x1"}), "function_count": 1} for i in range(5)
        }
        paired = er.build_paired(base_agg, pr_agg)
        stats = er.compute_paired_stats(paired)
        self.assertEqual(stats["n"], 5)
        self.assertGreater(stats["median_speedup"], 0)  # +50%
        self.assertEqual(len(paired["regressions"]), 0)


class TestEndToEnd(unittest.TestCase):
    def _run(self, root, extra_args=None):
        args = ["--runtime-path", str(root)] + (extra_args or [])
        return er.main(args)

    def test_clean_pr_faster_exit_0(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            files = {f"f{i}.smda": (["0x1000", "0x2000"], None) for i in range(4)}
            base = [{n: (a, 2.0) for n, (a, _) in files.items()} for _ in range(3)]
            pr = [{n: (a, 1.5) for n, (a, _) in files.items()} for _ in range(3)]
            self._make(root, base, pr)
            code = self._run(root)
            self.assertEqual(code, 0)
            model = json.loads((root / "cache" / "evaluation.json").read_text())
            self.assertTrue(model["correctness"]["pass"])
            self.assertGreater(model["performance"]["paired"]["median_speedup"], 0)
            # Markdown table stays contiguous (header + 2 side rows, no interleaving)
            md = (root / "cache" / "evaluation.md").read_text()
            self.assertIn("#### Correctness", md)
            self.assertIn("Wilcoxon signed-rank p", md)

    def test_correctness_regression_exit_1(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            base = [{"f0.smda": (["0x1", "0x2"], 1.0)} for _ in range(3)]
            pr = [{"f0.smda": (["0x1"], 1.0)} for _ in range(3)]  # PR dropped 0x2
            self._make(root, base, pr)
            self.assertEqual(self._run(root), 1)

    def test_base_nondeterminism_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            base = [
                {"f0.smda": (["0x1", "0x2"], 1.0)},
                {"f0.smda": (["0x1"], 1.0)},  # base disagrees with itself
                {"f0.smda": (["0x1", "0x2"], 1.0)},
            ]
            pr = [{"f0.smda": (["0x1", "0x2"], 1.0)} for _ in range(3)]
            self._make(root, base, pr)
            self.assertEqual(self._run(root), 2)

    def test_no_data_exit_0_and_require_data_exit_3(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)  # exists but contains no base_*/pr_* folders
            self.assertEqual(self._run(root), 0)
            self.assertEqual(self._run(root, ["--require-data"]), 3)

    def test_no_gate_never_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            base = [{"f0.smda": (["0x1", "0x2"], 1.0)} for _ in range(3)]
            pr = [{"f0.smda": (["0x1"], 1.0)} for _ in range(3)]
            self._make(root, base, pr)
            self.assertEqual(self._run(root, ["--no-gate"]), 0)

    def test_nested_artifact_layout_is_discovered(self):
        # Simulate download-artifact nesting runs under per-artifact subdirs.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for i in range(3):
                _write_report(root / "smda-base" / f"base_{i}", "f0", ["0x1", "0x2"], 2.0)
                _write_report(root / "smda-pr" / f"pr_{i}", "f0", ["0x1", "0x2"], 1.0)
            self.assertEqual(self._run(root), 0)
            model = json.loads((root / "cache" / "evaluation.json").read_text())
            self.assertEqual(model["correctness"]["n_common"], 1)

    @staticmethod
    def _make(root, base_runs, pr_runs):
        _make_runtime(root, base_runs, pr_runs)


if __name__ == "__main__":
    unittest.main()
