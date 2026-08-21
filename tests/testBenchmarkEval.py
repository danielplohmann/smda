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
    with open(folder / f"{name}.smda", "w", encoding="utf-8") as f:
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

    def test_pairwise_matrix_reports_every_run_combination(self):
        base = {
            "base_0": {"a.smda": self._rep(["0x1"], 2.0)},
            "base_1": {"a.smda": self._rep(["0x1"], 4.0)},
        }
        pr = {
            "pr_0": {"a.smda": self._rep(["0x1"], 1.0)},
            "pr_1": {"a.smda": self._rep(["0x1"], 3.0)},
        }

        rows = er.build_pairwise_matrix(base, pr)

        self.assertEqual(
            [r["comparison"] for r in rows], ["pr_0 vs base_0", "pr_0 vs base_1", "pr_1 vs base_0", "pr_1 vs base_1"]
        )
        self.assertEqual(rows[0]["function_set_matches"], 1)
        self.assertEqual(rows[0]["common_files"], 1)
        self.assertEqual(rows[0]["speedup_pct"], 50.0)


class TestNoiseAwareVerdict(unittest.TestCase):
    def _paired(self, base_t, pr_t):
        speedups = [(b - p) / b * 100.0 for b, p in zip(base_t, pr_t, strict=False)]
        return {"speedups": speedups, "base_times": base_t, "pr_times": pr_t}

    def test_small_consistent_diff_within_noise_is_inconclusive(self):
        paired = self._paired([1.0] * 12, [1.017] * 12)  # ~-1.7% consistent slowdown
        within = er.compute_paired_stats(paired, noise_floor_pct=4.0)
        self.assertIn("inconclusive", within["verdict"])
        # With no noise floor, the same consistent diff reads as a (spurious) regression.
        strict = er.compute_paired_stats(paired, noise_floor_pct=0.0)
        self.assertEqual(strict["verdict"], "PR is slower")

    def test_large_diff_beyond_noise_is_reported(self):
        paired = self._paired([2.0] * 12, [1.0] * 12)  # +50%, well beyond noise
        stats = er.compute_paired_stats(paired, noise_floor_pct=4.0)
        self.assertEqual(stats["verdict"], "PR is faster")


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
            model = json.loads((root / "cache" / "evaluation.json").read_text(encoding="utf-8"))
            self.assertTrue(model["correctness"]["pass"])
            self.assertGreater(model["performance"]["paired"]["median_speedup"], 0)
            # Markdown table stays contiguous (header + 2 side rows, no interleaving)
            md = (root / "cache" / "evaluation.md").read_text(encoding="utf-8")
            self.assertIn("#### Summary", md)
            self.assertIn("Median paired speedup", md)
            self.assertIn("Throughput estimate (func/s)", md)
            self.assertIn("Wilcoxon signed-rank p", md)
            self.assertIn("<summary>Pairwise run matrix (individual run medians, diagnostic)</summary>", md)
            self.assertIn("Diagnostic only", md)
            self.assertIn("pr_0 vs base_0", md)

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
            model = json.loads((root / "cache" / "evaluation.json").read_text(encoding="utf-8"))
            self.assertEqual(model["correctness"]["n_common"], 1)

    @staticmethod
    def _make(root, base_runs, pr_runs):
        _make_runtime(root, base_runs, pr_runs)


def _function(addr, instructions, inrefs=(), outrefs=None):
    """One xcfg entry: `instructions` is [(addr, mnemonic), ...] laid out in one block."""
    return {
        "blocks": {str(addr): [[a, "90", m, ""] for a, m in instructions]},
        "inrefs": list(inrefs),
        "outrefs": outrefs or {},
        "blockrefs": {},
    }


def _write_cfg(folder: Path, name: str, functions):
    folder.mkdir(parents=True, exist_ok=True)
    data = {"execution_time": 1.0, "xcfg": {str(a): f for a, f in functions.items()}}
    with open(folder / name, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


class TestChangedAddressLabels(unittest.TestCase):
    """The label rules are ordered, and the order is what makes them right."""

    BASE = {"absorbed_by": None, "inrefs": 0, "ends_in_return": False, "misaligned_overlap": 0}

    def _label(self, dropped=True, **overrides):
        return er.label_changed_address({**self.BASE, **overrides}, dropped=dropped)

    def test_padding_read_at_the_wrong_offset_reads_as_a_false_positive(self):
        self.assertEqual(self._label(), "likely_false_positive")

    def test_a_whole_routine_reads_as_a_loss(self):
        self.assertEqual(self._label(ends_in_return=True), "likely_loss")

    def test_a_referenced_address_reads_as_a_loss_however_its_body_ends(self):
        """A function ending in a tail-call `jmp`, inside a region the other side decodes
        differently, is still a function when something calls it - the body rules alone would
        call this padding."""
        self.assertEqual(self._label(inrefs=5, ends_in_return=False, misaligned_overlap=21), "likely_loss")

    def test_a_return_inside_a_differently_decoded_extent_is_not_a_loss(self):
        """A `ret` byte falls out of almost any run of data, so it only counts when the other
        side does not decode different instructions across the same bytes."""
        self.assertEqual(self._label(ends_in_return=True, misaligned_overlap=40), "likely_false_positive")

    def test_still_decoded_elsewhere_is_a_boundary_move_not_a_loss(self):
        self.assertEqual(self._label(absorbed_by=0x401000), "absorbed")

    def test_the_same_signals_read_the_other_way_for_an_added_address(self):
        self.assertEqual(self._label(absorbed_by=0x401000, dropped=False), "split_out")
        self.assertEqual(self._label(inrefs=1, dropped=False), "likely_recovery")
        self.assertEqual(self._label(dropped=False), "likely_new_false_positive")


class TestChangedAddressSignals(unittest.TestCase):
    def test_signals_are_read_from_the_two_reports(self):
        xcfg = {
            "1000": _function(1000, [(1000, "push"), (1002, "ret")], inrefs=[900], outrefs={"1000": [2000]}),
        }
        other_owner = {2000: 1900, 1001: 1001}
        signals = er.describe_changed_address(1000, xcfg, other_owner, sorted(other_owner))

        self.assertEqual(signals["inrefs"], 1)
        self.assertEqual(signals["instructions"], 2)
        self.assertTrue(signals["ends_in_return"])
        self.assertIsNone(signals["absorbed_by"])
        self.assertEqual(signals["branches_into_survivor_interior"], 1)
        self.assertEqual(signals["misaligned_overlap"], 1)

    def test_a_prefixed_return_still_counts_as_a_return(self):
        xcfg = {"1000": _function(1000, [(1000, "bnd ret")])}
        signals = er.describe_changed_address(1000, xcfg, {}, [])

        self.assertTrue(signals["ends_in_return"])

    def test_an_address_the_report_does_not_carry_is_skipped(self):
        self.assertIsNone(er.describe_changed_address(1000, {}, {}, []))


class TestClassifyRegressions(unittest.TestCase):
    def test_each_kind_of_change_is_labelled_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = {
                0x1000: _function(0x1000, [(0x1000, "push"), (0x1002, "ret")]),
                0x2000: _function(0x2000, [(0x2000, "add"), (0x2002, "add")]),
                0x3000: _function(0x3000, [(0x3000, "push"), (0x3002, "ret")]),
            }
            # 0x1000 survives; 0x2000 is padding; 0x3000 is still decoded inside 0x1000.
            pr = {
                0x1000: _function(0x1000, [(0x1000, "push"), (0x1002, "ret"), (0x3000, "push")]),
                0x4000: _function(0x4000, [(0x4000, "push"), (0x4002, "ret")], inrefs=[0x1000]),
            }
            _write_cfg(root / "base_0", "s.smda", base)
            _write_cfg(root / "pr_0", "s.smda", pr)
            regressions = [
                {
                    "file": "s.smda",
                    "only_in_base": ["8192", "12288"],
                    "only_in_pr": ["16384"],
                }
            ]

            result = er.classify_regressions(regressions, root / "base_0", root / "pr_0")

            self.assertEqual(
                result["counts"],
                {"likely_false_positive": 1, "absorbed": 1, "likely_recovery": 1},
            )
            labels = {row["addr"]: row["label"] for row in result["files"][0]["addresses"]}
            self.assertEqual(labels[0x2000], "likely_false_positive")
            self.assertEqual(labels[0x3000], "absorbed")
            self.assertEqual(labels[0x4000], "likely_recovery")

    def test_hex_spelled_addresses_are_read_the_same_as_decimal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root / "base_0", "s.smda", {0x1000: _function(0x1000, [(0x1000, "add")])})
            _write_cfg(root / "pr_0", "s.smda", {})

            result = er.classify_regressions(
                [{"file": "s.smda", "only_in_base": ["0x1000"], "only_in_pr": []}],
                root / "base_0",
                root / "pr_0",
            )

            self.assertEqual(result["counts"], {"likely_false_positive": 1})

    def test_an_unreadable_report_costs_the_reading_and_not_the_run(self):
        """The section is evidence, not a gate, so a corrupt report must not fail the job."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root / "base_0", "s.smda", {0x1000: _function(0x1000, [(0x1000, "ret")])})
            (root / "pr_0").mkdir(parents=True, exist_ok=True)
            (root / "pr_0" / "s.smda").write_text("{not json", encoding="utf-8")

            result = er.classify_regressions(
                [{"file": "s.smda", "only_in_base": ["4096"], "only_in_pr": []}],
                root / "base_0",
                root / "pr_0",
            )

            self.assertEqual(result["counts"], {})

    def test_a_file_missing_from_a_side_is_skipped_rather_than_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cfg(root / "base_0", "s.smda", {0x1000: _function(0x1000, [(0x1000, "ret")])})
            (root / "pr_0").mkdir(parents=True, exist_ok=True)

            result = er.classify_regressions(
                [{"file": "s.smda", "only_in_base": ["4096"], "only_in_pr": []}],
                root / "base_0",
                root / "pr_0",
            )

            self.assertEqual(result["counts"], {})
            self.assertEqual(result["files"], [])


class TestClassificationMarkdown(unittest.TestCase):
    def test_nothing_is_rendered_without_a_classification(self):
        self.assertEqual(er._classification_lines({}), [])
        self.assertEqual(er._classification_lines({"counts": {}}), [])

    def test_losses_are_listed_with_the_evidence_for_calling_them_losses(self):
        classification = {
            "counts": {"likely_loss": 1, "likely_false_positive": 2},
            "note": "note",
            "files": [
                {
                    "file": "s.smda",
                    "addresses": [
                        {
                            "addr": 0xA65150,
                            "label": "likely_loss",
                            "inrefs": 0,
                            "instructions": 16,
                            "ends_in_return": True,
                        }
                    ],
                }
            ],
        }

        rendered = "\n".join(er._classification_lines(classification))

        self.assertIn("Likely false positives removed", rendered)
        self.assertIn("| Likely real functions lost | **1** |", rendered)
        self.assertIn("0xa65150", rendered)
        self.assertIn("not gated", rendered)


class TestClassificationReachesTheModel(unittest.TestCase):
    def test_the_report_model_carries_the_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(2):
                _write_cfg(
                    root / f"base_{i}",
                    "s.smda",
                    {
                        0x1000: _function(0x1000, [(0x1000, "ret")]),
                        0x2000: _function(0x2000, [(0x2000, "add")]),
                    },
                )
                _write_cfg(root / f"pr_{i}", "s.smda", {0x1000: _function(0x1000, [(0x1000, "ret")])})

            model, status = er.evaluate(root)

            self.assertEqual(status, "ok")
            self.assertEqual(model["correctness"]["classification"]["counts"], {"likely_false_positive": 1})


if __name__ == "__main__":
    unittest.main()
