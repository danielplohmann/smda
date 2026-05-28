import json
import os
import shutil
import statistics
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

BENCHMARKS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../benchmarks"))
sys.path.insert(0, BENCHMARKS_DIR)

import compare_perf_gate  # noqa: E402
import profile_diagnostics  # noqa: E402
import smda_perf_runner  # noqa: E402


class TestPerformanceGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.corpus_dir = Path(self.temp_dir) / "corpus"
        self.corpus_dir.mkdir()
        self.output_dir = Path(self.temp_dir) / "output"
        self.output_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_target_filename_helpers(self):
        self.assertEqual(smda_perf_runner.parse_base_addr("dump_0x00400000"), 0x00400000)
        self.assertEqual(smda_perf_runner.parse_base_addr("dump7_0x00007ff712345678"), 0x00007FF712345678)
        self.assertEqual(smda_perf_runner.parse_base_addr("normal_file.exe"), 0)
        self.assertEqual(smda_perf_runner.get_bitness_from_filename("dump_0x00400000"), 32)
        self.assertEqual(smda_perf_runner.get_bitness_from_filename("dump_0x00007ff712345678"), 64)
        self.assertEqual(smda_perf_runner.get_bitness_from_filename("normal_file.exe"), 0)

    def test_discover_targets(self):
        (self.corpus_dir / "family_a").mkdir()
        (self.corpus_dir / "family_a" / "dump_0x00400000").write_bytes(b"MZ\x00\x00")
        (self.corpus_dir / "family_b").mkdir()
        (self.corpus_dir / "family_b" / "malware_unpacked").write_bytes(b"ELF\x00\x00")
        (self.corpus_dir / "family_b" / "random.txt").write_bytes(b"hello")

        targets = smda_perf_runner.discover_targets(self.corpus_dir)

        self.assertEqual([target.filename for target in targets], ["dump_0x00400000", "malware_unpacked"])
        self.assertEqual(targets[0].family, "family_a")
        self.assertEqual(targets[1].family, "family_b")

    def test_compare_helpers(self):
        self.assertEqual(compare_perf_gate.percent_delta(100.0, 110.0), 10.0)
        self.assertEqual(compare_perf_gate.percent_delta(100.0, 90.0), -10.0)
        self.assertEqual(compare_perf_gate.percent_delta(0.0, 50.0), 0.0)
        self.assertEqual(compare_perf_gate.format_seconds(1.2346), "1.235s")
        self.assertEqual(compare_perf_gate.format_percent(12.345), "+12.35%")
        self.assertEqual(compare_perf_gate.format_int_delta(10, 8), "-2")
        self.assertEqual(
            compare_perf_gate.status_text({"status_counts": {"ok": 5, "exception": 1}}), "exception:1, ok:5"
        )

    @patch("pyperf.BenchmarkSuite.load")
    def test_build_result_and_comment(self, mock_load):
        mock_bench_base = MagicMock()
        mock_bench_base.mean.return_value = 1.0
        mock_bench_base.stdev.return_value = 0.05
        mock_bench_head = MagicMock()
        mock_bench_head.mean.return_value = 1.04
        mock_bench_head.stdev.return_value = 0.04
        mock_suite_base = MagicMock()
        mock_suite_base.get_benchmarks.return_value = [mock_bench_base]
        mock_suite_head = MagicMock()
        mock_suite_head.get_benchmarks.return_value = [mock_bench_head]
        mock_load.side_effect = [mock_suite_base, mock_suite_head]

        base_summary_path = Path(self.temp_dir) / "base_summary.json"
        head_summary_path = Path(self.temp_dir) / "head_summary.json"
        base_summary_path.write_text(
            json.dumps(
                {
                    "total_report_execution_time": 10.0,
                    "target_count": 5,
                    "exception_count": 0,
                    "total_functions": 100,
                    "total_instructions": 500,
                    "max_rss_kb": 20000,
                    "status_counts": {"ok": 5},
                }
            ),
            encoding="utf-8",
        )
        head_summary_path.write_text(
            json.dumps(
                {
                    "total_report_execution_time": 10.2,
                    "target_count": 5,
                    "exception_count": 0,
                    "total_functions": 102,
                    "total_instructions": 510,
                    "max_rss_kb": 21000,
                    "status_counts": {"ok": 5},
                }
            ),
            encoding="utf-8",
        )
        args = MagicMock(
            base_pyperf=Path(self.temp_dir) / "base.pyperf.json",
            head_pyperf=Path(self.temp_dir) / "head.pyperf.json",
            base_summary=base_summary_path,
            head_summary=head_summary_path,
            threshold_percent=5.0,
        )

        result = compare_perf_gate.build_result(args)
        comment = compare_perf_gate.build_comment(result)

        self.assertFalse(result["failed"])
        self.assertEqual(result["result"], "PASS")
        self.assertAlmostEqual(result["pyperf"]["delta_percent"], 4.0)
        self.assertIn("1.000s +/- 0.050s", comment)
        self.assertIn("Artifacts include raw pyperf JSON", comment)

    @patch("pyperf.BenchmarkSuite.load")
    def test_single_value_pyperf_stdev_is_safe(self, mock_load):
        mock_bench = MagicMock()
        mock_bench.mean.return_value = 1.0
        mock_bench.stdev.side_effect = statistics.StatisticsError("not enough data")
        mock_suite = MagicMock()
        mock_suite.get_benchmarks.return_value = [mock_bench]
        mock_load.return_value = mock_suite

        self.assertEqual(compare_perf_gate.load_pyperf_mean(Path("suite.json")), (1.0, 0.0))

    def test_diagnostics_runner_args_include_manifest(self):
        args = MagicMock(
            repo=Path("/repo"),
            corpus_root=Path("/corpus"),
            manifest=Path("/corpus/manifest.jsonl"),
            limit=1,
        )

        command = profile_diagnostics.runner_args(args, Path("/out"))

        self.assertIn("smda_perf_runner.py", command[1])
        self.assertIn("--manifest", command)
        self.assertEqual(command[-1], "/corpus/manifest.jsonl")

    def test_diagnostics_summary_is_concise(self):
        profile_diagnostics.write_summary(self.output_dir, {"cprofile": {"status": "ok"}})

        summary = json.loads((self.output_dir / "diagnostics-summary.json").read_text(encoding="utf-8"))
        comment_text = (self.output_dir / "diagnostics-summary.md").read_text(encoding="utf-8")

        self.assertEqual(summary["cprofile"]["status"], "ok")
        self.assertIn("Failure diagnostics captured", comment_text)
        self.assertIn("Memray native allocation", comment_text)


if __name__ == "__main__":
    unittest.main()
