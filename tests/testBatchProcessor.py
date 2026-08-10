import json
import os
import shutil
import tempfile
import unittest
from concurrent.futures import Future
from unittest import mock

import pytest

from smda.SmdaConfig import SmdaConfig
from smda.utility.BatchProcessor import (
    LARGE_INPUT_RSS_FACTOR,
    _inputSize,
    _largeWorkerCount,
    _runPartitions,
    collectInputFiles,
    deriveReportStem,
    disassembleParallel,
    getDefaultWorkerCount,
    getMemoryBudget,
)

pytestmark = pytest.mark.slow

FIXTURES = [
    "cutwail_xored",
    "bashlite_xored",
    "komplex_xored",
    "njrat_xored",
    "blockblast_classes_xored",
    "pe_export_label_test_xored",
]


def _decrypt(path):
    with open(path, "rb") as f_binary:
        binary = f_binary.read()
    return bytes(bytearray(byte ^ (index % 256) for index, byte in enumerate(binary)))


class TestBatchProcessor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # decrypted copies are written to a temp dir so the pool can read real files without
        # ever executing them
        config = SmdaConfig()
        cls.tmp_dir = tempfile.mkdtemp(prefix="smda_batch_")
        cls.input_dir = os.path.join(cls.tmp_dir, "inputs", "nested")
        os.makedirs(cls.input_dir)
        for name in FIXTURES:
            source = os.path.join(config.PROJECT_ROOT, "tests", name)
            with open(os.path.join(cls.input_dir, name), "wb") as f_out:
                f_out.write(_decrypt(source))
        cls.input_root = os.path.join(cls.tmp_dir, "inputs")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _run(self, **kwargs):
        output_dir = tempfile.mkdtemp(dir=self.tmp_dir)
        results = {}
        for summary in disassembleParallel([self.input_root], output_dir=output_dir, timeout=0, **kwargs):
            results[summary["report_stem"]] = summary
        return output_dir, results

    def test_pooled_output_matches_serial_output(self):
        _, serial = self._run(workers=1)
        _, pooled = self._run(workers=4)
        self.assertEqual(len(FIXTURES), len(serial))
        self.assertEqual(set(serial), set(pooled))
        for stem in serial:
            self.assertEqual(serial[stem]["report_hash"], pooled[stem]["report_hash"], stem)
            self.assertNotEqual("", serial[stem]["report_hash"], stem)

    def test_recycling_workers_does_not_change_output(self):
        _, pooled = self._run(workers=4)
        _, recycled = self._run(workers=4, max_tasks_per_child=1)
        for stem in pooled:
            self.assertEqual(pooled[stem]["report_hash"], recycled[stem]["report_hash"], stem)

    def test_reports_are_written_per_input_file(self):
        output_dir, results = self._run(workers=2)
        for stem, summary in results.items():
            expected = os.path.join(output_dir, stem + ".smda")
            self.assertEqual(expected, summary["output_path"])
            with open(expected, encoding="utf-8") as f_in:
                as_dict = json.load(f_in)
            self.assertEqual(summary["num_functions"], as_dict["statistics"]["num_functions"])

    def test_resume_skips_finished_reports(self):
        output_dir = tempfile.mkdtemp(dir=self.tmp_dir)
        first = list(disassembleParallel([self.input_root], output_dir=output_dir, workers=2, timeout=0))
        self.assertEqual(len(FIXTURES), len(first))
        second = list(disassembleParallel([self.input_root], output_dir=output_dir, workers=2, timeout=0, resume=True))
        self.assertEqual([], second)

    def test_return_reports_yields_picklable_reports(self):
        summaries = list(
            disassembleParallel(
                [os.path.join(self.input_dir, "cutwail_xored")],
                output_dir=None,
                workers=1,
                timeout=0,
                return_reports=True,
            )
        )
        self.assertEqual(1, len(summaries))
        self.assertIsNotNone(summaries[0]["report"])
        self.assertEqual(summaries[0]["num_functions"], summaries[0]["report"].num_functions)

    def test_missing_input_path_is_reported(self):
        with self.assertRaises(FileNotFoundError):
            list(disassembleParallel([os.path.join(self.tmp_dir, "does_not_exist")], workers=1))

    def test_report_stems_are_path_relative(self):
        collected = collectInputFiles([self.input_root])
        stems = [stem for _, stem in collected]
        self.assertEqual(len(stems), len(set(stems)))
        self.assertIn(os.path.join("nested", "cutwail_xored").replace(os.sep, "_"), stems)
        self.assertEqual("a_b_c", deriveReportStem("/root/a/b/c", "/root"))

    def test_default_worker_count_is_positive(self):
        self.assertGreaterEqual(getDefaultWorkerCount(), 1)

    def test_splitting_large_inputs_onto_their_own_pool_does_not_change_output(self):
        _, pooled = self._run(workers=4)
        _, split = self._run(workers=4, large_input_bytes=64 * 1024, memory_budget=1 << 30)
        self.assertEqual(set(pooled), set(split))
        for stem in pooled:
            self.assertEqual(pooled[stem]["report_hash"], split[stem]["report_hash"], stem)

    def test_a_single_worker_keeps_large_inputs_on_the_one_pool(self):
        _, serial = self._run(workers=1)
        _, split = self._run(workers=1, large_input_bytes=64 * 1024)
        for stem in serial:
            self.assertEqual(serial[stem]["report_hash"], split[stem]["report_hash"], stem)

    def test_collected_pairs_are_reused_instead_of_rewalking_the_tree(self):
        collected = collectInputFiles([self.input_root])
        summaries = list(disassembleParallel([], workers=1, timeout=0, collected=collected[:1]))
        self.assertEqual([collected[0][1]], [summary["report_stem"] for summary in summaries])

    def test_vanished_input_is_sized_as_small(self):
        self.assertEqual(0, _inputSize(os.path.join(self.tmp_dir, "does_not_exist")))


class _ScriptedExecutor:
    """Stands in for ProcessPoolExecutor so the parent-side wave loop can be driven without
    spawning workers. A task whose path ends in 'boom' resolves to a raised exception."""

    instances = []

    def __init__(self, max_workers=None, **kwargs):
        self.max_workers = max_workers
        self.peak_in_flight = 0
        self.submitted = []
        _ScriptedExecutor.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def submit(self, _func, task):
        self.submitted.append(task["path"])
        future = Future()
        if task["path"].endswith("boom"):
            future.set_exception(RuntimeError("worker died"))
        else:
            future.set_result({"path": task["path"], "status": "ok"})
        return future


class TestPartitionDriver(unittest.TestCase):
    def setUp(self):
        _ScriptedExecutor.instances = []

    @staticmethod
    def _task(path):
        return {"path": path, "report_stem": os.path.basename(path)}

    def _run(self, paths, workers=2):
        tasks = [self._task(path) for path in paths]
        with mock.patch("smda.utility.BatchProcessor.ProcessPoolExecutor", _ScriptedExecutor):
            return list(_runPartitions([(tasks, workers, None)]))

    def test_a_dead_worker_becomes_an_error_summary_instead_of_aborting_the_run(self):
        summaries = self._run(["/corpus/a", "/corpus/boom", "/corpus/b"])

        by_path = {summary["path"]: summary for summary in summaries}
        self.assertEqual({"/corpus/a", "/corpus/b", "/corpus/boom"}, set(by_path))
        self.assertEqual("ok", by_path["/corpus/a"]["status"])
        failed = by_path["/corpus/boom"]
        self.assertEqual("error", failed["status"])
        self.assertEqual("boom", failed["report_stem"])
        self.assertEqual("RuntimeError: worker died", failed["error"])
        self.assertIsNone(failed["report"])

    def test_every_task_is_yielded_once_when_the_corpus_exceeds_the_in_flight_limit(self):
        paths = [f"/corpus/{index:02d}" for index in range(20)]

        summaries = self._run(paths, workers=2)

        self.assertEqual(paths, sorted(summary["path"] for summary in summaries))
        self.assertEqual(len(paths), len(summaries))

    def test_a_batch_is_yielded_in_path_order(self):
        paths = ["/corpus/c", "/corpus/a", "/corpus/b"]

        summaries = self._run(paths, workers=8)

        self.assertEqual(["/corpus/a", "/corpus/b", "/corpus/c"], [summary["path"] for summary in summaries])


class TestLargePartitionSizing(unittest.TestCase):
    def test_budget_is_a_fraction_of_physical_memory(self):
        # os.sysconf is POSIX-only; on Windows the budget is unknown by design and the
        # worker count alone governs admission
        if hasattr(os, "sysconf"):
            self.assertGreater(getMemoryBudget(), 0)
        else:
            self.assertIsNone(getMemoryBudget())

    def test_budget_is_unknown_without_sysconf(self):
        # create=True so this also runs where the attribute never existed
        with mock.patch.object(os, "sysconf", None, create=True):
            self.assertIsNone(getMemoryBudget())

    def test_budget_is_unknown_when_sysconf_rejects_the_key(self):
        with mock.patch.object(os, "sysconf", side_effect=ValueError, create=True):
            self.assertIsNone(getMemoryBudget())

    def test_budget_caps_concurrency_below_the_worker_count(self):
        budget = 2 * (1 << 20) * LARGE_INPUT_RSS_FACTOR
        self.assertEqual(2, _largeWorkerCount(1 << 20, 8, 10, budget))

    def test_unknown_budget_leaves_the_worker_count_in_charge(self):
        self.assertEqual(4, _largeWorkerCount(1 << 20, 8, 4, 0))

    def test_one_worker_survives_an_unaffordable_input(self):
        self.assertEqual(1, _largeWorkerCount(1 << 30, 8, 10, 1))


class TestCollectInputFilesRoots(unittest.TestCase):
    def _write_sample(self, directory, name):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "wb") as f_out:
            f_out.write(b"MZ")
        return path

    def test_same_named_samples_in_separate_input_dirs_get_distinct_stems(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            first = os.path.join(tmp_dir, "first")
            second = os.path.join(tmp_dir, "second")
            self._write_sample(first, "sample.bin")
            self._write_sample(second, "sample.bin")

            stems = [stem for _, stem in collectInputFiles([first, second])]

            self.assertEqual(sorted(stems), ["first_sample.bin", "second_sample.bin"])

    def test_same_named_samples_passed_as_files_get_distinct_stems(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            first = self._write_sample(os.path.join(tmp_dir, "first"), "sample.bin")
            second = self._write_sample(os.path.join(tmp_dir, "second"), "sample.bin")

            stems = [stem for _, stem in collectInputFiles([first, second])]

            self.assertEqual(sorted(stems), ["first_sample.bin", "second_sample.bin"])

    def test_single_directory_still_relativizes_against_itself(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self._write_sample(os.path.join(tmp_dir, "only"), "sample.bin")

            stems = [stem for _, stem in collectInputFiles([os.path.join(tmp_dir, "only")])]

            self.assertEqual(stems, ["sample.bin"])


if __name__ == "__main__":
    unittest.main()
