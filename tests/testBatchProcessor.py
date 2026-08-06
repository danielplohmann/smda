import json
import os
import shutil
import tempfile
import unittest

import pytest

from smda.SmdaConfig import SmdaConfig
from smda.utility.BatchProcessor import (
    collectInputFiles,
    deriveReportStem,
    disassembleParallel,
    getDefaultWorkerCount,
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


if __name__ == "__main__":
    unittest.main()
