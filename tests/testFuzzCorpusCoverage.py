"""Smoke test for fuzzing/corpus_coverage.py.

It runs in a subprocess because it starts its own coverage.py measurement, which
would collide with pytest-cov's tracer in this process.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import coverage

from smda.common.SmdaReport import SmdaReport

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "fuzzing" / "corpus_coverage.py"


def _run(*args):
    # keep pytest-cov's subprocess measurement from starting a second tracer
    env = {k: v for k, v in os.environ.items() if not k.startswith("COV_CORE_")}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, check=False, cwd=REPO_ROOT
    )


class TestCorpusCoverage(unittest.TestCase):
    def test_report_target_reaches_the_report_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "corpus"
            corpus.mkdir()
            (corpus / "a").write_bytes(json.dumps({"architecture": "intel", "functions": {}}).encode())
            (corpus / "b").write_bytes(b"not json")
            data_file = Path(tmp) / ".coverage.report"
            result = _run("report", str(corpus), "--data-file", str(data_file), "--report", str(Path(tmp) / "r.txt"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("report: replayed 2 inputs, 0 raised", result.stdout)

            data = coverage.CoverageData(basename=str(data_file))
            data.read()
            measured = {Path(f).name for f in data.measured_files()}
            self.assertIn("SmdaReport.py", measured)
            report_file = next(f for f in data.measured_files() if Path(f).name == "SmdaReport.py")
            entry = -SmdaReport.fromDict.__func__.__code__.co_firstlineno
            self.assertTrue(any(start == entry for start, _ in data.arcs(report_file)), "fromDict was never invoked")

    def test_unknown_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("nope", tmp, "--data-file", str(Path(tmp) / ".coverage"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown target", result.stderr)


if __name__ == "__main__":
    unittest.main()
