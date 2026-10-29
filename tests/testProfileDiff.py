"""Tests for profiling/diff_profiles.py, the base-vs-PR cProfile comparison."""

import cProfile
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from profiling import diff_profiles  # noqa: E402


def _work(n):
    return sum(_step(i) for i in range(n))


def _step(i):
    return i * i


def _dump(directory, name, n):
    path = os.path.join(directory, name)
    profiler = cProfile.Profile()
    profiler.enable()
    _work(n)
    profiler.disable()
    profiler.dump_stats(path)
    return path


class TestProfileDiff(unittest.TestCase):
    def test_changed_call_count_is_reported_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            base = diff_profiles.load(_dump(d, "base.prof", 100))
            pr = diff_profiles.load(_dump(d, "pr.prof", 250))
        markdown = diff_profiles.diff(base, pr, top=10)
        self.assertIn("Largest call-count changes:", markdown)
        self.assertRegex(markdown, r"\| `_step` \S*testProfileDiff\.py \| 100 \| 250 \| \+150 \|")
        self.assertIn("| **250** |", markdown)

    def test_identical_counts_list_no_call_changes(self):
        with tempfile.TemporaryDirectory() as d:
            base = diff_profiles.load(_dump(d, "base.prof", 100))
            pr = diff_profiles.load(_dump(d, "pr.prof", 100))
        markdown = diff_profiles.diff(base, pr, top=10)
        self.assertIn("0 function(s) changed call count", markdown)
        self.assertNotIn("Largest call-count changes:", markdown)

    def test_checkout_path_and_line_are_left_out_of_the_key(self):
        base_key = ("/home/runner/work/smda/smda/base-repo/src/smda/common/Tarjan.py", 40, "closure")
        pr_key = ("/home/runner/work/smda/smda/src/smda/common/Tarjan.py", 52, "closure")
        self.assertEqual(diff_profiles._normalize(base_key), ("smda/common/Tarjan.py", "closure"))
        self.assertEqual(diff_profiles._normalize(base_key), diff_profiles._normalize(pr_key))
        site = ("/opt/py/lib/python3.11/site-packages/capstone/__init__.py", 1194, "disasm_lite")
        self.assertEqual(diff_profiles._normalize(site), ("site-packages/capstone/__init__.py", "disasm_lite"))

    def test_nested_base_checkout_lines_up_with_the_pr(self):
        base_key = ("/home/runner/work/smda/smda/base-repo/profiling/_target.py", 61, "decrypt_binary")
        pr_key = ("/home/runner/work/smda/smda/profiling/_target.py", 61, "decrypt_binary")
        self.assertEqual(diff_profiles._normalize(base_key), ("profiling/_target.py", "decrypt_binary"))
        self.assertEqual(diff_profiles._normalize(base_key), diff_profiles._normalize(pr_key))
        installed = ("/opt/py/lib/python3.11/site-packages/smda/common/Tarjan.py", 40, "closure")
        self.assertEqual(diff_profiles._normalize(installed), ("smda/common/Tarjan.py", "closure"))

    def test_object_addresses_are_left_out_of_the_name(self):
        base_key = ("~", 0, "<built-in method __new__ of type object at 0x7f1e604496e0>")
        pr_key = ("~", 0, "<built-in method __new__ of type object at 0x7f3aa00496e0>")
        self.assertEqual(diff_profiles._normalize(base_key), ("~", "<built-in method __new__ of type object>"))
        self.assertEqual(diff_profiles._normalize(base_key), diff_profiles._normalize(pr_key))


if __name__ == "__main__":
    unittest.main()
