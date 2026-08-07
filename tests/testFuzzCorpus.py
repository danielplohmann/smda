"""Guards on the committed fuzz corpus floor (tests/fuzz_corpus/).

The floor exists so a fuzzing run starts from a known state even when the Actions cache
has evicted. That is only true if the entries stay restorable and stay inert at rest, so
both properties are asserted here rather than assumed.
"""

import logging
import sys
import unittest
from pathlib import Path

import pytest

logging.disable(logging.CRITICAL)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fuzzing"))

from restore_corpus import CORPUS_ROOT, deobfuscate, restore  # noqa: E402
from targets import TARGETS  # noqa: E402

pytestmark = pytest.mark.slow

MAX_TOTAL_BYTES = 1024 * 1024


class TestFuzzCorpusFloor(unittest.TestCase):
    def test_every_target_has_a_floor(self):
        for target in sorted(TARGETS):
            with self.subTest(target=target):
                entries = [p for p in (CORPUS_ROOT / target).iterdir() if p.is_file()]
                self.assertTrue(entries, f"no committed corpus floor for '{target}'")

    def test_the_floor_has_no_directory_for_an_unknown_target(self):
        for directory in CORPUS_ROOT.iterdir():
            if directory.is_dir():
                self.assertIn(directory.name, TARGETS)

    def test_entries_are_stored_obfuscated(self):
        for target in sorted(TARGETS):
            for entry in sorted((CORPUS_ROOT / target).iterdir()):
                if not entry.is_file():
                    continue
                with self.subTest(entry=f"{target}/{entry.name}"):
                    raw = entry.read_bytes()
                    if raw:
                        self.assertNotEqual(raw, deobfuscate(raw), "entry appears to be stored in the clear")

    def test_the_floor_stays_small(self):
        total = sum(p.stat().st_size for p in CORPUS_ROOT.rglob("*") if p.is_file())
        self.assertLess(total, MAX_TOTAL_BYTES, f"corpus floor grew to {total} bytes")

    def test_every_entry_replays_through_its_target(self):
        import tempfile

        for target in sorted(TARGETS):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                restored = restore(target, tmp)
                self.assertGreater(restored, 0)
                for entry in sorted(tmp.iterdir()):
                    TARGETS[target](entry.read_bytes())


if __name__ == "__main__":
    unittest.main()
