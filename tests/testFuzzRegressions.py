#!/usr/bin/python
"""Smoke-test the fuzz target bodies and replay any pinned crash reproducers.

The fuzzers themselves only run on Linux CI (atheris ships no arm64/macOS
wheels), which makes the target bodies easy to break unnoticed by an unrelated
API change. These tests import them directly — no atheris needed — so a renamed
loader accessor or a changed report field fails here instead of silently
degrading every future fuzzing run.

Crash artifacts found by CI are committed under tests/fuzz_regressions/ in the
repository's XOR-obfuscated fixture form, named ``<target>_<slug>_xored``; each
one is replayed here and must pass.
"""

import logging
import os
import sys
import unittest
from pathlib import Path

logging.disable(logging.CRITICAL)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fuzzing"))

from targets import TARGETS  # noqa: E402

REGRESSION_DIR = Path(__file__).resolve().parent / "fuzz_regressions"

# Inputs that must not raise for any target: the empty buffer, a truncated
# header, a plausible magic, and non-binary text.
SMOKE_INPUTS = [
    b"",
    b"\x00",
    b"MZ",
    b"MZ" + b"\x00" * 4096,
    b"\x7fELF\x02\x01\x01" + b"\x00" * 512,
    b"dex\n035\x00" + b"\x00" * 512,
    b'{"architecture": "intel"}',
    b"not a binary at all",
    bytes(range(256)) * 4,
]


def decode_fixture(data, name):
    if not name.endswith("_xored"):
        return data
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


class SmdaFuzzTargetSmokeTest(unittest.TestCase):
    def test_targets_tolerate_smoke_inputs(self):
        for target_name, target in sorted(TARGETS.items()):
            for payload in SMOKE_INPUTS:
                with self.subTest(target=target_name, size=len(payload)):
                    target(payload)

    def test_every_target_has_an_entry_point(self):
        fuzzing_dir = REPO_ROOT / "fuzzing"
        for target_name in TARGETS:
            self.assertTrue(
                (fuzzing_dir / f"fuzz_{target_name}.py").is_file(),
                f"missing fuzzing/fuzz_{target_name}.py entry point",
            )

    def test_workflow_covers_every_target(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "fuzzing.yml").read_text()
        for target_name in TARGETS:
            self.assertIn(f"fuzz_{target_name}", workflow, f"target {target_name} is not fuzzed in CI")


class SmdaFuzzRegressionTest(unittest.TestCase):
    def test_pinned_crash_artifacts_replay_cleanly(self):
        if not REGRESSION_DIR.is_dir():
            self.skipTest("no fuzz_regressions directory")
        artifacts = sorted(path for path in REGRESSION_DIR.iterdir() if path.is_file() and path.suffix != ".md")
        if not artifacts:
            self.skipTest("no pinned fuzz crash artifacts")
        for path in artifacts:
            target_name = path.name.split("_", 1)[0]
            with self.subTest(artifact=path.name):
                self.assertIn(target_name, TARGETS, f"{path.name} does not name a known target")
                TARGETS[target_name](decode_fixture(path.read_bytes(), path.name))


if __name__ == "__main__":
    if os.environ.get("SMDA_FUZZ_VERBOSE"):
        logging.disable(logging.NOTSET)
    unittest.main()
