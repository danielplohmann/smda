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
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

logging.disable(logging.CRITICAL)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fuzzing"))

from minimize import failure_type, shrink  # noqa: E402
from prune_corpus import prune  # noqa: E402
from targets import (  # noqa: E402
    FUZZING_ALLOWED_OPERATIONAL_EXCEPTION_TYPES,
    FUZZING_DEFECT_EXCEPTION_TYPES,
    FUZZING_LOADER_EXCEPTION_TYPES,
    TARGETS,
    MachoFileLoader,
    PeFileLoader,
    _reraise_real_defect,
)

pytestmark = pytest.mark.slow

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
    @staticmethod
    def _apply_oracle(exception, allow_struct_error=False):
        try:
            raise exception
        except Exception as caught:
            _reraise_real_defect(caught, allow_struct_error=allow_struct_error)

    def test_fuzzing_oracle_separates_defects_from_parse_errors(self):
        for exception_type in FUZZING_DEFECT_EXCEPTION_TYPES:
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                self._apply_oracle(exception_type("defect"))

        allowed_exceptions = (
            ValueError("malformed input"),
            UnicodeDecodeError("utf-8", b"\x80", 0, 1, "invalid start byte"),
        )
        for exception in allowed_exceptions:
            with self.subTest(exception_type=type(exception).__name__):
                self._apply_oracle(exception)

        self._apply_oracle(struct.error("truncated structure"), allow_struct_error=True)
        with self.assertRaises(struct.error):
            self._apply_oracle(struct.error("truncated structure"))
        self.assertEqual(FUZZING_ALLOWED_OPERATIONAL_EXCEPTION_TYPES, (ValueError, UnicodeDecodeError))
        self.assertEqual(FUZZING_LOADER_EXCEPTION_TYPES, (struct.error,))

    def test_targets_tolerate_smoke_inputs(self):
        for target_name, target in sorted(TARGETS.items()):
            for payload in SMOKE_INPUTS:
                with self.subTest(target=target_name, size=len(payload)):
                    target(payload)

    def test_formats_target_rejects_cross_format_lief_results(self):
        cases = ((0, "mirai_x64_xored"), (1, "cutwail_xored"), (2, "mirai_x64_xored"))
        for selector, fixture_name in cases:
            with self.subTest(selector=selector, fixture=fixture_name):
                fixture_path = REPO_ROOT / "tests" / fixture_name
                payload = decode_fixture(fixture_path.read_bytes(), fixture_name)[:8192]
                TARGETS["formats"](bytes([selector]) + payload)

    def test_formats_target_narrows_struct_error_allowlist(self):
        with (
            patch.object(PeFileLoader, "mapBinary", side_effect=struct.error("PE defect")),
            self.assertRaises(struct.error),
        ):
            TARGETS["formats"](b"\x00")

        with patch.object(MachoFileLoader, "mapBinary", side_effect=struct.error("truncated Mach-O")):
            TARGETS["formats"](b"\x02")

    def test_report_target_reraises_defects_from_json_decode(self):
        with (
            patch("targets.json.loads", side_effect=RecursionError("decoder defect")),
            self.assertRaises(RecursionError),
        ):
            TARGETS["report"](b"{}")

    def test_every_target_has_an_entry_point(self):
        fuzzing_dir = REPO_ROOT / "fuzzing"
        for target_name in TARGETS:
            self.assertTrue(
                (fuzzing_dir / f"fuzz_{target_name}.py").is_file(),
                f"missing fuzzing/fuzz_{target_name}.py entry point",
            )

    def test_dictionary_uses_only_libfuzzer_escapes(self):
        """libFuzzer accepts \\xAB, \\\\ and \\" only; anything else aborts the run at startup."""
        dictionary = (REPO_ROOT / "fuzzing" / "smda.dict").read_text(encoding="utf-8")
        for number, line in enumerate(dictionary.splitlines(), 1):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            match = re.fullmatch(r'[A-Za-z0-9_]+="(.*)"', entry)
            self.assertIsNotNone(match, f'line {number} is not a name="token" entry: {entry}')
            body = match.group(1)
            index = 0
            while index < len(body):
                if body[index] != "\\":
                    index += 1
                    continue
                following = body[index + 1 : index + 2]
                if following == "x":
                    self.assertRegex(
                        body[index + 2 : index + 4],
                        r"^[0-9a-fA-F]{2}$",
                        f"line {number} has a malformed hex escape: {entry}",
                    )
                    index += 4
                    continue
                self.assertIn(following, ("\\", '"'), f"line {number} uses unsupported escape: {entry}")
                index += 2

    def test_workflow_covers_every_target(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "fuzzing.yml").read_text(encoding="utf-8")
        for target_name in TARGETS:
            self.assertIn(f"fuzz_{target_name}", workflow, f"target {target_name} is not fuzzed in CI")


class SmdaFuzzToolingTest(unittest.TestCase):
    """The atheris-free crash-handling tooling, which only ever runs on a finding."""

    def test_shrink_reduces_to_the_failing_core(self):
        def predicate(candidate):
            return b"\xde\xad" in candidate

        payload = bytes(64) + b"\xde\xad" + bytes(64)
        self.assertEqual(shrink(payload, predicate), b"\xde\xad")

    def test_shrink_keeps_input_when_nothing_can_be_removed(self):
        self.assertEqual(shrink(b"\xde\xad", lambda candidate: b"\xde\xad" in candidate), b"\xde\xad")

    def test_failure_type_classifies_by_exception_type(self):
        def raiser(_data):
            raise ValueError("boom")

        self.assertIs(failure_type(raiser, b""), ValueError)
        self.assertIsNone(failure_type(lambda _data: None, b""))

    def test_prune_caps_file_count_keeping_smallest(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp)
            for size in (10, 20, 30, 40):
                (corpus / f"input_{size}").write_bytes(bytes(size))
            kept, kept_bytes, removed = prune(corpus, max_files=2, max_bytes=10**6)
            self.assertEqual((kept, kept_bytes, removed), (2, 30, 2))
            self.assertEqual(sorted(path.name for path in corpus.iterdir()), ["input_10", "input_20"])

    def test_prune_caps_total_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp)
            for size in (10, 20, 30):
                (corpus / f"input_{size}").write_bytes(bytes(size))
            kept, kept_bytes, removed = prune(corpus, max_files=100, max_bytes=35)
            self.assertEqual((kept, kept_bytes, removed), (2, 30, 1))


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
