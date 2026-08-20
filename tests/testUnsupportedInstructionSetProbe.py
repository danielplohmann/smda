import unittest
from pathlib import Path

from smda.common.instruction_set_probe import (
    MIN_RETURN_SITES,
    RETURN_SIGNATURES,
    countAlignedOccurrences,
    detectUnsupportedInstructionSet,
)
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

FIXTURES = Path(__file__).resolve().parent

# every bundled sample of an instruction set SMDA has no backend for
UNSUPPORTED_FIXTURES = {
    "mirai_arm_xored": "arm",
    "mirai_mips_xored": "mips",
    "mirai_mipsel_xored": "mips",
    "mirai_ppc_xored": "ppc",
    "mirai_sparc_xored": "sparc",
    "mirai_nios2_xored": "nios2",
    "mirai_openrisc_xored": "openrisc",
    "mirai_sh4_xored": "sh4",
    "mirai_m68k_xored": "m68k",
    "mirai_xtensa_xored": "xtensa",
}

# the instruction sets SMDA does have a backend for, which must never be claimed
SUPPORTED_FIXTURES = (
    "mirai_x64_xored",
    "mirai_i386_xored",
    "asprox_0x008D0000_xored",
    "cutwail_xored",
    "komplex_xored",
    "rust_pe_gnu_xored",
    "aarch64_static_xored",
    "blockblast_classes_xored",
    "njrat_xored",
)


def _load(name):
    data = (FIXTURES / name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _config():
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    return config


class ReturnSignatureCountTestSuite(unittest.TestCase):
    def test_only_aligned_occurrences_are_counted(self):
        buffer = b"\x00" + b"\x4e\x80\x00\x20" + b"\x00" * 3 + b"\x4e\x80\x00\x20"

        self.assertEqual(countAlignedOccurrences(buffer, b"\x4e\x80\x00\x20", 4), 1)
        self.assertEqual(countAlignedOccurrences(buffer, b"\x4e\x80\x00\x20", 1), 2)

    def test_a_missing_pattern_counts_zero(self):
        self.assertEqual(countAlignedOccurrences(b"\x00" * 64, b"\x4e\x80\x00\x20", 4), 0)


class UnsupportedInstructionSetDetectionTestSuite(unittest.TestCase):
    """Positive and negative controls together: without both, a probe that always answered
    "no" and one that always answered "yes" would each look correct from one side."""

    def test_every_unsupported_fixture_is_named(self):
        for name, expected in UNSUPPORTED_FIXTURES.items():
            with self.subTest(fixture=name):
                self.assertEqual(detectUnsupportedInstructionSet(_load(name)), expected)

    def test_no_supported_fixture_is_claimed(self):
        for name in SUPPORTED_FIXTURES:
            with self.subTest(fixture=name):
                self.assertIsNone(detectUnsupportedInstructionSet(_load(name)))

    def test_a_handful_of_return_words_is_below_the_threshold(self):
        pattern = RETURN_SIGNATURES["ppc"][0][0]
        buffer = pattern * (MIN_RETURN_SITES - 1)

        self.assertIsNone(detectUnsupportedInstructionSet(buffer))

    def test_the_same_words_at_the_threshold_are_recognized(self):
        """Positive control for the threshold itself, so the case above cannot be passing
        because the pattern is wrong rather than because the count is too low."""
        pattern = RETURN_SIGNATURES["ppc"][0][0]
        buffer = pattern * MIN_RETURN_SITES

        self.assertEqual(detectUnsupportedInstructionSet(buffer), "ppc")

    def test_return_words_too_sparse_for_the_buffer_are_ignored(self):
        pattern = RETURN_SIGNATURES["ppc"][0][0]
        buffer = pattern * MIN_RETURN_SITES + b"\x00" * (MIN_RETURN_SITES * 64 * 1024)

        self.assertIsNone(detectUnsupportedInstructionSet(buffer))


class UnsupportedBufferReportTestSuite(unittest.TestCase):
    """Analysing foreign machine code as intel returns a full report whose every block is
    wrong; naming the instruction set and refusing is the more useful answer."""

    def test_a_foreign_buffer_is_reported_as_an_error(self):
        report = Disassembler(config=_config()).disassembleBuffer(_load("mirai_ppc_xored"), 0x400000)

        self.assertEqual(report.status, "error")
        self.assertEqual(len(list(report.getFunctions())), 0)
        self.assertIn("ppc", report.message)

    def test_an_explicitly_named_architecture_still_wins(self):
        """A caller that hands foreign bytes to a named backend on purpose - the buffer fuzz
        target does exactly this - must not be overruled by the probe."""
        report = Disassembler(config=_config()).disassembleBuffer(
            _load("mirai_ppc_xored"), 0x400000, architecture="intel"
        )

        self.assertEqual(report.status, "ok")

    def test_an_x86_buffer_is_analysed_as_before(self):
        report = Disassembler(config=_config()).disassembleBuffer(_load("mirai_x64_xored"), 0x400000)

        self.assertEqual(report.status, "ok")
        self.assertGreater(len(list(report.getFunctions())), 0)


if __name__ == "__main__":
    unittest.main()
