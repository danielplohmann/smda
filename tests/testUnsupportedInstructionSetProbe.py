import unittest
from pathlib import Path
from unittest import mock

import smda.common.instruction_set_probe as probe
from smda.common.instruction_set_probe import (
    MIN_RETURN_SITES,
    NEIGHBOURHOOD_BYTES,
    RETURN_SIGNATURES,
    WINDOW_BYTES,
    countCodeReturnSites,
    detectUnsupportedInstructionSet,
    looksLikeText,
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

OPENRISC_RETURN = RETURN_SIGNATURES["openrisc"][0][0]


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


def _plant(pattern, count, spacing, filler=b"\x00", size=None):
    """`count` copies of `pattern`, `spacing` bytes apart, in filler that is not text."""
    size = size if size is not None else count * spacing + spacing
    buffer = bytearray(filler * (size // len(filler) + 1))[:size]
    for index in range(count):
        offset = index * spacing
        buffer[offset : offset + len(pattern)] = pattern
    return bytes(buffer)


class ReturnSignatureCountTestSuite(unittest.TestCase):
    def test_only_aligned_occurrences_are_counted(self):
        buffer = b"\x00" + b"\x4e\x80\x00\x20" + b"\x00" * 3 + b"\x4e\x80\x00\x20"

        self.assertEqual(countCodeReturnSites(buffer, b"\x4e\x80\x00\x20", 4, 8), 1)
        self.assertEqual(countCodeReturnSites(buffer, b"\x4e\x80\x00\x20", 1, 8), 2)

    def test_a_missing_pattern_counts_zero(self):
        self.assertEqual(countCodeReturnSites(b"\x00" * 64, b"\x4e\x80\x00\x20", 4, 8), 0)

    def test_a_buffer_dense_in_misaligned_copies_counts_none(self):
        """The scan resumes at the next aligned offset rather than the next byte, so a buffer
        offering an occurrence at every position costs one step per aligned slot instead of
        one per occurrence. The count is what matters here; the cost is why."""
        buffer = b"\x00" + b"\x1d\xf0" * 4096

        self.assertEqual(countCodeReturnSites(buffer, b"\x1d\xf0", 2, 8), 0)

    def test_the_same_pattern_aligned_is_counted(self):
        """Positive control: the buffer above reads zero because of where the copies sit, not
        because the pattern is wrong."""
        buffer = b"\x1d\xf0" * 4096

        self.assertEqual(countCodeReturnSites(buffer, b"\x1d\xf0", 2, 10), 10)


class ProbeCapTestSuite(unittest.TestCase):
    """A buffer can hold an occurrence at every position while none of them is aligned, so
    skipping to the next aligned offset still leaves one step per aligned slot. The cap bounds
    that: reaching it means the buffer is denser in near-misses than any real code, and the
    answer stays silence."""

    CAP = 4

    def test_the_walk_gives_up_once_the_cap_is_reached(self):
        buffer = _plant(OPENRISC_RETURN, 64, 8)

        with mock.patch.object(probe, "MAX_PROBES", self.CAP):
            self.assertEqual(countCodeReturnSites(buffer, OPENRISC_RETURN, 4, 1000), self.CAP)

    def test_the_same_buffer_is_counted_in_full_without_the_cap(self):
        """Positive control: the buffer really does hold 64 of them, so the number above is
        the cap and not the buffer running out."""
        buffer = _plant(OPENRISC_RETURN, 64, 8)

        self.assertEqual(countCodeReturnSites(buffer, OPENRISC_RETURN, 4, 1000), 64)

    def test_a_capped_walk_names_no_instruction_set(self):
        """The cap decides towards silence: a buffer it cannot finish reading is not claimed."""
        buffer = _plant(OPENRISC_RETURN, MIN_RETURN_SITES * 4, 8)

        with mock.patch.object(probe, "MAX_PROBES", self.CAP):
            self.assertIsNone(detectUnsupportedInstructionSet(buffer))


class TextNeighbourhoodTestSuite(unittest.TestCase):
    """A return word surrounded by UTF-16 is a letter pair, not an instruction. This is what
    separates real foreign code from a text table: over the ten bundled foreign samples not
    one hit sits in a neighbourhood like this."""

    def test_utf16_little_endian_surroundings_are_text(self):
        buffer = b"D\x00H\x00" * 32

        self.assertTrue(looksLikeText(buffer, 64))

    def test_utf16_big_endian_surroundings_are_text(self):
        buffer = b"\x00D\x00H" * 32

        self.assertTrue(looksLikeText(buffer, 64))

    def test_binary_surroundings_are_not_text(self):
        """Positive control: the same hit offset in filler that is not text must be kept, or
        the veto would reject every signature everywhere."""
        buffer = _plant(OPENRISC_RETURN, 4, 64)

        self.assertFalse(looksLikeText(buffer, 64))

    def test_a_neighbourhood_too_short_to_judge_is_not_text(self):
        self.assertFalse(looksLikeText(b"D\x00H\x00", 0))


class WindowedReturnSiteCountTestSuite(unittest.TestCase):
    def test_hits_inside_the_range_are_counted_and_text_is_skipped(self):
        code = _plant(OPENRISC_RETURN, 4, 64)
        text = b"D\x00H\x00" * 64

        self.assertEqual(countCodeReturnSites(code, OPENRISC_RETURN, 4, 8), 4)
        self.assertEqual(countCodeReturnSites(text, OPENRISC_RETURN, 4, 8), 0)

    def test_counting_stops_at_the_limit(self):
        code = _plant(OPENRISC_RETURN, 16, 64)

        self.assertEqual(countCodeReturnSites(code, OPENRISC_RETURN, 4, 3), 3)


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
        self.assertIsNone(detectUnsupportedInstructionSet(_plant(OPENRISC_RETURN, MIN_RETURN_SITES - 1, 64)))

    def test_the_same_words_at_the_threshold_are_recognized(self):
        """Positive control for the threshold itself, so the case above cannot be passing
        because the pattern is wrong rather than because the count is too low."""
        self.assertEqual(detectUnsupportedInstructionSet(_plant(OPENRISC_RETURN, MIN_RETURN_SITES, 64)), "openrisc")

    def test_return_words_spread_wider_than_a_window_are_not_enough(self):
        """The bar is density within one window, not a total. Sixteen hits scattered through
        a megabyte is what a large dump of ordinary data looks like."""
        spread = _plant(OPENRISC_RETURN, MIN_RETURN_SITES, WINDOW_BYTES // 2)

        self.assertIsNone(detectUnsupportedInstructionSet(spread))

    def test_the_same_count_packed_into_one_window_is_recognized(self):
        """Positive control for the window: the same buffer size and the same number of hits,
        close enough together to be a code region rather than noise."""
        packed = _plant(OPENRISC_RETURN, MIN_RETURN_SITES, 64, size=MIN_RETURN_SITES * (WINDOW_BYTES // 2))

        self.assertEqual(detectUnsupportedInstructionSet(packed), "openrisc")


class TextTableFalsePositiveTestSuite(unittest.TestCase):
    """`\\x44\\x00\\x48\\x00` is the openrisc return word and "DH" in UTF-16LE. A real stripped
    x86-64 shared object carried 21 aligned copies in an index table, at the same density as
    the sparsest bundled foreign sample, and the probe refused a legitimate x86 dump."""

    def test_a_utf16_table_spelling_the_return_word_is_not_claimed(self):
        table = b"D\x00H\x00" * (WINDOW_BYTES // 4)

        self.assertIsNone(detectUnsupportedInstructionSet(table))

    def test_the_same_words_outside_text_are_claimed(self):
        """Positive control: the veto rejects the company the hits keep, not the hits."""
        code = _plant(OPENRISC_RETURN, MIN_RETURN_SITES, NEIGHBOURHOOD_BYTES * 4)

        self.assertEqual(detectUnsupportedInstructionSet(code), "openrisc")


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
