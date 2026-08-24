import struct
import traceback
import unittest
from pathlib import Path
from unittest import mock

import smda.aarch64.FunctionCandidateManager as arm64_candidates
from smda.aarch64.FunctionCandidateManager import (
    _ARM64_PDATA_ENTRY_SIZE,
    _ARM64_PDATA_MIN_ENTRIES,
    _ARM64_PDATA_SAMPLE_STRIDE,
    _ARM64_PDATA_SEED_ENTRIES,
    FunctionCandidateManager,
)
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig

IMAGE_BASE = 0x180000000
TEXT_RVA = 0x1000
PDATA_RVA = 0x4000
IMAGE_SIZE = 0x8000
RECORDS = 24

FRAME_PROLOGUE = 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!
RET = 0xD65F03C0
MOVZ_X16 = 0xD2800010 | (0x1234 << 5)  # movz x16, #0x1234
BR_X16 = 0xD61F0200
UNDEFINED = 0x00000000
PACKED_UNWIND = 0x01 | (2 << 2)  # flag 1, FunctionLength 2 words
PACKED_FRAGMENT = 0x02 | (2 << 2)  # flag 2, FunctionLength 2 words


def _config(**overrides):
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _mappedImage(entries, stride, records=RECORDS, pdata_rva=PDATA_RVA, size=IMAGE_SIZE):
    """A mapped ARM64 image with no container header, as a memory dump of one would be."""
    image = bytearray(size)
    body = b"".join(struct.pack("<" + "I" * len(entries), *entries) for _ in range(records))
    image[TEXT_RVA : TEXT_RVA + len(body)] = body
    pdata = b"".join(struct.pack("<II", TEXT_RVA + stride * i, PACKED_UNWIND) for i in range(records))
    image[pdata_rva : pdata_rva + len(pdata)] = pdata
    return bytes(image), [IMAGE_BASE + TEXT_RVA + stride * i for i in range(records)]


def _candidateManager(image):
    binary_info = BinaryInfo(image)
    binary_info.base_addr = IMAGE_BASE
    binary_info.bitness = 64
    binary_info.is_buffer = True
    binary_info.architecture = "aarch64"
    disassembly = DisassemblyResult()
    disassembly.setBinaryInfo(binary_info)
    manager = FunctionCandidateManager(_config())
    manager.init(disassembly, None)
    return manager


def _exceptionCandidates(manager):
    # entry-shaped words are also picked up by the prologue scanner, so membership in
    # candidates alone cannot show that the exception path ran
    return {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}


class Arm64ExceptionRecordCarvingTestSuite(unittest.TestCase):
    """A memory image keeps the mapped code but usually not a parseable header, so the
    exception directory cannot be read from a data directory and has to be found in the bytes.
    The x64 side has carved its RUNTIME_FUNCTION table since 4.4.7; ARM64 did not."""

    def test_records_are_recovered_from_a_headerless_image(self):
        image, starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)

        self.assertEqual(_exceptionCandidates(_candidateManager(image)), set(starts))

    def test_nothing_is_carved_when_the_source_is_disabled(self):
        """Positive control: the candidates above come from the exception path, not from the
        prologue scan happening to flag the same words."""
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)
        binary_info = BinaryInfo(image)
        binary_info.base_addr = IMAGE_BASE
        binary_info.bitness = 64
        binary_info.is_buffer = True
        binary_info.architecture = "aarch64"
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        manager = FunctionCandidateManager(_config(USE_PE_ARM64_PDATA_CANDIDATES=False))
        manager.init(disassembly, None)

        self.assertEqual(_exceptionCandidates(manager), set())

    def test_thunk_entries_are_recovered_that_nothing_else_reaches(self):
        """A two-word veneer separated by an undefined word is reachable neither by the
        prologue scan nor by a linear sweep, so the exception records are the only evidence
        it is a function at all."""
        image, starts = _mappedImage((MOVZ_X16, BR_X16, UNDEFINED), stride=12)
        report = Disassembler(config=_config()).disassembleBuffer(image, IMAGE_BASE, bitness=64, architecture="aarch64")

        self.assertEqual(report.status, "ok")
        self.assertEqual({function.offset for function in report.getFunctions()}, set(starts))

    def test_a_table_shorter_than_the_minimum_run_is_not_carved(self):
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, records=8)

        self.assertEqual(_exceptionCandidates(_candidateManager(image)), set())


class Arm64CarvedFragmentRecordTestSuite(unittest.TestCase):
    """A packed fragment continues another function's body, so its begin address is a mid-body
    word rather than a function start. The parsed exception-directory path skips flag 2 for
    that reason; the carve read the begin address alone and admitted it whenever the word it
    names happened to read as an entry."""

    FRAGMENT_INDEX = 5

    def _carved(self, unwind_data):
        image, starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)
        patched = bytearray(image)
        struct.pack_into("<I", patched, PDATA_RVA + self.FRAGMENT_INDEX * _ARM64_PDATA_ENTRY_SIZE + 4, unwind_data)
        return _exceptionCandidates(_candidateManager(bytes(patched))), starts

    def test_a_packed_fragment_record_is_not_admitted(self):
        carved, starts = self._carved(PACKED_FRAGMENT)

        self.assertEqual(carved, set(starts) - {starts[self.FRAGMENT_INDEX]})

    def test_the_same_record_is_admitted_when_it_names_a_whole_function(self):
        """Positive control: only the two flag bits differ, so the address dropped above is
        dropped for the flag and not because the record stopped validating or the word it
        names stopped reading as an entry."""
        carved, starts = self._carved(PACKED_UNWIND)

        self.assertEqual(carved, set(starts))


class Arm64SamplingStrideTestSuite(unittest.TestCase):
    def test_the_stride_cannot_step_over_a_qualifying_table(self):
        """The scan samples every _ARM64_PDATA_SAMPLE_STRIDE bytes and needs
        _ARM64_PDATA_SEED_ENTRIES consecutive records from wherever it lands, so a table at
        an arbitrary offset is only reachable while the stride fits inside what a shortest
        qualifying table leaves after the seed run. Widening the stride, or raising the seed
        length without raising the minimum, silently stops carving short tables."""
        reachable = (_ARM64_PDATA_MIN_ENTRIES - _ARM64_PDATA_SEED_ENTRIES) * _ARM64_PDATA_ENTRY_SIZE

        self.assertLessEqual(_ARM64_PDATA_SAMPLE_STRIDE, reachable)


class Arm64CarveBudgetTestSuite(unittest.TestCase):
    """A buffer that looks like one enormous exception table keeps the record walk inside a
    single call, where the sampling loop's own poll never comes round again."""

    POLL_INTERVAL = 4096

    def _longTable(self, records):
        size = 0x2000 + records * _ARM64_PDATA_ENTRY_SIZE + 0x1000
        image = bytearray(size)
        for index in range(records):
            struct.pack_into("<II", image, 0x2000 + index * _ARM64_PDATA_ENTRY_SIZE, 4 + index * 4, PACKED_UNWIND)
        return bytes(image)

    def test_the_record_walk_gives_up_when_the_budget_is_spent(self):
        image = self._longTable(self.POLL_INTERVAL * 2)
        manager = _candidateManager(_mappedImage((FRAME_PROLOGUE, RET), stride=8)[0])
        manager._cb_analysis_timeout = lambda: True

        counted = manager._countArm64ExceptionRecords(image, len(image), 0x2000, len(image))

        self.assertEqual(counted, self.POLL_INTERVAL)

    def test_the_same_walk_completes_within_budget(self):
        """Positive control: with the budget intact the walk counts every record, so the stop
        above is the poll rather than the records failing validation."""
        image = self._longTable(self.POLL_INTERVAL * 2)
        manager = _candidateManager(_mappedImage((FRAME_PROLOGUE, RET), stride=8)[0])
        manager._cb_analysis_timeout = None

        counted = manager._countArm64ExceptionRecords(image, len(image), 0x2000, len(image))

        self.assertEqual(counted, self.POLL_INTERVAL * 2)

    def test_the_admit_loop_gives_up_when_the_budget_is_spent(self):
        """The budget is intact while the table is being located and spent afterwards.

        Answering "spent" throughout would stop the locate instead, and the admit loop this
        is about would never run - the test would pass while proving nothing.
        """
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, records=64)
        manager = _candidateManager(image)
        manager.candidates = {}
        manager._cb_analysis_timeout = lambda: (
            not any(frame.name == "_locateArm64ExceptionRecordTable" for frame in traceback.extract_stack())
        )

        with mock.patch.object(arm64_candidates, "_TIMEOUT_POLL_INTERVAL", 4):
            manager._carveArm64ExceptionRecords(IMAGE_BASE)

        self.assertEqual(len(_exceptionCandidates(manager)), 4)

    def test_the_admit_loop_takes_every_record_within_budget(self):
        """Positive control for the loop itself: the same table admits all 64 when nothing
        stops it, so the count above is the poll and not the table being short."""
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, records=64)
        manager = _candidateManager(image)
        manager.candidates = {}
        manager._cb_analysis_timeout = None

        with mock.patch.object(arm64_candidates, "_TIMEOUT_POLL_INTERVAL", 4):
            manager._carveArm64ExceptionRecords(IMAGE_BASE)

        self.assertEqual(len(_exceptionCandidates(manager)), 64)


class Arm64CarveFalsePositiveTestSuite(unittest.TestCase):
    """The validator's bar is only meaningful if real AArch64 code and data does not clear it."""

    def test_real_aarch64_code_is_not_mistaken_for_an_exception_table(self):
        fixture = Path(__file__).resolve().parent / "aarch64_static_xored"
        raw = bytes(byte ^ (index % 256) for index, byte in enumerate(fixture.read_bytes()))
        manager = _candidateManager(raw)

        self.assertEqual(manager._locateArm64ExceptionRecordTable(raw), (0, 0))
        self.assertEqual(_exceptionCandidates(manager), set())

    def test_no_bundled_non_arm64_image_holds_a_qualifying_table(self):
        """Measured more widely than this: over 2961 files (the bundled fixtures, 50 locally
        built x86 binaries and the system libraries on one machine) the scan located a
        qualifying run in 51, all of them x86, and the entry-shape gate admitted a candidate
        from none of them. Those files also all carry a section table, so the carve - which
        only runs on a headerless image - never reaches them at all."""
        for name in ("mirai_x64_xored", "mirai_i386_xored", "cutwail_xored", "rust_pe_gnu_xored"):
            with self.subTest(fixture=name):
                fixture = Path(__file__).resolve().parent / name
                raw = bytes(byte ^ (index % 256) for index, byte in enumerate(fixture.read_bytes()))
                manager = FunctionCandidateManager(_config())
                manager.disassembly = None
                manager._cb_analysis_timeout = None

                self.assertEqual(manager._locateArm64ExceptionRecordTable(raw), (0, 0))

    def test_the_same_buffer_with_a_planted_table_is_carved(self):
        """Positive control: the fixture is not simply too small or unreadable for the carve."""
        fixture = Path(__file__).resolve().parent / "aarch64_static_xored"
        raw = bytearray(byte ^ (index % 256) for index, byte in enumerate(fixture.read_bytes()))
        planted_at = len(raw) - RECORDS * _ARM64_PDATA_ENTRY_SIZE - 0x100
        for index in range(RECORDS):
            struct.pack_into("<II", raw, planted_at + index * _ARM64_PDATA_ENTRY_SIZE, 4 + index * 4, PACKED_UNWIND)

        offset, count = _candidateManager(bytes(raw))._locateArm64ExceptionRecordTable(bytes(raw))

        self.assertEqual((offset, count), (planted_at, RECORDS))


class Arm64ExceptionRecordValidationTestSuite(unittest.TestCase):
    def _manager(self):
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)
        return _candidateManager(image), image

    def test_a_well_formed_record_reads_back(self):
        manager, image = self._manager()

        self.assertEqual(
            manager._readArm64ExceptionRecord(image, len(image), PDATA_RVA, 0),
            (TEXT_RVA, PACKED_UNWIND),
        )

    def test_records_that_do_not_advance_are_rejected(self):
        manager, image = self._manager()

        self.assertIsNone(manager._readArm64ExceptionRecord(image, len(image), PDATA_RVA, TEXT_RVA))

    def test_a_reserved_unwind_flag_is_rejected(self):
        manager, image = self._manager()
        record = bytearray(image)
        struct.pack_into("<II", record, PDATA_RVA, TEXT_RVA, 0x3)

        self.assertIsNone(manager._readArm64ExceptionRecord(bytes(record), len(record), PDATA_RVA, 0))

    def test_a_misaligned_begin_address_is_rejected(self):
        manager, _image = self._manager()
        record = struct.pack("<II", TEXT_RVA + 1, PACKED_UNWIND)

        self.assertIsNone(manager._readArm64ExceptionRecord(record, 0x8000, 0, 0))

    def test_a_zero_begin_address_is_rejected(self):
        manager, _image = self._manager()
        record = struct.pack("<II", 0, PACKED_UNWIND)

        self.assertIsNone(manager._readArm64ExceptionRecord(record, 0x8000, 0, 0))

    def test_a_packed_record_of_zero_length_is_rejected(self):
        manager, _image = self._manager()
        record = struct.pack("<II", TEXT_RVA, 0x1)

        self.assertIsNone(manager._readArm64ExceptionRecord(record, 0x8000, 0, 0))

    def test_a_truncated_record_is_rejected(self):
        manager, image = self._manager()

        self.assertIsNone(manager._readArm64ExceptionRecord(image, len(image), len(image) - 4, 0))

    def test_an_xdata_pointer_outside_the_image_is_rejected(self):
        manager, image = self._manager()
        record = bytearray(image)
        struct.pack_into("<II", record, PDATA_RVA, TEXT_RVA, len(image) + 0x10)

        self.assertIsNone(manager._readArm64ExceptionRecord(bytes(record), len(record), PDATA_RVA, 0))

    def test_an_unreadable_xdata_header_is_rejected(self):
        """flag 0 points at a full .xdata record, whose header word has to declare version 0
        and a non-zero length; a pointer into zeroed bytes declares neither."""
        manager, image = self._manager()
        record = bytearray(image)
        struct.pack_into("<II", record, PDATA_RVA, TEXT_RVA, 0x6000)

        self.assertIsNone(manager._readArm64ExceptionRecord(bytes(record), len(record), PDATA_RVA, 0))

    def test_a_well_formed_xdata_header_is_accepted(self):
        """Positive control for the arm above: the same record with a valid .xdata header
        reads back, so the rejection is the header check and not the flag-0 path failing."""
        manager, image = self._manager()
        record = bytearray(image)
        struct.pack_into("<II", record, PDATA_RVA, TEXT_RVA, 0x6000)
        struct.pack_into("<I", record, 0x6000, 0x4)

        self.assertEqual(
            manager._readArm64ExceptionRecord(bytes(record), len(record), PDATA_RVA, 0),
            (TEXT_RVA, 0x6000),
        )

    def test_a_zero_unwind_pointer_is_rejected(self):
        manager, image = self._manager()
        record = bytearray(image)
        struct.pack_into("<II", record, PDATA_RVA, TEXT_RVA, 0)

        self.assertIsNone(manager._readArm64ExceptionRecord(bytes(record), len(record), PDATA_RVA, 0))

    def test_the_table_is_found_from_a_sample_landing_inside_it(self):
        """The scan samples at a stride, so it usually lands mid-table and has to walk back to
        the real first entry; a table that begins off-stride is what exercises that walk."""
        image, starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, pdata_rva=PDATA_RVA + 8)
        manager = _candidateManager(image)

        self.assertEqual(_exceptionCandidates(manager), set(starts))
        self.assertEqual(manager._locateArm64ExceptionRecordTable(image), (PDATA_RVA + 8, RECORDS))

    def test_a_spent_budget_stops_the_table_scan(self):
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)
        manager = _candidateManager(image)
        manager._cb_analysis_timeout = lambda: True

        self.assertEqual(manager._locateArm64ExceptionRecordTable(image), (0, 0))

    def test_no_qualifying_run_yields_no_table(self):
        manager, _image = self._manager()

        self.assertEqual(manager._locateArm64ExceptionRecordTable(b"\x00" * 0x400), (0, 0))


class Arm64CarvedRecordAdmissionTestSuite(unittest.TestCase):
    def _manager(self):
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8)
        return _candidateManager(image)

    def test_a_record_naming_a_mid_body_word_is_not_admitted(self):
        """Exception records also name funclets and fragments, whose begin address continues
        the enclosing function; seeding one as a start would split a real function."""
        manager = self._manager()
        before = _exceptionCandidates(manager)
        manager._admitCarvedExceptionRecord(IMAGE_BASE, TEXT_RVA + 4)

        self.assertEqual(_exceptionCandidates(manager), before)

    def test_a_record_naming_an_entry_word_is_admitted(self):
        """Positive control: the same call on an entry-shaped word does add a candidate, so
        the rejection above is the entry-shape gate rather than the call doing nothing."""
        # a table below the minimum run is not carved, so nothing is flagged up front
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, records=8)
        manager = _candidateManager(image)
        self.assertEqual(_exceptionCandidates(manager), set())
        manager._admitCarvedExceptionRecord(IMAGE_BASE, TEXT_RVA)

        self.assertEqual(_exceptionCandidates(manager), {IMAGE_BASE + TEXT_RVA})

    def test_a_begin_address_too_close_to_the_end_is_not_admitted(self):
        """A buffer whose length is not a multiple of the instruction size can hold a
        4-aligned address with fewer than four bytes behind it."""
        image, _starts = _mappedImage((FRAME_PROLOGUE, RET), stride=8, size=IMAGE_SIZE - 2)
        manager = _candidateManager(image)
        before = _exceptionCandidates(manager)
        manager._admitCarvedExceptionRecord(IMAGE_BASE, IMAGE_SIZE - 4)

        self.assertEqual(_exceptionCandidates(manager), before)


if __name__ == "__main__":
    unittest.main()
