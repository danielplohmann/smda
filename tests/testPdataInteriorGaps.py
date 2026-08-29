#!/usr/bin/python
"""Gap candidates the PE exception directory places inside a function.

A 64-bit PE names one RUNTIME_FUNCTION per function, each carrying the extent the
unwinder needs. An address strictly inside one of those extents belongs to a routine
that starts earlier, so it is not an entry -- but nothing references it and no earlier
flow reaches it, which is exactly the shape the gap scan books.

Builds a minimal spec-valid PE32+ x86-64 image (4-byte e_lfanew, real PE\\0\\0 signature
per the repo's PE fixture convention) with .text, .pdata and .xdata, so the rule can be
driven end to end rather than only at the lookup.
"""

import struct
import tempfile
import unittest

from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

IMAGE_BASE = 0x140000000
TEXT_RVA, PDATA_RVA, XDATA_RVA = 0x1000, 0x2000, 0x3000
FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000

#: UNWIND_INFO byte 0 packs Version (bits 0-2) and Flags (bits 3-7). 0x01 is version 1
#: with no flags; 0x21 sets UNW_FLAG_CHAININFO, which marks the record a fragment of
#: another function rather than a function of its own.
UNWIND_PRIMARY, UNWIND_CHAINED = 0x01, 0x21
UNWIND_PRIMARY_RVA, UNWIND_CHAINED_RVA = XDATA_RVA, XDATA_RVA + 4

#: push rbp; mov rbp,rsp; pop rbp; ret -- what the prologue scan reads as an entry.
ENTRY_SHAPED = bytes((0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3))
#: mov eax,1; ret -- decodes and returns but opens with no prologue pattern, so the gap
#: scan is the only pass that books it. That is the population this rule is aimed at: on
#: the measured corpus the addresses it refuses are ones no prologue and no reference
#: reached, and widening it to the prologue scan would be a change nothing here measures.
GAP_SHAPED = bytes((0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3))
INT3 = b"\xcc"


def _build_pe(pdata_bytes, text_bytes, xdata_bytes=None, exc_size=None):
    """Minimal PE32+ x86-64 image: .text (RX) @0x1000, .pdata @0x2000, .xdata @0x3000."""
    if xdata_bytes is None:
        xdata_bytes = struct.pack("<BBBB", UNWIND_PRIMARY, 0, 0, 0) + struct.pack("<BBBB", UNWIND_CHAINED, 0, 0, 0)
    if exc_size is None:
        exc_size = len(pdata_bytes)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)  # e_lfanew

    coff = struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 240, 0x0022)

    data_dirs = [(0, 0)] * 16
    data_dirs[3] = (PDATA_RVA, exc_size)  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # magic PE32+
        14,
        0,  # linker versions
        len(text_bytes),
        0,
        0,  # sizes of code / initialized / uninitialized data
        TEXT_RVA,  # entrypoint
        TEXT_RVA,  # base of code
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # win32 version
        0x4000,  # size of image
        FILE_ALIGN,  # size of headers
        0,  # checksum
        3,
        0,  # subsystem CUI, dll characteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,  # stack/heap reserve+commit
        0,  # loader flags
        16,  # number of rva and sizes
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)

    def shdr(name, rva, vsize, raw_off, raw_size, characteristics):
        return struct.pack("<8sIIIIIIHHI", name, vsize, rva, raw_size, raw_off, 0, 0, 0, 0, characteristics)

    sections = (
        shdr(b".text", TEXT_RVA, len(text_bytes), 0x200, 0x200, 0x60000020)  # CODE|EXECUTE|READ
        + shdr(b".pdata", PDATA_RVA, max(len(pdata_bytes), 1), 0x400, 0x200, 0x40000040)
        + shdr(b".xdata", XDATA_RVA, max(len(xdata_bytes), 1), 0x600, 0x200, 0x40000040)
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    assert len(headers) <= FILE_ALIGN
    blob = bytearray(0x800)
    blob[0 : len(headers)] = headers
    blob[0x200 : 0x200 + len(text_bytes)] = text_bytes
    blob[0x400 : 0x400 + len(pdata_bytes)] = pdata_bytes
    blob[0x600 : 0x600 + len(xdata_bytes)] = xdata_bytes
    return bytes(blob)


def _record(begin_rva, end_rva, unwind_rva):
    return struct.pack("<III", begin_rva, end_rva, unwind_rva)


def _manager(blob, interior_gaps=True):
    loader = FileLoader("/", map_file=True)
    loader._loadFile(blob)
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    config = SmdaConfig()
    config.USE_PE_X64_PDATA_INTERIOR_GAPS = interior_gaps
    manager = FunctionCandidateManager(config)
    manager.init(disassembly)
    return manager


def _analyse(blob, interior_gaps=True):
    """Analyse through the file path, so the PE is mapped and .pdata sits at its RVA.

    disassembleBuffer would read the same bytes as one flat span at the load address and
    every RVA in the table would then name the wrong byte.
    """
    config = SmdaConfig()
    config.USE_PE_X64_PDATA_INTERIOR_GAPS = interior_gaps
    with tempfile.NamedTemporaryFile(suffix=".exe") as handle:
        handle.write(blob)
        handle.flush()
        return Disassembler(config=config).disassembleFile(handle.name)


#: .text layout shared by the end-to-end cases. A real entry at +0x00 that returns after
#: six bytes, an island at +0x20 that nothing reaches and only the gap scan books, and a
#: second real entry at +0x40. The first record's extent covers the island; the island is
#: the address the rule has to refuse.
ISLAND_RVA = TEXT_RVA + 0x20
SECOND_RVA = TEXT_RVA + 0x40
SHATTERED_TEXT = (
    ENTRY_SHAPED
    + INT3 * (0x20 - len(ENTRY_SHAPED))
    + GAP_SHAPED
    + INT3 * (0x20 - len(GAP_SHAPED))
    + ENTRY_SHAPED
    + INT3 * (0x20 - len(ENTRY_SHAPED))
)
#: one record covering [+0x00, +0x40) -- the island at +0x20 is interior to it -- and one
#: covering the second function, so the table is not a single span
SHATTERED_PDATA = _record(TEXT_RVA, SECOND_RVA, UNWIND_PRIMARY_RVA) + _record(
    SECOND_RVA, SECOND_RVA + 0x20, UNWIND_PRIMARY_RVA
)


class PdataInteriorGapEndToEndTestSuite(unittest.TestCase):
    def test_an_entry_shaped_island_inside_a_declared_extent_is_not_a_function(self):
        report = _analyse(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        offsets = {function.offset for function in report.getFunctions()}
        self.assertIn(IMAGE_BASE + TEXT_RVA, offsets)
        self.assertIn(IMAGE_BASE + SECOND_RVA, offsets)
        self.assertNotIn(IMAGE_BASE + ISLAND_RVA, offsets)

    def test_the_same_island_is_a_function_with_the_rule_off(self):
        # the control: without this rule nothing else in the engine refuses the island, so
        # the assertion above is measuring the rule and not some unrelated filter
        report = _analyse(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT), interior_gaps=False)
        self.assertIn(IMAGE_BASE + ISLAND_RVA, {function.offset for function in report.getFunctions()})

    def test_a_chained_records_own_first_byte_is_refused(self):
        # a chained record is a fragment of another function, so unlike a primary record
        # its BeginAddress is interior as well and must not survive as an entry
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA) + _record(
            ISLAND_RVA, SECOND_RVA, UNWIND_CHAINED_RVA
        )
        report = _analyse(_build_pe(pdata, SHATTERED_TEXT))
        offsets = {function.offset for function in report.getFunctions()}
        self.assertIn(IMAGE_BASE + TEXT_RVA, offsets)
        self.assertNotIn(IMAGE_BASE + ISLAND_RVA, offsets)

    def test_a_primary_extent_whose_function_never_analysed_refuses_nothing(self):
        # the record names an address in the .pdata section itself, which is not code, so
        # nothing recovers a function there; the extent must then say nothing about the
        # island and the gap scan keeps it
        pdata = _record(PDATA_RVA, SECOND_RVA + 0x20, UNWIND_PRIMARY_RVA)
        report = _analyse(_build_pe(pdata, SHATTERED_TEXT))
        self.assertIn(IMAGE_BASE + ISLAND_RVA, {function.offset for function in report.getFunctions()})

    def test_the_flag_is_on_by_default(self):
        self.assertTrue(SmdaConfig().USE_PE_X64_PDATA_INTERIOR_GAPS)


class DeclaredExceptionRangeTestSuite(unittest.TestCase):
    """The lookup on its own, where every branch can be reached with a chosen table."""

    def _lookup(self, ranges, addr):
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        manager._pdata_ranges = list(ranges)
        manager._pdata_range_starts = None
        return manager.declaredExceptionRangeContaining(addr)

    def test_an_address_inside_a_primary_extent_answers(self):
        self.assertEqual(self._lookup([(0x1000, 0x1040, False)], 0x1020), (0x1000, 0x1040, False))

    def test_a_primary_extents_own_start_is_an_entry_and_does_not_answer(self):
        self.assertIsNone(self._lookup([(0x1000, 0x1040, False)], 0x1000))

    def test_a_chained_extents_own_start_answers(self):
        self.assertEqual(self._lookup([(0x1000, 0x1040, True)], 0x1000), (0x1000, 0x1040, True))

    def test_an_address_past_every_extent_does_not_answer(self):
        self.assertIsNone(self._lookup([(0x1000, 0x1040, False), (0x1040, 0x1080, False)], 0x2000))

    def test_an_address_before_every_extent_does_not_answer(self):
        self.assertIsNone(self._lookup([(0x1000, 0x1040, False)], 0x800))

    def test_an_earlier_extent_still_reaching_the_address_answers(self):
        # unsorted and overlapping input is not what a linker emits, but the section path
        # does not validate the table, so the walk back has to survive it
        ranges = [(0x1000, 0x1100, False), (0x1020, 0x1030, False)]
        self.assertEqual(self._lookup(ranges, 0x1080), (0x1000, 0x1100, False))

    def test_a_gap_between_two_extents_does_not_answer(self):
        ranges = [(0x1000, 0x1040, False), (0x1080, 0x10C0, False)]
        self.assertIsNone(self._lookup(ranges, 0x1060))

    def test_an_empty_table_answers_nothing(self):
        self.assertIsNone(self._lookup([], 0x1020))

    def test_the_sorted_index_is_reused_across_lookups(self):
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        manager._pdata_ranges = [(0x1040, 0x1080, False), (0x1000, 0x1040, False)]
        manager._pdata_range_starts = None
        self.assertEqual(manager.declaredExceptionRangeContaining(0x1020), (0x1000, 0x1040, False))
        self.assertEqual(manager._pdata_range_starts, [0x1000, 0x1040])
        self.assertEqual(manager.declaredExceptionRangeContaining(0x1060), (0x1040, 0x1080, False))


class PdataRangeRecordingTestSuite(unittest.TestCase):
    def test_both_primary_and_chained_records_contribute_an_extent(self):
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA) + _record(
            ISLAND_RVA, SECOND_RVA, UNWIND_CHAINED_RVA
        )
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        self.assertEqual(
            sorted(manager._pdata_ranges),
            [
                (IMAGE_BASE + TEXT_RVA, IMAGE_BASE + TEXT_RVA + 0x20, False),
                (IMAGE_BASE + ISLAND_RVA, IMAGE_BASE + SECOND_RVA, True),
            ],
        )

    def test_only_the_primary_record_becomes_an_exception_candidate(self):
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA) + _record(
            ISLAND_RVA, SECOND_RVA, UNWIND_CHAINED_RVA
        )
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        booked = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertIn(IMAGE_BASE + TEXT_RVA, booked)
        self.assertNotIn(IMAGE_BASE + ISLAND_RVA, booked)

    def test_a_degenerate_record_contributes_no_extent(self):
        # EndAddress <= BeginAddress describes nothing; keeping it would put a zero-width
        # or inverted span in the table the walk back assumes is ordered
        pdata = _record(TEXT_RVA, TEXT_RVA, UNWIND_PRIMARY_RVA)
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        self.assertEqual(manager._pdata_ranges, [])

    def test_reinitialising_the_manager_drops_the_previous_images_extents(self):
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        self.assertTrue(manager._pdata_ranges)
        loader = FileLoader("/", map_file=True)
        loader._loadFile(_build_pe(_record(TEXT_RVA, TEXT_RVA, UNWIND_PRIMARY_RVA), SHATTERED_TEXT))
        disassembly = DisassemblyResult()
        disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
        manager.init(disassembly)
        self.assertEqual(manager._pdata_ranges, [])


if __name__ == "__main__":
    unittest.main()
