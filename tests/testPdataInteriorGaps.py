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

import os
import struct
import tempfile
import unittest
from unittest import mock

import smda.intel.FunctionCandidateManager as intel_candidates
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import _PDATA_MIN_ENTRIES, FunctionCandidateManager
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


def _headerlessManager(records):
    """A manager over a buffer with no container, the shape a memory dump arrives in.

    The exception table has to be found in the bytes because there is no section header
    naming it, which is the path this exercises. Bitness is stated rather than read, as
    `disassembleBuffer` does for a dump, because nothing in the buffer declares it.
    """
    blob = bytearray(0x10000)
    body = ENTRY_SHAPED + INT3 * (0x20 - len(ENTRY_SHAPED))
    blob[TEXT_RVA : TEXT_RVA + 0x20 * _PDATA_MIN_ENTRIES] = body * _PDATA_MIN_ENTRIES
    blob[UNWIND_PRIMARY_RVA] = UNWIND_PRIMARY
    blob[0x5000 : 0x5000 + len(records)] = records
    loader = FileLoader("/", map_file=True)
    loader._loadFile(bytes(blob))
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    disassembly.binary_info.bitness = 64
    manager = FunctionCandidateManager(SmdaConfig())
    manager.init(disassembly)
    return manager


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
    # written into a directory rather than through NamedTemporaryFile: Windows keeps that
    # handle exclusive, so the analysis cannot open the path and reports nothing at all
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "fixture.exe")
        with open(path, "wb") as handle:
            handle.write(blob)
        return Disassembler(config=config).disassembleFile(path)


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
        """The recovered-function guard, exercised where the extent really does cover the island.

        An earlier version of this pointed the record at the `.pdata` section itself, which
        put End below Begin - so the extent was refused as untrustworthy and never recorded,
        and the assertion held for a reason that had nothing to do with the guard. Deleting
        the guard left it green.
        """
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        manager._pdata_ranges = [(IMAGE_BASE + TEXT_RVA, IMAGE_BASE + SECOND_RVA, False)]
        manager._pdata_range_starts = None
        manager.gap_pointer = IMAGE_BASE + ISLAND_RVA
        self.assertEqual(manager.nextGapCandidate(), IMAGE_BASE + ISLAND_RVA)

    def test_a_primary_extent_refuses_once_its_function_is_recovered(self):
        # the other arm of the same guard, so the pair fails if it is deleted
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        manager._pdata_ranges = [(IMAGE_BASE + TEXT_RVA, IMAGE_BASE + SECOND_RVA, False)]
        manager._pdata_range_starts = None
        manager.disassembly.functions = {IMAGE_BASE + TEXT_RVA: []}
        manager.gap_pointer = IMAGE_BASE + ISLAND_RVA
        self.assertNotEqual(manager.nextGapCandidate(), IMAGE_BASE + ISLAND_RVA)

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

    def test_an_enclosing_extent_two_short_ones_back_still_answers(self):
        # sorting by start does not order the ends, so a test that only peeks at the record
        # immediately before ends the walk on top of the extent that actually covers this
        ranges = [(0x1000, 0x2000, False), (0x1010, 0x1020, False), (0x1030, 0x1040, False)]
        self.assertEqual(self._lookup(ranges, 0x1050), (0x1000, 0x2000, False))

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

    def test_an_extent_running_past_the_image_contributes_nothing(self):
        # the expensive direction: seeding a bad candidate costs one address, but skipping a
        # region on a bad extent sends the gap pointer past the end of the image, which ends
        # gap analysis rather than resuming it
        pdata = _record(TEXT_RVA, 0x7FFFFFF0, UNWIND_PRIMARY_RVA)
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        self.assertEqual(manager._pdata_ranges, [])

    def test_the_image_bound_is_what_refuses_an_extent_inside_the_size_cap(self):
        # 0x7ffffff0 above is over the span cap as well, so it does not reach the image
        # bound and would pass with that check deleted. This span is under the cap and still
        # past the end of a 0x3200-byte image, which only the bound refuses.
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        self.assertLess(len(manager.disassembly.binary_info.binary), 0x5000)
        self.assertFalse(manager._isTrustworthyExceptionExtent(TEXT_RVA, 0x5000, UNWIND_PRIMARY_RVA))

    def test_an_unwind_pointer_that_is_not_dword_aligned_contributes_nothing(self):
        # the carved path already requires this; a declared table is not more trustworthy
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        self.assertFalse(manager._isTrustworthyExceptionExtent(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA + 1))

    def test_the_sorted_index_is_rebuilt_after_a_later_append(self):
        # every append happens before the gap scan reads the table, so this contract is not
        # exercised in production; it is asserted here so that stops being true silently
        beyond = IMAGE_BASE + SECOND_RVA + 0x30
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        self.assertIsNone(manager.declaredExceptionRangeContaining(beyond))
        manager._admitExceptionRecord(IMAGE_BASE, SECOND_RVA + 0x20, SECOND_RVA + 0x40, UNWIND_PRIMARY_RVA, False)
        self.assertIsNone(manager._pdata_range_starts)
        self.assertEqual(
            manager.declaredExceptionRangeContaining(beyond),
            (IMAGE_BASE + SECOND_RVA + 0x20, IMAGE_BASE + SECOND_RVA + 0x40, False),
        )

    def test_a_record_with_an_unreadable_unwind_info_contributes_nothing(self):
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, 0x900000)
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        self.assertEqual(manager._pdata_ranges, [])

    def test_a_record_whose_unwind_info_is_not_a_header_contributes_nothing(self):
        # `.text` opens 0x55, which is not one of the eight legal UNWIND_INFO first bytes.
        # This is the check that makes the chained flag worth trusting, and a chained
        # extent is the one that suppresses without waiting for its function to be found.
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, TEXT_RVA)
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        self.assertEqual(manager._pdata_ranges, [])

    def test_an_extent_longer_than_any_function_contributes_nothing(self):
        # an extent both inside the image and over the cap needs an image larger than the
        # cap, so the cap comes down rather than the fixture growing to a megabyte
        manager = _manager(_build_pe(SHATTERED_PDATA, SHATTERED_TEXT))
        self.assertTrue(manager._isTrustworthyExceptionExtent(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA))
        with mock.patch.object(intel_candidates, "_PDATA_MAX_FUNCTION_SIZE", 0x10):
            self.assertFalse(manager._isTrustworthyExceptionExtent(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA))

    def test_a_refused_extent_does_not_end_the_gap_scan(self):
        pdata = _record(TEXT_RVA, TEXT_RVA + 0x20, UNWIND_PRIMARY_RVA) + _record(
            ISLAND_RVA, 0x7FFFFFF0, UNWIND_CHAINED_RVA
        )
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        manager.gap_pointer = IMAGE_BASE + ISLAND_RVA
        self.assertEqual(manager.nextGapCandidate(), IMAGE_BASE + ISLAND_RVA)

    def test_the_record_is_still_seeded_when_its_extent_is_refused(self):
        # refusing an extent narrows what the record speaks for; it does not discard it
        pdata = _record(TEXT_RVA, 0x7FFFFFF0, UNWIND_PRIMARY_RVA)
        manager = _manager(_build_pe(pdata, SHATTERED_TEXT))
        booked = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertIn(IMAGE_BASE + TEXT_RVA, booked)

    def test_a_carved_table_seeds_candidates_and_contributes_no_extent(self):
        """A table found by searching the bytes may add candidates; it may not remove regions.

        A memory dump keeps its mapped bytes and usually not a section header, so the table
        has to be located in the bytes. A wrong entry then costs one bad candidate when it
        seeds, and every gap-only function it covers when it suppresses.
        """
        records = b"".join(
            _record(TEXT_RVA + index * 0x20, TEXT_RVA + index * 0x20 + 0x10, UNWIND_PRIMARY_RVA)
            for index in range(_PDATA_MIN_ENTRIES)
        )
        manager = _headerlessManager(records)
        booked = {addr for addr, candidate in manager.candidates.items() if candidate.is_exception_handler}
        self.assertTrue(booked, "the carved table should still seed candidates")
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
