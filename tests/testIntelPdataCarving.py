"""x64 RUNTIME_FUNCTION recovery from an image with no usable section table.

A memory dump carries the mapped image but rarely a parseable PE header, so `.pdata`
- the only source of *guaranteed* x64 function starts - disappears with the section
table. These tests pin the carver that recovers it from the raw image instead.
"""

import struct
import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

BASE = 0x140000000
IMAGE_SIZE = 0x4000
UNWIND_RVA = 0x3000
TABLE_RVA = 0x2000
FIRST_FUNCTION_RVA = 0x100
FUNCTION_STRIDE = 0x20

# UNWIND_INFO byte 0: Version 1 in bits 0-2, Flags in bits 3-7.
UNWIND_PLAIN = 0x01
UNWIND_CHAINED = 0x01 | (0x04 << 3)


def _image(num_entries, unwind_byte=UNWIND_PLAIN, table_rva=TABLE_RVA, stride=FUNCTION_STRIDE):
    blob = bytearray(IMAGE_SIZE)
    blob[UNWIND_RVA] = unwind_byte
    for index in range(num_entries):
        begin = FIRST_FUNCTION_RVA + index * stride
        entry = struct.pack("<III", begin, begin + 0x10, UNWIND_RVA)
        offset = table_rva + index * 12
        blob[offset : offset + 12] = entry
    return bytes(blob)


def _manager(blob, sections=()):
    binary_info = BinaryInfo(blob)
    binary_info.base_addr = BASE
    binary_info.bitness = 64
    binary_info.binary_size = len(blob)
    binary_info.getSections = lambda: iter(sections)

    manager = FunctionCandidateManager(SmdaConfig())
    manager.disassembly = SimpleNamespace(
        binary_info=binary_info,
        analysis_timeout=False,
        getRawBytes=lambda offset, size: blob[offset : offset + size],
    )
    manager.bitness = 64
    return manager


class IntelPdataCarvingTestSuite(unittest.TestCase):
    def test_carves_the_runtime_function_table_out_of_a_headerless_image(self):
        manager = _manager(_image(24))

        manager.locateExceptionHandlerCandidates()

        expected = {BASE + FIRST_FUNCTION_RVA + i * FUNCTION_STRIDE for i in range(24)}
        self.assertEqual(expected, set(manager.candidates))
        self.assertTrue(all(c.is_exception_handler for c in manager.candidates.values()))

    def test_a_run_shorter_than_the_minimum_is_not_trusted(self):
        # Three plausible RVAs are common in ordinary data; only a long sorted run
        # separates a real table from coincidence, so a short one must be ignored.
        manager = _manager(_image(8))

        manager.locateExceptionHandlerCandidates()

        self.assertEqual({}, manager.candidates)

    def test_carving_is_skipped_when_a_section_table_is_available(self):
        # A file-loaded binary already had its chance to read a real .pdata; carving there
        # would change established behaviour, so the section table gates it off entirely.
        manager = _manager(_image(24), sections=[(".text", BASE, BASE + 0x1000)])

        manager.locateExceptionHandlerCandidates()

        self.assertEqual({}, manager.candidates)

    def test_chained_entries_are_skipped_like_a_real_pdata_section(self):
        # UNW_FLAG_CHAININFO marks a split-off fragment of another function, not a start.
        manager = _manager(_image(24, unwind_byte=UNWIND_CHAINED))

        manager.locateExceptionHandlerCandidates()

        self.assertEqual({}, manager.candidates)

    def test_pdata_extents_are_recorded_for_the_carved_table(self):
        manager = _manager(_image(24))
        manager.config.USE_PE_X64_PDATA_ENDS = True

        manager.locateExceptionHandlerCandidates()

        self.assertIn(BASE + FIRST_FUNCTION_RVA, manager.pdata_start_addresses)
        self.assertIn(BASE + FIRST_FUNCTION_RVA + 0x10, manager.pdata_end_addresses)

    def test_the_table_is_found_from_a_sample_landing_at_any_entry_phase(self):
        # Sampling steps by a fixed stride, so it lands at an arbitrary offset inside the
        # 12-byte entries; the walk-back must still recover the true first entry.
        for table_rva in (TABLE_RVA, TABLE_RVA + 4, TABLE_RVA + 8):
            with self.subTest(table_rva=table_rva):
                manager = _manager(_image(40, table_rva=table_rva))

                manager.locateExceptionHandlerCandidates()

                self.assertEqual(40, len(manager.candidates))
                self.assertIn(BASE + FIRST_FUNCTION_RVA, manager.candidates)

    def test_entries_are_rejected_by_each_structural_guard(self):
        manager = _manager(_image(24))
        blob = manager.disassembly.binary_info.binary
        size = len(blob)

        def one(begin, end, unwind):
            """a full-size image carrying a single record at offset 0, so size == len(image)"""
            image = bytearray(IMAGE_SIZE)
            image[UNWIND_RVA] = UNWIND_PLAIN
            image[0:12] = struct.pack("<III", begin, end, unwind)
            return bytes(image)

        self.assertIsNotNone(manager._readExceptionRecord(blob, size, TABLE_RVA, 0))
        # a record straddling the end of the image
        self.assertIsNone(manager._readExceptionRecord(blob, size, size - 4, 0))
        # begin >= end, and an end past the image
        self.assertIsNone(manager._readExceptionRecord(one(0x200, 0x100, UNWIND_RVA), IMAGE_SIZE, 0, 0))
        self.assertIsNone(manager._readExceptionRecord(one(0x100, 0x9000, UNWIND_RVA), IMAGE_SIZE, 0, 0))
        # a zero begin, an implausibly large function, and an entry that breaks the sort order
        self.assertIsNone(manager._readExceptionRecord(one(0, 0x100, UNWIND_RVA), IMAGE_SIZE, 0, 0))
        self.assertIsNone(manager._readExceptionRecord(one(1, 0x101000, UNWIND_RVA), 0x200000, 0, 0))
        self.assertIsNone(manager._readExceptionRecord(blob, size, TABLE_RVA, 0x1000))
        # unwind info that is zero, outside the image, or not DWORD aligned
        for bad_unwind in (0, 0x9000, UNWIND_RVA + 1):
            self.assertIsNone(manager._readExceptionRecord(one(0x100, 0x110, bad_unwind), IMAGE_SIZE, 0, 0))
        # unwind info whose first byte is not a legal Version/Flags combination
        broken = bytearray(blob)
        broken[UNWIND_RVA] = 0xFF
        self.assertIsNone(manager._readExceptionRecord(bytes(broken), size, TABLE_RVA, 0))

    def test_the_longest_table_wins_when_the_image_holds_more_than_one_run(self):
        blob = bytearray(_image(20))
        # a second, longer run elsewhere in the image
        for index in range(48):
            begin = 0x1000 + index * 0x10
            offset = 0x800 + index * 12
            blob[offset : offset + 12] = struct.pack("<III", begin, begin + 8, UNWIND_RVA)
        manager = _manager(bytes(blob))

        offset, count = manager._locateExceptionRecordTable(manager.disassembly.binary_info.binary)

        self.assertEqual(0x800, offset)
        self.assertEqual(48, count)

    def test_a_tripped_timeout_stops_the_scan(self):
        manager = _manager(_image(24))
        manager.disassembly.analysis_timeout = True

        manager.locateExceptionHandlerCandidates()

        self.assertEqual({}, manager.candidates)


if __name__ == "__main__":
    unittest.main()
