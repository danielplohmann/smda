#!/usr/bin/python
"""The AArch64 gap scan jumps over bytes outside every executable section.

It used to step one word at a time through `.rodata`, `.eh_frame`, `.data` and the rest of
the mapped image, asking each word whether it sat in an executable section. None of those
words can become a candidate, so the scan now resumes at the start of the next executable
section, or ends when there is none.
"""

import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
AARCH64_NOP = b"\x1f\x20\x03\xd5"
FRAME_PROLOGUE = b"\xfd\x7b\xbf\xa9"

FIRST_EXEC = (BASE, BASE + 0x40)
SECOND_EXEC = (BASE + 0x1000, BASE + 0x1010)
IMAGE_SIZE = 0x2000


class RecordingCodeMap(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queried = []

    def __contains__(self, key):
        self.queried.append(key)
        return super().__contains__(key)


class AArch64GapScanExecSkipTest(unittest.TestCase):
    @staticmethod
    def manager(exec_ranges):
        image = bytearray(AARCH64_NOP * (IMAGE_SIZE // 4))
        # prologues everywhere outside the executable sections, so a word the scan reads
        # there would be booked
        image[0x40:0x1000] = FRAME_PROLOGUE * ((0x1000 - 0x40) // 4)
        image[0x1010:] = FRAME_PROLOGUE * ((IMAGE_SIZE - 0x1010) // 4)
        image[0x1000:0x1010] = FRAME_PROLOGUE * 4
        binary_info = BinaryInfo(bytes(image))
        binary_info.base_addr = BASE
        binary_info.bitness = 64
        binary_info.architecture = "aarch64"
        binary_info.code_areas = [[BASE, BASE + IMAGE_SIZE]]
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        disassembly.ins2fn = RecordingCodeMap()
        manager = FunctionCandidateManager(SmdaConfig())
        manager.init(disassembly, None)
        manager._exec_ranges = exec_ranges
        return manager

    def testResumesAtTheNextExecutableSection(self):
        manager = self.manager([FIRST_EXEC, SECOND_EXEC])
        self.assertEqual(manager.nextGapCandidate(FIRST_EXEC[1]), SECOND_EXEC[0])
        skipped = [a for a in manager.disassembly.code_map.queried if FIRST_EXEC[1] < a < SECOND_EXEC[0]]
        self.assertEqual(skipped, [])

    def testEndsPastTheLastExecutableSection(self):
        manager = self.manager([FIRST_EXEC, SECOND_EXEC])
        self.assertIsNone(manager.nextGapCandidate(SECOND_EXEC[1]))
        self.assertEqual(manager.disassembly.code_map.queried, [SECOND_EXEC[1]])

    def testSectionOrderAndOverlapDoNotHideCode(self):
        """lief lists sections in header order, which need not be address order, and a
        crafted header can declare overlapping sections."""
        nested = (BASE + 0x10, BASE + 0x20)
        manager = self.manager([SECOND_EXEC, FIRST_EXEC, nested])
        self.assertEqual(manager._mergedRanges(manager._exec_ranges), [FIRST_EXEC, SECOND_EXEC])
        self.assertEqual(manager.nextGapCandidate(FIRST_EXEC[1]), SECOND_EXEC[0])


if __name__ == "__main__":
    unittest.main()
