import unittest

from smda.aarch64.definitions import INSTRUCTION_SIZE
from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64CandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelCandidateManager
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
# Long enough that a single scan crosses the timeout-check interval twice.
SKIPPED_BYTES = 4096 * 8
AARCH64_NOP = b"\x1f\x20\x03\xd5"


def _disassembly(image, bitness, architecture):
    binary_info = BinaryInfo(image)
    binary_info.base_addr = BASE
    binary_info.bitness = bitness
    binary_info.architecture = architecture
    binary_info.code_areas = [[BASE, BASE + len(image)]]
    disassembly = DisassemblyResult()
    disassembly.setBinaryInfo(binary_info)
    return disassembly


class _TripsImmediately:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return True


class IntelGapScanTimeoutTest(unittest.TestCase):
    def _manager(self):
        # 0x55 is neither padding nor a nop, so a claimed run of it is walked one byte
        # per iteration - the shape that makes a single scan long.
        image = b"\x55" * (SKIPPED_BYTES + 16)
        disassembly = _disassembly(image, 32, "intel")
        for offset in range(SKIPPED_BYTES):
            disassembly.data_map.add(BASE + offset)
        manager = IntelCandidateManager(SmdaConfig())
        manager.init(disassembly, None)
        return manager

    def testLongScanCompletesWithoutATimeout(self):
        manager = self._manager()
        self.assertEqual(manager.nextGapCandidate(BASE), BASE + SKIPPED_BYTES)
        self.assertFalse(manager.disassembly.analysis_timeout)

    def testLongScanStopsWhenTheAnalysisBudgetIsSpent(self):
        manager = self._manager()
        callback = _TripsImmediately()
        manager._cb_analysis_timeout = callback
        self.assertIsNone(manager.nextGapCandidate(BASE))
        self.assertTrue(manager.disassembly.analysis_timeout)
        self.assertEqual(callback.calls, 1)


class AArch64GapScanTimeoutTest(unittest.TestCase):
    def _manager(self):
        image = AARCH64_NOP * (SKIPPED_BYTES // INSTRUCTION_SIZE) + b"\xfd\x7b\xbf\xa9" * 4
        disassembly = _disassembly(image, 64, "aarch64")
        manager = AArch64CandidateManager(SmdaConfig())
        manager.init(disassembly, None)
        return manager

    def testLongScanCompletesWithoutATimeout(self):
        manager = self._manager()
        self.assertEqual(manager.nextGapCandidate(BASE), BASE + SKIPPED_BYTES)
        self.assertFalse(manager.disassembly.analysis_timeout)

    def testLongScanStopsWhenTheAnalysisBudgetIsSpent(self):
        manager = self._manager()
        callback = _TripsImmediately()
        manager._cb_analysis_timeout = callback
        self.assertIsNone(manager.nextGapCandidate(BASE))
        self.assertTrue(manager.disassembly.analysis_timeout)
        self.assertEqual(callback.calls, 1)


if __name__ == "__main__":
    unittest.main()
