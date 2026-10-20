import unittest

from smda.aarch64.definitions import INSTRUCTION_SIZE
from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64CandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelCandidateManager
from smda.SmdaConfig import SmdaConfig
from tests.testArmDisassembler import IDIOMS

BASE = 0x400000
# Long enough that a single scan crosses the timeout-check interval twice.
SKIPPED_BYTES = 4096 * 8
AARCH64_NOP = b"\x1f\x20\x03\xd5"
FOUR_GIB = 2**32


def _disassembly(image, bitness, architecture, base=BASE):
    binary_info = BinaryInfo(image)
    binary_info.base_addr = base
    binary_info.bitness = bitness
    binary_info.architecture = architecture
    binary_info.code_areas = [[base, base + len(image)]]
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


class IntelGapScanEndTest(unittest.TestCase):
    """The scan ends at the image end, wherever the image sits in the address space.

    It used to end at the address mask, 0xFFFFFFFF for a 32-bit image. That is below the base
    of an image at 4 GiB or above and the last byte of one that ends at 4 GiB, so the scan could
    keep coming back to it until the analysis timeout stopped it; on an image ending at 4 GiB,
    only when that byte was not padding.
    """

    def _manager(self, image, base):
        manager = IntelCandidateManager(SmdaConfig())
        manager.init(_disassembly(image, 32, "intel", base=base), None)
        # trips once the scan spins, so a regression fails here instead of hanging the suite
        manager._cb_analysis_timeout = _TripsImmediately()
        return manager

    def testAnImageBasedAt4GiBHasNoGapToOffer(self):
        manager = self._manager(b"\x55" * 0x100, FOUR_GIB)
        self.assertIsNone(manager.nextGapCandidate())
        self.assertFalse(manager.disassembly.analysis_timeout)

    def testAnImageEndingAt4GiBStopsAfterItsLastByte(self):
        image = b"\xcc" * 0xFF + b"\x55"
        base = FOUR_GIB - len(image)
        manager = self._manager(image, base)
        self.assertEqual(manager.nextGapCandidate(base), FOUR_GIB - 1)
        self.assertIsNone(manager.nextGapCandidate(manager.getNextGap(dont_skip=True)))
        self.assertFalse(manager.disassembly.analysis_timeout)

    def testTheInImageAddressMaskIsOfferedOnlyOnce(self):
        manager = self._manager(b"\xcc" * 0x40, FOUR_GIB - 0x20)
        manager.function_gaps = []
        manager.gap_pointer = FOUR_GIB - 0x10
        self.assertEqual(manager.getNextGap(), FOUR_GIB - 1)
        manager.gap_pointer = FOUR_GIB - 1
        self.assertEqual(manager.getNextGap(), FOUR_GIB + 0x20)

    def testMissingBinaryInfoKeepsTheLegacyFallback(self):
        manager = IntelCandidateManager(SmdaConfig())
        manager.disassembly = DisassemblyResult()
        manager.gap_pointer = BASE
        self.assertEqual(manager.getNextGap(), FOUR_GIB - 1)

    def testTheCheckpointPrecedesAFailedCandidateResumeAboveIt(self):
        manager = self._manager(b"\x55\xcc\xcc\xcc" + b"\x55" * 0x40, FOUR_GIB - 4)
        manager.function_gaps = []
        manager.gap_pointer = FOUR_GIB - 4
        self.assertEqual(manager.getNextGap(dont_skip=True), FOUR_GIB - 1)

    def testAFailedNonPaddingCheckpointDoesNotRepeat(self):
        manager = self._manager(b"\xcc" * 0x1F + b"\x55" + b"\xcc" * 0x20, FOUR_GIB - 0x20)
        manager.function_gaps = []
        manager.gap_pointer = FOUR_GIB - 0x10
        self.assertEqual(manager.nextGapCandidate(manager.getNextGap()), FOUR_GIB - 1)
        self.assertIsNone(manager.nextGapCandidate(manager.getNextGap(dont_skip=True)))
        self.assertFalse(manager.disassembly.analysis_timeout)

    def testTheCheckpointDoesNotSkipAnEarlierFailedCandidateResume(self):
        manager = self._manager(b"\x55\xcc\xcc\xcc" + b"\x55" * 0x40, FOUR_GIB - 0x14)
        manager.function_gaps = []
        manager.gap_pointer = FOUR_GIB - 0x14
        self.assertEqual(manager.getNextGap(dont_skip=True), FOUR_GIB - 0x10)


class GapScanEndReportTest(unittest.TestCase):
    """The same, end to end: a short TIMEOUT is all the time the scan used to take."""

    # main calls helper; the last byte is not padding, so the scan has to stop on it
    CODE = (
        b"\x55\x89\xe5\xe8\x08\x00\x00\x00\x5d\xc3"
        + b"\xcc" * 6
        + b"\x55\x89\xe5\x31\xc0\x5d\xc3"
        + b"\xcc" * 8
        + b"\x55"
    )

    def _report(self, base):
        config = SmdaConfig()
        config.TIMEOUT = 5
        config.WITH_STRINGS = False
        return Disassembler(config).disassembleBuffer(self.CODE, base, bitness=32)

    def testA32BitBufferAt4GiBFinishes(self):
        # 32-bit seed addresses (prologues, call targets) are masked to 32 bits and land below
        # 4 GiB, outside the image, so nothing is recovered; what is asserted is that the
        # analysis says so promptly
        report = self._report(FOUR_GIB)
        self.assertEqual(report.status, "ok")

    def testAnImageEndingAt4GiBFinishesWithWhatItFindsLower(self):
        top = FOUR_GIB - len(self.CODE)
        lower = top - 0x10000000
        top_report = self._report(top)
        lower_report = self._report(lower)
        self.assertEqual(top_report.status, "ok")
        offsets = sorted(function.offset - top for function in top_report.getFunctions())
        self.assertEqual(offsets, [0, 0x10])
        self.assertEqual(offsets, sorted(function.offset - lower for function in lower_report.getFunctions()))
        self.assertEqual(top_report.num_instructions, lower_report.num_instructions)

    def testAFailedGapBefore4GiBDoesNotLoseTheFunctionAboveIt(self):
        code = self.CODE[:23] + b"\x55" + b"\x00" * 24 + bytes.fromhex("5589e531c05dc3")
        reports = []
        for base in (FOUR_GIB - 0x30, FOUR_GIB - 0x10000030):
            config = SmdaConfig()
            config.TIMEOUT = 5
            report = Disassembler(config).disassembleBuffer(code, base, bitness=32)
            self.assertEqual(report.status, "ok")
            self.assertEqual(sorted(function.offset - base for function in report.getFunctions()), [0, 0x10, 0x30])
            reports.append(report)
        self.assertEqual(reports[0].num_instructions, reports[1].num_instructions)


class ArmGapScanEndReportTest(unittest.TestCase):
    """The ARM scan rounded the old end marker up to 4 GiB, inside an image based at or across it.

    Above it, 4 GiB is below the base, and for this A32 buffer the scan walked the unmapped space
    up to the base a word at a time.
    """

    def _report(self, base):
        config = SmdaConfig()
        config.TIMEOUT = 5
        config.WITH_STRINGS = False
        return Disassembler(config).disassembleBuffer(IDIOMS, base, 32, architecture="arm")

    def testAnArmBufferAt4GiBFinishes(self):
        self.assertEqual(self._report(FOUR_GIB).status, "ok")

    def testAnArmBufferAbove4GiBFinishes(self):
        self.assertEqual(self._report(0x140000000).status, "ok")

    def testAnArmBufferAcross4GiBFinishes(self):
        self.assertEqual(self._report(FOUR_GIB - 0x78).status, "ok")


if __name__ == "__main__":
    unittest.main()
