#!/usr/bin/python
"""What the gap scan does after a candidate fails to become a function.

`function_gaps` is a snapshot taken once, when the gap phase opens, and never refreshed. The
resume path in `getNextGap` only looks past the candidate when that candidate *became* a
function -- it tests membership in `code_map` -- so one that failed resumed at the next entry of
that stale snapshot, abandoning whatever was left of the gap it was found in. Everything between
the failed candidate and the end of its gap was never offered as a candidate at all.
"""

import logging
import unittest

from smda.common.FunctionCandidateManager import FunctionCandidateManager as CommonFunctionCandidateManager
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import _FAILED_GAP_RESUME_WINDOW, FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

BASE_ADDR = 0x400000
GAP_START = 0x401000
GAP_END = 0x402000
#: the entry of the next gap in the snapshot, which is what an abandoned gap resumes at
NEXT_GAP_START = 0x403000


class _BufferBinaryInfo:
    """The parts of BinaryInfo the gap resume reads, over a raw buffer."""

    def __init__(self, binary):
        self.bitness = 64
        self.base_addr = BASE_ADDR
        self.binary = binary
        self.binary_size = len(binary)
        self.code_areas = []


def bufferWithPadding(pad_start, pad_length):
    """A buffer whose only 0xCC run covers `pad_length` bytes from `pad_start` (an address)."""
    buffer = bytearray(b"\x90" * (GAP_END + 0x2000 - BASE_ADDR))
    offset = pad_start - BASE_ADDR
    buffer[offset : offset + pad_length] = b"\xcc" * pad_length
    return bytes(buffer)


def managerAt(gap_pointer, buffer, manager_class=FunctionCandidateManager, recovered=None, gaps=None):
    manager = manager_class(SmdaConfig())
    disassembly = DisassemblyResult()
    disassembly.binary_info = _BufferBinaryInfo(buffer)
    if recovered is not None:
        start, end = recovered
        for address in range(start, end):
            disassembly.code_map[address] = start
            disassembly.ins2fn[address] = start
        disassembly.function_borders[start] = (start, end)
    manager.disassembly = disassembly
    manager.gap_pointer = gap_pointer
    manager.function_gaps = gaps or [
        (GAP_START, GAP_END, GAP_END - GAP_START),
        (NEXT_GAP_START, NEXT_GAP_START + 0x1000, 0x1000),
    ]
    return manager


class FailedGapResumeTargetTest(unittest.TestCase):
    """The Intel backend's answer for where to pick the gap back up."""

    def testThePaddingRunInsideTheGapNamesTheEntryAfterIt(self):
        # 0x401140..0x401150 is padding, so the entry the compiler aligned is at 0x401150
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10))
        self.assertEqual(manager._failedGapResumeTarget(), 0x401150)

    def testAnUnalignedEntryAfterPaddingIsDeclined(self):
        # a lone 0xCC inside a data structure leaves the rest of that structure unaligned;
        # resuming there books the remainder as a function, which is what this refuses
        manager = managerAt(0x401100, bufferWithPadding(0x401145, 0x01))
        self.assertIsNone(manager._failedGapResumeTarget())

    def testAGapWithNoPaddingInTheWindowNamesNothing(self):
        manager = managerAt(0x401100, bytes(b"\x90" * (GAP_END + 0x2000 - BASE_ADDR)))
        self.assertIsNone(manager._failedGapResumeTarget())

    def testAPaddingRunThatFillsTheWindowNamesNothing(self):
        # nothing inside the window says where the run stops, so it cannot name an entry
        manager = managerAt(0x401100, bufferWithPadding(0x401101, 0x2000))
        self.assertIsNone(manager._failedGapResumeTarget())

    def testATargetAlwaysAdvancesPastTheFailedCandidate(self):
        # the resume feeds straight back into gap_pointer, so a target at or behind the failed
        # candidate would re-offer it forever
        for pad_start in (0x401101, 0x401110, 0x401140, 0x401800):
            manager = managerAt(0x401100, bufferWithPadding(pad_start, 0x10))
            target = manager._failedGapResumeTarget()
            if target is not None:
                self.assertGreater(target, 0x401100, f"padding at 0x{pad_start:x} did not advance")

    def testAnAddressBelowTheImageBaseNamesNothing(self):
        """A negative offset must fail rather than slice.

        `getRawBytes` slices the image directly, and a negative start reads from its tail. The
        buffer here is shorter than the search window, which is what makes that tail slice
        non-empty -- with a larger image the same bug returns nothing and hides.
        """
        small = bytearray(b"\x90" * 0x200)
        # not at the very end: a run reaching the window's edge is refused for another reason,
        # which would let this pass without exercising the guard it is about
        small[0x1E0:0x1F0] = b"\xcc" * 0x10
        manager = managerAt(BASE_ADDR - 0x100, bytes(small))
        self.assertTrue(manager.disassembly.getRawBytes(-0xFF, _FAILED_GAP_RESUME_WINDOW))
        self.assertIsNone(manager._failedGapResumeTarget())

    def testAnImageWithNoBinaryInfoNamesNothing(self):
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10))
        manager.disassembly.binary_info = None
        self.assertIsNone(manager._failedGapResumeTarget())

    def testABackendWithoutAnOverrideNamesNothing(self):
        # the common manager keeps the historical behaviour, so a backend that does not carve
        # padding cannot start resuming on evidence it has no reading of
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10), manager_class=CommonFunctionCandidateManager)
        self.assertIsNone(manager._failedGapResumeTarget())


class FailedGapResumeTest(unittest.TestCase):
    """What `getNextGap` does with that answer."""

    def testAFailedCandidateResumesInsideItsOwnGap(self):
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10))
        self.assertEqual(manager.getNextGap(dont_skip=True), 0x401150)

    def testAFailedCandidateWithNoResumeTargetStillAbandonsTheGap(self):
        # the historical behaviour, which is what a gap holding no padding keeps
        manager = managerAt(0x401100, bytes(b"\x90" * (GAP_END + 0x2000 - BASE_ADDR)))
        self.assertEqual(manager.getNextGap(dont_skip=True), NEXT_GAP_START)

    def testACandidateThatBecameAFunctionStillResumesJustPastIt(self):
        # the pre-existing branch: the address is in the code map, so its function's end wins
        # and the padding answer is never consulted
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10), recovered=(0x401100, 0x401120))
        self.assertEqual(manager.getNextGap(dont_skip=True), 0x401120)

    def testTheResumeOnlyAppliesWhenTheScanAskedNotToSkip(self):
        manager = managerAt(0x401100, bufferWithPadding(0x401140, 0x10))
        self.assertEqual(manager.getNextGap(dont_skip=False), NEXT_GAP_START)

    def testTheResumeNeverOvershootsTheNextGap(self):
        """Padding past the end of a short gap must not resume beyond where the next one starts.

        The window the backend searches is fixed, so on a gap shorter than it the first padding
        run can lie in the *next* gap. Resuming there would skip that gap's opening bytes --
        the same class of loss this change exists to fix, one gap along.
        """
        near = [(GAP_START, 0x401200, 0x200), (0x401200, 0x401400, 0x200)]
        manager = managerAt(0x401100, bufferWithPadding(0x401240, 0x10), gaps=near)
        # the backend does name a target, and it is past the next gap's start
        self.assertEqual(manager._failedGapResumeTarget(), 0x401250)
        self.assertEqual(manager.getNextGap(dont_skip=True), 0x401200)


if __name__ == "__main__":
    unittest.main()
