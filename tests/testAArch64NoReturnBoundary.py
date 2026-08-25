"""A callee that does not return must not merge its caller with the next function."""

import logging
import unittest
from pathlib import Path

import pytest

from smda.aarch64.definitions import FRAME_RECORD_WINDOW, opens_stack_frame
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
#: without the boundary rule this image merges fifteen declared functions into two
FIXTURE = CORPUS_DIR / "malpedia" / "osx.frostyferret_ef27a525ec0b.xored"

SUB_SP_0X40 = 0xD10103FF  # sub sp, sp, #0x40
STP_FP_LR_AT_0X30 = 0xA9037BFD  # stp x29, x30, [sp, #0x30]
STP_CALLEE_SAVED = 0xA9024FF4  # stp x20, x19, [sp, #0x20]
SUB_X0_SP = 0xD10103E0  # sub x0, sp, #0x40
ADD_SP_0X40 = 0x910103FF  # add sp, sp, #0x40
STP_FP_LR_PREINDEX = 0xA9B87BFD  # stp x29, x30, [sp, #-0x80]!
NOP = 0xD503201F


def _decode(path):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(path.read_bytes()))


class OpensStackFrameTest(unittest.TestCase):
    def testAllocationFollowedByTheFrameRecordIsAFrameOpening(self):
        self.assertTrue(opens_stack_frame([SUB_SP_0X40, STP_FP_LR_AT_0X30]))
        self.assertTrue(opens_stack_frame([SUB_SP_0X40, STP_CALLEE_SAVED, STP_FP_LR_AT_0X30]))

    def testAnAllocationOnItsOwnIsNot(self):
        # control: the allocation is the same word in both cases, so it is the frame
        # record and not the allocation that decides
        self.assertFalse(opens_stack_frame([SUB_SP_0X40]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, NOP, NOP, NOP]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, STP_CALLEE_SAVED, NOP, NOP]))

    def testTheFrameRecordHasToArriveInsideTheWindow(self):
        inside = [SUB_SP_0X40] + [NOP] * (FRAME_RECORD_WINDOW - 1) + [STP_FP_LR_AT_0X30]
        outside = [SUB_SP_0X40] + [NOP] * FRAME_RECORD_WINDOW + [STP_FP_LR_AT_0X30]
        self.assertTrue(opens_stack_frame(inside))
        self.assertFalse(opens_stack_frame(outside))

    def testOnlyAnAllocationOffTheStackPointerCounts(self):
        self.assertFalse(opens_stack_frame([SUB_X0_SP, STP_FP_LR_AT_0X30]))
        self.assertFalse(opens_stack_frame([ADD_SP_0X40, STP_FP_LR_AT_0X30]))

    def testThePreIndexedFrameStoreIsNotThisShape(self):
        # it allocates and stores at once, needs no preceding allocation, and is
        # already recognised on its own by is_function_prologue
        self.assertFalse(opens_stack_frame([STP_FP_LR_PREINDEX, STP_FP_LR_AT_0X30]))

    def testAShortOrEmptyWindowDoesNotMatch(self):
        self.assertFalse(opens_stack_frame([]))
        self.assertFalse(opens_stack_frame([None, STP_FP_LR_AT_0X30]))
        self.assertFalse(opens_stack_frame([SUB_SP_0X40, None, None, None]))


@pytest.mark.slow
class NoReturnCallBoundaryTest(unittest.TestCase):
    """Fifteen declared functions in one real image are reached only through this rule."""

    #: entries the image declares that follow a `bl` to a callee with no return
    MERGED_STARTS = (
        0x100008950,
        0x1000089A0,
        0x1000089F0,
        0x100008A40,
        0x100008B10,
        0x100008B60,
        0x100008BB0,
        0x100008C00,
        0x100008D00,
        0x100008D50,
        0x100008DA0,
        0x100008E04,
        0x100008E54,
        0x100008EB8,
        0x100008F08,
    )

    def testEveryEntryAfterANoReturnCallIsItsOwnFunction(self):
        config = SmdaConfig()
        config.TIMEOUT = 300
        report = Disassembler(config).disassembleUnmappedBuffer(_decode(FIXTURE))
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")
        recovered = {function.offset for function in report.getFunctions()}
        self.assertEqual(sorted(set(self.MERGED_STARTS) - recovered), [])

    def testTheBoundaryIsTheCutAndNotASeededCandidate(self):
        # the fall-through path cuts the caller and leaves the entry to the ordinary
        # candidate machinery; seeding a tailcall candidate as well measured worse on
        # both AArch64 corpora, so it follows RESOLVE_TAILCALLS. Turning that on must
        # not lose any of the functions the cut recovers.
        config = SmdaConfig()
        config.TIMEOUT = 300
        buffer = _decode(FIXTURE)
        off = Disassembler(config).disassembleUnmappedBuffer(buffer)
        seeded = SmdaConfig()
        seeded.TIMEOUT = 300
        seeded.RESOLVE_TAILCALLS = True
        on = Disassembler(seeded).disassembleUnmappedBuffer(buffer)
        self.assertEqual(off.status, "ok")
        self.assertEqual(on.status, "ok")
        recovered = {function.offset for function in off.getFunctions()}
        self.assertEqual(sorted(set(self.MERGED_STARTS) - recovered), [])
        # control: the flag really does change what is seeded, so the assertion above is
        # not passing because both runs are the same run
        self.assertNotEqual(recovered, {function.offset for function in on.getFunctions()})

    def testTheCallerBeforeThemIsStillOneFunction(self):
        # control: the rule cuts at the entry that follows the call, not at every call
        config = SmdaConfig()
        config.TIMEOUT = 300
        report = Disassembler(config).disassembleUnmappedBuffer(_decode(FIXTURE))
        recovered = {function.offset for function in report.getFunctions()}
        self.assertIn(0x100008900, recovered)
        self.assertNotIn(0x100008904, recovered)


@pytest.mark.slow
class GapRunIntoADiscoveredFunctionTest(unittest.TestCase):
    """A branch to a function gap analysis found is not a branch into an interior.

    The gap sweep refuses a straight-line run whose unconditional branch lands in
    already-decoded code that is not a function-start candidate, which is the shape of a
    mid-function tail. The candidate set it consults is a snapshot taken before analysis
    and gap analysis never adds to it, so a function that pass discovered looked exactly
    like an interior and took the branch veneers pointing at it down with it.
    """

    #: twelve adjacent one-instruction branch veneers, every one declared by the image
    VENEER_RUN = tuple(range(0x100007ABC, 0x100007AEC, 4))

    def setUp(self):
        config = SmdaConfig()
        config.TIMEOUT = 300
        self.report = Disassembler(config).disassembleUnmappedBuffer(_decode(FIXTURE))
        self.recovered = {function.offset for function in self.report.getFunctions()}

    def testEveryVeneerInTheRunIsRecovered(self):
        self.assertEqual(self.report.status, "ok")
        self.assertEqual([hex(a) for a in self.VENEER_RUN if a not in self.recovered], [])

    def testTheTargetsThoseVeneersBranchToAreThemselvesFunctions(self):
        # control: the run is only interesting because its targets are real entries. Two of
        # them are reached by gap analysis rather than by the prologue scan, and those are
        # the two whose veneers the stale snapshot used to lose.
        for target in (0x10000642C, 0x10000643C, 0x100006400, 0x100007984, 0x100007AEC):
            self.assertIn(target, self.recovered)


if __name__ == "__main__":
    unittest.main()
