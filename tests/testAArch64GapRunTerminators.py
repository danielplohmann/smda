"""The two AArch64 gap-run walks stop at different terminators, and the difference is load-bearing."""

import types
import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
IMAGE_SIZE = 0x4000

NOP = 0xD503201F
RET = 0xD65F03C0
BRK = 0xD4200000  # brk #0
PROLOGUE = 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!
EPILOGUE = 0xA8C17BFD  # ldp x29, x30, [sp], #16
MOV_W0_1 = 0x52800020  # mov w0, #1
MOV_W1_2 = 0x52800041  # mov w1, #2


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


class GapRunPastATrapTest(unittest.TestCase):
    """A trap does not end the function whose body it sits in, so the suppression walk reads on.

    `brk`/`hlt`/`udf` end a function for instruction analysis, which is that analysis's own
    convention and not a boundary the image declares. The block behind a bounds check still
    belongs to the routine that checked the bound, so an unconditional branch out of that block
    into the routine's interior says the same thing about a gap candidate ahead of it as it
    would with no trap in between: the run is a mid-function tail, not a new function.
    """

    def _image(self):
        """Four parts. An entry that calls the host, so the host is a call-reference candidate
        and is recovered before gap analysis starts. The host, whose second word is the
        interior address nothing else names. A suppressed run, opening on no prologue and
        referenced by nothing, so the gap scan is the only thing that reaches it, whose
        straight-line run passes a `brk` and then branches into that interior. And a booked run
        of exactly the same four words, differing only in that its branch goes to the host's
        entry rather than into its body."""
        host = BASE + 0x1000
        interior = host + 4
        suppressed = BASE + 0x2000
        booked = BASE + 0x3000

        words = {BASE: PROLOGUE, BASE + 4: _bl(BASE + 4, host), BASE + 8: EPILOGUE, BASE + 12: RET}
        words.update({host: PROLOGUE, interior: MOV_W0_1, host + 8: MOV_W1_2, host + 12: EPILOGUE, host + 16: RET})
        for run, target in ((suppressed, interior), (booked, host)):
            words.update({run: MOV_W0_1, run + 4: BRK, run + 8: MOV_W1_2, run + 12: _b(run + 12, target)})

        image = bytearray(NOP.to_bytes(4, "little") * (IMAGE_SIZE // 4))
        for word_address, word in words.items():
            image[word_address - BASE : word_address - BASE + 4] = word.to_bytes(4, "little")
        return bytes(image), host, interior, suppressed, booked

    def setUp(self):
        image, self.host, self.interior, self.suppressed, self.booked = self._image()
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config, backend="aarch64").disassembleBuffer(
            image,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + IMAGE_SIZE]],
            architecture="aarch64",
        )
        self.assertEqual(report.status, "ok")
        self.functions = {function.offset for function in report.getFunctions()}

    def testARunThatBranchesIntoAnInteriorPastATrapIsNotBooked(self):
        self.assertNotIn(self.suppressed, self.functions)

    def testTheSameRunBranchingToARealEntryIsBooked(self):
        """Control, and the one that makes the assertion above mean anything. Both runs carry
        the same trap in the same place and both end at it once analysed, so if the trap were
        what decided, this address would be missing too."""
        self.assertIn(self.booked, self.functions)

    def testTheHostAndItsCallerAreStillRecovered(self):
        """Control. Both assertions above would hold on an image that failed to analyse."""
        self.assertIn(self.host, self.functions)
        self.assertIn(BASE, self.functions)

    def testTheAddressBranchedIntoIsAnInteriorAndNotAnEntry(self):
        """Control: the suppressed run is refused for branching into a body, so that address
        has to be a body and not a function the analysis happens to have recovered."""
        self.assertNotIn(self.interior, self.functions)


class GapRunTerminatorSetsTest(unittest.TestCase):
    """The two walks, isolated from the traversal that reaches them, over identical words."""

    #: the walks read from here; the landing-pad walk skips this first word as the pad itself
    RUN = 0x40
    #: where the run's closing `b` lands, and the only address the fake code map holds
    TARGET = 0x80
    BUFFER_SIZE = 0x100

    def _manager(self, second_word):
        """A manager over four words: an ordinary instruction, `second_word`, another ordinary
        instruction, then `b` to TARGET. Both walks read nothing but the mapped words, the code
        map and the function / candidate sets, so standing those in keeps the second word the
        only thing that varies between the cases below."""
        words = {
            self.RUN: MOV_W0_1,
            self.RUN + 4: second_word,
            self.RUN + 8: MOV_W1_2,
            self.RUN + 12: _b(self.RUN + 12, self.TARGET),
        }
        buffer = bytearray(NOP.to_bytes(4, "little") * (self.BUFFER_SIZE // 4))
        for word_address, word in words.items():
            buffer[word_address : word_address + 4] = word.to_bytes(4, "little")

        manager = FunctionCandidateManager(SmdaConfig())
        # exactly what the two walks read, and nothing else: a reader can tell from this
        # stand-in what either of them is allowed to depend on
        manager.disassembly = types.SimpleNamespace(
            binary_info=types.SimpleNamespace(base_addr=0, binary=bytes(buffer), binary_size=self.BUFFER_SIZE),
            # TARGET is decoded code that is nobody's entry, which is what "interior" means here
            code_map={self.TARGET: 1},
            functions={},
        )
        return manager

    def testTheSkipAfterARefusedLandingPadStopsAtATrap(self):
        # it resumes one instruction past the trap, i.e. it never reaches the `b` two words on
        self.assertEqual(self._manager(BRK)._endOfRefusedLandingPadRun(self.RUN), self.RUN + 8)

    def testTheSuppressionWalkReadsPastTheTrapToTheBranch(self):
        self.assertTrue(self._manager(BRK)._gapRunFlowsIntoInterior(self.RUN))

    def testTheSuppressionWalkStillStopsAtAReturn(self):
        """Control: the walk has a terminator set, it is just not the same one. Swap the trap
        for a `ret` and the branch behind it stops being reachable evidence."""
        self.assertFalse(self._manager(RET)._gapRunFlowsIntoInterior(self.RUN))

    def testTheSkipStopsAtAReturnInTheSamePlace(self):
        """Control: for the skip a trap and a return are interchangeable, which is the whole
        asymmetry - the same word pair splits the two walks apart."""
        self.assertEqual(self._manager(RET)._endOfRefusedLandingPadRun(self.RUN), self.RUN + 8)

    def testABranchToARecoveredFunctionIsNotAnInterior(self):
        """Control: reading past the trap is only a suppression when what it finds is a body.
        The same run reaching a real entry is not evidence against the candidate."""
        manager = self._manager(BRK)
        manager.disassembly.functions = {self.TARGET: object()}
        self.assertFalse(manager._gapRunFlowsIntoInterior(self.RUN))


if __name__ == "__main__":
    unittest.main()
