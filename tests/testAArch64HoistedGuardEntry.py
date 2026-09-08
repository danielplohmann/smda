"""A guard hoisted above the frame setup is a function's first instruction, not a stray tail.

At -O2 a compiler emits an argument check ahead of the prologue, so the routine opens on a
`cbz`/`cbnz` and its frame setup sits one instruction in. What separates that from the shape
the same word class really does take mid-function is position, not the word, so each case
below is paired with the other.
"""

import unittest

from smda.aarch64.definitions import is_conditional_branch
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
IMAGE_SIZE = 0x2100
#: past the scaffold, 16-aligned, and reached by nothing the scaffold does
REGION = BASE + 0x2000

NOP = 0xD503201F
RET = 0xD65F03C0
PROLOGUE = 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!
FRAME_POINTER = 0x910003FD  # mov x29, sp
EPILOGUE = 0xA8C17BFD  # ldp x29, x30, [sp], #16
MOV_W0_0 = 0x52800000  # mov w0, #0
MOV_W0_1 = 0x52800020  # mov w0, #1
MOV_W1_2 = 0x52800041  # mov w1, #2
MOV_W2_3 = 0x52800062  # mov w2, #3

#: enough call-referenced 16-aligned entries, each carrying more than one reference, for the
#: alignment floor to infer 16
LEAF_COUNT = 22
LEAVES = tuple(BASE + 0x1000 + index * 0x10 for index in range(LEAF_COUNT))
SCAFFOLD_ENTRIES = frozenset({BASE, *LEAVES})


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


def _cbz(source, target):
    return 0xB4000000 | ((((target - source) // 4) & 0x7FFFF) << 5)  # cbz x0, <label>


def _scaffold(words, called=()):
    """The leaves and their caller, so the alignment floor infers 16 rather than 0 and no
    routine below is refused on its alignment instead of on the word it opens with. An address
    in `called` is called twice from that caller, which is how a routine here reaches the first
    pass instead of the gap scan."""
    for leaf in LEAVES:
        words.update({leaf: PROLOGUE, leaf + 4: MOV_W0_1, leaf + 8: EPILOGUE, leaf + 12: RET})
    address = BASE
    words[address] = PROLOGUE
    address += 4
    for target in [*LEAVES, *called]:
        for _call in range(2):  # more than one reference each, or the floor infers nothing
            words[address] = _bl(address, target)
            address += 4
    words[address] = EPILOGUE
    words[address + 4] = RET


def _render(words):
    """A NOP-filled image with each word of `words` written at its address."""
    image = bytearray(NOP.to_bytes(4, "little") * (IMAGE_SIZE // 4))
    for word_address, word in words.items():
        image[word_address - BASE : word_address - BASE + 4] = word.to_bytes(4, "little")
    return bytes(image)


def _disassemble(image):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    return Disassembler(config, backend="aarch64").disassembleBuffer(
        image, base_addr=BASE, bitness=64, code_areas=[[BASE, BASE + IMAGE_SIZE]]
    )


class HoistedGuardEntryTest(unittest.TestCase):
    """Nothing calls the routine and its first word is no prologue, so the gap scan is the only
    pass that reaches it. The frame setup one word in is 4-aligned and uncalled, so the
    alignment floor keeps it out of the first pass too -- which is why refusing the entry did
    not simply lose the routine: the start booked in its place came from the same gap scan,
    four bytes on, and the guard's own target became a second one."""

    def _image(self):
        words = {}
        _scaffold(words)
        words.update(
            {
                REGION: _cbz(REGION, REGION + 0x18),  # the entry: the argument check
                REGION + 0x04: PROLOGUE,  # the word booked in the entry's place today
                REGION + 0x08: FRAME_POINTER,
                REGION + 0x0C: MOV_W0_1,
                REGION + 0x10: EPILOGUE,
                REGION + 0x14: RET,
                REGION + 0x18: MOV_W0_0,  # the guard's target, the early return
                REGION + 0x1C: RET,
            }
        )
        return _render(words)

    def setUp(self):
        report = _disassemble(self._image())
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.identified_alignment, 16)
        self.functions = {function.offset for function in report.getFunctions()}

    def testTheHoistedGuardIsRecoveredAsTheFunctionEntry(self):
        self.assertIn(REGION, self.functions)

    def testTheRoutineIsRecoveredAsOneFunctionAndNothingElse(self):
        # the whole set, not the frame setup's absence alone: an assertion naming one address
        # goes on passing with the false positive moved four bytes along
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheScaffoldAroundTheRoutineIsRecovered(self):
        """Control: an image that analysed into nothing would satisfy the assertion above."""
        self.assertEqual(sorted(SCAFFOLD_ENTRIES - self.functions), [])


class MidFunctionConditionalBranchTest(unittest.TestCase):
    """Control for the case above: the same word class after ordinary code, inside a routine the
    first pass already recovered from its call reference. There it is a block tail and must stay
    out of the function set whatever the scan does with one that opens a routine."""

    def _image(self):
        words = {}
        _scaffold(words, called=(REGION,))
        words.update(
            {
                REGION: PROLOGUE,
                REGION + 0x04: FRAME_POINTER,
                REGION + 0x08: MOV_W1_2,  # ordinary code ahead of the branch, so it is a tail
                REGION + 0x0C: _cbz(REGION + 0x0C, REGION + 0x18),
                REGION + 0x10: MOV_W0_1,
                REGION + 0x14: _b(REGION + 0x14, REGION + 0x1C),
                REGION + 0x18: MOV_W0_0,
                REGION + 0x1C: EPILOGUE,
                REGION + 0x20: RET,
            }
        )
        return _render(words)

    def setUp(self):
        report = _disassemble(self._image())
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.identified_alignment, 16)
        self.functions = {function.offset for function in report.getFunctions()}

    def testTheBlockTailIsNotBookedAsAFunctionStart(self):
        # again the whole set: neither the branch nor either arm may become a function
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheBranchIsTheSameWordClassAsTheOneOpeningAGuardedEntry(self):
        """Control: both words are what `is_conditional_branch` matches, so what tells the two
        cases apart is position -- this one stays out because its routine was claimed first."""
        self.assertTrue(is_conditional_branch(_cbz(REGION + 0x0C, REGION + 0x18)))
        self.assertTrue(is_conditional_branch(_cbz(REGION, REGION + 0x18)))


class UnclaimedConditionalBranchWithoutAFrameSetupTest(unittest.TestCase):
    """A conditional branch opening an unclaimed gap, with ordinary code rather than a frame
    setup behind it, so neither reading is confirmed by its surroundings. This is the population
    that decided how far the guard could go."""

    def _image(self):
        words = {}
        _scaffold(words)
        words.update(
            {
                REGION: _cbz(REGION, REGION + 0x0C),
                REGION + 0x04: MOV_W0_1,  # ordinary code, not a frame setup
                REGION + 0x08: MOV_W2_3,
                REGION + 0x0C: RET,
            }
        )
        return _render(words)

    def setUp(self):
        report = _disassemble(self._image())
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.identified_alignment, 16)
        self.functions = {function.offset for function in report.getFunctions()}

    def testTheScanBooksTheBlockAtItsFirstWord(self):
        """One start either way; the refusal only decided which word it sat on -- `+0x04` with
        it, the block's real first word without. Narrowing it to entries a frame setup vouches
        for would have put it back at `+0x04`, which is why narrowing bought nothing here."""
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheRegionIsOneFunctionStartUnderEitherRule(self):
        """Control: the count did not move, only the address did."""
        starts = self.functions - SCAFFOLD_ENTRIES
        self.assertEqual(len(starts), 1)
        self.assertEqual([hex(start) for start in starts if not REGION <= start < REGION + 0x10], [])


if __name__ == "__main__":
    unittest.main()
