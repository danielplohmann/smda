"""A guard hoisted above the frame setup is a function's first instruction, not a stray tail.

At -O2 a compiler emits an argument check ahead of the prologue, so the routine opens on a
`cbz`/`cbnz` and its frame setup sits one instruction in. The gap scan used to refuse a
leading conditional branch outright, on the claim that a function never opens with one, and
so it walked past such an entry and booked the frame setup four bytes along instead -- a miss
and a false positive from one routine. The tests below hold the scan to telling that shape
apart from the one the claim is actually true of: a conditional branch that follows ordinary
code inside a function, which the analysis has to keep out by having already claimed it
rather than by refusing the word.
"""

import unittest

from smda.aarch64.definitions import is_conditional_branch
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
IMAGE_SIZE = 0x2100
#: where every image below puts the routine under test: past the scaffold, 16-aligned, and
#: reached by nothing the scaffold does
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

#: enough call-referenced entries, all 16-aligned, for the alignment floor to infer 16.
#: The inference needs more than twenty candidates carrying more than one reference each.
LEAF_COUNT = 22
LEAVES = tuple(BASE + 0x1000 + index * 0x10 for index in range(LEAF_COUNT))
#: everything the scaffold itself contributes to the recovered set, so a test can compare
#: the whole rest of that set against what the region under test should produce
SCAFFOLD_ENTRIES = frozenset({BASE, *LEAVES})


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


def _cbz(source, target):
    return 0xB4000000 | ((((target - source) // 4) & 0x7FFFF) << 5)  # cbz x0, <label>


def _scaffold(words, called=()):
    """The leaves and their caller, giving the alignment floor a population to infer 16 from.

    Without it the floor is 0 and a routine is refused or admitted on its alignment rather
    than on the word it opens with, which is not what any of these tests is asking about.
    Each address in `called` is called from the same caller, which is how a routine in one of
    these images is recovered by the first pass instead of by the gap scan.
    """
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
    """The routine's first word is the guard the compiler hoisted above its frame setup.

    Nothing calls it and its first word is no prologue, so the gap scan is the only pass that
    can reach it. The frame setup one word in is 4-aligned and nothing calls it either, so the
    alignment floor keeps it out of the first pass -- which is why refusing the entry did not
    simply lose the routine: the start booked in its place came from the same gap scan, four
    bytes past the entry it had just walked over, and the guard's own target became a second
    one. Recovering the entry removes both.
    """

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
        # The whole set is compared rather than the frame setup's absence alone: refusing the
        # entry booked both that word and the guard's own target, so an assertion naming one
        # address would go on passing with the false positive moved along.
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheScaffoldAroundTheRoutineIsRecovered(self):
        """Control. An image that analysed into nothing at all would satisfy the assertion
        above about what is absent for a reason that has nothing to do with guards."""
        self.assertEqual(sorted(SCAFFOLD_ENTRIES - self.functions), [])


class MidFunctionConditionalBranchTest(unittest.TestCase):
    """Control for the case above: the shape the gap scan's guard is written for.

    The same class of word, in the position where the claim behind the guard holds -- after
    ordinary code, inside a routine the first pass already recovered from its call reference.
    There it is a block tail and must not be booked as a function start, whatever the scan
    decides about a conditional branch that opens a routine.
    """

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
        # again the whole set, so that neither the branch nor either of the two arms it
        # decides between can become a function under another address
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheBranchIsTheSameWordClassAsTheOneOpeningAGuardedEntry(self):
        """Control: the two cases are told apart by position and by nothing else. Both words
        are what `is_conditional_branch` matches, so nothing about the word itself keeps this
        one out -- it stays out because the routine around it was claimed first."""
        self.assertTrue(is_conditional_branch(_cbz(REGION + 0x0C, REGION + 0x18)))
        self.assertTrue(is_conditional_branch(_cbz(REGION, REGION + 0x18)))


class UnclaimedConditionalBranchWithoutAFrameSetupTest(unittest.TestCase):
    """A conditional branch opening an unclaimed gap, with ordinary code behind it.

    Nothing calls this block and no prologue follows the branch, so neither the hoisted-guard
    reading nor the block-tail reading is confirmed by the words around it. This is the
    population that decided how far the guard could go: refusing the word never kept the
    region out of the function set, it only moved the start four bytes along, so there was no
    reduction in false starts to weigh against the entries the refusal cost.
    """

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
        """One start either way; the guard only decided which word it sat on.

        With the refusal in place this was `{REGION + 0x04}` -- a function beginning one
        instruction into the block, because the scan stepped over the branch and booked the
        next word. Without it the same single start lands on the block's real first word.
        Narrowing the refusal to entries a frame setup vouches for would have put it back at
        `+0x04`, which is why narrowing was not the cheaper half of the choice.
        """
        self.assertEqual(self.functions - SCAFFOLD_ENTRIES, {REGION})

    def testTheRegionIsOneFunctionStartUnderEitherRule(self):
        """Control: the count did not move, only the address did. The refusal bought no
        reduction in false starts over this shape, which is what made it the deciding
        population rather than the guarded-entry one."""
        starts = self.functions - SCAFFOLD_ENTRIES
        self.assertEqual(len(starts), 1)
        self.assertEqual([hex(start) for start in starts if not REGION <= start < REGION + 0x10], [])


if __name__ == "__main__":
    unittest.main()
