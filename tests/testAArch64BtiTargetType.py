#!/usr/bin/python
"""`bti j` marks a jump target, not a callable entry.

`USE_AARCH64_BTI_TARGET_TYPE` refuses a `bti j` word as a function start: the hint says an
indirect *branch* may land there, which a compiler emits for jump-table cases and cleanup
blocks inside a routine, where `bti c` marks a call target and stays a plausible entry.

Every AArch64 binary bundled with this repo carries its `bti j` words inside exception
landing pads, where the shape test refuses them on its own account and the LSDA rule refuses
them before that -- so on those the flag is redundant and changes nothing either way. The
image below places the word where the shape test would otherwise accept it: after alignment
padding, opening a block that looks exactly like an entry, in a raw buffer that declares no
`.eh_frame` and so no landing pads at all. That is the one arrangement in which the flag
decides the outcome by itself.
"""

import struct
import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000

NOP = 0xD503201F
RET = 0xD65F03C0
#: stp x29, x30, [sp, #-16]! / ldp x29, x30, [sp], #16 -- an ordinary frame open and close
STP_FRAME = 0xA9BF7BFD
LDP_FRAME = 0xA8C17BFD

BTI = 0xD503241F
BTI_C = 0xD503245F
BTI_J = 0xD503249F
BTI_JC = 0xD50324DF

#: where the hint word lands, and where the block behind it starts
HINT = BASE + 0x20
BODY = HINT + 4


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def image(hint):
    """A function, alignment padding, then `hint` opening an entry-shaped block."""
    return (
        words(STP_FRAME, NOP, LDP_FRAME, RET)
        + words(NOP, NOP, NOP, NOP)
        + words(hint, STP_FRAME, LDP_FRAME, RET)
        + words(NOP, NOP)
    )


def recovered(hint, target_type):
    config = SmdaConfig()
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.CALCULATE_HASHING = False
    config.USE_AARCH64_BTI_TARGET_TYPE = target_type
    report = Disassembler(config).disassembleBuffer(image(hint), BASE, bitness=64, architecture="aarch64")
    return {function.offset for function in report.getFunctions()}


class AArch64BtiTargetTypeTest(unittest.TestCase):
    def testTheFlagIsOnByDefault(self):
        self.assertTrue(SmdaConfig().USE_AARCH64_BTI_TARGET_TYPE)

    def testAJumpOnlyHintIsNotAnEntry(self):
        self.assertNotIn(HINT, recovered(BTI_J, True))
        # the block behind it is still recovered, so the hint word is refused rather than the
        # code it labels being lost with it
        self.assertIn(BODY, recovered(BTI_J, True))

    def testTheSameWordIsAnEntryWithTheFlagOff(self):
        # the control that makes the case above measure this rule and not some other filter
        self.assertIn(HINT, recovered(BTI_J, False))
        self.assertNotIn(BODY, recovered(BTI_J, False))

    def testACallTargetHintStaysAnEntry(self):
        # `bti c` is the hint a compiler puts on a real function under branch protection
        for target_type in (False, True):
            self.assertIn(HINT, recovered(BTI_C, target_type))

    def testTheCombinedAndBareHintsAreUnaffected(self):
        # `bti jc` admits a call, and a bare `bti` admits both, so neither says jump-only
        for hint in (BTI_JC, BTI):
            self.assertEqual(recovered(hint, False), recovered(hint, True))
            self.assertIn(HINT, recovered(hint, True))

    def testTheFirstFunctionIsRecoveredInEveryArrangement(self):
        # every assertion above reads a set that is empty on a run that did nothing
        for hint in (BTI, BTI_C, BTI_J, BTI_JC):
            for target_type in (False, True):
                self.assertIn(BASE, recovered(hint, target_type))


if __name__ == "__main__":
    unittest.main()
