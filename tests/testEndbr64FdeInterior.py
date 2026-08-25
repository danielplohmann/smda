"""A CET landing pad inside a declared FDE range is not a function start.

`endbr64` marks every indirect-branch target, not every function entry, so gcc emits one at
each destination of a computed goto or a switch inside a single routine. The image says which
is which: an FDE covers one routine, so a pad that is not its range's own start is interior.

The fixture is a real gcc -O2 -fcf-protection=full binary built for this, because no bundled
sample carries the shape - `elf_cet_landing_pads_x64_xored`, whose `dispatch` compiles to one
FDE containing four pads that are branch targets rather than entries.
"""

import logging
import os
import unittest

import lief

from smda.common.EhFrameDecoder import decodeEhFrameFdeRanges
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

FIXTURE = "elf_cet_landing_pads_x64_xored"
ENDBR64 = b"\xf3\x0f\x1e\xfa"


def loadFixture():
    path = os.path.join(str(os.path.abspath(os.path.dirname(__file__))), FIXTURE)
    with open(path, "rb") as handle:
        data = handle.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def fdeRanges(binary):
    section = binary.get_section(".eh_frame")
    return sorted(
        (start, start + length)
        for start, length in decodeEhFrameFdeRanges(bytes(section.content), section.virtual_address)
        if length
    )


def padsInText(binary):
    text = binary.get_section(".text")
    data = bytes(text.content)
    base = text.virtual_address
    return [base + index for index in range(len(data) - 3) if data[index : index + 4] == ENDBR64]


class Endbr64FdeInteriorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.buffer = loadFixture()
        cls.binary = lief.ELF.parse(list(cls.buffer))
        cls.ranges = fdeRanges(cls.binary)
        cls.pads = padsInText(cls.binary)
        starts = {start for start, _ in cls.ranges}
        cls.pads_at_a_start = [pad for pad in cls.pads if pad in starts]
        cls.interior_pads = [pad for pad in cls.pads if any(start < pad < end for start, end in cls.ranges)]

    def testTheFixtureCarriesBothShapes(self):
        # Without this the comparisons below would pass on a binary that has neither.
        self.assertTrue(self.ranges, "the fixture declares no FDE ranges")
        self.assertEqual(len(self.pads_at_a_start), 4)
        self.assertEqual(len(self.interior_pads), 4)
        self.assertFalse(set(self.pads_at_a_start) & set(self.interior_pads))

    def testAnInteriorPadIsNotSeeded(self):
        # `is_initial_candidate` is set by the seeding scans and never by gap analysis, so it
        # isolates the decision this rule makes. A pad the scan declines can still be reached
        # later by the gap scan when nothing claimed the bytes - that is a different pass and
        # a separate question.
        candidates = self.candidates()
        for pad in self.interior_pads:
            candidate = candidates.get(pad)
            self.assertFalse(
                candidate is not None and candidate.is_initial_candidate,
                f"0x{pad:x} sits inside a declared FDE range and was still seeded",
            )

    def testAPadThatStartsItsOwnRangeIsStillSeeded(self):
        # The control: the same byte pattern, refused above, is still seeded where the image
        # declares a routine begins at it. Without this the test would also pass if the
        # endbr64 seed had simply been removed.
        candidates = self.candidates()
        seeded = [pad for pad in self.pads_at_a_start if pad in candidates and candidates[pad].is_initial_candidate]
        self.assertEqual(len(seeded), len(self.pads_at_a_start))

    def candidates(self):
        disassembler = Disassembler(config=SmdaConfig())
        disassembler.disassembleBuffer(self.buffer, 0, 64)
        return disassembler.disassembler.fc_manager.candidates


class DeclaredFdeRangePredicateTest(unittest.TestCase):
    """The predicate itself, including the boundaries the range lookup has to get right."""

    def setUp(self):
        self.buffer = loadFixture()
        disassembler = Disassembler(config=SmdaConfig())
        self.report = disassembler.disassembleBuffer(self.buffer, 0, 64)
        self.manager = disassembler.disassembler.fc_manager

    def testRangeStartsAndEndsAreNotInterior(self):
        ranges = self.manager.ehFrameFdeRanges()
        self.assertTrue(ranges)
        for start, end in ranges:
            self.assertIsNone(self.manager.declaredFdeRangeContaining(start))
            self.assertIsNone(self.manager.declaredFdeRangeContaining(end))
            self.assertEqual(self.manager.declaredFdeRangeContaining(start + 1), (start, end))

    def testAnAddressOutsideEveryRangeIsNotInterior(self):
        ranges = self.manager.ehFrameFdeRanges()
        beyond = max(end for _, end in ranges) + 0x1000
        self.assertIsNone(self.manager.declaredFdeRangeContaining(beyond))
        self.assertIsNone(self.manager.declaredFdeRangeContaining(0))

    def testRangesAreNotMerged(self):
        # Consecutive functions are laid out end-to-start, so a helper that merged adjacent
        # ranges would collapse .text into one span and call every address but the first
        # interior. The fixture has such a pair; both have to survive as separate ranges.
        ranges = self.manager.ehFrameFdeRanges()
        adjacent = [index for index in range(1, len(ranges)) if ranges[index][0] == ranges[index - 1][1]]
        self.assertTrue(adjacent, "the fixture has no end-to-start pair to check merging against")
        for index in adjacent:
            self.assertIsNone(self.manager.declaredFdeRangeContaining(ranges[index][0]))


if __name__ == "__main__":
    unittest.main()
