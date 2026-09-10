import logging
import re
import unittest

from smda.DisassemblyResult import DisassemblyResult
from smda.intel.definitions import DEFAULT_PROLOGUES, DEFAULT_PROLOGUES_64
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

BASE_ADDR = 0x400000
PAD = b"\xcc" * 16
#: sub rsp, 0x20 / nops / add rsp, 0x20 / ret -- enough body that neither match is at a buffer edge
BODY = b"\x48\x83\xec\x20" + b"\x90" * 8 + b"\x48\x83\xc4\x20\xc3"
FRAME_PROLOGUE = b"\x55\x48\x89\xe5"  # push rbp; mov rbp, rsp
CALLEE_SAVED = b"\x41\x57\x41\x56"  # push r15; push r14
HOTPATCH_PROLOGUE = b"\x8b\xff\x55\x8b\xec"  # mov edi, edi; push ebp; mov ebp, esp


class _BufferBinaryInfo:
    """The parts of BinaryInfo the candidate scan reads, over a raw buffer.

    A buffer with no container is what the seeding scan sees on a memory dump, and it
    keeps the test to the one pass under examination rather than a whole analysis.
    """

    def __init__(self, bitness, base_addr, binary):
        self.bitness = bitness
        self.base_addr = base_addr
        self.binary = binary
        self.binary_size = len(binary)
        self.code_areas = []

    def getSections(self):
        return iter(())

    def _getLiefType(self):
        # "OTHER" is what BinaryInfo answers for a buffer lief cannot parse, which is what
        # the PE-only branches of the exception walk test against
        return "OTHER"

    def getExceptionDirectory(self):
        return None

    def getLiefBinary(self):
        # A raw buffer has no container, so the declared-range lookup finds no `.eh_frame`
        # and the rules built on it are inert here -- which is what a memory dump also sees.
        return None


def scannedPrologueOrder(bitness=64):
    """The patterns `locatePrologueCandidates` hands to the seeding scan, in scan order."""
    manager = FunctionCandidateManager(SmdaConfig())
    disassembly = DisassemblyResult()
    disassembly.binary_info = _BufferBinaryInfo(bitness, BASE_ADDR, PAD + BODY + PAD)
    order = []
    seed = manager._seedPrologueMatches

    def recording(pattern, *args, **kwargs):
        order.append(pattern)
        return seed(pattern, *args, **kwargs)

    manager._seedPrologueMatches = recording
    manager.init(disassembly)
    return order


def seededStarts(buffer, bitness=64):
    manager = FunctionCandidateManager(SmdaConfig())
    disassembly = DisassemblyResult()
    disassembly.binary_info = _BufferBinaryInfo(bitness, BASE_ADDR, bytes(buffer))
    manager.init(disassembly)
    return {addr for addr, candidate in manager.candidates.items() if candidate.is_initial_candidate}


class InteriorPrologueSuppressionTest(unittest.TestCase):
    """A prologue match starting where another prologue match ends is inside that
    function's body: no function consists only of its own opening instructions."""

    def testACalleeSavedRunAfterAFrameSetupIsNotAFunctionStart(self):
        opened = FRAME_PROLOGUE + CALLEE_SAVED + BODY
        standalone = CALLEE_SAVED + BODY
        buffer = PAD + opened + PAD + standalone + PAD
        entry = BASE_ADDR + len(PAD)
        interior = entry + len(FRAME_PROLOGUE)
        other_entry = BASE_ADDR + len(PAD) + len(opened) + len(PAD)

        seeded = seededStarts(buffer)
        self.assertIn(entry, seeded)
        self.assertNotIn(interior, seeded)
        # control: the same byte pattern is still seeded where nothing precedes it, so
        # the rule is about position and not about the pattern being untrustworthy
        self.assertIn(other_entry, seeded)

    def testTheRuleReadsThePrecedingBytesAndNotTheDistance(self):
        # push rbp; mov rbp, rsi -- one byte off the seeded frame prologue and not on the list
        not_a_prologue = b"\x55\x48\x89\xe6"
        buffer = PAD + not_a_prologue + CALLEE_SAVED + BODY + PAD
        follower = BASE_ADDR + len(PAD) + len(not_a_prologue)
        self.assertIn(follower, seededStarts(buffer))

    def testTheEarlierMatchHasToBeACandidateOfItsOwn(self):
        # the frame prologue is cut off by the start of the buffer, so nothing precedes
        # the callee-saved run that the scan admitted, and it stands on its own
        buffer = FRAME_PROLOGUE[2:] + CALLEE_SAVED + BODY + PAD
        follower = BASE_ADDR + len(FRAME_PROLOGUE[2:])
        self.assertIn(follower, seededStarts(buffer))

    def testA32BitScanNeverConsultsThe64BitPatterns(self):
        # `push r15; push r14` is 64-bit-only and is not seeded at 32 bits at all, so the
        # 32-bit scan cannot suppress on it either: `push ebp; mov ebp, esp` after it stands
        buffer = PAD + CALLEE_SAVED + b"\x55\x8b\xec" + BODY + PAD
        follower = BASE_ADDR + len(PAD) + len(CALLEE_SAVED)
        seeded = seededStarts(buffer, bitness=32)
        self.assertIn(follower, seeded)
        self.assertNotIn(BASE_ADDR + len(PAD), seeded)

    def testAnAddressSomethingCallsSurvivesTheRule(self):
        """A call target is already a candidate before the prologue scan runs.

        The rule declines to *add* a prologue candidate; it never removes one. Reference
        discovery runs three passes earlier, so an entry the image calls directly keeps
        its candidacy even when the bytes in front of it are another seeded prologue.
        """
        opened = FRAME_PROLOGUE + CALLEE_SAVED + BODY
        entry = BASE_ADDR + len(PAD)
        interior = entry + len(FRAME_PROLOGUE)
        # control: with nothing calling it, the interior match is refused
        self.assertNotIn(interior, seededStarts(PAD + opened + PAD))

        # e8 rel32 to the interior address, placed after the function so the call site
        # is not itself inside the bytes under test
        call_site = BASE_ADDR + len(PAD) + len(opened)
        displacement = interior - (call_site + 5)
        call = b"\xe8" + displacement.to_bytes(4, "little", signed=True)
        self.assertIn(interior, seededStarts(PAD + opened + call + BODY + PAD))

    def testTheHotpatchPadIsStillTheEntryItAlwaysWas(self):
        # control for the neighbouring rule: `mov edi, edi` pads the entry and the bare
        # prologue two bytes in is the body, which is decided by a different test than this one
        buffer = PAD + HOTPATCH_PROLOGUE + BODY + PAD
        entry = BASE_ADDR + len(PAD)
        seeded = seededStarts(buffer, bitness=32)
        self.assertIn(entry, seeded)
        self.assertNotIn(entry + 2, seeded)

    def testTheBaseFamilyIsScannedBeforeThe64BitFamily(self):
        """The refusal is directional, so the containing prologue has to be seeded first.

        `_opensInsideAnEarlierPrologue` refuses a match only when the address the
        preceding prologue starts at is *already* a candidate. Nothing re-examines a
        match once a later pattern seeds the prologue in front of it, so the rule
        refuses B-after-A and never A-after-B: the clang pair it was written for,
        `push rbp; mov rbp, rsp` then `push r15; push r14`, is refused only because
        the frame prologue is scanned first.

        That makes the family order load-bearing rather than incidental. The
        behavioural tests above do fail when it changes, but they fail as an
        unexpected address and can be quieted by editing the expected set, which
        would drop the suppression this rule was measured to be worth. This one
        fails as what it is.

        The CET pad scanned between the two families is deliberately left out.
        `endbr64` opens a function ahead of `push rbp; mov rbp, rsp`, and being
        scanned second it does seed that pair four bytes into every such entry --
        19,536 times over the 260-cell built C/C++ matrix, across 40 of its
        cells. It changes no reported function: the entry is recovered from the
        pad and the interior candidate is absorbed into it, so moving the pad
        ahead of the base family leaves TP, FP and FN identical on the nine cells
        where the pattern is densest. Pinning a position that carries nothing
        would only make the order harder to change for the reasons it should be.
        """
        order = scannedPrologueOrder()
        for prologue in DEFAULT_PROLOGUES + DEFAULT_PROLOGUES_64:
            self.assertIn(re.escape(prologue), order)
        last_base = max(order.index(re.escape(p)) for p in DEFAULT_PROLOGUES)
        first_wide = min(order.index(re.escape(p)) for p in DEFAULT_PROLOGUES_64)
        self.assertLess(
            last_base,
            first_wide,
            "DEFAULT_PROLOGUES must all be scanned before DEFAULT_PROLOGUES_64: the "
            "interior-prologue refusal only fires when the containing prologue is already "
            "a candidate, so moving a pattern across the two families, or reordering the "
            "two scans, silently stops it refusing the body matches it was measured on.",
        )

    def testAContainingPrologueIsScannedBeforeThePatternItEndsWith(self):
        """A pattern that is the tail of a longer one must be scanned after it.

        `\x8b\xff\x55\x8b\xec` is the MSVC hotpatch pad in front of
        `\x55\x8b\xec`, so the bare form matches two bytes into every padded
        entry. The neighbouring hotpatch rule refuses that match on the same
        "already a candidate" test the interior rule uses, which again holds only
        because the padded form is seeded first.

        Stated over the patterns themselves rather than over the pair that exists
        today, so a prologue added later that happens to end with one already on
        the list is covered without anyone remembering to come back here.
        """
        order = scannedPrologueOrder()
        seeded = DEFAULT_PROLOGUES + DEFAULT_PROLOGUES_64
        pairs = [
            (longer, shorter)
            for longer in seeded
            for shorter in seeded
            if longer != shorter and longer.endswith(shorter)
        ]
        self.assertTrue(pairs, "expected at least the hotpatch pad over the bare frame prologue")
        for longer, shorter in pairs:
            self.assertLess(
                order.index(re.escape(longer)),
                order.index(re.escape(shorter)),
                f"{longer!r} ends with {shorter!r}, so every match of the shorter one inside it "
                f"names a body rather than an entry. The rules that refuse those matches test "
                f"whether the longer form is already a candidate, so it has to be scanned first.",
            )

    def testA32BitScanSeedsOnlyTheBaseFamily(self):
        """The 64-bit family is gated on bitness, so nothing at 32 bits can depend on it."""
        order = scannedPrologueOrder(bitness=32)
        for prologue in DEFAULT_PROLOGUES:
            self.assertIn(re.escape(prologue), order)
        for prologue in DEFAULT_PROLOGUES_64:
            self.assertNotIn(re.escape(prologue), order)


if __name__ == "__main__":
    unittest.main()
