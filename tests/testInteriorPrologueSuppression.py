import logging
import unittest

from smda.DisassemblyResult import DisassemblyResult
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

    def getExceptionDirectory(self):
        return None

    def getLiefBinary(self):
        # A raw buffer has no container, so the declared-range lookup finds no `.eh_frame`
        # and the rules built on it are inert here -- which is what a memory dump also sees.
        return None

    def _getLiefType(self):
        # what BinaryInfo answers when there is no container to identify: not PE, so the
        # exception-directory walk does not read a section named `.pdata` as one
        return "OTHER"


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


if __name__ == "__main__":
    unittest.main()
