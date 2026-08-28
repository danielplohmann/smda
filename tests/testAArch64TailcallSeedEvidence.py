import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
IMAGE_SIZE = 0x3100

NOP = 0xD503201F
RET = 0xD65F03C0
PROLOGUE = 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!
EPILOGUE = 0xA8C17BFD  # ldp x29, x30, [sp], #16
MOV_W0_1 = 0x52800020
MOV_W1_2 = 0x52800041
MOV_W2_3 = 0x52800062

#: enough call-referenced entries, all 16-aligned, for the alignment floor to infer 16.
#: The inference needs more than twenty candidates carrying more than one reference each.
LEAF_COUNT = 22


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


class TailcallSeedEvidenceTest(unittest.TestCase):
    """A direct branch is not a direct call, and only the second is the image's own evidence.

    Candidate discovery infers an alignment for function starts and refuses a candidate below
    it, exempting the ones a call reference vouches for. Recording a branch target as an
    inbound call reference puts a mid-function address through that exemption, where it
    outranks the routine it sits inside.
    """

    def _image(self):
        words = {}
        leaves = [BASE + 0x1000 + index * 0x10 for index in range(LEAF_COUNT)]
        for leaf in leaves:
            words.update({leaf: PROLOGUE, leaf + 4: MOV_W0_1, leaf + 8: EPILOGUE, leaf + 12: RET})

        address = BASE
        words[address] = PROLOGUE
        address += 4
        for leaf in leaves:
            for _call in range(2):
                words[address] = _bl(address, leaf)
                address += 4
        words[address] = EPILOGUE
        words[address + 4] = RET

        # A 16-aligned routine whose body holds a merely 4-aligned word. It opens on no
        # prologue and nothing calls it, so the gap scan is what recovers it -- which is
        # after every candidate booked in the first pass.
        victim = BASE + 0x2000
        interior = victim + 4
        words.update({victim: MOV_W1_2, interior: MOV_W0_1, victim + 8: MOV_W2_3, victim + 12: RET})

        # the seeding site: a routine ending in a backward branch into that body
        seeder = BASE + 0x3000
        words.update({seeder: PROLOGUE, seeder + 4: EPILOGUE, seeder + 8: _b(seeder + 8, interior)})

        image = bytearray(NOP.to_bytes(4, "little") * (IMAGE_SIZE // 4))
        for word_address, word in words.items():
            image[word_address - BASE : word_address - BASE + 4] = word.to_bytes(4, "little")
        return bytes(image), victim, interior, seeder

    def setUp(self):
        image, self.victim, self.interior, self.seeder = self._image()
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

    def testTheBranchTargetIsNotBookedAsAFunction(self):
        self.assertNotIn(self.interior, self.functions)

    def testTheRoutineItSitsInsideIsRecovered(self):
        """The other half of the same move: the interior address did not merely stop being a
        function, it stopped displacing the one it belongs to."""
        self.assertIn(self.victim, self.functions)

    def testTheBranchingRoutineIsStillRecovered(self):
        """Control. Both assertions above would hold on an image that failed to analyse."""
        self.assertIn(self.seeder, self.functions)
        self.assertIn(BASE, self.functions)


class TailcallCandidateHasNoCallReferenceTest(unittest.TestCase):
    """The mechanism, isolated from the traversal that reaches it."""

    def _manager(self):
        import types

        from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager

        config = SmdaConfig()
        manager = FunctionCandidateManager(config)
        manager.disassembly = types.SimpleNamespace(
            binary_info=types.SimpleNamespace(bitness=64, base_addr=0, binary=b"\x00" * 0x10000),
            analysis_timeout=False,
        )
        manager.bitness = 64
        manager.identified_alignment = 16
        manager._code_areas = []
        return manager

    def testABookedTailcallCarriesNoInboundCallReference(self):
        manager = self._manager()

        self.assertTrue(manager.addTailcallCandidate(0x1004))
        self.assertEqual(manager.candidates[0x1004].call_ref_sources, set())

    def testTheAlignmentFloorThenRefusesIt(self):
        manager = self._manager()
        manager.addTailcallCandidate(0x1004)
        manager._buildQueue()

        self.assertNotIn(0x1004, [candidate.addr for candidate in manager.getNextFunctionStartCandidate()])

    def testACalledAddressIsStillExemptFromTheFloor(self):
        """Control: the exemption is not removed, only stopped from being manufactured. An
        address something really calls still passes the floor at the same alignment."""
        manager = self._manager()
        manager.addReferenceCandidate(0x1004, 0x2000)
        manager._buildQueue()

        self.assertIn(0x1004, [candidate.addr for candidate in manager.getNextFunctionStartCandidate()])


if __name__ == "__main__":
    unittest.main()
