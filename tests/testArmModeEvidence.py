"""Which instruction set a function is decoded in, when weak and strong evidence disagree, and
where a function ends after a call that does not return.

The images are ``llvm-mc -triple=thumbv7-linux-gnueabihf`` + ``ld.lld -Ttext=<base>``, loaded
as raw buffers so that nothing but the code itself names the instruction sets.
"""

import unittest

from smda.arm.ArmDisassembler import ArmDisassembler
from smda.arm.FunctionCandidateManager import MODE_DECODED, MODE_GUESS, MODE_SCAN, MODE_STATED
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

# start (T32):    push {r4, lr}; bl helper_t; movs r0, #3; blx noret_a; .hword 0xd4d4 (lld's fill)
# noret_a (A32):  mov r0, #1; b noret_a
# helper_t (T32): adds r0, #1; bx lr
# start2 (T32):   push {r4, lr}; bl helper_t; bl noret_t; .hword 0xd4d4
# noret_t (T32):  movs r0, #2; b noret_t; .hword 0xd4d4
LLD_FILL_BASE = 0x10000
LLD_FILL = bytes.fromhex("10b500f009f8032000f002e8d4d400bf0100a0e3fdffffea0130704710b5fff7fbff00f001f8d4d40220fde7d4d4")
LLD_FILL_FUNCTIONS = {0x10000: True, 0x10010: False, 0x10018: True, 0x1001C: True, 0x10028: True}

# main (T32):  push {r4, lr}; blx F; pop {r4, pc}
# leaf1, leaf2 (T32), leaf2 loading a literal word that reads as a T32 ``bl F``
# leaf3 (T32): push {r4, lr}; bl leaf1; bl leaf2; pop {r4, pc}
# F (A32):     push {r4, lr}; mov r0, #7; pop {r4, pc}
SCAN_VS_BLX_BASE = 0x1000
SCAN_VS_BLX = bytes.fromhex("10b500f00ee810bd401c70470048704700f006f810b5fff7f7fffff7f7ff10bd10402de90700a0e31080bde8")

# main (A32): push {r4, lr}; bl G; bl H; pop {r4, pc}
# G (A32):    cmp r0, #0; b 0x2000000 (out of the image)
# H (A32):    cmp r0, #0; bxeq lr; b 0 (an undefined weak symbol in a static link)
OUT_OF_IMAGE_BASE = 0x10000
OUT_OF_IMAGE = bytes.fromhex("10402de9010000eb020000eb1080bde8000050e3f9bf7fea000050e31eff2f01f6bfffea")

# main (A32): push {r4, lr}; bl F; pop {r4, pc}
# F (A32):    b .+4 (as -O0 code opens a function); mov r0, #1; bx lr
BRANCH_TO_NEXT = bytes.fromhex("10402de9000000eb1080bde8ffffffea0100a0e31eff2fe1")


def _disassemble(buffer, base):
    return Disassembler(SmdaConfig()).disassembleBuffer(buffer, base, architecture="arm")


def _modes(report):
    return {function.offset: function.architecture_metadata["thumb"] for function in report.getFunctions()}


class ArmCallIntoFillTest(unittest.TestCase):
    """lld pads to the next section with ``0xd4d4``, which decodes as ``bmi``: a call that does
    not return, followed by that fill, ends its function instead of branching into another."""

    def setUp(self):
        self.report = _disassemble(LLD_FILL, LLD_FILL_BASE)

    def test_the_functions_and_their_instruction_sets(self):
        self.assertEqual(_modes(self.report), LLD_FILL_FUNCTIONS)

    def test_the_caller_ends_at_its_last_call(self):
        for start, last_call in ((0x10000, 0x10008), (0x1001C, 0x10022)):
            instructions = list(self.report.getFunction(start).getInstructions())
            self.assertEqual(instructions[-1].offset, last_call)
            self.assertIn(instructions[-1].mnemonic, ("bl", "blx"))

    def test_no_instruction_decodes_the_fill(self):
        fill = {0x1000C, 0x10026, 0x1002C}
        decoded = {
            instruction.offset for function in self.report.getFunctions() for instruction in function.getInstructions()
        }
        self.assertFalse(fill & decoded)


class ArmScannedCallVersusBlxTest(unittest.TestCase):
    """A literal word that reads as a T32 ``bl F`` names F as Thumb; the ``blx F`` decoded on a
    path names it A32 and wins."""

    def test_the_decoded_blx_decides_the_instruction_set(self):
        report = _disassemble(SCAN_VS_BLX, SCAN_VS_BLX_BASE)
        function = report.getFunction(0x1020)
        self.assertIsNotNone(function)
        self.assertFalse(function.architecture_metadata["thumb"])
        self.assertEqual(
            [instruction.mnemonic for instruction in function.getInstructions()],
            ["push", "mov", "pop"],
        )
        self.assertTrue(_modes(report)[0x1000])


class ArmBranchOutOfImageTest(unittest.TestCase):
    def test_a_branch_out_of_the_image_refuses_the_function(self):
        report = _disassemble(OUT_OF_IMAGE, OUT_OF_IMAGE_BASE)
        functions = _modes(report)
        self.assertNotIn(0x10010, functions)
        self.assertIn(0x10000, functions)

    def test_a_branch_to_zero_is_an_undefined_weak_symbol(self):
        report = _disassemble(OUT_OF_IMAGE, OUT_OF_IMAGE_BASE)
        self.assertIn(0x10018, _modes(report))


class ArmBranchToNextInstructionTest(unittest.TestCase):
    def test_a_first_branch_to_the_next_instruction_is_no_stub(self):
        report = _disassemble(BRANCH_TO_NEXT, 0x10000)
        self.assertEqual(_modes(report), {0x10000: False, 0x1000C: False})
        self.assertEqual(report.getFunction(0x1000C).num_instructions, 3)


class ArmModeStrengthTest(unittest.TestCase):
    """A statement about an address's instruction set replaces a weaker one, never a stronger
    one; among equals the first stands, except for the image's own statements."""

    def setUp(self):
        self.disassembler = ArmDisassembler(SmdaConfig())
        binary_info = BinaryInfo(SCAN_VS_BLX)
        binary_info.base_addr = SCAN_VS_BLX_BASE
        binary_info.bitness = 32
        self.disassembler.analyzeBuffer(binary_info)
        self.manager = self.disassembler.fc_manager

    def test_strength_order(self):
        manager = self.manager
        address = 0x1100
        manager.noteMode(address, True, MODE_GUESS)
        manager.noteMode(address, False, MODE_SCAN)
        self.assertIs(manager.notedThumb(address), False)
        manager.noteMode(address, True, MODE_SCAN)
        self.assertIs(manager.notedThumb(address), False)
        manager.noteMode(address, True, MODE_DECODED)
        self.assertIs(manager.notedThumb(address), True)
        manager.noteMode(address, False, MODE_SCAN)
        self.assertIs(manager.notedThumb(address), True)
        manager.noteMode(address, False, MODE_STATED)
        manager.noteMode(address, True, MODE_DECODED)
        self.assertIs(manager.notedThumb(address), False)
        manager.noteMode(address, True, MODE_STATED)
        self.assertIs(manager.notedThumb(address), True)

    def test_a_function_decoded_in_the_overruled_set_is_decoded_again(self):
        disassembly = self.disassembler.disassembly
        self.assertIn(0x1020, disassembly.functions)
        self.manager.noteMode(0x1020, True, MODE_STATED)
        self.disassembler.analyzeFunction(0x1000)
        self.assertNotIn(0x1024, disassembly.instructions)
        self.assertNotEqual(disassembly.function_metadata.get(0x1020), {"thumb": False})
        candidate = self.manager.candidates[0x1020]
        self.assertTrue(candidate.is_thumb)
        self.assertIn(candidate, self.manager.candidate_queue)


if __name__ == "__main__":
    unittest.main()
