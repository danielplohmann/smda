import unittest

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from smda.aarch64.AArch64Backend import _hasDataRefImmediate
from smda.aarch64.dataflow import propagateConstants


def _decode(cs, words, base=0x1000):
    """Decode a little-endian sequence of 32-bit AArch64 words into detailed capstone
    instructions, starting at base."""
    instructions = []
    addr = base
    for word in words:
        instructions.append(next(cs.disasm(word.to_bytes(4, "little"), addr)))
        addr += 4
    return instructions


class _NoImageDisassembler:
    """Minimal disassembler stub for the ldr branch: nothing is inside the image, so no
    load ever resolves and only register invalidation is exercised."""

    class disassembly:
        @staticmethod
        def isAddrWithinMemoryImage(addr):
            return False

        @staticmethod
        def getBytes(addr, size):
            return None


class AArch64DataflowTestSuite(unittest.TestCase):
    """Regression tests for _applyConstantWrite: the add-with-shift handling (immediate
    and register forms) and the fallback invalidation for unmodeled mnemonics that
    redefine a previously-tracked register."""

    def setUp(self):
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

    def test_add_immediate_applies_lsl_shift(self):
        # mov x1, #5 ; add x0, x1, #4, lsl #12  ->  x0 = 5 + (4 << 12) = 16389,
        # NOT 5 + 4 = 9 (the pre-fix bug: op2.shift was ignored entirely).
        words = [0xD28000A1, 0x91401020]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[1].mnemonic, "add")
        self.assertEqual(instructions[1].op_str, "x0, x1, #4, lsl #12")

        constants = propagateConstants(instructions, None)

        self.assertEqual(constants.get("x1"), 5)
        self.assertEqual(constants.get("x0"), 5 + (4 << 12))

    def test_add_register_applies_lsl_shift(self):
        # mov x1, #5 ; mov x2, #7 ; add x0, x1, x2, lsl #3  ->  x0 = 5 + (7 << 3) = 61,
        # NOT 5 + 7 = 12 (the pre-fix bug: op2.shift was ignored for the reg+reg form too).
        words = [0xD28000A1, 0xD28000E2, 0x8B020C20]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[2].mnemonic, "add")
        self.assertEqual(instructions[2].op_str, "x0, x1, x2, lsl #3")

        constants = propagateConstants(instructions, None)

        self.assertEqual(constants.get("x1"), 5)
        self.assertEqual(constants.get("x2"), 7)
        self.assertEqual(constants.get("x0"), 5 + (7 << 3))

    def test_unmodeled_mnemonic_invalidates_previously_tracked_register(self):
        # mov x0, #5 ; sub x0, x0, #1 -- "sub" is not one of the tracked mnemonics
        # (adrp/adr/add/mov/movz/movk/ldr/ldur), so the previously resolved value for
        # x0 must be dropped, not left stale at 5.
        words = [0xD28000A0, 0xD1000400]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[1].mnemonic, "sub")
        self.assertEqual(instructions[1].op_str, "x0, x0, #1")

        constants = propagateConstants(instructions, None)

        self.assertNotIn("x0", constants)

    def test_post_index_load_invalidates_writeback_base(self):
        # mov x1, #0x100 ; ldr x0, [x1], #8 -- the post-index form increments x1 to 0x108.
        # The base register is a MEM operand, so neither the ldr branch (which writes only
        # operands[0]) nor the CS_AC_WRITE fallback (which pops only REG operands) touched
        # it, and x1 stayed stale at 0x100.
        words = [0xD2802001, 0xF8408420]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[1].op_str, "x0, [x1], #8")
        self.assertTrue(instructions[1].writeback)

        constants = propagateConstants(instructions, _NoImageDisassembler())

        self.assertNotIn("x1", constants)

    def test_pre_index_store_invalidates_writeback_base(self):
        # mov x1, #0x100 ; str x0, [x1, #8]! -- str never reaches the ldr branch at all,
        # and the generic clobber loop skips the MEM operand carrying the writeback.
        words = [0xD2802001, 0xF8008C20]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[1].op_str, "x0, [x1, #8]!")
        self.assertTrue(instructions[1].writeback)

        constants = propagateConstants(instructions, None)

        self.assertNotIn("x1", constants)

    def test_plain_offset_load_keeps_base_register(self):
        # mov x1, #0x100 ; ldr x0, [x1, #8] -- no writeback, so x1 must survive intact
        words = [0xD2802001, 0xF9400420]
        instructions = _decode(self.cs, words)
        self.assertEqual(instructions[1].op_str, "x0, [x1, #8]")
        self.assertFalse(instructions[1].writeback)

        constants = propagateConstants(instructions, _NoImageDisassembler())

        self.assertEqual(constants.get("x1"), 0x100)

    def test_bl_invalidates_the_link_register_it_writes_implicitly(self):
        # adrp x30, #0x1000 ; bl #... -> the branch clobbers x30 (capstone names it lr and
        # reports it only in the implicit regs_write list, since bl's sole operand is the
        # branch immediate), so the tracked page value must not survive the call.
        instructions = _decode(self.cs, [0x9000001E, 0x94000001])
        self.assertEqual(instructions[0].mnemonic, "adrp")
        self.assertEqual(instructions[1].mnemonic, "bl")

        self.assertEqual(propagateConstants(instructions[:1], None).get("lr"), 0x1000)
        self.assertNotIn("lr", propagateConstants(instructions, None))

    def test_blr_invalidates_the_link_register_it_writes_implicitly(self):
        # The same implicit x30 write on the register-indirect call, whose own operand is a
        # register - so it clears the modelled branches' operands[0] check and would still
        # never reach the link register without the implicit-write pass.
        instructions = _decode(self.cs, [0x9000001E, 0xD63F0100])
        self.assertEqual(instructions[1].mnemonic, "blr")

        self.assertNotIn("lr", propagateConstants(instructions, None))

    def test_br_leaves_tracked_registers_alone(self):
        # Counter-case: a plain indirect branch writes no register, so the implicit-write
        # pass must not invalidate anything the modelled branches resolved.
        instructions = _decode(self.cs, [0x9000001E, 0xD61F0100])
        self.assertEqual(instructions[1].mnemonic, "br")

        self.assertEqual(propagateConstants(instructions, None).get("lr"), 0x1000)


class DataRefImmediateGateTestSuite(unittest.TestCase):
    """The gate that decides whether _recordDataRefs re-decodes an instruction for details."""

    IN_IMAGE = lambda self, value: False  # noqa: E731

    def test_operands_without_an_immediate_marker_are_rejected_outright(self):
        self.assertFalse(_hasDataRefImmediate("x0, x1", 0x1000, 0x2000, self.IN_IMAGE))

    def test_immediate_inside_the_image_and_outside_code_areas_is_accepted(self):
        self.assertTrue(_hasDataRefImmediate("x0, #0x1500", 0x1000, 0x2000, self.IN_IMAGE))

    def test_immediate_outside_the_image_is_rejected(self):
        self.assertFalse(_hasDataRefImmediate("x0, #0x9000", 0x1000, 0x2000, self.IN_IMAGE))

    def test_immediate_inside_a_code_area_is_rejected(self):
        self.assertFalse(_hasDataRefImmediate("x0, #0x1500", 0x1000, 0x2000, lambda value: True))

    def test_a_token_int_cannot_parse_is_skipped_rather_than_raising(self):
        # base 0 rejects a leading zero, so "#08" reaches the ValueError arm
        self.assertTrue(_hasDataRefImmediate("x0, #08, #0x1500", 0x1000, 0x2000, self.IN_IMAGE))


if __name__ == "__main__":
    unittest.main()
