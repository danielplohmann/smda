import unittest

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

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


if __name__ == "__main__":
    unittest.main()
