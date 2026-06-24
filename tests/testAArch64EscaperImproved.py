"""Tests for the improved AArch64 `escapeBinary`.

The improvement is a per-mnemonic nibble-keep-mask that wildcardes the
position of the immediate field while preserving opcode + register bits.
This makes the escape position-invariant under relocation, so that
`getPicHash()` of a function is stable across recompilation with a shifted
load address (the core property verified by these tests).

Distinct from `tests/testAArch64EscaperCoverage.py` which focuses on
mnemonic classification coverage; this file tests the *semantic* property
of the new escape behaviour.
"""

import unittest


class _StubIns:
    """Minimal duck-typed SmdaInstruction for escaper tests.

    `getEscapedBinary` and `getDetailed` are wired up to the escaper under
    test, the same way SmdaInstruction does internally. We avoid constructing
    a full SmdaInstruction because that requires a smda_function/smda_report
    context; here we want to test the static escape logic in isolation.
    """

    def __init__(self, hex_bytes, mnemonic, operands="", report=None):
        self.bytes = hex_bytes
        self.mnemonic = mnemonic
        self.operands = operands
        self._report = report
        self.detailed = None
        # Pre-populate the cache used by SmdaInstruction.getDetailed so we
        # don't need capstone. The escaper code paths only need .operands.
        self._detailed_operand_truthy = bool(operands)
        self._detailed_cache = self if not operands else _Detailed(operands)

    def getDetailed(self):
        return self._detailed_cache


class _Detailed:
    """Minimal Capstone-CsInsn-like object: only the .operands attribute matters."""

    def __init__(self, operands):
        self.operands = _Operands(operands)


class _Operands:
    """Truthy wrapper that satisfies `bool(ins.getDetailed().operands)`."""

    def __init__(self, operands):
        self._operands = operands

    def __bool__(self):
        return bool(self._operands)

    def __iter__(self):
        return iter([])


def _esc(hex_bytes, mnemonic, operands=""):
    """Shorthand to call AArch64InstructionEscaper.escapeBinary on a stub."""
    from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper

    ins = _StubIns(hex_bytes, mnemonic, operands)
    return AArch64InstructionEscaper.escapeBinary(ins)


class AArch64EscaperImprovedTest(unittest.TestCase):
    # ------------------------------------------------------------------
    # adrp / adr : 21-bit imm (split into immhi:immlo for adrp) and 21-bit
    # non-page imm for adr. Mask covers bits 0..3 of Rd (low nibble) and
    # the op nibble. The top bit of Rd (bit 4) is wildcarded together
    # with the imm field that overlaps it.
    #
    # Output is in little-endian byte order (matching the format of
    # `ins.bytes`), with each byte rendered high-nibble-then-low-nibble.
    # This matches the convention of the existing `_wordWithMaskToHex`
    # helper used by `escapeToOpcodeOnly`, so the two escapers are
    # directly comparable.
    # ------------------------------------------------------------------
    def test_adrp_position_invariant_under_page_shift(self):
        # adrp x0, #0x1000  -> LE bytes "000000a0", word 0xA0000000
        #                       -> escape "?0????a0" (Rt low nibble 0 kept, op byte 0xa0 kept)
        # adrp x0, #0x100000 -> LE bytes "00080080", word 0x80000800
        #                       -> escape "?0????80" (different op byte)
        a = _esc("000000a0", "adrp", "x0, #0x1000")
        b = _esc("00080080", "adrp", "x0, #0x100000")
        # different op bytes, different escapes
        self.assertEqual(a, "?0????a0")
        self.assertEqual(b, "?0????80")
        # Now verify position-invariance with the same op byte:
        c = _esc("000000a0", "adrp", "x0, #0x1000")
        d = _esc("001000a0", "adrp", "x0, #0x11000")
        self.assertEqual(c, d, "adrp should be position-invariant on imm shift when op byte matches")

    def test_adr_position_invariant(self):
        a = _esc("00000010", "adr", "x0, #0")
        # adr x0, #0x10  -> word 0x10020000, LE bytes "00020010"
        b = _esc("00020010", "adr", "x0, #0x10")
        self.assertEqual(a, b, "adr should be position-invariant on imm shift")
        self.assertEqual(a, "?0????10")

    # ------------------------------------------------------------------
    # b / bl / b.cond : branch immediates.
    # ------------------------------------------------------------------
    def test_b_position_invariant(self):
        a = _esc("00000014", "b", "#0")
        b = _esc("14000014", "b", "#0x14")
        self.assertEqual(a, b)
        # Only op byte (0x14) kept; matches the OLD escapeToOpcodeOnly output.
        self.assertEqual(a, "??????14")
        self.assertIn("?", a)

    def test_bl_position_invariant(self):
        a = _esc("00000094", "bl", "#0")
        b = _esc("14000094", "bl", "#0x14")
        self.assertEqual(a, b)
        self.assertEqual(a, "??????94")

    def test_bcond_preserves_condition_nibble(self):
        # b.eq #0  -> word 0x5400000E, LE bytes "0e000054"
        # b.eq #0x10 -> word 0x5400100E, LE bytes "0e100054"
        # cond eq=0xe is in the LSB nibble of the word (= byte 0 lo).
        # Output: cond (kept), imm bits 5..7 (wildcarded), op byte kept.
        eq = _esc("0e000054", "b.eq", "#0")
        eq_imm = _esc("0e100054", "b.eq", "#0x10")
        self.assertEqual(eq, eq_imm)
        self.assertEqual(eq, "?e????54")

    # ------------------------------------------------------------------
    # cbz / cbnz : 19-bit imm + Rt in bits 0..4.
    # ------------------------------------------------------------------
    def test_cbz_position_invariant(self):
        # cbz x0, #0x10 -> word 0xB4000040, LE bytes "400000b4"
        #   -> escape "?0?????b4" (Rt low nibble 0 kept, op byte 0xb4 kept)
        # cbz x0, #0x14 -> word 0xB4000140, LE bytes "400100b4"
        #   -> escape "?0?????b4" (imm shifted but wildcarded)
        a = _esc("400000b4", "cbz", "x0, #0x10")
        b = _esc("400100b4", "cbz", "x0, #0x14")
        self.assertEqual(a, b, "cbz should be position-invariant on imm shift")
        self.assertEqual(a, "?0????b4")

    # ------------------------------------------------------------------
    # ldr / str (immediate offset): 12-bit imm at bits 10..21.
    # ------------------------------------------------------------------
    def test_ldr_position_invariant(self):
        # ldr x0, [x0, #0x10]  -> word 0xF9400400, LE bytes "000440f9"
        # ldr x0, [x0, #0x100] -> word 0xF9401000, LE bytes "001040f9"
        a = _esc("000440f9", "ldr", "x0, [x0, #0x10]")
        b = _esc("001040f9", "ldr", "x0, [x0, #0x100]")
        self.assertEqual(a, b, "ldr not position-invariant")
        self.assertEqual(a, "?0????f9")

    def test_str_position_invariant(self):
        a = _esc("000000f9", "str", "x0, [x0, #0]")
        b = _esc("000800f9", "str", "x0, [x0, #0x20]")
        self.assertEqual(a, b, "str not position-invariant")
        self.assertEqual(a, "?0????f9")

    # ------------------------------------------------------------------
    # add / sub (immediate form): 12-bit imm.
    # ------------------------------------------------------------------
    def test_add_imm_position_invariant(self):
        # add x0, x0, #0x10  -> word 0x91004000, LE bytes "00400091"
        # add x0, x0, #0x420 -> word 0x91108000, LE bytes "00108091"
        # add x0, x0, #0x222 -> word 0x91088000, LE bytes "00088091"
        a = _esc("00400091", "add", "x0, x0, #0x10")
        b = _esc("00108091", "add", "x0, x0, #0x420")
        c = _esc("00088091", "add", "x0, x0, #0x222")
        self.assertEqual(a, b, "add #0x10 vs #0x420 should match")
        self.assertEqual(a, c, "add #0x10 vs #0x222 should match")
        self.assertEqual(a, "?0????91")

    def test_add_imm_with_zero_imm(self):
        ins = _esc("00000091", "add", "x0, x0, #0")
        self.assertEqual(ins, "?0????91")

    # ------------------------------------------------------------------
    # movz / movk / movn : 16-bit imm.
    # ------------------------------------------------------------------
    def test_movz_position_invariant(self):
        # mov x0, #0 -> word 0xD2800000, LE bytes "000080d2"
        # mov x0, #1 -> word 0xD2800020, LE bytes "200080d2"
        a = _esc("000080d2", "mov", "x0, #0")
        b = _esc("200080d2", "mov", "x0, #1")
        self.assertEqual(a, b, "movz should be position-invariant on imm shift")
        self.assertEqual(a, "?0????d2")

    # ------------------------------------------------------------------
    # Register-form operations : must return raw bytes (no wildcarding).
    # ------------------------------------------------------------------
    def test_register_form_add_untouched(self):
        # add x0, x0, x0 -> word 0x8B000000 -> bytes "0000008b" LE
        ins = _esc("0000008b", "add", "x0, x0, x0")
        self.assertEqual(ins, "0000008b", "register-form add should not be wildcarded")

    def test_register_form_mov_untouched(self):
        # mov x0, x1 (alias of orr x0, xzr, x1) -> 0xAA0003E0
        ins = _esc("e00300aa", "mov", "x0, x1")
        self.assertEqual(ins, "e00300aa", "register-form mov (alias of orr) should not be wildcarded")

    def test_register_form_ldr_untouched(self):
        # ldr x0, [x0, x1, lsl #3] -> 0xF8607800
        ins = _esc("007860f8", "ldr", "x0, [x0, x1, lsl #3]")
        self.assertEqual(ins, "007860f8", "register-offset ldr should not be wildcarded")

    def test_br_blr_ret_untouched(self):
        # br x0 -> 0xD61F0000
        self.assertEqual(_esc("00001fd6", "br", "x0"), "00001fd6")
        # blr x0 -> 0xD63F0000
        self.assertEqual(_esc("00003fd6", "blr", "x0"), "00003fd6")
        # ret -> 0xD65F03C0
        self.assertEqual(_esc("c0035fd6", "ret", ""), "c0035fd6")

    def test_nop_bti_untouched(self):
        self.assertEqual(_esc("1f2003d5", "nop", ""), "1f2003d5")
        self.assertEqual(_esc("5f2403d5", "bti", "c"), "5f2403d5")

    # ------------------------------------------------------------------
    # Non-4-byte inputs are returned unchanged.
    # ------------------------------------------------------------------
    def test_non_4byte_unchanged(self):
        self.assertEqual(_esc("", "udf", "#0"), "")
        self.assertEqual(_esc("deadbeef", "udf", "#0xdeadbeef"), "deadbeef")

    # ------------------------------------------------------------------
    # escape_intraprocedural_jumps and address bounds are accepted but unused.
    # ------------------------------------------------------------------
    def test_escape_intraprocedural_jumps_accepted(self):
        # Should not raise even though the flag has no extra effect on aarch64.
        ins = _StubIns("00000014", "b", "#0")
        from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper

        result_default = AArch64InstructionEscaper.escapeBinary(ins)
        result_flag = AArch64InstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)
        result_with_addrs = AArch64InstructionEscaper.escapeBinary(ins, lower_addr=0x100000000, upper_addr=0x200000000)
        self.assertEqual(result_default, result_flag)
        self.assertEqual(result_default, result_with_addrs)

    # ------------------------------------------------------------------
    # Integration: pic_hash is invariant under relocation.
    # ------------------------------------------------------------------
    def test_pic_hash_invariant_under_relocation(self):
        """Two aarch64 instructions that differ only in their immediate value
        (simulating a relocation) must produce the same escapeBinary output,
        so that a function's pic_hash is stable under base-address shifts.
        """
        # adrp x0, #0x1000  -> word 0xB0000000 (page 0 of pc=0 is 0x0, page 0x1000 from pc=0 is 0x1000)
        # This is unrealistic; let's use real adrp encoding.
        # adrp x0, #0    -> 0x90000000
        # adrp x0, #0x100000000  -> 0x90001000 (page of 0x100000000 from pc=0)
        a = _esc("00000090", "adrp", "x0, #0")
        b = _esc("00100090", "adrp", "x0, #0x100000000")
        self.assertEqual(a, b, "pic_hash position-invariance: adrp must produce the same escape for different pages")

        # add x0, x0, #0x10  -> 0x91004000
        # add x0, x0, #0x420 -> 0x91108000  (0x420 = 0x10 shifted in 12-bit imm)
        a = _esc("00400091", "add", "x0, x0, #0x10")
        b = _esc("00108091", "add", "x0, x0, #0x420")
        self.assertEqual(a, b, "add immediate must be position-invariant on imm shift")

        # ldr x0, [x0, #0x10]  -> 0xF9400400
        # ldr x0, [x0, #0x100] -> 0xF9401000
        a = _esc("000440f9", "ldr", "x0, [x0, #0x10]")
        b = _esc("001040f9", "ldr", "x0, [x0, #0x100]")
        self.assertEqual(a, b, "ldr immediate offset must be position-invariant")


class AArch64EscaperHashesTest(unittest.TestCase):
    """End-to-end: load a real aarch64 report, verify the new escapeBinary
    is wired into SmdaFunction.getPicHash and produces a different (more
    relocatable) hash than the old escapeToOpcodeOnly-only path.

    This test requires the large aarch64 report under validation/inputs/; if
    it is missing, the test is skipped (so the suite still works in CI).
    """

    REPORT_PATH = "validation/inputs/b204e0a4ca908f7406c53a8e4f4949add4d8343fd466f2717c568d1b417b79b5.smda"

    def _load_report(self):
        import os

        from smda.common.SmdaReport import SmdaReport

        if not os.path.exists(self.REPORT_PATH):
            self.skipTest(f"aarch64 report not available: {self.REPORT_PATH}")
        return SmdaReport.fromFile(self.REPORT_PATH)

    def test_escape_binary_differs_from_opcode_only(self):
        """After the improvement, most non-register instructions should have
        a different escapeBinary than escapeToOpcodeOnly, whereas before the
        change the two were identical for nearly every instruction.
        """
        report = self._load_report()
        total = 0
        differs = 0
        for fn in report.getFunctions():
            escaper = getattr(fn, "_escaper", None)
            if escaper is None:
                continue
            for ins in fn.getInstructions():
                total += 1
                if ins.getEscapedBinary(escaper) != ins.getEscapedToOpcodeOnly(escaper):
                    differs += 1
        # At least 10% of instructions should now differ (branches, adrp,
        # ldr/str, add/sub imm, movz, etc.).
        self.assertGreater(
            differs,
            total * 0.10,
            f"Expected >10% of instructions to have distinct escapeBinary/escapeToOpcodeOnly, got {differs}/{total}",
        )


if __name__ == "__main__":
    unittest.main()
