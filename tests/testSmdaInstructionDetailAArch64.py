import unittest
from types import SimpleNamespace
from unittest.mock import patch

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.common.SmdaFunction import AARCH64_PIC_HASH_ESCAPE_VERSION, SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x401000


def _aarch64_instruction(offset, raw_bytes, mnemonic, operands):
    report = SmdaReport(None)
    report.architecture = "aarch64"
    report.bitness = 64
    report.base_addr = BASE
    report.binary_size = 0x100
    report.code_areas = []
    report.data_refs_from = {}
    smda_function = SimpleNamespace(smda_report=report)
    return SmdaInstruction([offset, raw_bytes, mnemonic, operands], smda_function=smda_function)


def _disassemble_words(words):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    code = b"".join(word.to_bytes(4, "little") for word in words)
    return Disassembler(config, backend="aarch64").disassembleBuffer(
        code,
        base_addr=BASE,
        bitness=64,
        code_areas=[[BASE, BASE + len(code)]],
        architecture="aarch64",
    )


class TestAArch64GetDetailed(unittest.TestCase):
    def test_aarch64_instruction_detail_is_available(self):
        ins = _aarch64_instruction(BASE, "3f2303d5", "paciasp", "")

        detailed = ins.getDetailed()

        self.assertEqual(detailed.mnemonic, "paciasp")
        self.assertEqual(detailed.address, BASE)
        self.assertEqual(detailed.size, 4)
        self.assertEqual([detailed.reg_name(reg) for reg in detailed.regs_read], ["sp", "lr"])
        self.assertEqual([detailed.reg_name(reg) for reg in detailed.regs_write], ["lr"])


class TestAArch64InstructionEscaper(unittest.TestCase):
    def test_memory_operand_escaping_keeps_bracketed_operands_together(self):
        ins = _aarch64_instruction(BASE, "fd7bbfa9", "stp", "x29, x30, [sp, #-0x10]!")

        self.assertEqual(ins.getEscapedOperands(AArch64InstructionEscaper), "REG, REG, PTR")

    def test_vector_register_layout_qualifier_escapes_as_register(self):
        ins = _aarch64_instruction(BASE, "200c014e", "dup", "v0.16b, w1")

        self.assertEqual(ins.getEscapedOperands(AArch64InstructionEscaper), "REG, REG")

    def test_opcode_only_masks_preserve_nibble_aligned_opcode_bits(self):
        branch = _aarch64_instruction(BASE, "03000094", "bl", "#0x401010")
        arithmetic = _aarch64_instruction(BASE, "200080d2", "mov", "x0, #1")

        self.assertEqual(branch.getEscapedToOpcodeOnly(AArch64InstructionEscaper), "??????94")
        self.assertEqual(arithmetic.getEscapedToOpcodeOnly(AArch64InstructionEscaper), "????8?d2")

    def test_aarch64_control_flow_operands_are_not_data_refs(self):
        ins = _aarch64_instruction(BASE, "03000094", "bl", "#0x401020")

        self.assertEqual(list(ins.getDataRefs()), [])

    def test_aarch64_functions_use_escaper_for_similarity_hash_sequences(self):
        report_a = _disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        report_b = _disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800040,  # mov x0, #2
                0xD65F03C0,  # ret
            ]
        )
        function_a = report_a.getFunction(BASE)
        function_b = report_b.getFunction(BASE)

        self.assertIs(function_a._escaper, AArch64InstructionEscaper)
        self.assertIs(function_b._escaper, AArch64InstructionEscaper)
        self.assertIsNotNone(function_a.pic_hash)
        self.assertIsNotNone(function_b.pic_hash)
        self.assertEqual(function_a.getPicHashSequence(report_a), function_b.getPicHashSequence(report_b))
        self.assertEqual(function_a.getOpcHashSequence(), function_b.getOpcHashSequence())
        self.assertIn(b"?", function_a.getPicHashSequence(report_a))
        self.assertIn(b"?", function_a.getOpcHashSequence())

    def test_extended_shift_operands_follow_capstone_register_operand_model(self):
        ins = _aarch64_instruction(BASE, "8a0d09ca", "eor", "w9, w9, w14, lsl #8")

        self.assertEqual(ins.getEscapedOperands(AArch64InstructionEscaper), "REG, REG, REG")

    def test_movk_and_float_immediates_escape_via_capstone_operands(self):
        movk = _aarch64_instruction(BASE, "a6cea5f2", "movk", "x6, #0x2e75, lsl #16")
        fmov = _aarch64_instruction(BASE, "9e670110", "fmov", "d0, #0.50000000")

        self.assertEqual(movk.getEscapedOperands(AArch64InstructionEscaper), "REG, CONST")
        self.assertEqual(fmov.getEscapedOperands(AArch64InstructionEscaper), "REG, CONST")

    def test_unhandled_corpus_mnemonics_classify_into_known_groups(self):
        samples = [
            ("umulh", "", "A"),
            ("csel", "x0, x1, x2, eq", "A"),
            ("ubfx", "", "A"),
            ("ldaxr", "x0, [x1]", "M"),
            ("brk", "#1", "P"),
            ("aese", "v0.16b, v1.16b", "V"),
            ("fcvtzs", "x0, d0", "F"),
            ("and", "v0.16b, v1.16b, v2.16b", "V"),
        ]
        for mnemonic, operands, expected_group in samples:
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(AArch64InstructionEscaper.escapeMnemonic(mnemonic, operands), expected_group)

    def test_smull_classifies_as_arithmetic_not_vector(self):
        ins = _aarch64_instruction(BASE + 0x67F0, "007c289b", "smull", "x0, w0, w8")

        self.assertEqual(AArch64InstructionEscaper.escapeMnemonic("smull", ins.operands), "A")
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonicForInstruction(ins), "A")

    def test_ld1_lane_operands_use_vector_layout_detection(self):
        ins = _aarch64_instruction(BASE, "0084404d", "ld1", "{v0.d}[1], [x0]")

        self.assertEqual(AArch64InstructionEscaper.escapeMnemonicForInstruction(ins), "V")

    def test_system_and_barrier_operands_escape_via_capstone_classes(self):
        mrs = _aarch64_instruction(BASE, "0841df5e", "mrs", "x0, tpidrro_el0")
        dsb = _aarch64_instruction(BASE, "9f3b03d5", "dsb", "ishld")
        prfm = _aarch64_instruction(BASE, "200080f9", "prfm", "pldl1keep, [x1]")

        self.assertEqual(mrs.getEscapedOperands(AArch64InstructionEscaper), "REG, SYSREG")
        self.assertEqual(dsb.getEscapedOperands(AArch64InstructionEscaper), "BARRIER")
        self.assertEqual(prfm.getEscapedOperands(AArch64InstructionEscaper), "PTR")

    def test_smc_classifies_as_privileged(self):
        ins = _aarch64_instruction(BASE, "034000d4", "smc", "#0x200")

        self.assertEqual(AArch64InstructionEscaper.escapeMnemonic("smc", ins.operands), "P")
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonicForInstruction(ins), "P")

    def test_bfi_classifies_as_arithmetic(self):
        ins = _aarch64_instruction(BASE, "e41c1833", "bfi", "w4, w7, #8, #8")

        self.assertEqual(AArch64InstructionEscaper.escapeMnemonicForInstruction(ins), "A")

    def test_eret_fallback_classifies_as_control_flow(self):
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonic("eret", ""), "C")
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonic("eretaa", ""), "C")

    def test_ret_masks_opcode_bytes_for_pic_sequences(self):
        ins = _aarch64_instruction(BASE, "c0035fd6", "ret", "")

        self.assertEqual(ins.getEscapedToOpcodeOnly(AArch64InstructionEscaper), "??????d6")

    def test_bl_offsets_only_returns_offset_token(self):
        ins = _aarch64_instruction(BASE, "03000094", "bl", "#0x401010")

        self.assertEqual(AArch64InstructionEscaper.escapeOperands(ins, offsets_only=True), "OFFSET")

    def test_non_control_offsets_only_preserves_operand_text_with_capstone(self):
        ins = _aarch64_instruction(BASE, "200080d2", "mov", "x0, #1")

        self.assertEqual(AArch64InstructionEscaper.escapeOperands(ins, offsets_only=True), "x0, #1")

    def test_non_control_offsets_only_preserves_operand_text_in_fallback(self):
        ins = _aarch64_instruction(BASE, "a6cea5f2", "movk", "x6, #0x2e75, lsl #16")

        with patch.object(type(ins), "getDetailed", side_effect=AttributeError("simulated capstone failure")):
            self.assertEqual(AArch64InstructionEscaper.escapeOperands(ins, offsets_only=True), "x6, #0x2e75, lsl #16")

    def test_fallback_operand_escaping_folds_trailing_shift(self):
        ins = _aarch64_instruction(BASE, "a6cea5f2", "movk", "x6, #0x2e75, lsl #16")

        with patch.object(type(ins), "getDetailed", side_effect=AttributeError("simulated capstone failure")):
            self.assertEqual(AArch64InstructionEscaper.escapeOperands(ins), "REG, CONST")

    def test_unknown_mnemonic_returns_unhandled_group_in_fallback(self):
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonic("notarealinsn", ""), "U")

    def test_imported_aarch64_report_recalculates_pic_hash_before_escape_version(self):
        report = _disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        function = report.getFunction(BASE)
        expected_pic_hash = function.pic_hash
        function_dict = function.toDict()
        function_dict["metadata"]["pic_hash"] = 0x0123456789ABCDEF

        imported = SmdaFunction.fromDict(function_dict, version="4.0.0", smda_report=report)

        self.assertEqual(imported.pic_hash, expected_pic_hash)
        self.assertLess([4, 0, 0], AARCH64_PIC_HASH_ESCAPE_VERSION)

    def test_imported_aarch64_report_keeps_pic_hash_at_escape_version(self):
        report = _disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        function_dict = report.getFunction(BASE).toDict()
        stored_pic_hash = 0x0123456789ABCDEF
        function_dict["metadata"]["pic_hash"] = stored_pic_hash

        imported = SmdaFunction.fromDict(function_dict, version="4.1.0", smda_report=report)

        self.assertEqual(imported.pic_hash, stored_pic_hash)

    def test_aarch64_imported_function_without_binary_info_keeps_escaper(self):
        report = _disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        imported = SmdaFunction.fromDict(
            report.getFunction(BASE).toDict(), version=report.smda_version, smda_report=report
        )

        self.assertIs(imported._escaper, AArch64InstructionEscaper)
        self.assertEqual(imported.getOpcHashSequence(), report.getFunction(BASE).getOpcHashSequence())


if __name__ == "__main__":
    unittest.main()
