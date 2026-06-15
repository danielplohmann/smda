import unittest
from types import SimpleNamespace

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x401000


def _aarch64_instruction(offset, raw_bytes, mnemonic, operands):
    report = SmdaReport(None)
    report.architecture = "aarch64"
    report.bitness = 64
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


if __name__ == "__main__":
    unittest.main()
