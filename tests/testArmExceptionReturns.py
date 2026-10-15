import unittest

from smda.arm.definitions import is_return_instruction, split_mnemonic
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000
PROLOGUE = bytes.fromhex("10402de9")
CONTINUATION = bytes.fromhex("0100a0e31eff2fe1")


def _disassemble(exception_return):
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.TIMEOUT = 0
    return Disassembler(config).disassembleBuffer(PROLOGUE + exception_return + CONTINUATION, BASE, architecture="arm")


class ArmExceptionReturnTest(unittest.TestCase):
    def test_conditioned_flag_setting_bases_keep_their_condition_and_flags(self):
        self.assertEqual(split_mnemonic("subseq"), ("sub", "eq", True))
        self.assertEqual(split_mnemonic("movseq"), ("mov", "eq", True))

    def test_conditional_exception_returns_preserve_the_fallthrough(self):
        cases = {
            "subseq": bytes.fromhex("04f05e02"),
            "movseq": bytes.fromhex("0ef0b001"),
            "ldmeq": bytes.fromhex("0080fd08"),
        }
        for mnemonic, encoding in cases.items():
            with self.subTest(mnemonic=mnemonic):
                report = _disassemble(encoding)
                function = report.getFunction(BASE)
                self.assertIsNotNone(function)
                self.assertEqual(function.num_instructions, 4)
                self.assertEqual(function.num_returns, 2)
                self.assertEqual(sorted(block.offset for block in function.getBlocks()), [BASE, BASE + 8])
                self.assertEqual(function.blockrefs[BASE], [BASE + 8])
                self.assertEqual([ins.mnemonic for ins in function.getInstructions()][1], mnemonic)
                self.assertIsNone(report.getFunction(BASE + 8))

    def test_exception_returns_are_counted_in_return_summaries(self):
        self.assertTrue(is_return_instruction("subseq", "pc, lr, #4"))
        self.assertTrue(is_return_instruction("movseq", "pc, lr"))
        self.assertTrue(is_return_instruction("ldmeq", "sp!, {pc} ^"))


if __name__ == "__main__":
    unittest.main()
