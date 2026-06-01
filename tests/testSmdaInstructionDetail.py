import logging
import unittest
from types import SimpleNamespace

from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport


def _intel_instruction(offset, raw_bytes, mnemonic, operands, bitness=32):
    report = SmdaReport(None)
    report.architecture = "intel"
    report.bitness = bitness
    smda_function = SimpleNamespace(smda_report=report)
    return SmdaInstruction([offset, raw_bytes, mnemonic, operands], smda_function=smda_function)


class TestGetDetailed(unittest.TestCase):
    def test_single_instruction_is_returned_unchanged(self):
        detailed = _intel_instruction(0x1000, "90", "nop", "").getDetailed()
        self.assertEqual(detailed.mnemonic, "nop")
        self.assertEqual(detailed.address, 0x1000)
        self.assertEqual(detailed.size, 1)

    def test_wait_prefixed_x87_returns_span_consistent_operation(self):
        # `9bd93c24` is the WAIT-prefixed FSTCW that IDA/SMDA store as one instruction, but
        # Capstone splits into `wait` + `fnstcw word ptr [esp]`. getDetailed() must return the
        # x87 operation, with its memory operand and an (address + size) reaching the byte span end.
        offset = 0x4D3F1F0
        ins = _intel_instruction(offset, "9bd93c24", "fstcw", "word ptr [esp]")
        with self.assertNoLogs(logger="smda.common.SmdaInstruction", level=logging.WARNING):
            detailed = ins.getDetailed()
        self.assertEqual(detailed.mnemonic, "fnstcw")
        self.assertEqual(detailed.address + detailed.size, offset + 4)
        self.assertTrue(detailed.operands)

    def test_empty_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            _intel_instruction(0x1000, "", "nop", "").getDetailed()

    def test_non_intel_architecture_raises(self):
        ins = _intel_instruction(0x1000, "90", "nop", "")
        ins.smda_function.smda_report.architecture = "dalvik"
        with self.assertRaises(NotImplementedError):
            ins.getDetailed()


if __name__ == "__main__":
    unittest.main()
