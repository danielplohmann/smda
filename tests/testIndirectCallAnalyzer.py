import unittest
from unittest.mock import MagicMock

from smda.intel.IndirectCallAnalyzer import IndirectCallAnalyzer


class IndirectCallAnalyzerTestSuite(unittest.TestCase):
    """Basic tests for IndirectCallAnalyzer regex and logic"""

    def test_regex_matching(self):
        analyzer = IndirectCallAnalyzer(MagicMock())

        # Test mov <reg>, <reg>
        match = analyzer.RE_MOV_REG_REG.match("eax, ebx")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg1"), "eax")
        self.assertEqual(match.group("reg2"), "ebx")

        # Test mov <reg>, <const>
        match = analyzer.RE_MOV_REG_CONST.match("ecx, 0x12345678")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "ecx")
        self.assertEqual(match.group("val"), "0x12345678")

        # Test mov <reg>, dword ptr [<addr>]
        match = analyzer.RE_REG_DWORD_PTR_ADDR.match("edx, dword ptr [0x8048000]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "edx")
        self.assertEqual(match.group("addr"), "0x8048000")

        # Test mov <reg>, qword ptr [rip + <addr>]
        match = analyzer.RE_REG_QWORD_PTR_RIP_ADDR.match("rax, qword ptr [rip + 0x1234]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "rax")
        self.assertEqual(match.group("addr"), "0x1234")

        # Test lea <reg>, [<addr>]
        match = analyzer.RE_REG_ADDR.match("rsi, [0x400000]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "rsi")
        self.assertEqual(match.group("addr"), "0x400000")

    def test_processBlock_logic(self):
        disassembler = MagicMock()
        disassembler.resolveApi.return_value = (None, None)
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.getDword = MagicMock(return_value=0x12345678)

        analysis_state = MagicMock()
        analyzer.state = analysis_state
        # block is a list of [address, size, mnemonic, op_str]
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 2, "mov", "ebx, eax"],
        ]
        registers = {}
        register_name = "ebx"
        processed = []
        depth = 1

        # Mock disassembly
        analyzer.disassembly = MagicMock()
        analyzer.disassembly.isAddrWithinMemoryImage.return_value = True

        result = analyzer.processBlock(analysis_state, block, registers, register_name, processed, depth)

        # result should be True because we found an absolute value for the register we were looking for
        self.assertTrue(result, f"processBlock should return True, but returned {result}")
        # eax should have 0x402000
        self.assertEqual(registers.get("eax"), 0x402000, f"Expected eax to be 0x402000, but got {registers.get('eax')}")


if __name__ == "__main__":
    unittest.main()
