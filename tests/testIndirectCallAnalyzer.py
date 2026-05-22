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

    def test_processBlock_preserves_known_import_slot(self):
        import_slot = 0x403000
        memory_value = 0x500000
        disassembler = MagicMock()
        disassembler.disassembly.apis = {}
        disassembler.resolveApi.return_value = ("kernel32.dll", "CreateFileA")
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.getDword = MagicMock(return_value=memory_value)

        analysis_state = MagicMock()
        analyzer.state = analysis_state
        analyzer.current_calling_addr = 0x401006
        registers = {}

        result = analyzer.processBlock(
            analysis_state,
            [[0x401000, 6, "mov", "eax, dword ptr [0x403000]"]],
            registers,
            "eax",
            [],
            1,
        )

        self.assertTrue(result)
        self.assertEqual(registers["eax"], import_slot)
        analyzer.getDword.assert_not_called()
        self.assertEqual(
            disassembler.disassembly.apis[import_slot],
            {
                "referencing_addr": [0x401006],
                "dll_name": "kernel32.dll",
                "api_name": "CreateFileA",
            },
        )

    def test_processBlock_uses_dword_when_pointer_is_not_import_slot(self):
        disassembler = MagicMock()
        disassembler.disassembly.apis = {}
        disassembler.disassembly.isAddrWithinMemoryImage.return_value = True
        disassembler.resolveApi.return_value = (None, None)
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.getDword = MagicMock(return_value=0x401234)

        analysis_state = MagicMock()
        analyzer.state = analysis_state
        analyzer.current_calling_addr = 0x401006
        registers = {}

        result = analyzer.processBlock(
            analysis_state,
            [[0x401000, 6, "mov", "eax, dword ptr [0x403000]"]],
            registers,
            "eax",
            [],
            1,
        )

        self.assertTrue(result)
        self.assertEqual(registers["eax"], 0x401234)
        analyzer.getDword.assert_called_once_with(0x403000)
        disassembler.fc_manager.addCandidate.assert_called_once_with(0x401234, reference_source=0x401006)


if __name__ == "__main__":
    unittest.main()
