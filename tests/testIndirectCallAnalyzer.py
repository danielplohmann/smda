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

    def test_regex_matching_legacy_3letter_registers(self):
        # Confirm no regression on the pre-existing 3-letter legacy register coverage.
        analyzer = IndirectCallAnalyzer(MagicMock())

        match = analyzer.RE_MOV_REG_REG.match("eax, ebx")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg1"), "eax")
        self.assertEqual(match.group("reg2"), "ebx")

    def test_regex_matching_extended_registers_and_wide_immediates(self):
        analyzer = IndirectCallAnalyzer(MagicMock())

        # Test mov <reg>, <reg> with r8-r15 family registers (2-3 chars)
        match = analyzer.RE_MOV_REG_REG.match("r8, r9")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg1"), "r8")
        self.assertEqual(match.group("reg2"), "r9")

        # Test mov <reg>, <const> with a sized r10-r15 register and a 64-bit immediate
        match = analyzer.RE_MOV_REG_CONST.match("r10, 0x1234567890abcdef")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "r10")
        self.assertEqual(match.group("val"), "0x1234567890abcdef")

        # Test mov <reg>, dword ptr [<addr>] with an r11 register and a 64-bit address
        match = analyzer.RE_REG_DWORD_PTR_ADDR.match("r11, dword ptr [0x1234567890abcdef]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "r11")
        self.assertEqual(match.group("addr"), "0x1234567890abcdef")

        # Test mov <reg>, qword ptr [rip + <addr>] with an r12 register and a 64-bit address
        match = analyzer.RE_REG_QWORD_PTR_RIP_ADDR.match("r12, qword ptr [rip + 0x1234567890abcdef]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "r12")
        self.assertEqual(match.group("addr"), "0x1234567890abcdef")

        # Test lea <reg>, [<addr>] with an r13 register and a 64-bit address
        match = analyzer.RE_REG_ADDR.match("r13, [0x1234567890abcdef]")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("reg"), "r13")
        self.assertEqual(match.group("addr"), "0x1234567890abcdef")

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

    def test_getDword_returns_none_on_short_or_missing_bytes(self):
        disassembler = MagicMock()
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.disassembly = MagicMock()
        analyzer.disassembly.isAddrWithinMemoryImage.return_value = True

        for raw_bytes in (None, b"\x01\x02"):
            with self.subTest(raw_bytes=raw_bytes):
                analyzer.disassembly.getBytes.return_value = raw_bytes
                result = analyzer.getDword(0x401000)
                self.assertIsNone(result, f"getDword should return None for getBytes() == {raw_bytes!r}")

    def test_resolveRegisterCalls_continues_after_empty_start_block(self):
        disassembler = MagicMock()
        # hasattr(disassembler.config, "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK") must be False
        # so resolveRegisterCalls falls back to its default max_calls of 50.
        disassembler.config = MagicMock(spec=[])
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.processBlock = MagicMock()

        analysis_state = MagicMock()
        analysis_state.start_addr = 0x401000
        analysis_state.call_register_ins = [0x401000, 0x402000]

        # Second call site's block is resolvable. Real FunctionAnalysisState
        # instructions are tuples (hashable), which resolveRegisterCalls relies
        # on when keying calls_per_block by start_block[0].
        resolvable_block = [(0x402000, 5, "call", "eax")]

        def searchBlock_side_effect(state, addr):
            if addr == 0x401000:
                return []
            return resolvable_block

        analyzer.searchBlock = MagicMock(side_effect=searchBlock_side_effect)

        analyzer.resolveRegisterCalls(analysis_state)

        # The first call site's empty block lookup must not abort resolution
        # for the second, independent call site.
        analyzer.processBlock.assert_called_once()
        called_args = analyzer.processBlock.call_args[0]
        self.assertEqual(called_args[1], resolvable_block)


if __name__ == "__main__":
    unittest.main()
