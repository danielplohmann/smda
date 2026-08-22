import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.DisassemblyResult import DisassemblyResult
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

    def _resolveThrough(self, block, register_name="eax", calling_addr=0x401100, bitness=32):
        """Run the backward walk over `block` and return the register values it recovered.

        The walk renames what it is tracking as it follows a copy chain, so the value can land
        under a different key than the one it started from - the dict is what to assert on.
        """
        disassembler = MagicMock()
        disassembler.resolveApi.return_value = (None, None)
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.disassembly = MagicMock()
        analyzer.disassembly.isAddrWithinMemoryImage.return_value = True
        analyzer.disassembly.binary_info.bitness = bitness
        analyzer.current_calling_addr = calling_addr
        analyzer.current_slot = None
        analyzer.state = MagicMock()
        registers = {}
        analyzer.processBlock(analyzer.state, block, registers, register_name, [], 0)
        return registers

    def test_a_write_between_the_definition_and_the_call_stops_the_walk(self):
        """The walk modelled mov and lea and read every other mnemonic as harmless, so an
        instruction that changes the register in between was skipped and the value from before
        it resolved - a wrong call target, not a missing one."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 3, "add", "eax, 4"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_an_unmodelled_mov_write_stops_the_walk(self):
        """The mov/lea exemption assumed the patterns below model every mov. They model only
        some forms, and `mov eax, dword ptr [esi]` - the vtable dispatch load - is not one of
        them, so the walk read past the real last write and bound the call to a dead
        assignment. On a 32-bit PE corpus that shape reaches the walk a few hundred times per
        sample."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 2, "mov", "eax, dword ptr [esi]"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_an_unmodelled_write_through_a_sub_register_stops_the_walk(self):
        """al is part of eax, so a value written through one is readable through the other."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 2, "mov", "al, byte ptr [esi]"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_an_unmodelled_write_of_an_untracked_register_does_not_stop_the_walk(self):
        """Control for the rule above: only the tracked register's value is at stake, so an
        unmodelled write elsewhere must not throw the resolution away."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 2, "mov", "ebx, dword ptr [esi]"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {"eax": 0x402000})

    def test_a_store_to_memory_does_not_stop_the_walk(self):
        """Second control: a mov whose destination is memory writes no register at all."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 5, "mov", "dword ptr [0x400500], eax"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {"eax": 0x402000})

    def test_a_call_between_the_definition_and_the_call_stops_the_walk(self):
        """Same class through the ABI rather than the operand: a call clobbers the register
        without naming it at all."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 5, "call", "0x403000"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_a_branch_between_the_definition_and_the_call_does_not_stop_the_walk(self):
        """A backtracked window spans blocks, so a branch sits between the definition and the
        call routinely - across the bundled fixtures it is what stopped 612 of 978 walks. A
        branch writes rip and the flags and no general register, so the value survives it."""
        for mnemonic in ("jne", "jmp"):
            with self.subTest(mnemonic=mnemonic):
                block = [
                    [0x401000, 5, "mov", "eax, 0x402000"],
                    [0x401005, 2, "cmp", "ecx, 1"],
                    [0x401007, 2, mnemonic, "0x401100"],
                    [0x401100, 2, "call", "eax"],
                ]

                self.assertEqual(self._resolveThrough(block).get("eax"), 0x402000)

    def test_a_loop_between_the_definition_and_the_call_still_stops_the_walk(self):
        """Control on the other side of the same set: `loop` is a branch too, and it decrements
        rcx, so it is deliberately not preserved."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 2, "loop", "0x401100"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_a_call_preserves_a_callee_saved_register(self):
        """A resolved target is booked as a function candidate, so a walk that stops early costs
        a function rather than an API name. Every x86 convention preserves ebx, so the definition
        is still the value the call receives."""
        block = [
            [0x401000, 5, "mov", "ebx, 0x402000"],
            [0x401005, 5, "call", "0x403000"],
            [0x401100, 2, "call", "ebx"],
        ]

        self.assertEqual(self._resolveThrough(block, register_name="ebx").get("ebx"), 0x402000)

    def test_a_callee_saved_register_survives_a_call_in_64_bit_code(self):
        block = [
            [0x401000, 7, "mov", "rbx, 0x402000"],
            [0x401007, 5, "call", "0x403000"],
            [0x401100, 2, "call", "rbx"],
        ]

        self.assertEqual(self._resolveThrough(block, register_name="rbx", bitness=64).get("rbx"), 0x402000)

    def test_rsi_does_not_survive_a_call_in_64_bit_code(self):
        """Control: esi is callee-saved on x86 and rsi is not under the SysV ABI, so the set is
        chosen by bitness rather than by register name alone."""
        block = [
            [0x401000, 7, "mov", "rsi, 0x402000"],
            [0x401007, 5, "call", "0x403000"],
            [0x401100, 2, "call", "rsi"],
        ]

        self.assertEqual(self._resolveThrough(block, register_name="rsi", bitness=64), {})

    def test_a_vector_move_does_not_stop_the_walk(self):
        """A move whose destination is a vector register writes no general register."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 4, "movaps", "xmm0, xmmword ptr [ecx]"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block).get("eax"), 0x402000)

    def test_a_string_move_still_stops_the_walk(self):
        """Control on the mnemonic capstone overloads: `movsd` also spells the string
        instruction, which writes esi and edi, so it is deliberately not preserved."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 1, "movsd", "dword ptr es:[edi], dword ptr [esi]"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block), {})

    def test_an_undisturbed_definition_still_resolves(self):
        """Positive control: the walk still starts at the call being resolved - which is itself
        a clobber - and still reads a definition that nothing in between touched. Without this,
        a guard that gave up immediately would satisfy both cases above."""
        block = [
            [0x401000, 5, "mov", "eax, 0x402000"],
            [0x401005, 1, "nop", ""],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block).get("eax"), 0x402000)

    def test_a_copy_chain_still_resolves(self):
        """Second control: the mnemonics the walk does model keep working, so the guard has not
        simply disabled resolution."""
        block = [
            [0x401000, 5, "mov", "edx, 0x402000"],
            [0x401005, 2, "mov", "eax, edx"],
            [0x401100, 2, "call", "eax"],
        ]

        self.assertEqual(self._resolveThrough(block).get("edx"), 0x402000)

    def test_processBlock_preserves_known_import_slot(self):
        import_slot = 0x403000
        memory_value = 0x500000
        disassembler = MagicMock()
        disassembler.disassembly = DisassemblyResult()
        disassembler.disassembly.binary_info = SimpleNamespace(base_addr=0x400000, binary_size=0x10000)
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
        self.assertEqual(
            disassembler.disassembly.import_slots,
            {import_slot: ("kernel32.dll", "CreateFileA")},
        )

    def test_api_reference_deduplication_preserves_list_shape(self):
        disassembly = DisassemblyResult()

        disassembly.addApiReference(0x403000, 0x401006, "kernel32.dll", "CreateFileA")
        disassembly.addApiReference(0x403000, 0x401006, "kernel32.dll", "CreateFileA")
        disassembly.addApiReference(0x403000, 0x401010, "kernel32.dll", "CreateFileA")

        self.assertEqual(disassembly.apis[0x403000]["referencing_addr"], [0x401006, 0x401010])

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

    def test_per_block_call_cap_does_not_abandon_later_blocks(self):
        disassembler = MagicMock()
        disassembler.config = MagicMock(spec=[])
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.processBlock = MagicMock()

        cap = 50
        block_a = [(0x401000 + 2 * i, 2, "call", "eax") for i in range(cap + 2)]
        block_b = [(0x402000, 2, "call", "ebx")]

        analysis_state = MagicMock()
        analysis_state.start_addr = 0x401000
        analysis_state.call_register_ins = [ins[0] for ins in block_a] + [ins[0] for ins in block_b]

        def searchBlock_side_effect(state, addr):
            return block_b if addr == 0x402000 else block_a

        analyzer.searchBlock = MagicMock(side_effect=searchBlock_side_effect)

        analyzer.resolveRegisterCalls(analysis_state)

        # the cap on block A must skip only block A's surplus call sites, not
        # abandon block B's independent call site
        processed_starts = [call[0][1][0][0] for call in analyzer.processBlock.call_args_list]
        self.assertIn(0x402000, processed_starts)
        self.assertEqual(sum(1 for addr in processed_starts if addr == 0x401000), cap)


if __name__ == "__main__":
    unittest.main()
