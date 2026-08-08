#!/usr/bin/python
"""Regressions for Intel control-flow and dataflow defects found by a whole-tree audit."""

import unittest

from smda.Disassembler import Disassembler
from smda.intel.IndirectCallAnalyzer import IndirectCallAnalyzer
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig

BASE = 0x401000


def _disassemble(code, bitness=64):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    return Disassembler(config).disassembleBuffer(
        code,
        base_addr=BASE,
        bitness=bitness,
        code_areas=[[BASE, BASE + len(code)]],
        oep=0,
    )


class IntelTerminatorTestSuite(unittest.TestCase):
    """capstone never emits a bare "iret": it is iretd/iretq, and retf becomes retfq
    under REX.W. The escaper already enumerates all of them; definitions.py did not."""

    def _first_function_mnemonics(self, code, bitness=64):
        report = _disassemble(code, bitness=bitness)
        function = report.getFunction(BASE)
        self.assertIsNotNone(function)
        return [instruction.mnemonic for instruction in function.getInstructions()]

    def test_iretq_ends_the_function(self):
        self.assertEqual(self._first_function_mnemonics(b"\x48\xcf\x90\x90\xc3"), ["iretq"])

    def test_iretd_ends_the_function(self):
        self.assertEqual(self._first_function_mnemonics(b"\xcf\x90\x90\xc3", bitness=32), ["iretd"])

    def test_retfq_ends_the_function(self):
        self.assertEqual(self._first_function_mnemonics(b"\x48\xcb\x90\x90\xc3"), ["retfq"])

    def test_ud2_ends_the_function(self):
        self.assertEqual(self._first_function_mnemonics(b"\x0f\x0b\x90\x90\xc3"), ["ud2"])

    def test_sysret_ends_the_function(self):
        # capstone reports sysret/sysexit in its own "iret" group: no fallthrough successor
        self.assertEqual(self._first_function_mnemonics(b"\x0f\x07\x90\x90\xc3"), ["sysret"])

    def test_sysexit_ends_the_function(self):
        self.assertEqual(self._first_function_mnemonics(b"\x0f\x35\x90\x90\xc3", bitness=32), ["sysexit"])


class IntelFarCallTestSuite(unittest.TestCase):
    class _RecordingState:
        def __init__(self):
            self.code_refs = []
            self.call_register_ins = []

        def setLeaf(self, value):
            pass

        def addCodeRef(self, addr_from, addr_to, by_jump=False):
            self.code_refs.append((addr_from, addr_to))

    class _RecordingDisassembler:
        def __init__(self):
            self.call_targets = []
            self.api_targets = []
            self.disassembly = None

        @staticmethod
        def getReferencedAddr(op_str):
            return int(op_str.split(",")[0], 16)

        def _handleCallTarget(self, state, addr_from, addr_to):
            self.call_targets.append((addr_from, addr_to))

        def _handleApiTarget(self, addr_from, slot, target):
            self.api_targets.append((addr_from, slot, target))
            return False

    def test_a_far_call_books_no_reference_to_its_segment_selector(self):
        # capstone renders lcall's far pair with a comma (a colon only for ljmp), so the
        # operand string still starts with "0x" and the direct-call arm read the selector
        backend = X86Backend()
        state = self._RecordingState()
        disassembler = self._RecordingDisassembler()

        backend._analyzeCallInstruction(disassembler, (0x20, 7, "lcall", "0x33, 0x401000"), state)

        self.assertEqual(state.code_refs, [])
        self.assertEqual(disassembler.call_targets, [])
        self.assertEqual(disassembler.api_targets, [])


class IndirectCallDataflowTestSuite(unittest.TestCase):
    class _StubDisassembly:
        def __init__(self, qwords=None):
            self.qwords = qwords or {}

        def dereferenceQword(self, addr):
            return self.qwords.get(addr)

        def isAddrWithinMemoryImage(self, addr):
            return True

        def addApiReference(self, *args):
            pass

    class _StubState:
        def setLeaf(self, value):
            pass

    class _StubDisassembler:
        def __init__(self, disassembly):
            self.disassembly = disassembly
            self.resolved = []

        def resolveApi(self, addr, absolute_addr):
            return None, None

    def _analyzer(self, qwords=None):
        disassembly = self._StubDisassembly(qwords)
        disassembler = self._StubDisassembler(disassembly)

        class _FcManager:
            def __init__(self):
                self.candidates = []

            def addCandidate(self, addr, reference_source=None):
                self.candidates.append(addr)

        disassembler.fc_manager = _FcManager()
        analyzer = IndirectCallAnalyzer(disassembler)
        analyzer.state = self._StubState()
        return analyzer, disassembler

    def test_lea_puts_the_address_itself_in_the_register(self):
        analyzer, disassembler = self._analyzer()
        registers = {}
        block = ((0x1000, 7, "lea", "rax, [0x402000]", b""),)

        analyzer.processBlock(None, block, registers, "rax", [], 0)

        self.assertEqual(registers["rax"], 0x402000)
        self.assertEqual(disassembler.fc_manager.candidates, [0x402000])

    def test_a_rip_relative_load_uses_the_whole_qword_from_the_slot(self):
        # mov rax, qword ptr [rip + 0x1234] at 0x1000 with a 7-byte encoding: the slot is
        # 0x8241 and the register receives what it holds, not rip plus the slot's low half
        analyzer, disassembler = self._analyzer(qwords={0x1000 + 7 + 0x1234: 0x402000})
        registers = {}
        block = ((0x1000, 7, "mov", "rax, qword ptr [rip + 0x1234]", b""),)

        analyzer.processBlock(None, block, registers, "rax", [], 0)

        self.assertEqual(registers["rax"], 0x402000)


class JumpTableBacktrackWindowTestSuite(unittest.TestCase):
    def test_the_direct_handler_reaches_the_oldest_backtracked_instruction(self):
        analyzer = JumpTableAnalyzer.__new__(JumpTableAnalyzer)

        class _StubDisassembler:
            @staticmethod
            def getReferencedAddr(op_str):
                return 0x403000

        class _StubState:
            def __init__(self):
                self.data_refs = []

            def addDataRef(self, addr_from, addr_to, size=1):
                self.data_refs.append((addr_from, addr_to, size))

        analyzer.disassembler = _StubDisassembler()
        state = _StubState()
        # the matching mov is the oldest entry in the window, which [:0:-1] never visited
        backtracked = [
            (0x1000, 6, "mov", "eax, dword ptr [ebx + 0x403000]", b""),
            (0x1006, 2, "nop", "", b""),
        ]

        self.assertEqual(analyzer._directHandler("eax", state, backtracked), 0x403000)
        self.assertEqual(state.data_refs, [(0x1000, 0x403000, 4)])


class IntelEscaperClassificationTestSuite(unittest.TestCase):
    def test_a_segment_qualified_memory_operand_stays_a_pointer(self):
        for operand in ("dword ptr es:[edi]", "dword ptr ds:[esi]", "qword ptr fs:[0x30]"):
            with self.subTest(operand=operand):
                self.assertEqual(IntelInstructionEscaper.escapeField(operand), "PTR")

    def test_a_far_pointer_immediate_is_still_a_constant(self):
        self.assertEqual(IntelInstructionEscaper.escapeField("0x33:0x401000"), "CONST")

    def test_avx512_vector_halves_and_mask_registers_are_escaped(self):
        for operand in ("xmm20", "ymm18", "zmm3", "k0", "k1"):
            with self.subTest(operand=operand):
                self.assertEqual(IntelInstructionEscaper.escapeField(operand), "XREG")

    def test_a_writemasked_vector_operand_is_escaped(self):
        # capstone attaches the EVEX writemask to the register operand, and spells the
        # zeroing form as two brace groups separated by a space
        for operand in ("zmm0 {k1}", "zmm0 {k1} {z}", "xmm20 {k7}", "ymm18 {k3} {z}"):
            with self.subTest(operand=operand):
                self.assertEqual(IntelInstructionEscaper.escapeField(operand), "XREG")

    def test_a_broadcast_memory_operand_stays_a_pointer(self):
        self.assertEqual(IntelInstructionEscaper.escapeField("dword ptr [rax]{1to16}"), "PTR")

    def test_string_and_system_mnemonics_share_their_family_group(self):
        for mnemonic, sibling in (
            ("movsq", "movsw"),
            ("cmpsq", "cmpsw"),
            ("popaw", "popal"),
            ("pushaw", "pushal"),
            ("xgetbv", "xsetbv"),
            ("rorx", "sarx"),
        ):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(
                    IntelInstructionEscaper.escapeMnemonic(mnemonic),
                    IntelInstructionEscaper.escapeMnemonic(sibling),
                )


class JumpTableDirectEntriesTestSuite(unittest.TestCase):
    def test_direct_table_entries_are_read_little_endian(self):
        analyzer = JumpTableAnalyzer.__new__(JumpTableAnalyzer)
        table = b"\x00\x10\x40\x00" + b"\x20\x10\x40\x00"

        class _StubDisassembly:
            @staticmethod
            def isAddrWithinMemoryImage(addr):
                return True

            @staticmethod
            def getBytes(addr, size):
                start = addr - 0x403000
                chunk = table[start : start + size]
                return chunk if len(chunk) == size else None

        analyzer.disassembly = _StubDisassembly()

        self.assertEqual(analyzer._extractDirectTableOffsets(2, 0x403000), [0x401000, 0x401020])


if __name__ == "__main__":
    unittest.main()
