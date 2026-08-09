import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.common.arch.ArchBackend import ArchBackend
from smda.common.RecursiveDisassembler import RecursiveDisassembler
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionAnalysisState import FunctionAnalysisState
from smda.intel.IndirectCallAnalyzer import IndirectCallAnalyzer
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
SLOT_TABLE = 0x403000


def _memory_image():
    """A 0x10000 image whose custom import table at SLOT_TABLE+8 points at 0x500000."""
    image = bytearray(0x10000)
    struct.pack_into("<I", image, SLOT_TABLE - BASE + 8, 0x500000)
    struct.pack_into("<Q", image, SLOT_TABLE - BASE + 0x10, 0x500000)
    struct.pack_into("<Q", image, SLOT_TABLE - BASE + 0x1000, 0x600000)
    return bytes(image)


def _disassembly():
    disassembly = DisassemblyResult()
    disassembly.binary_info = SimpleNamespace(base_addr=BASE, binary_size=0x10000, binary=_memory_image())
    return disassembly


def _analyzer(disassembly, resolved=("kernel32.dll", "CreateFileA")):
    disassembler = MagicMock()
    disassembler.disassembly = disassembly
    disassembler.resolveApi.return_value = resolved
    disassembler.config.MAX_INDIRECT_CALLS_PER_BASIC_BLOCK = 50
    return IndirectCallAnalyzer(disassembler)


class ImportSlotLoadTestSuite(unittest.TestCase):
    """A slot that is only loaded into a register still names the API it holds.

    A language runtime that dispatches its own syscalls (Go on Windows is the
    common case) never issues "call [slot]" - it loads the slot and hands the
    pointer to a shared helper, so a call/jmp-driven pass sees no API at all.
    """

    def _run(self, mnemonic, op_str, address=0x401000, size=7):
        disassembly = _disassembly()
        state = FunctionAnalysisState(address, disassembly)
        state.addInstruction(address, size, mnemonic, op_str, b"")
        disassembler = MagicMock()
        disassembler.disassembly = disassembly
        disassembler.getReferencedAddr = lambda operands: RecursiveDisassembler.getReferencedAddr(
            disassembler, operands
        )
        X86Backend.recordImportSlotLoads(X86Backend, disassembler, state)
        return disassembler._handleApiTarget.call_args_list

    def test_a_rip_relative_slot_load_is_recorded_against_its_slot(self):
        # 0x401000 + 7 + 0x2009 == 0x403010, the qword slot holding 0x500000
        calls = self._run("mov", "rax, qword ptr [rip + 0x2009]")

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], ((0x401000, 0x403010, 0x500000), {"slot": 0x403010}))

    def test_a_negative_rip_displacement_resolves_behind_the_instruction(self):
        calls = self._run("mov", "rax, qword ptr [rip - 0x1ff7]", address=0x405000)

        self.assertEqual(calls[0][0][1], 0x403010)

    def test_an_absolute_dword_slot_load_is_recorded(self):
        calls = self._run("mov", "eax, dword ptr [0x403008]")

        self.assertEqual(calls[0], ((0x401000, 0x403008, 0x500000), {"slot": 0x403008}))

    def test_an_instruction_that_is_not_a_mov_is_ignored(self):
        # lea takes the address of the slot rather than the pointer inside it
        self.assertEqual(self._run("lea", "rax, qword ptr [rip + 0x2009]"), [])

    def test_a_prefixed_mov_is_still_recognised(self):
        self.assertEqual(len(self._run("rep mov", "rax, qword ptr [rip + 0x2009]")), 1)

    def test_a_store_into_a_slot_is_not_a_load(self):
        # writing to a slot is import patching, a different fact
        self.assertEqual(self._run("mov", "qword ptr [rip + 0x2009], rax"), [])

    def test_a_register_relative_slot_stays_on_the_computed_slot_path(self):
        self.assertEqual(self._run("mov", "rax, qword ptr [rbx + 0x10]"), [])

    def test_a_slot_outside_the_image_dereferences_to_nothing(self):
        self.assertEqual(self._run("mov", "rax, qword ptr [0x999999]"), [])

    def test_a_backend_without_the_pass_records_nothing(self):
        # the base hook is a no-op so a backend that has no such shape opts out by doing nothing
        self.assertIsNone(ArchBackend.recordImportSlotLoads(ArchBackend, MagicMock(), MagicMock()))


class ImportSlotLoadConfigTestSuite(unittest.TestCase):
    """The pass is opt-in, and enabling it must not move CFG recovery."""

    @staticmethod
    def _asprox():
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asprox_0x008D0000_xored")
        with open(path, "rb") as handle:
            return bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))

    def test_the_flag_is_off_by_default(self):
        self.assertFalse(SmdaConfig().RECORD_IMPORT_SLOT_LOADS)

    def test_enabling_the_pass_annotates_without_moving_recovery(self):
        buffer = self._asprox()
        reports = {}
        for flag in (False, True):
            config = SmdaConfig()
            config.RECORD_IMPORT_SLOT_LOADS = flag
            reports[flag] = Disassembler(config=config).disassembleBuffer(buffer, 0x8D0000)

        # the pass books no code refs and no candidates, so recovery is identical by construction
        self.assertEqual(reports[True].num_functions, reports[False].num_functions)
        self.assertEqual(reports[True].num_instructions, reports[False].num_instructions)
        self.assertEqual(
            sorted(f.offset for f in reports[True].getFunctions()),
            sorted(f.offset for f in reports[False].getFunctions()),
        )


class CollectComputedSlotTestSuite(unittest.TestCase):
    """X86Backend has to hand the analyzer a base register and a displacement, or nothing."""

    def _state(self):
        return FunctionAnalysisState(0x401000, _disassembly())

    def _call(self, op_str):
        state = self._state()
        X86Backend._analyzeCallInstruction(X86Backend, MagicMock(), (0x401000, 6, "call", op_str), state)
        return state.call_memreg_ins

    def test_a_call_through_a_register_slot_is_collected_with_its_displacement(self):
        self.assertEqual(self._call("dword ptr [ebx + 0x2c]"), [(0x401000, "ebx", 0x2C, 4)])
        self.assertEqual(self._call("qword ptr [rbx + 0x2c]"), [(0x401000, "rbx", 0x2C, 8)])

    def test_a_negative_displacement_keeps_its_sign(self):
        self.assertEqual(self._call("dword ptr [ebx - 0x10]"), [(0x401000, "ebx", -0x10, 4)])

    def test_a_bare_decimal_displacement_is_read_as_decimal(self):
        # capstone omits the 0x prefix below 10, which covers the usual pointer strides
        self.assertEqual(self._call("dword ptr [esi + 8]"), [(0x401000, "esi", 8, 4)])
        self.assertEqual(self._call("dword ptr [esi - 2]"), [(0x401000, "esi", -2, 4)])

    def test_a_slot_without_a_displacement_collects_as_offset_zero(self):
        self.assertEqual(self._call("dword ptr [ebx]"), [(0x401000, "ebx", 0, 4)])

    def test_an_indexed_operand_is_not_a_single_slot_and_is_ignored(self):
        self.assertEqual(self._call("dword ptr [ebx + ecx*4]"), [])
        self.assertEqual(self._call("dword ptr [ebx + ecx*4 + 0x10]"), [])

    def test_an_absolute_slot_stays_on_the_existing_path(self):
        self.assertEqual(self._call("dword ptr [0x403008]"), [])

    def test_a_jmp_through_a_register_slot_is_collected_too(self):
        state = self._state()
        disassembler = MagicMock()
        disassembler.jumptable_analyzer.getJumpTargets.return_value = []
        X86Backend._analyzeJmpInstruction(X86Backend, disassembler, (0x401000, 6, "jmp", "dword ptr [esi + 4]"), state)

        self.assertEqual(state.call_memreg_ins, [(0x401000, "esi", 4, 4)])


class ResolveComputedSlotTestSuite(unittest.TestCase):
    """The base register is recovered by the existing backward pass; the slot is base + disp."""

    def _state(self, block, memreg):
        state = MagicMock()
        state.getBlocks.return_value = [block]
        state._block_index = None
        state.call_memreg_ins = memreg
        return state

    def test_a_computed_slot_is_recorded_as_an_import(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 5, "mov", "ebx, 0x403000"], [0x401005, 6, "call", "dword ptr [ebx + 8]"]]
        state = self._state(block, [(0x401005, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {SLOT_TABLE + 8: ("kernel32.dll", "CreateFileA")})
        self.assertEqual(disassembly.apis[0x500000]["referencing_addr"], [0x401005])

    def test_a_qword_slot_is_dereferenced_as_eight_bytes(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 5, "mov", "rbx, 0x403000"], [0x401005, 6, "call", "qword ptr [rbx + 0x10]"]]
        state = self._state(block, [(0x401005, "rbx", 0x10, 8)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {SLOT_TABLE + 0x10: ("kernel32.dll", "CreateFileA")})

    def test_recording_the_slot_books_no_code_ref_and_no_candidate(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 5, "mov", "ebx, 0x403000"], [0x401005, 6, "call", "dword ptr [ebx + 8]"]]
        state = self._state(block, [(0x401005, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        state.addCodeRef.assert_not_called()
        state.setLeaf.assert_not_called()
        analyzer.disassembler.fc_manager.addCandidate.assert_not_called()

    def test_a_slot_that_resolves_to_no_api_records_nothing(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly, resolved=("", ""))
        block = [[0x401000, 5, "mov", "ebx, 0x403000"], [0x401005, 6, "call", "dword ptr [ebx + 8]"]]
        state = self._state(block, [(0x401005, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {})

    def test_a_slot_outside_the_image_is_not_dereferenced(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 5, "mov", "ebx, 0x900000"], [0x401005, 6, "call", "dword ptr [ebx + 8]"]]
        state = self._state(block, [(0x401005, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {})

    def test_a_block_stops_being_walked_past_the_indirect_call_cap(self):
        # the sibling pass caps the same backward walk at MAX_INDIRECT_CALLS_PER_BASIC_BLOCK,
        # and virtual dispatch puts far more of these in one block than "call <reg>" ever did
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        analyzer.disassembler.config.MAX_INDIRECT_CALLS_PER_BASIC_BLOCK = 3
        block = [[0x401000, 5, "mov", "ebx, 0x403000"]] + [
            [0x401005 + index, 6, "call", "dword ptr [ebx + 8]"] for index in range(10)
        ]
        state = self._state(block, [(0x401005 + index, "ebx", 8, 4) for index in range(10)])
        walked = []
        unwalked = analyzer.processBlock

        def counting_process_block(*args, **kwargs):
            walked.append(args[1][0][0])
            return unwalked(*args, **kwargs)

        analyzer.processBlock = counting_process_block

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(len(walked), 3)

    def test_an_unresolvable_base_register_records_nothing(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 2, "pop", "ebx"], [0x401005, 6, "call", "dword ptr [ebx + 8]"]]
        state = self._state(block, [(0x401005, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {})

    def test_a_call_address_outside_every_block_is_skipped(self):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        block = [[0x401000, 5, "mov", "ebx, 0x403000"]]
        state = self._state(block, [(0x402000, "ebx", 8, 4)])

        analyzer.resolveComputedImportSlots(state)

        self.assertEqual(disassembly.import_slots, {})


class RipRelativeSlotTestSuite(unittest.TestCase):
    """A rip-relative slot can sit either side of the instruction that loads it."""

    def _load(self, op_str):
        disassembly = _disassembly()
        analyzer = _analyzer(disassembly)
        analyzer.state = MagicMock()
        registers = {}
        # rip is 0x403027: -0x17 reaches the slot at 0x403010, +0xfd9 the one at 0x404000
        analyzer.processBlock(MagicMock(), [[0x403020, 7, "mov", op_str]], registers, "rax", [], 0)
        return registers

    def test_a_slot_behind_the_instruction_resolves(self):
        self.assertEqual(self._load("rax, qword ptr [rip - 0x17]"), {"rax": 0x500000})

    def test_a_slot_ahead_of_the_instruction_resolves(self):
        self.assertEqual(self._load("rax, qword ptr [rip + 0xfd9]"), {"rax": 0x600000})


class MergeImportedFunctionsTestSuite(unittest.TestCase):
    """A runtime-built import table has to reach the report, without displacing the static one."""

    @staticmethod
    def _disassembly(static_imports, import_slots):
        return SimpleNamespace(
            binary_info=SimpleNamespace(getImportedFunctions=lambda: static_imports),
            import_slots=import_slots,
        )

    def test_without_resolved_slots_the_static_view_is_passed_through(self):
        self.assertIsNone(SmdaReport._mergeImportedFunctions(self._disassembly(None, {})))
        static = {0x1000: ("kernel32.dll", "ExitProcess")}
        self.assertEqual(SmdaReport._mergeImportedFunctions(self._disassembly(static, {})), static)

    def test_resolved_slots_reach_a_report_that_has_no_parseable_import_table(self):
        disassembly = self._disassembly(None, {0x2000: ("KERNEL32.dll", "CreateFileA")})

        self.assertEqual(SmdaReport._mergeImportedFunctions(disassembly), {0x2000: ("kernel32.dll", "CreateFileA")})

    def test_a_static_entry_wins_over_a_resolved_one_at_the_same_slot(self):
        disassembly = self._disassembly(
            {0x2000: ("kernel32.dll", "ExitProcess")},
            {0x2000: ("other.dll", "Guessed"), 0x2004: ("user32.dll", "MessageBoxA")},
        )

        self.assertEqual(
            SmdaReport._mergeImportedFunctions(disassembly),
            {0x2000: ("kernel32.dll", "ExitProcess"), 0x2004: ("user32.dll", "MessageBoxA")},
        )

    def test_a_resolved_slot_without_a_library_keeps_an_empty_name(self):
        disassembly = self._disassembly(None, {0x2000: (None, "CreateFileA")})

        self.assertEqual(SmdaReport._mergeImportedFunctions(disassembly), {0x2000: ("", "CreateFileA")})


if __name__ == "__main__":
    unittest.main()
