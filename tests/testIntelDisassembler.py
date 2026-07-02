import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.FunctionAnalysisState import FunctionAnalysisState
from smda.intel.FunctionCandidate import FunctionCandidate
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.intel.MnemonicTfIdf import MnemonicTfIdf
from smda.SmdaConfig import SmdaConfig


class DummyProvider:
    def __init__(self, is_api=False, is_symbol=False, api_result=("", ""), symbols=None):
        self._is_api = is_api
        self._is_symbol = is_symbol
        self._api_result = api_result
        self._symbols = symbols or {}

    def update(self, binary_info):
        return

    def isApiProvider(self):
        return self._is_api

    def isSymbolProvider(self):
        return self._is_symbol

    def getApi(self, to_address, api_address=None):
        return self._api_result

    def getSymbol(self, address):
        return self._symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._symbols


class TestIntelDisassembler(unittest.TestCase):
    def _create_disassembler(self):
        disassembler = IntelDisassembler.__new__(IntelDisassembler)
        disassembler.label_providers = []
        disassembler.api_providers = []
        disassembler.symbol_providers = []
        return disassembler

    def test_register_label_provider_caches_capabilities(self):
        disassembler = self._create_disassembler()
        api_provider = DummyProvider(is_api=True, api_result=("kernel32.dll", "CreateFileA"))
        symbol_provider = DummyProvider(is_symbol=True, symbols={0x401000: "entry"})
        hybrid_provider = DummyProvider(
            is_api=True,
            is_symbol=True,
            api_result=("user32.dll", "MessageBoxA"),
            symbols={0x401100: "handler"},
        )

        disassembler._registerLabelProvider(api_provider)
        disassembler._registerLabelProvider(symbol_provider)
        disassembler._registerLabelProvider(hybrid_provider)

        self.assertEqual(disassembler.api_providers, [api_provider, hybrid_provider])
        self.assertEqual(disassembler.symbol_providers, [symbol_provider, hybrid_provider])

    def test_symbol_and_api_resolution_use_registered_provider_sets(self):
        disassembler = self._create_disassembler()
        disassembler._registerLabelProvider(DummyProvider(is_api=True, api_result=("kernel32.dll", "CreateFileA")))
        disassembler._registerLabelProvider(DummyProvider(is_symbol=True, symbols={0x401000: "entry"}))
        disassembler._registerLabelProvider(
            DummyProvider(is_symbol=True, symbols={0x401000: "entry", 0x401100: "handler"})
        )

        self.assertEqual(disassembler.resolveApi(0x401000, 0x500000), ("kernel32.dll", "CreateFileA"))
        self.assertEqual(disassembler.resolveSymbol(0x401100), "handler")
        self.assertEqual(set(disassembler.getSymbolCandidates()), {0x401000, 0x401100})

    def test_function_candidate_alignment_and_empty_tfidf_are_safe(self):
        binary_info = BinaryInfo(b"\x90" * 0x40)
        binary_info.base_addr = 0
        binary_info.bitness = 32

        candidate = FunctionCandidate(binary_info, 0x10)

        self.assertEqual(candidate.alignment, 16)
        self.assertIsNone(candidate.getTfIdf())

    def test_mnemonic_tfidf_empty_counts_returns_zero(self):
        self.assertEqual(MnemonicTfIdf().tfidf({}), 0.0)

    def test_pointer_reference_uses_byte_prefixes(self):
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 64
        manager.disassembly = SimpleNamespace(
            binary_info=SimpleNamespace(base_addr=0x1000),
            getRawBytes=lambda offset, size: b"\xff\x25" if size == 2 else (1).to_bytes(4, "little", signed=True),
        )

        self.assertEqual(manager.resolvePointerReference(0x20), 0x1028)

    def test_get_referenced_addr_preserves_sign(self):
        disassembler = IntelDisassembler.__new__(IntelDisassembler)
        self.assertEqual(disassembler.getReferencedAddr("qword ptr [rip - 0x20]"), -0x20)
        self.assertEqual(disassembler.getReferencedAddr("qword ptr [rip + 0x20]"), 0x20)
        self.assertEqual(disassembler.getReferencedAddr("dword ptr [0x401000]"), 0x401000)
        self.assertEqual(disassembler.getReferencedAddr("0x401000"), 0x401000)
        self.assertEqual(disassembler.getReferencedAddr("eax"), 0)

    def test_rip_relative_call_negative_displacement_resolves_correct_slot(self):
        # 8-byte import-like slot at 0x1000 (value outside the image), then a function
        # at 0x1008 that calls through the slot with a negative RIP-relative displacement
        buf = (
            (0x7FFF12345678).to_bytes(8, "little")  # 0x1000: slot
            + b"\x55"  # 0x1008: push rbp
            + b"\x48\x89\xe5"  # 0x1009: mov rbp, rsp
            + b"\xff\x15\xee\xff\xff\xff"  # 0x100c: call qword ptr [rip - 0x12] -> 0x1000
            + b"\x5d"  # 0x1012: pop rbp
            + b"\xc3"  # 0x1013: ret
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x1008, result.functions)
        # the call must reference the slot at 0x1000, not a bogus positive displacement target
        self.assertIn(0x1000, result.code_refs_from.get(0x100C, set()))

    def test_rip_relative_call_through_in_image_slot_reaches_target(self):
        # the slot at 0x1000 points at a second function inside the image: the call must
        # be booked against the dereferenced target so recursion reaches the real function
        buf = (
            (0x1028).to_bytes(8, "little")  # 0x1000: slot -> in-image function
            + b"\x55"  # 0x1008: push rbp
            + b"\x48\x89\xe5"  # 0x1009: mov rbp, rsp
            + b"\xff\x15\xee\xff\xff\xff"  # 0x100c: call qword ptr [rip - 0x12] -> 0x1000
            + b"\x5d"  # 0x1012: pop rbp
            + b"\xc3"  # 0x1013: ret
            + b"\xcc" * 20  # 0x1014: padding
            + b"\x55"  # 0x1028: push rbp
            + b"\x48\x89\xe5"  # 0x1029: mov rbp, rsp
            + b"\x5d"  # 0x102c: pop rbp
            + b"\xc3"  # 0x102d: ret
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x1028, result.functions)
        self.assertIn(0x1028, result.code_refs_from.get(0x100C, set()))

    def test_loop_taken_edge_is_disassembled(self):
        # a forward loop target is only reachable via the taken edge; it must end up
        # as a block of the same function
        buf = (
            b"\x55"  # 0x1000: push ebp
            + b"\x89\xe5"  # 0x1001: mov ebp, esp
            + b"\xb9\x03\x00\x00\x00"  # 0x1003: mov ecx, 3
            + b"\xe2\x04"  # 0x1008: loop 0x100e
            + b"\x31\xc0"  # 0x100a: xor eax, eax
            + b"\x5d"  # 0x100c: pop ebp
            + b"\xc3"  # 0x100d: ret
            + b"\x89\xc0"  # 0x100e: mov eax, eax (loop target)
            + b"\xeb\xf8"  # 0x1010: jmp 0x100a
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertEqual(result.ins2fn.get(0x100E), 0x1000)

    def test_resolve_indirect_switch_stops_at_image_end(self):
        disassembler = IntelDisassembler.__new__(IntelDisassembler)
        disassembler.disassembly = SimpleNamespace(
            isAddrWithinMemoryImage=lambda addr: 0x1000 <= addr < 0x1008,
            getByte=lambda addr: 0 if 0x1000 <= addr < 0x1008 else None,
        )
        disassembler.fc_manager = SimpleNamespace(getFunctionStartCandidates=lambda: set())

        # walks from 0x1004 past the image end without raising on the None byte
        self.assertEqual(
            disassembler.resolveIndirectSwitch(0x1000, 1),
            list(range(0x1004, 0x1008)),
        )

    def test_push_ret_obfuscation_detected_at_address_zero(self):
        # a push at address 0 (base-0 buffer) must not disable push-ret detection;
        # the stub at 0x0 becomes a candidate through the call in the second function
        buf = (
            b"\x68\x10\x00\x00\x00"  # 0x0: push 0x10
            + b"\xc3"  # 0x5: ret
            + b"\xcc" * 10  # 0x6: padding
            + b"\x31\xc0"  # 0x10: xor eax, eax (push-ret destination)
            + b"\xc3"  # 0x12: ret
            + b"\x55"  # 0x13: push ebp
            + b"\x89\xe5"  # 0x14: mov ebp, esp
            + b"\xe8\xe5\xff\xff\xff"  # 0x16: call 0x0
            + b"\x5d"  # 0x1b: pop ebp
            + b"\xc3"  # 0x1c: ret
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x0, result.functions)
        self.assertEqual(result.ins2fn.get(0x10), 0x0)

    def test_accepts_missing_timeout_callback(self):
        binary_info = BinaryInfo(b"\x90\xc3")
        binary_info.base_addr = 0
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertFalse(result.analysis_timeout)

    def test_repeated_reference_candidates_participate_in_conflict_resolution(self):
        config = SmdaConfig()
        config.HIGH_ACCURACY = True
        binary_info = BinaryInfo(b"\x90" * 0x40)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32

        manager = FunctionCandidateManager(config)
        manager.disassembly = SimpleNamespace(binary_info=binary_info)
        manager.bitness = 32
        manager.addReferenceCandidate(0x1010, 0x1000)
        manager.addReferenceCandidate(0x1010, 0x1005)
        manager._buildQueue()

        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.instruction_start_bytes = {0x1000}
        state.processed_bytes = {0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005}

        manager.updateCandidates(state)

        self.assertEqual(manager.candidates[0x1010].call_ref_sources, {0x1000})

    def test_late_reference_candidates_participate_in_conflict_resolution(self):
        config = SmdaConfig()
        config.HIGH_ACCURACY = True
        binary_info = BinaryInfo(b"\x90" * 0x40)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32

        manager = FunctionCandidateManager(config)
        manager.disassembly = SimpleNamespace(binary_info=binary_info)
        manager.bitness = 32
        manager._buildQueue()
        manager.addCandidate(0x1010, reference_source=0x1000)
        manager.addCandidate(0x1010, reference_source=0x1005)

        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.instruction_start_bytes = {0x1000}
        state.processed_bytes = {0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005}

        manager.updateCandidates(state)

        self.assertEqual(manager.candidates[0x1010].call_ref_sources, {0x1000})

    def test_function_gaps_cover_head_and_tail_without_code_areas(self):
        # Raw memory dumps are loaded without section info (_code_areas is empty). The gap scan
        # must still cover the head (before the first instruction) and tail (after the last
        # instruction) of the mapped image, otherwise functions that lie entirely before the first
        # or after the last already-discovered instruction (e.g. trailing jmp/thunk tables) are
        # never reached by the gap pass.
        manager = FunctionCandidateManager(SmdaConfig())
        binary_info = BinaryInfo(b"\x00" * 0x100)
        binary_info.base_addr = 0x1000
        binary_info.binary_size = 0x100
        manager._code_areas = []
        # only one already-discovered instruction, in the middle of the image
        manager.disassembly = SimpleNamespace(binary_info=binary_info, code_map={0x1080: 1})

        manager.updateFunctionGaps()

        # a head gap [base_addr, first_instruction) and a tail gap [last_instruction, image_end)
        self.assertIn([0x1000, 0x1080, 0x80], manager.function_gaps)
        self.assertIn([0x1080, 0x1100, 0x80], manager.function_gaps)

    @staticmethod
    def _ins(mnemonic, op_str, address=0x1000, size=0):
        # (address, size, mnemonic, op_str) as produced by capstone disasm_lite
        return (address, size, mnemonic, op_str)

    def test_syscall_number_resolved_from_direct_mov(self):
        disassembler = self._create_disassembler()
        # mov rax, 0x3c ; syscall  -> exit (60)
        preceding = [self._ins("mov", "rax, 0x3c")]
        self.assertEqual(disassembler._resolveSyscallNumber(preceding, 64), 60)
        # 32-bit eax variant
        preceding32 = [self._ins("mov", "eax, 0x1")]
        self.assertEqual(disassembler._resolveSyscallNumber(preceding32, 32), 1)

    def test_syscall_number_backtracks_over_unrelated_instructions(self):
        disassembler = self._create_disassembler()
        # mov rax, 0x3c ; xor edi, edi ; syscall  -> still resolves to 60
        preceding = [self._ins("mov", "rax, 0x3c"), self._ins("xor", "edi, edi")]
        self.assertEqual(disassembler._resolveSyscallNumber(preceding, 64), 60)
        # 64-bit also honors a zero-extending eax write
        preceding_eax = [self._ins("mov", "eax, 0x3c"), self._ins("mov", "rsi, 0x0")]
        self.assertEqual(disassembler._resolveSyscallNumber(preceding_eax, 64), 60)
        # movabs (capstone's mnemonic for the imm64 mov encoding) is honored
        preceding_movabs = [self._ins("movabs", "rax, 0x3c")]
        self.assertEqual(disassembler._resolveSyscallNumber(preceding_movabs, 64), 60)

    def test_syscall_number_unresolved_on_clobber_or_boundary(self):
        disassembler = self._create_disassembler()
        # rax overwritten by an untrackable instruction after the mov -> None
        clobbered = [self._ins("mov", "rax, 0x3c"), self._ins("xor", "rax, rax")]
        self.assertIsNone(disassembler._resolveSyscallNumber(clobbered, 64))
        # a control-flow boundary between the mov and the syscall stops backtracking
        across_boundary = [self._ins("mov", "rax, 0x3c"), self._ins("call", "0x401000")]
        self.assertIsNone(disassembler._resolveSyscallNumber(across_boundary, 64))
        # prefixed boundary mnemonic ("bnd ret") is still recognized after prefix split
        across_prefixed_boundary = [self._ins("mov", "rax, 0x3c"), self._ins("bnd ret", "")]
        self.assertIsNone(disassembler._resolveSyscallNumber(across_prefixed_boundary, 64))
        # value sourced from a register/memory operand is not a parseable immediate
        from_register = [self._ins("mov", "rax, rbx")]
        self.assertIsNone(disassembler._resolveSyscallNumber(from_register, 64))
        # no preceding instructions at all
        self.assertIsNone(disassembler._resolveSyscallNumber([], 64))

    def test_syscall_number_continues_past_read_only_instructions(self):
        disassembler = self._create_disassembler()
        # cmp/test/push read rax as a source but do not clobber it -> still resolves
        for read_only in (self._ins("cmp", "rax, 1"), self._ins("test", "rax, rax"), self._ins("push", "rax")):
            preceding = [self._ins("mov", "rax, 0x3c"), read_only]
            self.assertEqual(disassembler._resolveSyscallNumber(preceding, 64), 60)

    def test_syscall_number_unresolved_on_implicit_rax_clobber(self):
        disassembler = self._create_disassembler()
        # instructions that implicitly write rax/eax must stop resolution (no false 60)
        for implicit in (
            self._ins("cpuid", ""),  # operand-less implicit write
            self._ins("rdtsc", ""),
            self._ins("xgetbv", ""),  # operand-less, writes edx:eax
            self._ins("lodsq", ""),
            self._ins("cdqe", ""),
            self._ins("div", "rcx"),  # implicit rax:rdx write with an explicit operand
            self._ins("imul", "rcx"),  # one-operand form writes rdx:rax
        ):
            preceding = [self._ins("mov", "rax, 0x3c"), implicit]
            self.assertIsNone(disassembler._resolveSyscallNumber(preceding, 64))
        # xchg writes both operands, even when rax is the second one
        xchg_second = [self._ins("mov", "rax, 0x3c"), self._ins("xchg", "qword ptr [rdi], rax")]
        self.assertIsNone(disassembler._resolveSyscallNumber(xchg_second, 64))
        # multi-operand imul to an unrelated register does not clobber rax
        imul_other = [self._ins("mov", "rax, 0x3c"), self._ins("imul", "rbx, rcx, 2")]
        self.assertEqual(disassembler._resolveSyscallNumber(imul_other, 64), 60)


if __name__ == "__main__":
    unittest.main()
