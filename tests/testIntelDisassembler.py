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

    def _candidate(self, buf, bitness=64, addr=0x1000, base_addr=0x1000):
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base_addr
        binary_info.bitness = bitness
        return FunctionCandidate(binary_info, addr)

    def test_extended_amd64_prologues_score_as_common_start(self):
        # endbr64; push rbp; mov rbp, rsp
        self.assertTrue(self._candidate(bytes.fromhex("f30f1efa554889e5")).hasCommonFunctionStart())
        # endbr64; sub rsp, 0x10
        self.assertTrue(self._candidate(bytes.fromhex("f30f1efa4883ec10")).hasCommonFunctionStart())
        # push r15; push r14
        self.assertTrue(self._candidate(bytes.fromhex("41574156")).hasCommonFunctionStart())
        # mov [rsp+8], rbx
        self.assertTrue(self._candidate(bytes.fromhex("48895c2408")).hasCommonFunctionStart())
        # sub rsp, 0x20
        candidate = self._candidate(bytes.fromhex("4883ec20"))
        self.assertTrue(candidate.hasCommonFunctionStart())
        self.assertGreater(candidate.getFunctionStartScore(), 0)

    def test_bare_endbr64_without_recognized_continuation_scores_zero(self):
        candidate = self._candidate(bytes.fromhex("f30f1efa9090909090"))
        self.assertFalse(candidate.hasCommonFunctionStart())
        self.assertEqual(candidate.getFunctionStartScore(), 0)

    def test_extended_amd64_prologues_are_64bit_only(self):
        # the masked sub-rsp/mov-rsp patterns are REX-prefixed and must not match in 32-bit mode
        candidate = self._candidate(bytes.fromhex("4883ec20"), bitness=32)
        self.assertFalse(candidate.hasCommonFunctionStart())

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

    def _first_gap_candidate(self, stub, base=0x1000, stub_off=0x10):
        # Build a buffer with a gap (between two mapped instructions at base and base+0x100),
        # int3-padded up to `stub` at base+stub_off, then drive the gap scanner once.
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs

        buf = bytearray(b"\x90")  # base+0x00: a mapped instruction bounding the gap
        buf += b"\xcc" * (stub_off - len(buf))  # int3 padding leading into the gap
        buf += stub  # base+stub_off: the candidate bytes under test
        buf += b"\xcc" * (0x200 - len(buf))  # trailing fill

        binary_info = BinaryInfo(bytes(buf))
        binary_info.base_addr = base
        binary_info.binary_size = len(buf)
        binary_info.bitness = 32
        disassembly = SimpleNamespace(
            binary_info=binary_info,
            code_map={base: 1, base + 0x100: 1},
            data_map={},
            getRawBytes=lambda offset, n: bytes(buf)[offset : offset + n],
        )
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = disassembly
        manager.bitness = 32
        manager.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        return manager.nextGapCandidate()

    def test_hotpatch_prologue_not_skipped_as_effective_nop(self):
        # `mov edi, edi; push ebp; mov ebp, esp` is an MSVC hotpatch stub whose leading
        # `mov edi, edi` (0x8bff) is an effective NOP but IS the true function start. The
        # gap scanner must return the stub start, not skip it to the `push ebp` two bytes
        # later (which would mislocate the function and drop its true entry).
        self.assertEqual(self._first_gap_candidate(b"\x8b\xff\x55\x8b\xec"), 0x1010)
        # control: a bare `mov edi, edi` not followed by a real prologue is still treated
        # as an effective NOP and skipped, so it is never returned as the candidate start.
        self.assertNotEqual(self._first_gap_candidate(b"\x8b\xff\x90\x90\x90"), 0x1010)

    def test_is_hotpatch_prologue_predicate(self):
        # The shared predicate backs both the gap scanner and the post-call alignment-cut
        # path, so lock its contract directly: both `mov edi, edi` encodings of the MSVC
        # hotpatch stub match in 32-bit, non-hotpatch windows do not, and 64-bit never
        # matches (the stub is a 32-bit convention; COMMON_PROLOGUES["5"][64] is empty).
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 32
        self.assertTrue(manager.isHotpatchPrologue(b"\x8b\xff\x55\x8b\xec"))
        self.assertTrue(manager.isHotpatchPrologue(b"\x89\xff\x55\x8b\xec"))
        self.assertFalse(manager.isHotpatchPrologue(b"\x8b\xff\x90\x90\x90"))
        self.assertFalse(manager.isHotpatchPrologue(b"\x55\x8b\xec\x83\xec"))  # bare prologue, no NOP
        manager.bitness = 64
        self.assertFalse(manager.isHotpatchPrologue(b"\x8b\xff\x55\x8b\xec"))

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

        # a head gap [base_addr, first_instruction) and a tail gap that starts AFTER the last
        # instruction's address (max_code + 1, mirroring the interior-hole branch). Starting the
        # tail gap at max_code itself would leave the gap-pointer on a code_map address, which
        # getNextGap() cannot advance past -- the tail would never be scanned.
        self.assertIn([0x1000, 0x1080, 0x80], manager.function_gaps)
        self.assertIn([0x1081, 0x1100, 0x7F], manager.function_gaps)

    def test_gap_scan_skips_single_byte_padding_run(self):
        config = SmdaConfig()
        binary_info = BinaryInfo(b"\x00\x90\xcc\x55\xc3")
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32
        binary_info.binary_size = len(binary_info.binary)

        manager = FunctionCandidateManager(config)
        manager.disassembly = SimpleNamespace(
            binary_info=binary_info,
            code_map={},
            data_map={},
            getRawBytes=lambda offset, size: binary_info.binary[offset : offset + size],
        )
        manager.bitness = 32
        manager.capstone = SimpleNamespace(disasm_lite=lambda data, offset: [(offset, 1, "push", "ebp")])
        manager.function_gaps = [[0x1000, 0x1005, 5]]
        manager.gap_pointer = 0x1000

        self.assertEqual(manager.nextGapCandidate(), 0x1003)

    def test_locate_prologue_candidates_seeds_extended_amd64_prologues(self):
        buf = bytes.fromhex(
            "f30f1efa554889e5"  # 0x1000: endbr64; push rbp; mov rbp, rsp
            "41574156"  # 0x1008: push r15; push r14
            "48895c2408"  # 0x100c: mov [rsp+8], rbx
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.binary_size = len(buf)

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 64

        manager.locatePrologueCandidates()

        self.assertEqual(
            {0x1000, 0x1008, 0x100C} & manager.candidates.keys(),
            {0x1000, 0x1008, 0x100C},
        )

    def test_locate_prologue_candidates_does_not_seed_generic_sub_rsp(self):
        # "sub rsp, imm8" alone is a common mid-function idiom (e.g. a call-alignment stub), not
        # a reliable independent function-start signal; it must not be raw-scanned as a FEP.
        buf = bytes.fromhex("4883ec20")
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.binary_size = len(buf)

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 64

        manager.locatePrologueCandidates()

        self.assertEqual(manager.candidates, {})

    def test_locate_prologue_candidates_skips_extended_amd64_prologues_for_32bit(self):
        buf = bytes.fromhex("4883ec20")
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32
        binary_info.binary_size = len(buf)

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 32

        manager.locatePrologueCandidates()

        self.assertEqual(manager.candidates, {})

    def test_prefixed_call_keeps_fallthrough_in_same_block(self):
        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.instructions = [
            (0x1000, 6, "bnd call", "0x1010", b""),
            (0x1006, 2, "xor", "eax, eax", b""),
            (0x1008, 1, "ret", "", b""),
        ]
        state.instruction_start_bytes = {0x1000, 0x1006, 0x1008}
        state.addCodeRef(0x1000, 0x1010, by_jump=False)
        state.addCodeRef(0x1000, 0x1006, by_jump=False)

        self.assertEqual([[ins[0] for ins in block] for block in state.getBlocks()], [[0x1000, 0x1006, 0x1008]])

    def test_alignment_sequence_recognizes_prefixed_ret(self):
        # a bnd-prefixed ret right after a run of alignment padding is still real code, not
        # more padding - isAlignmentSequence() must recognize it like a plain "ret".
        manager = FunctionCandidateManager(SmdaConfig())
        instruction_sequence = [
            SimpleNamespace(address=0x100F, bytes=b"\x90", mnemonic="nop"),
            SimpleNamespace(address=0x1010, bytes=b"\xf2\xc3", mnemonic="bnd ret"),
        ]

        self.assertFalse(manager.isAlignmentSequence(instruction_sequence))

    def test_gap_stub_with_prefixed_jmp_is_accepted(self):
        # a single bnd-prefixed jmp stub discovered via gap-scanning (e.g. a misaligned
        # import-jmp thunk) must still be accepted as a legitimate function, matching the
        # plain "jmp" case.
        state = FunctionAnalysisState(0x1000, SimpleNamespace(getByte=lambda addr: 0xF2))
        state.is_sanely_ending = False
        state.num_blocks_analyzed = 0
        state.instructions = [(0x1000, 6, "bnd jmp", "dword ptr [0x2000]", b"")]

        self.assertTrue(state.finalizeAnalysis(as_gap=True))

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
