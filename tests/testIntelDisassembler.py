import logging
import unittest
from types import SimpleNamespace

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.FunctionAnalysisState import FunctionAnalysisState
from smda.intel.FunctionCandidate import FunctionCandidate
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.intel.MnemonicTfIdf import MnemonicTfIdf
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig


class _RecordingCandidateManager(FunctionCandidateManager):
    """A FunctionCandidateManager stand-in that skips the queue/init machinery but
    reuses the real isAlignmentSequence/isHotpatchPrologue/hasCommonPrologue logic
    (they only touch self.bitness/self.disassembly), so alignment-cut tests exercise
    the actual production code paths instead of re-implementing them."""

    def __init__(self, binary_info, bitness, candidate_addrs=None):
        self.bitness = bitness
        self.disassembly = SimpleNamespace(binary_info=binary_info)
        self.candidates = set(candidate_addrs or [])
        self.added_candidates = []

    def addCandidate(self, addr, is_gap=False, reference_source=None):
        self.added_candidates.append(addr)


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

    def is_active(self):
        return self._is_api or self._is_symbol


class ImportSlotProvider(DummyProvider):
    def __init__(self, slot, dll_name, api_name):
        super().__init__(is_api=True)
        self.slot = slot
        self.dll_name = dll_name
        self.api_name = api_name

    def getApi(self, to_address, api_address=None):
        if to_address == self.slot:
            return (self.dll_name, self.api_name)
        return ("", "")


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

    def test_extended_amd64_prologues_score_exact_tiers(self):
        # endbr64; push rbp; mov rbp, rsp -- DEFAULT_PROLOGUES entry, falls back to the
        # single-byte 0x55 tier (33) since "554889e5" itself isn't a COMMON_PROLOGUES key.
        self.assertEqual(self._candidate(bytes.fromhex("f30f1efa554889e5")).getFunctionStartScore(), 33)
        # push r15; push r14 -- exact 4-byte match, tier 40
        self.assertEqual(self._candidate(bytes.fromhex("41574156")).getFunctionStartScore(), 40)
        # push rbx; sub rsp, imm8 -- exact 5-byte match, tier 40
        self.assertEqual(self._candidate(bytes.fromhex("40534883ec20")).getFunctionStartScore(), 40)
        # push rbp; sub rsp, imm8 -- exact 5-byte match, tier 40
        self.assertEqual(self._candidate(bytes.fromhex("40554883ec18")).getFunctionStartScore(), 40)
        # endbr64 stripped, then push rbx; sub rsp, imm8 underneath -- still tier 40
        self.assertEqual(self._candidate(bytes.fromhex("f30f1efa40534883ec20")).getFunctionStartScore(), 40)
        # mov [rsp+disp8], rbx -- exact 4-byte match, tier 30 (below push;sub, above the
        # single-byte 0x48 REX.W fallback, per the maintainer's lower MSVC precision for this pattern)
        self.assertEqual(self._candidate(bytes.fromhex("48895c2408")).getFunctionStartScore(), 30)
        # bare "sub rsp, imm8" -- no longer an independent pattern at any length; falls back
        # to the single-byte 0x48 (REX.W) tier (21)
        self.assertEqual(self._candidate(bytes.fromhex("4883ec20")).getFunctionStartScore(), 21)

    def test_extended_amd64_prologues_negative_guards(self):
        # push rbx; sub rsp, imm8 WITHOUT the leading bare REX (0x40) byte does not hit the
        # tier-40 pattern -- it falls back to the single-byte 0x53 tier (6)
        self.assertEqual(self._candidate(bytes.fromhex("534883ec20")).getFunctionStartScore(), 6)
        # mov [rsp+disp8], rax (ModRM reg=000, not rbx's reg=011) does not alias the
        # rbx-specific mov-spill pattern -- falls back to the single-byte 0x48 tier (21)
        self.assertEqual(self._candidate(bytes.fromhex("4889442408")).getFunctionStartScore(), 21)
        # mov [rsp+disp32], rbx (mod=10, ModRM 0x9c) must not alias the disp8 form (mod=01,
        # ModRM 0x5c) -- falls back to the single-byte 0x48 tier (21)
        self.assertEqual(self._candidate(bytes.fromhex("48899c2408000000")).getFunctionStartScore(), 21)

    def test_bare_endbr64_without_recognized_continuation_scores_zero(self):
        candidate = self._candidate(bytes.fromhex("f30f1efa9090909090"))
        self.assertFalse(candidate.hasCommonFunctionStart())
        self.assertEqual(candidate.getFunctionStartScore(), 0)

    def test_extended_amd64_prologues_are_64bit_only(self):
        # the exact push;sub/mov-spill patterns are REX-prefixed and must not match in 32-bit mode
        for hexbytes in ("4883ec20", "40534883ec20", "40554883ec18", "48895c2408"):
            with self.subTest(hexbytes=hexbytes):
                candidate = self._candidate(bytes.fromhex(hexbytes), bitness=32)
                self.assertFalse(candidate.hasCommonFunctionStart())

    def test_mnemonic_tfidf_empty_counts_returns_zero(self):
        self.assertEqual(MnemonicTfIdf().tfidf({}), 0.0)

    def test_mnemonic_tfidf_tables_are_cached_and_bitness_isolated(self):
        tfidf32 = MnemonicTfIdf(bitness=32)
        mov32 = tfidf32.getFrequency("mov")

        tfidf64 = MnemonicTfIdf(bitness=64)

        self.assertEqual(tfidf32.getFrequency("mov"), mov32)
        self.assertNotEqual(tfidf64.getFrequency("mov"), mov32)
        self.assertIs(tfidf32.idf, MnemonicTfIdf(bitness=32).idf)
        self.assertEqual(tfidf32.getFrequency("unknown-mnemonic"), tfidf32._max_idf)
        with self.assertRaises(TypeError):
            tfidf32.idf["mov"] = 0

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

    def test_language_score_does_not_claim_cpp_from_thiscall_instruction_patterns(self):
        func = b"\x55\x48\x89\xe5\x5d\xc3"  # push rbp; mov rbp, rsp; pop rbp; ret
        code = func * 10
        thiscall_tail = b"\x8b\x4d\x04\xe8\x01\x02\x03\x00"
        buf = code + thiscall_tail
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [[0x1000, 0x1000 + len(code)]]

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertGreater(len(result.functions), 1)
        self.assertEqual(result.language["c++"], 0.0)
        self.assertEqual(result.language_guess, "c/asm")

    def test_direct_import_stub_calls_resolve_at_original_caller(self):
        base = 0x1000
        import_slot = 0x2000
        caller = (
            b"\x55"  # 0x1000: push rbp
            + b"\x48\x89\xe5"  # 0x1001: mov rbp, rsp
            + b"\xe8\x17\x00\x00\x00"  # 0x1004: call 0x1020
            + b"\x5d"  # 0x1009: pop rbp
            + b"\xc3"  # 0x100a: ret
        )
        stub = b"\xff\x25\xda\x0f\x00\x00"  # 0x1020: jmp qword ptr [rip + 0xfda] -> 0x2000
        buf = caller + b"\xcc" * (0x20 - len(caller)) + stub

        for stub_kind in ("elf", "macho"):
            with self.subTest(stub_kind=stub_kind):
                binary_info = BinaryInfo(buf)
                binary_info.base_addr = base
                binary_info.bitness = 64
                binary_info.architecture = "intel"
                binary_info._plt_ranges = [(0x1020, 0x1020 + len(stub))] if stub_kind == "elf" else []
                binary_info._macho_stub_ranges = [(0x1020, 0x1020 + len(stub))] if stub_kind == "macho" else []

                disassembler = IntelDisassembler(SmdaConfig())
                disassembler._registerLabelProvider(ImportSlotProvider(import_slot, "libsystem", "puts"))
                result = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=None)

                self.assertIn(0x1000, result.functions)
                self.assertIn(0x1020, result.code_refs_from[0x1004])
                self.assertEqual(result.getApiRefs(0x1000), {0x1004: "libsystem!puts"})
                self.assertIn(0x1004, result.apis[import_slot]["referencing_addr"])

    def test_direct_jmp_tailcall_to_stub_resolves_at_original_caller(self):
        # A thin wrapper that tail-calls an import via a bare "jmp" (instead of
        # "call") must resolve through the same PLT/Mach-O-stub decode as the
        # direct-call case (sibling of PAT-SMDA-004, caught by the mandatory sweep).
        base = 0x1000
        import_slot = 0x2000
        caller = (
            b"\x55"  # 0x1000: push rbp
            + b"\x48\x89\xe5"  # 0x1001: mov rbp, rsp
            + b"\xe8\x0c\x00\x00\x00"  # 0x1004: call 0x1015 (calls the tailcall wrapper)
            + b"\x5d"  # 0x1009: pop rbp
            + b"\xc3"  # 0x100a: ret
        )
        wrapper = b"\xeb\x09"  # 0x1015: jmp 0x1020 (tailcall straight into the stub)
        stub = b"\xff\x25\xda\x0f\x00\x00"  # 0x1020: jmp qword ptr [rip + 0xfda] -> 0x2000
        buf = caller + b"\xcc" * (0x15 - len(caller)) + wrapper + b"\xcc" * (0x20 - 0x15 - len(wrapper)) + stub

        for stub_kind in ("elf", "macho"):
            with self.subTest(stub_kind=stub_kind):
                binary_info = BinaryInfo(buf)
                binary_info.base_addr = base
                binary_info.bitness = 64
                binary_info.architecture = "intel"
                binary_info._plt_ranges = [(0x1020, 0x1020 + len(stub))] if stub_kind == "elf" else []
                binary_info._macho_stub_ranges = [(0x1020, 0x1020 + len(stub))] if stub_kind == "macho" else []

                disassembler = IntelDisassembler(SmdaConfig())
                disassembler._registerLabelProvider(ImportSlotProvider(import_slot, "libsystem", "puts"))
                result = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=None)

                self.assertIn(0x1015, result.functions)
                self.assertIn(0x1020, result.code_refs_from[0x1015])
                self.assertEqual(result.getApiRefs(0x1015), {0x1015: "libsystem!puts"})
                self.assertIn(0x1015, result.apis[import_slot]["referencing_addr"])

    def test_32bit_pic_plt_call_resolves_ebx_relative_import_slot(self):
        base = 0x1000
        import_slot = 0x200C
        caller = (
            b"\x55"  # 0x1000: push ebp
            + b"\x89\xe5"  # 0x1001: mov ebp, esp
            + b"\xe8\x18\x00\x00\x00"  # 0x1003: call 0x1020
            + b"\x5d"  # 0x1008: pop ebp
            + b"\xc3"  # 0x1009: ret
        )
        stub = (
            b"\xf3\x0f\x1e\xfb"  # 0x1020: endbr32
            + b"\xf2\xff\xa3\x0c\x00\x00\x00"  # 0x1024: bnd jmp dword ptr [ebx + 0xc]
        )
        buf = caller + b"\xcc" * (0x20 - len(caller)) + stub

        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base
        binary_info.bitness = 32
        binary_info.architecture = "intel"
        binary_info._plt_ranges = [(0x1020, 0x1020 + len(stub))]
        binary_info._macho_stub_ranges = []
        binary_info._elf_got_bases = [0x2000]
        binary_info.imported_functions = {import_slot: ("libc.so.6", "puts")}

        disassembler = IntelDisassembler(SmdaConfig())
        disassembler._registerLabelProvider(ImportSlotProvider(import_slot, "libc.so.6", "puts"))
        result = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x1020, result.code_refs_from[0x1003])
        self.assertEqual(result.getApiRefs(0x1000), {0x1003: "libc.so.6!puts"})
        self.assertIn(0x1003, result.apis[import_slot]["referencing_addr"])

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

    def test_push_ret_through_a_register_does_not_reference_address_zero(self):
        # `push eax; ret` names no literal, so the operand reader returns its
        # "nothing found" 0 -- which a base-0 image accepts as a real address
        buf = (
            b"\xcc" * 0x100
            + b"\x55"  # 0x100: push ebp
            + b"\x89\xe5"  # 0x101: mov ebp, esp
            + b"\x31\xc0"  # 0x103: xor eax, eax
            + b"\x50"  # 0x105: push eax
            + b"\xc3"  # 0x106: ret
            + b"\xcc" * 0x100
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x100, result.functions)
        self.assertNotIn(0, result.code_refs_to)

    def test_push_ret_through_a_literal_still_resolves(self):
        """Positive control for the pair above, in the same layout: a push naming a
        real address must still be followed, on either side of the register case."""
        buf = (
            b"\xcc" * 0x100
            + b"\x55"  # 0x100: push ebp
            + b"\x89\xe5"  # 0x101: mov ebp, esp
            + b"\x68\x20\x02\x00\x00"  # 0x103: push 0x220
            + b"\xc3"  # 0x108: ret
            + b"\xcc" * 0x117
            + b"\x31\xc0"  # 0x220: xor eax, eax
            + b"\xc3"  # 0x222: ret
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertIn(0x100, result.functions)
        self.assertEqual(result.ins2fn.get(0x220), 0x100)

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

    def _gap_manager(self, stub, base=0x1000, stub_off=0x10):
        # Same layout as _first_gap_candidate, but hands back the manager so a test can drive
        # the scan more than once and observe the retained-pad bookkeeping between calls.
        buf = bytearray(b"\x90")
        buf += b"\xcc" * (stub_off - len(buf))
        buf += stub
        buf += b"\xcc" * (0x200 - len(buf))

        binary_info = BinaryInfo(bytes(buf))
        binary_info.base_addr = base
        binary_info.binary_size = len(buf)
        binary_info.bitness = 32
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(
            binary_info=binary_info,
            code_map={base: 1, base + 0x100: 1},
            data_map={},
            getRawBytes=lambda offset, n: bytes(buf)[offset : offset + n],
        )
        manager.bitness = 32
        manager.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        return manager

    def test_hotpatch_pad_before_a_non_ebp_prologue_is_the_candidate_start(self):
        # `mov edi, edi` opens every hotpatchable MSVC function, not only those continuing with
        # `push ebp; mov ebp, esp`. As padding it exists solely to reach the next 16-byte
        # boundary, so a pad that does not end on one is the function's true entry and must be
        # the candidate; skipping it would mislocate the start two bytes late.
        self.assertEqual(self._first_gap_candidate(b"\x8b\xff\x56\x8b\xf2"), 0x1010)
        self.assertEqual(self._first_gap_candidate(b"\x89\xff\x83\xec\x0c"), 0x1010)
        # control: the same pad two bytes earlier DOES end on the boundary, so it is genuine
        # alignment filler and the candidate is the aligned address behind it.
        self.assertEqual(self._first_gap_candidate(b"\x8b\xff\x56\x8b\xf2", stub_off=0x0E), 0x1010)

    def test_is_unaligned_entry_pad_predicate(self):
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 32
        self.assertTrue(manager.isUnalignedEntryPad(b"\x8b\xff", 0x1012, b"\x56\x8b\xf2\x00\x00\x00\x00"))
        # ends on a 16-byte boundary -> alignment filler
        self.assertFalse(manager.isUnalignedEntryPad(b"\x8b\xff", 0x1010, b"\x56\x8b\xf2\x00\x00\x00\x00"))
        # more padding behind it -> still inside the filler run, not the run's function entry
        self.assertFalse(manager.isUnalignedEntryPad(b"\x8b\xff", 0x1012, b"\x90\x90\x90\x90\x90\x90\x90"))
        # the pad set is per bitness: `mov edi, edi` is the x86 hotpatch convention, and widening
        # x86 to the other effective NOPs was measured to cost true positives
        self.assertFalse(manager.isUnalignedEntryPad(b"\x66\x90", 0x1012, b"\x56\x8b\xf2\x00\x00\x00\x00"))
        manager.bitness = 64
        self.assertFalse(manager.isUnalignedEntryPad(b"\x8b\xff", 0x1012, b"\x56\x8b\xf2\x00\x00\x00\x00"))
        self.assertTrue(manager.isUnalignedEntryPad(b"\x66\x90", 0x1012, b"\x0f\xb6\x01\x84\xc0\x74\x24"))
        self.assertFalse(manager.isUnalignedEntryPad(b"\x66\x90", 0x1010, b"\x0f\xb6\x01\x84\xc0\x74\x24"))
        # a bitness with no pad set at all matches nothing
        manager.bitness = 16
        self.assertFalse(manager.isUnalignedEntryPad(b"\x66\x90", 0x1012, b"\x0f\xb6\x01\x84\xc0\x74\x24"))

    def test_retained_hotpatch_pad_that_yields_no_function_resumes_behind_the_pad(self):
        # When the retained pad produces no function it really was padding, so the scan must
        # continue two bytes on instead of following the caller's next-gap address, which would
        # abandon every remaining byte of the current gap.
        manager = self._gap_manager(b"\x8b\xff\x56\x8b\xf2")
        self.assertEqual(manager.nextGapCandidate(), 0x1010)
        self.assertEqual(manager.nextGapCandidate(0x1100), 0x1012)

    def test_retained_hotpatch_pad_that_became_a_function_follows_the_next_gap(self):
        manager = self._gap_manager(b"\x8b\xff\x56\x8b\xf2")
        self.assertEqual(manager.nextGapCandidate(), 0x1010)
        manager.disassembly.code_map[0x1010] = 1
        self.assertNotEqual(manager.nextGapCandidate(0x1100), 0x1012)

    def test_gap_scan_skips_hlt_and_ud2_trap_filler(self):
        # hlt (0xf4) and ud2 (0x0f 0x0b) are trap filler a function never opens with;
        # the gap scanner must skip them like int3 and promote the code behind them.
        self.assertEqual(self._first_gap_candidate(b"\xf4\x55\x8b\xec"), 0x1011)
        self.assertEqual(self._first_gap_candidate(b"\x0f\x0b\x55\x8b\xec"), 0x1012)

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

    def test_jmp_to_resolved_import_as_first_instruction_marks_thunk_call(self):
        # A single "jmp dword ptr [import_slot]" that is the function's very first
        # instruction is a textbook single-instruction import-thunk stub: the entire
        # function body is the jmp, so it must be flagged as a thunk call.
        disassembler = self._create_disassembler()
        disassembler._registerLabelProvider(ImportSlotProvider(0x1020, "kernel32.dll", "ExitProcess"))
        disassembler.disassembly = SimpleNamespace(
            apis={},
            addApiReference=lambda *a, **kw: None,
            addImportSlot=lambda *a, **kw: None,
            dereferenceDword=lambda addr: 0x9999 if addr == 0x1020 else None,
            isAddrWithinMemoryImage=lambda addr: True,
        )
        disassembler.tailcall_analyzer = SimpleNamespace(addJump=lambda *a, **kw: None)
        backend = X86Backend.__new__(X86Backend)

        state = FunctionAnalysisState(0x1000, disassembler.disassembly)
        instruction = (0x1000, 6, "jmp", "dword ptr [0x1020]")

        backend._analyzeJmpInstruction(disassembler, instruction, state)

        self.assertTrue(state.is_thunk_call)

    def test_jmp_to_resolved_import_deep_in_function_does_not_mark_thunk_call(self):
        # The identical jmp-to-resolved-API shape, but reached only after a preceding
        # instruction inside the same function, is a thunk-shaped tailcall INSIDE a
        # larger routine, not a whole-function thunk -- it must not be flagged.
        disassembler = self._create_disassembler()
        disassembler._registerLabelProvider(ImportSlotProvider(0x1020, "kernel32.dll", "ExitProcess"))
        disassembler.disassembly = SimpleNamespace(
            apis={},
            addApiReference=lambda *a, **kw: None,
            addImportSlot=lambda *a, **kw: None,
            dereferenceDword=lambda addr: 0x9999 if addr == 0x1020 else None,
            isAddrWithinMemoryImage=lambda addr: True,
        )
        disassembler.tailcall_analyzer = SimpleNamespace(addJump=lambda *a, **kw: None)
        backend = X86Backend.__new__(X86Backend)

        state = FunctionAnalysisState(0x1010, disassembler.disassembly)
        state.addInstruction(0x1010, 1, "push", "ebp", b"\x55")
        instruction = (0x1013, 6, "jmp", "dword ptr [0x1020]")

        backend._analyzeJmpInstruction(disassembler, instruction, state)

        self.assertFalse(state.is_thunk_call)

    def test_direct_jmp_to_resolved_import_as_first_instruction_marks_thunk_call(self):
        disassembler = self._create_disassembler()
        disassembler._registerLabelProvider(ImportSlotProvider(0x1020, "kernel32.dll", "ExitProcess"))
        disassembler.disassembly = SimpleNamespace(
            apis={},
            addApiReference=lambda *a, **kw: None,
            addImportSlot=lambda *a, **kw: None,
            functions={},
            isAddrWithinMemoryImage=lambda addr: True,
        )
        disassembler.fc_manager = SimpleNamespace(getFunctionStartCandidates=lambda: set())
        disassembler.tailcall_analyzer = SimpleNamespace(addJump=lambda *a, **kw: None)
        backend = X86Backend.__new__(X86Backend)
        backend._resolveImportSlot = lambda d, target: 0x1020

        state = FunctionAnalysisState(0x1000, disassembler.disassembly)
        backend._analyzeJmpInstruction(disassembler, (0x1000, 5, "jmp", "0x1100"), state)

        self.assertTrue(state.is_thunk_call)
        self.assertTrue(state.is_sanely_ending)

    def test_direct_jmp_to_resolved_import_deep_in_function_does_not_mark_thunk_call(self):
        disassembler = self._create_disassembler()
        disassembler._registerLabelProvider(ImportSlotProvider(0x1020, "kernel32.dll", "ExitProcess"))
        disassembler.disassembly = SimpleNamespace(
            apis={},
            addApiReference=lambda *a, **kw: None,
            addImportSlot=lambda *a, **kw: None,
            functions={},
            isAddrWithinMemoryImage=lambda addr: True,
        )
        disassembler.fc_manager = SimpleNamespace(getFunctionStartCandidates=lambda: set())
        disassembler.tailcall_analyzer = SimpleNamespace(addJump=lambda *a, **kw: None)
        backend = X86Backend.__new__(X86Backend)
        backend._resolveImportSlot = lambda d, target: 0x1020

        state = FunctionAnalysisState(0x1000, disassembler.disassembly)
        state.addInstruction(0x1000, 1, "push", "rbp", b"\x55")
        backend._analyzeJmpInstruction(disassembler, (0x1001, 5, "jmp", "0x1100"), state)

        self.assertFalse(state.is_thunk_call)
        self.assertTrue(state.is_sanely_ending)

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
            "40534883ec20"  # 0x100c: push rbx; sub rsp, imm8
            "40554883ec18"  # 0x1012: push rbp; sub rsp, imm8
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.binary_size = len(buf)

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 64

        manager.locatePrologueCandidates()

        expected = {0x1000, 0x1008, 0x100C, 0x1012}
        self.assertEqual(expected & manager.candidates.keys(), expected)

    def test_locate_prologue_candidates_does_not_seed_common_mid_function_idioms(self):
        # "sub rsp, imm8" alone (no leading push) and "mov [rsp+disp8], rbx" (a shadow-space
        # register spill) are both common MID-FUNCTION idioms, not reliable independent
        # function-start signals on their own (measured: seeding the mov-spill pattern across the
        # Bao x64 MSVC corpus added 537 false positives corpus-wide for zero recovered true
        # positives) -- neither must be raw-scanned as a FEP, though both are still scored via
        # COMMON_PROLOGUES when a candidate already exists by other means. Same for a push;sub
        # missing the leading bare-REX byte and a non-rbx register spill -- neither is one of the
        # exact seeded patterns either.
        for hexbytes in ("4883ec20", "534883ec20", "4889442408", "48895c2408"):
            with self.subTest(hexbytes=hexbytes):
                buf = bytes.fromhex(hexbytes)
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
        for hexbytes in ("4883ec20", "40534883ec20", "48895c2408"):
            with self.subTest(hexbytes=hexbytes):
                buf = bytes.fromhex(hexbytes)
                binary_info = BinaryInfo(buf)
                binary_info.base_addr = 0x1000
                binary_info.bitness = 32
                binary_info.binary_size = len(buf)

                manager = FunctionCandidateManager(SmdaConfig())
                manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
                manager.bitness = 32

                manager.locatePrologueCandidates()

                self.assertEqual(manager.candidates, {})

    def _seed_prologues_32bit(self, buf, code_areas=None):
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32
        binary_info.binary_size = len(buf)

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 32
        if code_areas:
            manager._code_areas = code_areas

        manager.locatePrologueCandidates()
        return manager.candidates.keys()

    def test_prologue_seeding_reports_a_tripped_timeout_to_its_caller(self):
        # locatePrologueCandidates walks several patterns; the first one to see the timeout
        # returns True so the rest are abandoned instead of each rediscovering it.
        binary_info = BinaryInfo(bytes.fromhex("558bec"))
        binary_info.base_addr = 0x1000
        binary_info.bitness = 32
        binary_info.binary_size = 3

        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager.bitness = 32
        manager._cb_analysis_timeout = lambda: True

        self.assertTrue(manager._seedPrologueMatches(b"\x55\x8b\xec"))
        self.assertEqual({}, manager.candidates)

    def test_prologue_scan_skips_the_body_behind_a_hotpatch_pad(self):
        # MSVC emits `mov edi, edi` ahead of `push ebp; mov ebp, esp` and the pad is the
        # function's entry, so the bare 3-byte prologue also matching two bytes in must not
        # seed a second candidate there -- ground truth counts only the pad.
        candidates = self._seed_prologues_32bit(bytes.fromhex("8bff558bec" + "90" * 11 + "558bec"))

        self.assertIn(0x1000, candidates)
        self.assertNotIn(0x1002, candidates)
        # a bare prologue with no pad in front of it is still seeded where it matches
        self.assertIn(0x1010, candidates)

    def test_prologue_scan_seeds_the_body_when_the_pad_is_outside_the_code_area(self):
        # The pad two bytes back is normally seeded by the 5-byte pattern scanned first, which
        # is what makes skipping the body safe. When the code filter rejected the pad, nothing
        # stands behind the body, so it must be seeded rather than dropped.
        candidates = self._seed_prologues_32bit(
            bytes.fromhex("8bff558bec" + "90" * 11 + "558bec"), code_areas=[[0x1002, 0x1020]]
        )

        self.assertNotIn(0x1000, candidates)
        self.assertIn(0x1002, candidates)

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

    def test_reachable_collision_ends_block_and_removes_code_ref(self):
        # 0x1000's only outgoing code ref is its own fall-through to 0x1006 (no mismatch,
        # so the ordinary "jump ref points elsewhere" cut does NOT fire), but 0x1006 has
        # separately been marked a colliding address (belongs to another function). getBlocks()
        # must still end the block at 0x1000 and drop the now-invalid code ref to 0x1006.
        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.instructions = [
            (0x1000, 6, "mov", "eax, 1", b""),
            (0x1006, 2, "xor", "eax, eax", b""),
            (0x1008, 1, "ret", "", b""),
        ]
        state.instruction_start_bytes = {0x1000, 0x1006, 0x1008}
        state.addCodeRef(0x1000, 0x1006, by_jump=False)
        state.addCollision(0x1006)

        blocks = state.getBlocks()

        self.assertEqual([[ins[0] for ins in block] for block in blocks], [[0x1000]])
        self.assertNotIn(0x1006, state.code_refs_from.get(0x1000, set()))
        self.assertNotIn((0x1000, 0x1006), state.code_refs)

    def test_alignment_sequence_recognizes_prefixed_ret(self):
        # a bnd-prefixed ret right after a run of alignment padding is still real code, not
        # more padding - isAlignmentSequence() must recognize it like a plain "ret".
        manager = FunctionCandidateManager(SmdaConfig())
        instruction_sequence = [
            SimpleNamespace(address=0x100F, bytes=b"\x90", mnemonic="nop"),
            SimpleNamespace(address=0x1010, bytes=b"\xf2\xc3", mnemonic="bnd ret"),
        ]

        self.assertFalse(manager.isAlignmentSequence(instruction_sequence))

    def test_alignment_sequence_accepts_lite_tuples(self):
        manager = FunctionCandidateManager(SmdaConfig())
        instruction_bytes = b"\x90\xc3"
        instruction_sequence = [
            (0x100F, 1, "nop", ""),
            (0x1010, 1, "ret", ""),
        ]

        self.assertFalse(manager.isAlignmentSequence(instruction_sequence, instruction_bytes))

    def test_function_state_tracks_max_instruction_start(self):
        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.is_next_instruction_reachable = False

        state.addInstruction(0x1005, 1, "nop", "", b"\x90")
        state.addInstruction(0x1001, 1, "nop", "", b"\x90")

        self.assertEqual(state.max_instruction_start, 0x1005)

    def test_import_stub_ranges_are_cached(self):
        binary_info = SimpleNamespace(
            _plt_ranges=[(0x1000, 0x1010)],
            _macho_stub_ranges=[(0x2000, 0x2010)],
        )

        first = X86Backend._getImportStubRanges(binary_info)
        second = X86Backend._getImportStubRanges(binary_info)

        self.assertIs(first, second)
        self.assertEqual(first, [(0x1000, 0x1010), (0x2000, 0x2010)])

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
        # xadd writes both operands too, even when the syscall register is only the
        # source (second) operand -- regression for the xadd/xchg dual-write class
        xadd_second = [self._ins("mov", "eax, 0x3c"), self._ins("xadd", "ebx, eax")]
        self.assertIsNone(disassembler._resolveSyscallNumber(xadd_second, 64))
        # xadd to an unrelated pair of registers does not clobber rax
        xadd_other = [self._ins("mov", "rax, 0x3c"), self._ins("xadd", "rbx, rcx")]
        self.assertEqual(disassembler._resolveSyscallNumber(xadd_other, 64), 60)
        # multi-operand imul to an unrelated register does not clobber rax
        imul_other = [self._ins("mov", "rax, 0x3c"), self._ins("imul", "rbx, rcx, 2")]
        self.assertEqual(disassembler._resolveSyscallNumber(imul_other, 64), 60)

    def _analyze(self, backend, mnemonic, op_str, preceding_ins, bitness=64):
        state = FunctionAnalysisState(0x1000, SimpleNamespace())
        state.current_block = preceding_ins
        d = SimpleNamespace(disassembly=SimpleNamespace(binary_info=SimpleNamespace(bitness=bitness)))
        i = self._ins(mnemonic, op_str, address=0x1010, size=2)
        backend.analyzeInstruction(d, i, state, previous_instruction=None, start_addr=0x1000)
        return state

    def test_exit_group_syscall_ends_function(self):
        backend = X86Backend()
        state = self._analyze(backend, "syscall", "", [self._ins("mov", "eax, 231")])
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)

    def test_int0x80_exit_and_exit_group_end_function(self):
        backend = X86Backend()
        for eax_value in (1, 252):
            state = self._analyze(backend, "int", "0x80", [self._ins("mov", f"eax, {eax_value}")])
            self.assertTrue(state.is_sanely_ending, f"eax={eax_value}")
            self.assertTrue(state.is_block_ending_instruction, f"eax={eax_value}")

    def test_int0x80_resolves_full_width_rax_write(self):
        # a 64-bit binary may still write the syscall number via the full "rax" spelling before
        # dropping into the 32-bit int 0x80 gate; backtracking must not drop "rax" from the
        # clobber set (that would silently walk past the real write and misresolve/miss the exit)
        backend = X86Backend()
        state = self._analyze(backend, "int", "0x80", [self._ins("mov", "rax, 1")])
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)

    def test_int0x80_truncates_wider_than_32bit_resolution(self):
        # int 0x80 only reads the low 32 bits (eax); a resolved value wider than that must
        # still be recognized by its low 32 bits, not compared against the raw wide integer
        backend = X86Backend()
        state = self._analyze(backend, "int", "0x80", [self._ins("mov", "rax, 0x100000001")])
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)

    def test_syscall_and_int0x80_other_numbers_do_not_end_function(self):
        backend = X86Backend()
        # syscall 39 (getpid) must not be treated as a program-ending syscall
        state = self._analyze(backend, "syscall", "", [self._ins("mov", "eax, 39")])
        self.assertFalse(state.is_sanely_ending)
        # int 0x80 with eax=4 (write) must not end the function
        state = self._analyze(backend, "int", "0x80", [self._ins("mov", "eax, 4")])
        self.assertFalse(state.is_sanely_ending)
        # other int vectors are unaffected (not treated as a syscall gate at all)
        state = self._analyze(backend, "int", "0x2e", [self._ins("mov", "eax, 1")])
        self.assertFalse(state.is_sanely_ending)

    def test_int0x80_exit_reports_the_program_end_at_debug_level(self):
        # the whole suite runs under a global logging.disable(), which suppresses records
        # regardless of logger level, so the debug arm needs that lifted rather than just a
        # level change - restore the previous value so later tests keep their quiet output
        backend = X86Backend()
        logger = logging.getLogger("smda.intel.X86Backend")
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        try:
            with self.assertLogs(logger, level=logging.DEBUG) as captured:
                state = self._analyze(backend, "int", "0x80", [self._ins("mov", "eax, 1")])
        finally:
            logging.disable(previous_disable)

        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(any("program ending instruction" in line for line in captured.output))

    def test_an_import_stub_of_pure_padding_resolves_to_no_slot(self):
        # endbr/nop are skipped while looking for the stub's jmp, so a window holding
        # nothing else runs the scan out of instructions with no slot to report
        binary_info = SimpleNamespace(_plt_ranges=[(0x1000, 0x1010)], _macho_stub_ranges=[])
        disassembler = SimpleNamespace(
            disassembly=SimpleNamespace(binary_info=binary_info),
            capstone=Cs(CS_ARCH_X86, CS_MODE_64),
            _getDisasmWindowBuffer=lambda addr: b"\xf3\x0f\x1e\xfa" + b"\x90" * 4,
        )

        self.assertIsNone(X86Backend._resolveImportSlot(disassembler, 0x1000))

    def _analyzeCallAlignmentCut(self, tail_bytes, lief_type="PE", bitness=64, candidate_addrs=None):
        # lays out: call rel32 @ call_addr; effective-NOP padding ("mov eax, eax" x5,
        # then a 1-byte "nop") up to the next 16-byte boundary (align_addr); tail_bytes
        # at align_addr. The padding must use a real-mnemonic effective NOP (not
        # int3/hlt) -- an int3 first byte would instead match analyzeInstruction()'s
        # earlier int3/hlt branch and never reach the call-alignment branch under test.
        # Mirrors the real analyzeInstruction() call site (RecursiveDisassembler.
        # _getDisasmWindowBuffer, capstone disasm_lite tuples) closely enough to
        # exercise the production alignment-cut branch in X86Backend.analyzeInstruction
        # end-to-end.
        base_addr = 0x400000
        call_addr = 0x401000
        pad_start = call_addr + 5
        align_addr = pad_start + (16 - pad_start % 16)

        data = bytearray(0x2000)
        rel_call = call_addr - base_addr
        data[rel_call : rel_call + 5] = b"\xe8\x00\x00\x00\x00"
        pad_len = align_addr - pad_start
        rel_pad = pad_start - base_addr
        padding = b"\x8b\xc0" * ((pad_len - 1) // 2) + b"\x90" * (pad_len - 2 * ((pad_len - 1) // 2))
        assert len(padding) == pad_len
        data[rel_pad : rel_pad + pad_len] = padding
        rel_tail = align_addr - base_addr
        data[rel_tail : rel_tail + len(tail_bytes)] = tail_bytes
        binary = bytes(data)

        binary_info = SimpleNamespace(bitness=bitness, base_addr=base_addr, binary=binary)
        binary_info._getLiefType = lambda: lief_type

        fc_manager = _RecordingCandidateManager(binary_info, bitness, candidate_addrs=candidate_addrs)
        capstone = Cs(CS_ARCH_X86, CS_MODE_64 if bitness == 64 else CS_MODE_32)

        def _get_window(addr):
            rel = addr - base_addr
            return binary[rel : rel + 15]

        d = SimpleNamespace(
            capstone=capstone,
            disassembly=SimpleNamespace(binary_info=binary_info, language_guess="msvc"),
            fc_manager=fc_manager,
            _getDisasmWindowBuffer=_get_window,
        )
        state = FunctionAnalysisState(call_addr, SimpleNamespace())
        previous_instruction = (call_addr, 5, "call", "0x407000")
        current_instruction = (pad_start, 2, "mov", "eax, eax")

        backend = X86Backend()
        result = backend.analyzeInstruction(
            d,
            current_instruction,
            state,
            previous_instruction=previous_instruction,
            start_addr=call_addr - 0x100,
        )
        return result, state, fc_manager, align_addr

    def test_pe_alignment_cut_not_taken_for_non_entry_shaped_seed(self):
        # "cmp eax, ebx" (0x39 0xd8) sitting at the 16-byte-aligned seed address is not
        # a recognized function prologue -- MSVC pads mid-function the same way it pads
        # between real functions, so alignment-only evidence must NOT split the function
        # here (root cause of the fixed bug: this used to cut unconditionally on PE).
        tail = b"\x39\xd8\xc3\x90\x90\x90\x90\x90\x90"
        result, state, fc_manager, _align_addr = self._analyzeCallAlignmentCut(tail)
        self.assertFalse(result)
        self.assertFalse(state.is_sanely_ending)
        self.assertFalse(state.is_block_ending_instruction)
        self.assertEqual(fc_manager.added_candidates, [])

    def test_pe_alignment_cut_still_taken_for_entry_shaped_seed(self):
        # "push rbx; sub rsp, 0x20" at the seed address IS a recognized common
        # prologue (COMMON_PROLOGUES["5"][64]) -- the cut must still happen; the fix
        # only gates alignment-only evidence, it doesn't disable the cut outright.
        tail = b"\x40\x53\x48\x83\xec\x20\x90\x90\x90"
        result, state, fc_manager, align_addr = self._analyzeCallAlignmentCut(tail)
        self.assertTrue(result)
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)
        self.assertEqual(fc_manager.added_candidates, [align_addr])

    def test_pe_alignment_cut_bypassed_by_candidate_evidence(self):
        # when the padding-start address is itself a tracked function candidate
        # (candidate evidence, not alignment-only evidence), the entry-shape gate is
        # bypassed entirely even though the seed address is not entry-shaped --
        # candidate evidence is already curated upstream and isn't re-validated here.
        tail = b"\x39\xd8\xc3\x90\x90\x90\x90\x90\x90"
        pad_start = 0x401005
        result, state, _fc_manager, _align_addr = self._analyzeCallAlignmentCut(tail, candidate_addrs=[pad_start])
        self.assertTrue(result)
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)

    def test_non_pe_alignment_cut_unaffected_by_entry_shape(self):
        # the same non-entry-shaped seed on a non-PE image (e.g. ELF) must still cut --
        # the entry-shape gate is PE-specific and must not affect other formats, which
        # legitimately pad between (not within) real functions with prologue-less starts.
        tail = b"\x39\xd8\xc3\x90\x90\x90\x90\x90\x90"
        result, state, fc_manager, align_addr = self._analyzeCallAlignmentCut(tail, lief_type="ELF")
        self.assertTrue(result)
        self.assertTrue(state.is_sanely_ending)
        self.assertTrue(state.is_block_ending_instruction)
        self.assertEqual(fc_manager.added_candidates, [align_addr])


class _StubChainCandidateManager(FunctionCandidateManager):
    """Drives locateStubChainCandidates without the init/queue machinery: the real block
    regexes, address arithmetic and data_map bookkeeping run, only candidate creation is
    recorded."""

    BASE_ADDR = 0x400000

    def __init__(self, binary):
        self.bitness = 64
        self._code_areas = []
        self.candidates = {}
        self.recovered = []
        self.disassembly = SimpleNamespace(
            binary_info=SimpleNamespace(binary=binary, base_addr=self.BASE_ADDR),
            data_map=set(),
        )

    def ensureCandidate(self, addr):
        self.recovered.append(addr)
        return True


class StubChainCandidateTestSuite(unittest.TestCase):
    PAD = b"\x00" * 16

    def _locate(self, chain):
        manager = _StubChainCandidateManager(self.PAD + chain + self.PAD)
        manager.locateStubChainCandidates()
        return manager

    def test_jmp_stub_chain_yields_one_candidate_per_entry(self):
        chain = b"\xff\x25\x11\x22\x33\x44" + b"\xff\x25\x55\x66\x77\x88"

        manager = self._locate(chain)

        base = _StubChainCandidateManager.BASE_ADDR + len(self.PAD)
        self.assertEqual([base, base + 6], manager.recovered)

    def test_plt_chain_yields_one_candidate_per_entry_and_marks_the_interleaved_bytes(self):
        entry = b"\xff\x25\x11\x22\x33\x44\x68\x00\x00\x00\x00\xe9\x00\x00\x00\x00"
        chain = entry + entry

        manager = self._locate(chain)

        base = _StubChainCandidateManager.BASE_ADDR + len(self.PAD)
        self.assertEqual([base, base + 16], manager.recovered)
        self.assertTrue(set(range(base + 6, base + 16)).issubset(manager.disassembly.data_map))

    def test_plt_sec_chain_yields_one_candidate_per_endbr64_guarded_entry(self):
        entry = b"\xf3\x0f\x1e\xfa\xf2\xff\x25\x11\x22\x33\x44\x0f\x1f\x44\x00\x00"
        chain = entry + entry

        manager = self._locate(chain)

        base = _StubChainCandidateManager.BASE_ADDR + len(self.PAD)
        self.assertEqual([base, base + 16], manager.recovered)
        self.assertTrue(set(range(base + 7, base + 12)).issubset(manager.disassembly.data_map))

    def test_a_lone_stub_is_not_a_chain(self):
        manager = self._locate(b"\xff\x25\x11\x22\x33\x44")

        self.assertEqual([], manager.recovered)


if __name__ == "__main__":
    unittest.main()
