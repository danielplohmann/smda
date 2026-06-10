import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
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


if __name__ == "__main__":
    unittest.main()
