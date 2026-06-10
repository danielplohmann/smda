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

    def test_accepts_missing_timeout_callback(self):
        binary_info = BinaryInfo(b"\x90\xc3")
        binary_info.base_addr = 0
        binary_info.bitness = 32
        binary_info.architecture = "intel"

        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)

        self.assertFalse(result.analysis_timeout)


if __name__ == "__main__":
    unittest.main()
