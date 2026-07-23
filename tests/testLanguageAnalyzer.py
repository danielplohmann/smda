import re
import unittest
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.LanguageAnalyzer import LanguageAnalyzer


class _DummyDisassembly:
    def __init__(self, binary, functions=None):
        self.binary_info = BinaryInfo(binary)
        self.functions = functions or {}

    def getRawBytes(self, start, size):
        return self.binary_info.binary[start : start + size]


class TestLanguageAnalyzer(unittest.TestCase):
    def test_identify_reuses_thiscall_pattern_counts(self):
        binary = b"\x00" * 0x80 + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" + b"\x00" * 8 + b"\x8b\xc8\xe8\x04\x05\x06\xff"
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions=dict.fromkeys(range(24))))
        original_findall = re.findall
        findall_calls = []

        def counting_findall(pattern, subject):
            findall_calls.append((pattern, subject))
            return original_findall(pattern, subject)

        with mock.patch("smda.common.LanguageAnalyzer.re.findall", side_effect=counting_findall):
            result = analyzer.identify()

        self.assertEqual(result["_count_thiscalls"], 2)
        self.assertEqual(result["c++"], 0.5)
        self.assertEqual(len(findall_calls), 2)
        self.assertEqual(len({call[0] for call in findall_calls}), 2)
        self.assertTrue(all(call[1] == binary for call in findall_calls))

    def test_identify_prefers_go_build_id_over_zero_function_cpp_artifact(self):
        # identify() runs at candidate-discovery time, before any function exists, so its
        # c++ score always divides by 1 (max(1, len(functions))) and is inflated to 1.0 by
        # even a single thiscall-shaped byte pattern. An exact "Go build ID" match must still
        # win the guess, or a real Go binary gets misclassified as c++ (defeating the
        # Go-specific alignment exception in X86Backend).
        binary = b'Go build ID: "abc123def456"' + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))

        result = analyzer.identify()

        self.assertGreater(result["go"], 0.5)
        self.assertEqual(result["c++"], 1)  # the pre-disassembly zero-function artifact
        self.assertEqual(result["_guess"], "go")

    def test_identify_prefers_rust_signature_over_zero_function_cpp_artifact(self):
        # same rationale as the Go case above: an unambiguous Rust marker string must win the
        # guess over the inflated pre-disassembly c++ score, or a real Rust binary gets
        # misclassified as c++.
        binary = b"RUST_MIN_STACK" + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))

        result = analyzer.identify()

        self.assertGreater(result["rust"], 0.5)
        self.assertEqual(result["c++"], 1)  # the pre-disassembly zero-function artifact
        self.assertEqual(result["_guess"], "rust")

    def test_rescore_renormalizes_cpp_score_and_guess_with_real_function_count(self):
        binary = b'Go build ID: "abc123def456"' + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))
        result = analyzer.identify()
        thiscall_count = result["_count_thiscalls"]

        rescored = analyzer.rescore(result, 100)

        self.assertEqual(rescored["c++"], min(1, 6.0 * thiscall_count / 100))
        self.assertLess(rescored["c++"], 1)
        self.assertEqual(rescored["_guess"], "go")

    def test_uses_bytes_for_pe_and_language_markers(self):
        binary = bytearray(b"MZ" + b"\x00" * 0x100)
        binary[0x3C:0x40] = (0x80).to_bytes(4, "little")
        binary[0x80:0x82] = b"PE"
        binary.extend(b"MSVBVM60.DLL\x00mscorelib.dll\x00Borland\\locales\x00")
        analyzer = LanguageAnalyzer(_DummyDisassembly(bytes(binary)))

        self.assertTrue(analyzer.validPEHeader())
        self.assertEqual(analyzer.getVisualBasicScore(), 0.5)
        self.assertGreaterEqual(analyzer.getDotNetScore(), 0.35)
        self.assertEqual(analyzer.getDelphiScore(), 0.5)


if __name__ == "__main__":
    unittest.main()
