import unittest
from types import SimpleNamespace
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.LanguageAnalyzer import LanguageAnalyzer


class _DummyDisassembly:
    def __init__(self, binary, functions=None):
        self.binary_info = BinaryInfo(binary)
        self.functions = functions or {}

    def getRawBytes(self, start, size):
        return self.binary_info.binary[start : start + size]


class _MalformedSymbolListBinary:
    exported_functions = []
    exported_symbols = []
    symtab_symbols = []
    symbols = []

    @property
    def dynamic_symbols(self):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


class _MalformedImportedLibrariesBinary:
    @property
    def imported_libraries(self):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


class _MalformedLibraryName:
    def lower(self):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


class TestLanguageAnalyzer(unittest.TestCase):
    def test_identify_prefers_cpp_itanium_symbols_over_generic_c_asm(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        binary = SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[
                SimpleNamespace(name="_Z3foov"),
                SimpleNamespace(name="_ZN1AC1Ev"),
                SimpleNamespace(name="_ZTV1A"),
            ],
        )
        analyzer.disassembly.binary_info.getLiefBinary = lambda: binary

        result = analyzer.identify()

        self.assertEqual(analyzer._cpp_symbol_count, 3)
        self.assertEqual(result["c++"], 0.8)
        self.assertEqual(result["rust"], 0.0)
        self.assertEqual(analyzer.getGuess(), "c++")
        self.assertTrue(all(isinstance(score, float) for score in result.values()))

    def test_identify_recognizes_non_rust_itanium_nested_names(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        binary = SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[
                SimpleNamespace(name="_ZN3foo3barE"),
                SimpleNamespace(name="_ZN3foo3bazEv"),
                SimpleNamespace(name="_ZN3foo3quxEi"),
            ],
        )
        analyzer.disassembly.binary_info.getLiefBinary = lambda: binary

        result = analyzer.identify()

        self.assertEqual(result["c++"], 0.8)
        self.assertEqual(result["rust"], 0.0)

    def test_identify_recognizes_documented_msvc_cpp_decorated_symbols(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        binary = SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[],
            symbols=[
                SimpleNamespace(name="?a@@YAHD@Z"),
                SimpleNamespace(name="?c@b@@AAGXM@Z"),
                SimpleNamespace(name="?test@@YAXXZ"),
            ],
        )
        analyzer.disassembly.binary_info.getLiefBinary = lambda: binary

        result = analyzer.identify()

        self.assertEqual(analyzer._cpp_symbol_count, 3)
        self.assertEqual(result["c++"], 0.8)
        self.assertEqual(analyzer.getGuess(), "c++")

    def test_identify_recognizes_msvc_decorated_data_symbols(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[],
            symbols=[
                SimpleNamespace(name="?value@Cls@@2HA"),
                SimpleNamespace(name="?counter@ns@@3HA"),
                SimpleNamespace(name="?table@@3PAHA"),
            ],
        )

        self.assertEqual(analyzer.identify()["c++"], 0.8)

    def test_cpp_symbol_scan_stops_once_the_score_saturates(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        names = [f"_Z{len(f'foo{index}')}foo{index}v" for index in range(50)]
        analyzer.disassembly.binary_info.getLiefBinary = lambda: SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[SimpleNamespace(name=name) for name in names],
        )

        score, count = analyzer.getCppSymbolScore()

        self.assertEqual((score, count), (0.8, LanguageAnalyzer.CPP_SYMBOL_EVIDENCE_THRESHOLD))

    def test_identify_scores_single_validated_cpp_symbol_as_weak_evidence(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[SimpleNamespace(name="_Z3foov")],
        )

        result = analyzer.identify()

        self.assertEqual(analyzer._cpp_symbol_count, 1)
        self.assertEqual(result["c++"], 0.4)
        self.assertEqual(analyzer.getGuess(), "c++")

    def test_cpp_symbol_scoring_skips_malformed_lief_symbol_lists(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: _MalformedSymbolListBinary()

        result = analyzer.identify()

        self.assertEqual(result["c++"], 0.0)
        self.assertEqual(analyzer.getGuess(), "c/asm")

    def test_visualbasic_import_outweighs_a_string_only_reference(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"MSVBVM60.DLL", functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: SimpleNamespace(imported_libraries=["MSVBVM60.DLL"])

        self.assertEqual(analyzer.getVisualBasicScore(), 0.9)

    def test_visualbasic_score_falls_back_when_imported_libraries_are_malformed(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"MSVBVM60.DLL", functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: _MalformedImportedLibrariesBinary()

        self.assertEqual(analyzer.getVisualBasicScore(), 0.2)

    def test_visualbasic_score_skips_a_malformed_library_name(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"", functions={}))
        analyzer.disassembly.binary_info.getLiefBinary = lambda: SimpleNamespace(
            imported_libraries=[_MalformedLibraryName(), "MSVBVM60.DLL"]
        )

        self.assertEqual(analyzer.getVisualBasicScore(), 0.9)

    def test_cpp_symbol_scoring_selects_the_active_macho_slice(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        analyzer.disassembly.binary_info.bitness = 64
        analyzer.disassembly.binary_info.architecture = "aarch64"
        fat_binary = object()
        macho_slice = SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[],
            dynamic_symbols=[
                SimpleNamespace(name="__Z3foov"),
                SimpleNamespace(name="__ZN1AC1Ev"),
                SimpleNamespace(name="__ZTV1A"),
            ],
        )
        analyzer.disassembly.binary_info.getLiefBinary = lambda: fat_binary

        with mock.patch(
            "smda.common.LanguageAnalyzer.get_active_macho_binary",
            return_value=macho_slice,
        ) as select_active:
            score, count = analyzer.getCppSymbolScore()

        self.assertEqual((score, count), (0.8, 3))
        select_active.assert_called_once_with(fat_binary, bitness=64, architecture="aarch64")

    def test_validated_go_pclntab_outweighs_a_build_id_string(self):
        pclntab = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
        analyzer = LanguageAnalyzer(_DummyDisassembly(pclntab, functions={}))

        result = analyzer.identify()

        self.assertEqual(result["go"], 0.9)
        self.assertEqual(analyzer.getGuess(), "go")

    def test_identify_exports_only_language_scores_and_merges_delphi_kb_score(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))

        with mock.patch.object(analyzer, "getDelphiKbScore", return_value=1.0):
            result = analyzer.identify()

        self.assertEqual(
            set(result),
            {"c/asm", "delphi", ".net", "visualbasic", "go", "rust", "c++"},
        )
        self.assertEqual(result["delphi"], 1.0)
        self.assertTrue(all(isinstance(score, float) for score in result.values()))

    def test_identify_does_not_treat_thiscall_patterns_as_cpp_language_evidence(self):
        binary = b"\x00" * 0x80 + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" + b"\x00" * 8 + b"\x8b\xc8\xe8\x04\x05\x06\xff"
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions=dict.fromkeys(range(24))))
        result = analyzer.identify()

        self.assertEqual(result["c++"], 0.0)
        self.assertEqual(analyzer.getGuess(), "c/asm")

    def test_identify_prefers_go_build_id_over_non_language_instruction_patterns(self):
        binary = b'Go build ID: "abc123def456"' + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))

        result = analyzer.identify()

        self.assertGreater(result["go"], 0.5)
        self.assertEqual(result["c++"], 0.0)
        self.assertEqual(analyzer.getGuess(), "go")

    def test_identify_prefers_rust_signature_over_non_language_instruction_patterns(self):
        binary = b"RUST_MIN_STACK" + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))

        result = analyzer.identify()

        self.assertGreater(result["rust"], 0.5)
        self.assertEqual(result["c++"], 0.0)
        self.assertEqual(analyzer.getGuess(), "rust")

    def test_rescore_keeps_symbol_based_cpp_score_independent_of_function_count(self):
        binary = b'Go build ID: "abc123def456"' + b"\x8b\x4d\x04\xe8\x01\x02\x03\x00" * 3
        analyzer = LanguageAnalyzer(_DummyDisassembly(binary, functions={}))
        result = analyzer.identify()
        rescored = analyzer.rescore(result, 100)

        self.assertEqual(rescored["c++"], 0.0)
        self.assertEqual(analyzer.getGuess(), "go")

    def test_uses_bytes_for_pe_and_language_markers(self):
        binary = bytearray(b"MZ" + b"\x00" * 0x100)
        binary[0x3C:0x40] = (0x80).to_bytes(4, "little")
        binary[0x80:0x82] = b"PE"
        binary.extend(b"MSVBVM60.DLL\x00mscorelib.dll\x00Borland\\locales\x00")
        analyzer = LanguageAnalyzer(_DummyDisassembly(bytes(binary)))

        self.assertTrue(analyzer.validPEHeader())
        self.assertEqual(analyzer.getVisualBasicScore(), 0.2)
        self.assertGreaterEqual(analyzer.getDotNetScore(), 0.35)
        self.assertEqual(analyzer.getDelphiScore(), 0.25)

    def test_delphi_string_table_is_only_weak_language_evidence(self):
        delphi_string = b"\x00\x00\x01\x06ABCDEF\x00"
        analyzer = LanguageAnalyzer(_DummyDisassembly(delphi_string * 101))

        self.assertEqual(analyzer.getDelphiScore(), 0.35)

    def test_validated_delphi_objects_are_structural_language_evidence(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"TObject"))

        with mock.patch.object(analyzer, "getDelphiObjects", return_value={0x1000: "TObject"}):
            self.assertEqual(analyzer.getDelphiScore(), 0.6)

        analyzer = LanguageAnalyzer(_DummyDisassembly(b"TObject"))
        with mock.patch.object(
            analyzer,
            "getDelphiObjects",
            return_value={address: f"TObject{address}" for address in range(5)},
        ):
            self.assertEqual(analyzer.getDelphiScore(), 0.9)


class TestLanguageEvidenceMemoization(unittest.TestCase):
    def test_delphi_score_is_stable_between_identify_and_check_delphi(self):
        delphi_string = b"\x00\x00\x01\x0aABCDEFGHIJ\x00"
        analyzer = LanguageAnalyzer(_DummyDisassembly(delphi_string * 101))

        identified = analyzer.identify()

        self.assertEqual(analyzer.getDelphiScore(), identified["delphi"])
        self.assertEqual(analyzer.checkDelphi(), identified["delphi"] > 0.5)

    def test_cpp_symbol_score_is_stable_between_identify_and_rescore(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32, functions={}))
        binary = SimpleNamespace(
            exported_functions=[],
            exported_symbols=[],
            symtab_symbols=[SimpleNamespace(name=f"_ZN4test{index}barEv") for index in range(3)],
            dynamic_symbols=[],
            symbols=[],
        )
        with (
            mock.patch.object(analyzer.disassembly.binary_info, "getLiefBinary", return_value=binary),
            mock.patch("smda.common.LanguageAnalyzer.get_active_macho_binary", return_value=binary),
        ):
            identified = analyzer.identify()
            rescored = analyzer.rescore(dict(identified), 100)

        self.assertEqual(rescored["c++"], identified["c++"])
        self.assertEqual(analyzer.getCppSymbolScore()[0], identified["c++"])

    def test_empty_string_scan_is_not_repeated(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00" * 32))

        self.assertEqual(analyzer.getStrings(), [])
        self.assertIs(analyzer.getStrings(), analyzer.strings)


class TestDelphiHeuristics(unittest.TestCase):
    def test_real_world_locales_registry_key_is_delphi_evidence(self):
        analyzer = LanguageAnalyzer(_DummyDisassembly(b"\x00Software\\Borland\\Locales\x00"))

        self.assertEqual(analyzer.getDelphiScore(), 0.25)

    def test_delphi_string_table_counts_a_newline_length_byte(self):
        delphi_string = b"\x00\x00\x01\x0aABCDEFGHIJ\x00"
        analyzer = LanguageAnalyzer(_DummyDisassembly(delphi_string * 101))

        self.assertEqual(analyzer.getDelphiScore(), 0.35)


if __name__ == "__main__":
    unittest.main()
