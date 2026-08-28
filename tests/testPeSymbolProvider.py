import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import lief
import pytest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


class _MockImportEntry:
    def __init__(self, name, iat_address, *, is_ordinal=False, ordinal=0):
        self.name = name
        self.iat_address = iat_address
        self.is_ordinal = is_ordinal
        self.ordinal = ordinal


class _MockImportLibrary:
    def __init__(self, name, entries):
        self.name = name
        self.entries = entries


class _MockDelayImportEntry:
    def __init__(self, name, *, is_ordinal=False, ordinal=0):
        self.name = name
        self.is_ordinal = is_ordinal
        self.ordinal = ordinal


class _MockDelayImport:
    def __init__(self, name, iat, entries):
        self.name = name
        self.iat = iat
        self.entries = entries


class _MockExport:
    def __init__(self, name, address, *, is_extern=False, is_forwarded=False):
        self.name = name
        self.address = address
        self.is_extern = is_extern
        self.is_forwarded = is_forwarded


class _MockSection:
    def __init__(self, characteristics, virtual_address):
        self.characteristics = characteristics
        self.virtual_address = virtual_address


class _MockSymbol:
    """Models what lief actually hands back for a PE COFF symbol.

    Symbol.section is None for every PE symbol on both 0.17 and 1.0, and the section is
    identified by the 1-based section_idx instead; 0, -1 and -2 mean undefined-external,
    absolute and debug. The earlier stub gave every symbol a real section object, which is
    why the suite stayed green while the provider recovered nothing from a real binary.
    """

    def __init__(self, name, value, *, section_idx=1):
        self.name = name
        self.value = value
        self.complex_type = SimpleNamespace(name="FUNCTION")
        self.section = None
        self.section_idx = section_idx


class _MockPeBinary:
    def __init__(
        self,
        *,
        imports=None,
        exported_functions=None,
        sections=None,
        symbols=None,
        delay_imports=None,
        imagebase=0x140000000,
        addressof_entrypoint=0x1000,
    ):
        self.imports = imports or []
        self.exported_functions = exported_functions or []
        self.sections = sections or []
        self.symbols = symbols or []
        self.imagebase = imagebase
        self.optional_header = SimpleNamespace(addressof_entrypoint=addressof_entrypoint)
        self.delay_imports = delay_imports or []
        self.has_delay_imports = bool(self.delay_imports)
        self.has_imports = bool(self.imports)

    def get_export(self):
        if not self.exported_functions:
            return None
        return SimpleNamespace(entries=self.exported_functions)


class TestPeSymbolProviderImports(unittest.TestCase):
    def test_win_api_resolver_searches_all_configured_dump_databases(self):
        cached_databases = {
            "/first.json": (
                {
                    0x1000: ("first.dll", "FirstApi"),
                    0x3000: ("first.dll", "SharedAddress"),
                },
                False,
            ),
            "/second.json": (
                {
                    0x2000: ("second.dll", "SecondApi"),
                    0x3000: ("second.dll", "SharedAddress"),
                },
                False,
            ),
        }
        config = SimpleNamespace(API_COLLECTION_FILES={"first": "/first.json", "second": "/second.json"})
        with mock.patch.object(WinApiResolver, "_db_cache", cached_databases):
            resolver = WinApiResolver(config)
        resolver.update(SimpleNamespace(is_buffer=True))

        self.assertIsNone(resolver._os_name)
        self.assertEqual(resolver.getApi(0, 0x1000), ("first.dll", "FirstApi"))
        self.assertEqual(resolver.getApi(0, 0x2000), ("second.dll", "SecondApi"))
        self.assertEqual(resolver.getApi(0, 0x3000), ("first.dll", "SharedAddress"))

        resolver.setOsName("second")
        self.assertEqual(resolver.getApi(0, 0x1000), (None, None))
        self.assertEqual(resolver.getApi(0, 0x3000), ("second.dll", "SharedAddress"))

    def test_resolve_os_name_keeps_an_already_pinned_name(self):
        resolver = WinApiResolver(SimpleNamespace(API_COLLECTION_FILES={}))
        resolver.setOsName("pinned")
        resolver._resolveOsName()
        self.assertEqual(resolver._os_name, "pinned")

    def test_win_api_resolver_defers_parsing_uncached_databases(self):
        api_db = {
            "os_name": "testos",
            "dlls": {
                "0000_test_testdll.dll": {
                    "bitness": 32,
                    "base_address": 0x70000000,
                    "exports": [{"name": "TestApi", "address": 0x1000, "ordinal": 1}],
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "apiscout_testos.json")
            with open(db_path, "w", encoding="utf-8") as f_json:
                json.dump(api_db, f_json)
            config = SimpleNamespace(API_COLLECTION_FILES={"testos": db_path})
            resolver = WinApiResolver(config)

            # an uncached database is only parsed once an API lookup needs it
            self.assertEqual(list(resolver._api_map.keys()), ["lief"])
            self.assertIsNone(resolver._os_name)
            self.assertEqual(resolver._deferred_dbs, [("testos", db_path)])

            resolver.update(SimpleNamespace(is_buffer=True))
            self.assertEqual(resolver.getApi(0, 0x70001000), ("testdll.dll", "TestApi"))
            self.assertEqual(resolver._os_name, "testos")
            self.assertIsNone(resolver._deferred_dbs)

    def test_win_api_resolver_keeps_an_explicit_os_name_across_deferred_loading(self):
        api_db = {
            "os_name": "present",
            "dlls": {
                "0000_test_presentdll.dll": {
                    "bitness": 32,
                    "base_address": 0x70000000,
                    "exports": [{"name": "PresentApi", "address": 0x1000, "ordinal": 1}],
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "apiscout_present.json")
            with open(db_path, "w", encoding="utf-8") as f_json:
                json.dump(api_db, f_json)
            config = SimpleNamespace(
                API_COLLECTION_FILES={"present": db_path, "absent": os.path.join(tmp_dir, "missing.json")}
            )
            resolver = WinApiResolver(config)
            resolver.setOsName("absent")
            resolver.update(SimpleNamespace(is_buffer=True))

            # only one of the two databases loads, but the caller pinned the other one
            self.assertEqual(resolver.getApi(0, 0x70001000), (None, None))
            self.assertEqual(resolver._os_name, "absent")

    def test_parse_imports_uses_active_base_addr_not_imagebase(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("CreateFileW", 0x3000)])],
            imagebase=0x140000000,
        )
        imports = provider.parseImports(pe_binary, base_addr=0x400000)
        self.assertEqual(imports, {0x403000: ("kernel32.dll", "CreateFileW")})
        self.assertNotIn(0x140003000, imports)

    def test_parse_imports_defaults_to_imagebase(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("ExitProcess", 0x2000)])],
            imagebase=0x140000000,
        )
        imports = provider.parseImports(pe_binary)
        self.assertEqual(imports, {0x140002000: ("kernel32.dll", "ExitProcess")})

    def test_parse_imports_preserves_explicit_zero_base_addr(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("ExitProcess", 0x2000)])],
            imagebase=0x140000000,
        )
        imports = provider.parseImports(pe_binary, base_addr=0)
        self.assertEqual(imports, {0x2000: ("kernel32.dll", "ExitProcess")})
        self.assertNotIn(0x140002000, imports)

    def test_win_api_resolver_matches_parse_imports(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("CreateFileW", 0x3000)])],
            imagebase=0x140000000,
        )
        expected = provider.parseImports(pe_binary, base_addr=0x400000)

        resolver = WinApiResolver(SimpleNamespace(API_COLLECTION_FILES={}))
        with mock.patch("lief.PE.Binary", _MockPeBinary):
            resolver.update(
                SimpleNamespace(
                    is_buffer=False,
                    base_addr=0x400000,
                    getLiefBinary=lambda: pe_binary,
                )
            )
        self.assertEqual(resolver._api_map["lief"], expected)

    def test_parse_imports_includes_delay_imports(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("CreateFileW", 0x3000)])],
            delay_imports=[
                _MockDelayImport(
                    "PSAPI.DLL",
                    0x4000,
                    [_MockDelayImportEntry("GetMappedFileNameA"), _MockDelayImportEntry("EnumProcessModules")],
                )
            ],
            imagebase=0x140000000,
        )
        imports = provider.parseImports(pe_binary, base_addr=0x400000)
        self.assertEqual(imports[0x403000], ("kernel32.dll", "CreateFileW"))
        self.assertEqual(imports[0x404000], ("psapi.dll", "GetMappedFileNameA"))
        self.assertEqual(imports[0x404004], ("psapi.dll", "EnumProcessModules"))

    def test_parse_imports_resolves_delay_import_ordinals(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            delay_imports=[
                _MockDelayImport("SHELL32.dll", 0x5000, [_MockDelayImportEntry(None, is_ordinal=True, ordinal=123)])
            ],
            imagebase=0x140000000,
        )
        imports = provider.parseImports(pe_binary, base_addr=0x400000)
        self.assertEqual(imports[0x405000], ("shell32.dll", "#123"))

    def test_win_api_resolver_includes_delay_imports(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("CreateFileW", 0x3000)])],
            delay_imports=[_MockDelayImport("PSAPI.DLL", 0x4000, [_MockDelayImportEntry("GetMappedFileNameA")])],
            imagebase=0x140000000,
        )
        expected = provider.parseImports(pe_binary, base_addr=0x400000)

        resolver = WinApiResolver(SimpleNamespace(API_COLLECTION_FILES={}))
        with mock.patch("lief.PE.Binary", _MockPeBinary):
            resolver.update(
                SimpleNamespace(
                    is_buffer=False,
                    base_addr=0x400000,
                    getLiefBinary=lambda: pe_binary,
                )
            )
        self.assertEqual(resolver._api_map["lief"], expected)


class TestPeSymbolProviderMetadata(unittest.TestCase):
    def test_collect_symbols_merges_exports_and_coff_symbols(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            exported_functions=[_MockExport("exported_func", 0x1000)],
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("local_func", 0x200)],
            imagebase=0x140000000,
        )
        symbols = provider.collectSymbols(pe_binary, base_addr=0x400000)
        self.assertEqual(symbols[0x401000], "exported_func")
        self.assertEqual(symbols[0x401200], "local_func")

    def test_collect_symbols_preserves_explicit_zero_base_addr(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            exported_functions=[_MockExport("exported_func", 0x1000)],
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("local_func", 0x200)],
            imagebase=0x140000000,
        )
        symbols = provider.collectSymbols(pe_binary, base_addr=0)
        self.assertEqual(symbols[0x1000], "exported_func")
        self.assertEqual(symbols[0x1200], "local_func")
        self.assertNotIn(0x140001000, symbols)

    def test_parse_oep_uses_base_addr_plus_rva(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(imagebase=0x140000000, addressof_entrypoint=0x1730)
        provider._parseOep(pe_binary, base_addr=0x400000)
        self.assertEqual(provider.getFunctionSymbols()[0x401730], "original_entry_point")

    def test_binary_info_pe_imported_functions_use_base_addr(self):
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("ExitProcess", 0x2000)])],
            imagebase=0x140000000,
        )
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=pe_binary),
            mock.patch("lief.PE.Binary", _MockPeBinary),
        ):
            imported = binary_info.getImportedFunctions()
        self.assertEqual(imported, {0x402000: ("kernel32.dll", "ExitProcess")})

    def test_imported_functions_keep_msvc_decorated_names(self):
        decorated = "?compute@Solver@@QEAAHH@Z"
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("solver.dll", [_MockImportEntry(decorated, 0x2000)])],
            imagebase=0x140000000,
        )
        provider = PeSymbolProvider(None)
        self.assertEqual(provider.parseImports(pe_binary, base_addr=0x400000), {0x402000: ("solver.dll", decorated)})

        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=pe_binary),
            mock.patch("lief.PE.Binary", _MockPeBinary),
        ):
            imported = binary_info.getImportedFunctions()
        self.assertEqual(imported, {0x402000: ("solver.dll", decorated)})

    def test_rebased_dump_xmetadata_and_api_parity(self):
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("CreateFileW", 0x3000)])],
            exported_functions=[_MockExport("exported_func", 0x1000)],
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("local_func", 0x200)],
            imagebase=0x140000000,
        )
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        resolver = WinApiResolver(SimpleNamespace(API_COLLECTION_FILES={}))
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=pe_binary),
            mock.patch("lief.PE.Binary", _MockPeBinary),
        ):
            exported = binary_info.getExportedFunctions()
            imported = binary_info.getImportedFunctions()
            symbols = binary_info.getSymbols()
            resolver.update(binary_info)

        self.assertEqual(exported, {0x401000: "exported_func"})
        self.assertEqual(imported, {0x403000: ("kernel32.dll", "CreateFileW")})
        self.assertEqual(symbols[0x401000], "exported_func")
        self.assertEqual(symbols[0x401200], "local_func")
        self.assertNotIn(0x140001000, exported)
        self.assertNotIn(0x140003000, imported)
        self.assertEqual(resolver._api_map["lief"], imported)

    def test_binary_info_pe_symbols_merge_exports_and_coff(self):
        pe_binary = _MockPeBinary(
            exported_functions=[_MockExport("exported_func", 0x1000)],
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("local_func", 0x200)],
            imagebase=0x140000000,
        )
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=pe_binary),
            mock.patch("lief.PE.Binary", _MockPeBinary),
        ):
            symbols = binary_info.getSymbols()
        self.assertEqual(symbols[0x401000], "exported_func")
        self.assertEqual(symbols[0x401200], "local_func")

    def test_parse_exports_skips_forwarded_and_extern_entries(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            exported_functions=[
                _MockExport("real_func", 0x1000),
                _MockExport("forwarded_func", 0, is_forwarded=True),
                _MockExport("extern_func", 0, is_extern=True),
            ],
            imagebase=0x140000000,
        )
        symbols = provider.parseExports(pe_binary, base_addr=0x400000)
        self.assertEqual(symbols, {0x401000: "real_func"})

    def test_parse_symbols_skips_entries_with_an_out_of_range_section_idx(self):
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[
                _MockSymbol("local_func", 0x200),
                _MockSymbol("undefined_func", 0, section_idx=0),
            ],
            imagebase=0x140000000,
        )
        symbols = provider.parseSymbols(pe_binary, base_addr=0x400000)
        self.assertEqual(symbols, {0x401200: "local_func"})

    def test_parse_symbols_resolves_a_symbol_whose_section_is_none(self):
        # danielplohmann/smda#229: lief leaves Symbol.section None for every PE symbol, so a
        # provider keyed on it recovers nothing from a binary carrying a full COFF symtab
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            sections=[_MockSection(0x20000000, 0x1000), _MockSection(0x40000000, 0x5000)],
            symbols=[
                _MockSymbol("first_section_func", 0x200, section_idx=1),
                _MockSymbol("second_section_func", 0x30, section_idx=2),
            ],
            imagebase=0x140000000,
        )
        self.assertTrue(all(symbol.section is None for symbol in pe_binary.symbols))

        symbols = provider.parseSymbols(pe_binary, base_addr=0x400000)

        self.assertEqual({0x401200: "first_section_func", 0x405030: "second_section_func"}, symbols)

    def test_parse_symbols_warns_when_a_populated_symtab_yields_nothing(self):
        # the failure this replaces was silent, so a corpus could be built entirely unnamed
        provider = PeSymbolProvider(None)
        pe_binary = _MockPeBinary(
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("undefined_func", 0, section_idx=0)],
            imagebase=0x140000000,
        )
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this test only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

        with self.assertLogs("smda.common.labelprovider.PeSymbolProvider", level="WARNING") as logged:
            self.assertEqual({}, provider.parseSymbols(pe_binary, base_addr=0x400000))
        self.assertIn("1 function symbols", logged.output[0])


@pytest.mark.slow
class TestPeCoffSymbolFixture(unittest.TestCase):
    """danielplohmann/smda#229, against a PE that really carries a COFF symbol table.

    None of the other bundled PEs has one - cutwail is packed, njrat is .NET, and
    pe_export_label_test is a stub - which is why a provider recovering nothing from a full
    symtab went unnoticed. The fixture is a Rust hello-world built for
    x86_64-pc-windows-gnu and linked by mingw-w64, so it is our own build rather than a
    sample: rustc 1.97.1, release, debuginfo=2.
    """

    @classmethod
    def setUpClass(cls):
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rust_pe_gnu_xored")
        raw = Path(fixture).read_bytes()
        cls.binary = bytes(byte ^ (index % 256) for index, byte in enumerate(raw))
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as handle:
            handle.write(cls.binary)
            cls.path = handle.name
        cls.report = Disassembler(SmdaConfig()).disassembleFile(cls.path)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def test_lief_leaves_every_pe_symbol_without_a_section(self):
        # the contract the fix rests on: resolve through section_idx, never through section
        lief_binary = lief.parse(self.path)
        symbols = list(lief_binary.symbols)

        self.assertGreater(len(symbols), 1000)
        self.assertTrue(all(symbol.section is None for symbol in symbols))
        self.assertTrue(any(1 <= symbol.section_idx <= len(list(lief_binary.sections)) for symbol in symbols))

    def test_names_are_recovered_from_the_coff_symbol_table(self):
        functions = list(self.report.getFunctions())
        named = [f for f in functions if f.function_name and not f.function_name.startswith("sub_")]

        # before the fix this recovered exactly one name, original_entry_point, from the OEP
        # handling rather than from the symbol table
        self.assertGreater(len(named), 1000)
        self.assertGreater(len(named) / len(functions), 0.75)

    def test_a_known_mingw_entry_point_is_named(self):
        names = {f.function_name for f in self.report.getFunctions()}

        self.assertIn("mainCRTStartup", names)
        self.assertIn("__tmainCRTStartup", names)

    def test_rust_names_reach_the_report_demangled(self):
        names = {f.function_name for f in self.report.getFunctions() if f.function_name}

        # RustSymbolProvider resolved PE COFF symbols through Symbol.section, which lief
        # never populates, so it contributed nothing and these arrived spelled "_RNv..."
        self.assertEqual([name for name in names if name.startswith(("_R", "__R"))], [])
        self.assertIn("std::rt::lang_start::<()>::{closure#0}", names)


class TestPeCxxSymbolFixture(unittest.TestCase):
    """A PE whose COFF symbol table carries Itanium C++ names.

    None of the other bundled PEs has any: the Rust fixture's names are all Rust-mangled,
    and the rest carry no symbol table at all. Built here rather than sampled - a small C++
    translation unit compiled for x86_64-w64-mingw32 by g++ 16.2.0 at -O1 -g.
    """

    @classmethod
    def setUpClass(cls):
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cxx_pe_gnu_xored")
        raw = Path(fixture).read_bytes()
        binary = bytes(byte ^ (index % 256) for index, byte in enumerate(raw))
        binary_info = BinaryInfo(binary)
        binary_info.file_path = ""
        binary_info.base_addr = 0x140000000
        provider = PeSymbolProvider(None)
        provider.update(binary_info)
        cls.symbols = provider.getFunctionSymbols()

    def _symbols(self):
        return self.symbols

    def test_itanium_cxx_names_are_demangled(self):
        names = set(self._symbols().values())

        self.assertEqual([name for name in names if name.startswith(("_Z", "__Z"))], [])
        self.assertIn("demo::Widget::Widget()", names)
        self.assertIn("demo::Widget::~Widget()", names)

    def test_a_rust_name_would_be_left_to_the_rust_provider(self):
        # the two providers partition the namespace: this one expands Itanium C++, and a
        # name the Rust evidence gate claims is not its to rewrite
        provider = RustSymbolProvider(None)

        self.assertFalse(provider._is_rust_symbol("_ZN12FileExplorerC2Ev"))
        self.assertTrue(provider._is_rust_symbol("_RNvC6_123foo3bar"))

    def test_a_signature_with_arguments_is_expanded(self):
        measure = [name for name in self._symbols().values() if "measure" in name]

        self.assertEqual(len(measure), 1)
        self.assertIn("demo::Widget::measure(", measure[0])
        self.assertIn("double) const", measure[0])


class TestPeMsvcSymbolFixture(unittest.TestCase):
    """The MSVC arm of the dispatch, on a PE that really carries decorated names.

    tests/msvc_cxx_pe_xored is a small C++ translation unit built for
    x86_64-pc-windows-msvc by clang-cl 22.1.7, exporting free functions, a namespace, a
    class returned by value and one extern "C" name.
    """

    @classmethod
    def setUpClass(cls):
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "msvc_cxx_pe_xored")
        raw = Path(fixture).read_bytes()
        binary = bytes(byte ^ (index % 256) for index, byte in enumerate(raw))
        binary_info = BinaryInfo(binary)
        binary_info.file_path = ""
        binary_info.base_addr = 0x180000000
        provider = PeSymbolProvider(None)
        provider.update(binary_info)
        cls.symbols = provider.getFunctionSymbols()

    def test_no_exported_name_is_left_decorated(self):
        self.assertEqual([name for name in self.symbols.values() if name.startswith("?")], [])

    def test_a_namespaced_signature_is_expanded(self):
        names = set(self.symbols.values())

        self.assertIn("double __cdecl geometry::dot(struct Matrix const &, struct Matrix const &)", names)
        self.assertIn("int __cdecl geometry::classify(struct Matrix const *, char, bool)", names)

    def test_a_class_returned_by_value_keeps_its_return_type(self):
        names = set(self.symbols.values())

        self.assertIn(
            "struct Matrix __cdecl geometry::combine(struct Matrix const &, double, unsigned int)",
            names,
        )

    def test_an_undecorated_name_is_left_alone(self):
        self.assertIn("c_linkage", set(self.symbols.values()))


if __name__ == "__main__":
    unittest.main()
