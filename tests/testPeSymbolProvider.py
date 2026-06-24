import unittest
from types import SimpleNamespace
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.WinApiResolver import WinApiResolver


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


class _MockExport:
    def __init__(self, name, address):
        self.name = name
        self.address = address


class _MockSection:
    def __init__(self, characteristics, virtual_address):
        self.characteristics = characteristics
        self.virtual_address = virtual_address


class _MockSymbol:
    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.complex_type = SimpleNamespace(name="FUNCTION")


class _MockPeBinary:
    def __init__(
        self,
        *,
        imports=None,
        exported_functions=None,
        sections=None,
        symbols=None,
        imagebase=0x140000000,
        addressof_entrypoint=0x1000,
    ):
        self.imports = imports or []
        self.exported_functions = exported_functions or []
        self.sections = sections or []
        self.symbols = symbols or []
        self.imagebase = imagebase
        self.optional_header = SimpleNamespace(addressof_entrypoint=addressof_entrypoint)


class TestPeSymbolProviderImports(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
