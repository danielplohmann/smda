import unittest
from types import SimpleNamespace
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.ItaniumDemangler import demangle_itanium_symbol


class _MockExport:
    def __init__(self, name, address):
        self.name = name
        self.address = address


class _MockSymbol:
    def __init__(self, name, value=0, is_function=True, imported=False, shndx=None, demangled_name=None):
        self.name = name
        self.demangled_name = demangled_name
        self.value = value
        self.is_function = is_function
        self.imported = imported
        self.shndx = shndx
        self.has_version = False


class _MalformedNameSymbol:
    def __init__(self, *, address=0, value=0, imported=False, is_function=True, shndx=0):
        self.address = address
        self.value = value
        self.imported = imported
        self.is_function = is_function
        self.shndx = shndx
        self.has_version = False

    @property
    def name(self):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


class _MockReloc:
    def __init__(self, address, symbol):
        self.address = address
        self.symbol = symbol
        self.has_symbol = symbol is not None


class _MockElfBinary:
    def __init__(self, *, exported_functions, symtab_symbols, dynamic_symbols, relocations, entrypoint):
        self.header = SimpleNamespace(entrypoint=entrypoint)
        self.exported_functions = exported_functions
        self.symtab_symbols = symtab_symbols
        self.dynamic_symbols = dynamic_symbols
        self.relocations = relocations


def _binary_info(mock_binary):
    return SimpleNamespace(is_buffer=False, getLiefBinary=lambda: mock_binary)


# An imported API (printf) is reachable two ways: as an undefined dynamic symbol (value 0)
# and as a relocation against its GOT slot at 0x4000. Local/exported functions live in .text.
IMPORTED_API = _MockSymbol("printf", value=0, imported=True)
MOCK_ELF = _MockElfBinary(
    exported_functions=[_MockExport("exported_func", 0x1000)],
    symtab_symbols=[_MockSymbol("local_func", value=0x2000)],
    dynamic_symbols=[_MockSymbol("dyn_defined", value=0x3000), IMPORTED_API],
    relocations=[_MockReloc(0x4000, IMPORTED_API)],
    entrypoint=0x500,
)


class TestElfProviderClassification(unittest.TestCase):
    def test_itanium_demangler_uses_bundled_pycxxfilt(self):
        self.assertEqual(demangle_itanium_symbol("_Z3foov"), "foo()")
        self.assertEqual(demangle_itanium_symbol("_ZTV1A"), "vtable for A")
        self.assertEqual(demangle_itanium_symbol("not_mangled"), "not_mangled")

    def test_itanium_demangler_keeps_invalid_prefixed_symbols_raw(self):
        self.assertEqual(demangle_itanium_symbol("_Znotreally"), "_Znotreally")

    def test_symbol_provider_is_not_an_api_provider(self):
        provider = ElfSymbolProvider(None)
        self.assertTrue(provider.isSymbolProvider())
        self.assertFalse(provider.isApiProvider())

    def test_api_resolver_is_not_a_symbol_provider(self):
        resolver = ElfApiResolver(None)
        self.assertTrue(resolver.isApiProvider())
        self.assertFalse(resolver.isSymbolProvider())
        self.assertEqual(resolver.getSymbol(0x4000), "")
        self.assertEqual(resolver.getFunctionSymbols(), {})


class TestElfApiSymbolSeparation(unittest.TestCase):
    def test_symbol_provider_keeps_only_local_symbols(self):
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            provider.update(_binary_info(MOCK_ELF))
        symbols = provider.getFunctionSymbols()
        # local/exported/defined function symbols and the OEP are present
        self.assertEqual(symbols[0x1000], "exported_func")
        self.assertEqual(symbols[0x2000], "local_func")
        self.assertEqual(symbols[0x3000], "dyn_defined")
        self.assertEqual(symbols[0x500], "original_entry_point")
        # imported API name and its relocation slot are NOT treated as symbols
        self.assertNotIn("printf", symbols.values())
        self.assertNotIn(0x4000, symbols)

    def test_api_resolver_still_resolves_imported_relocation(self):
        resolver = ElfApiResolver(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            resolver.update(_binary_info(MOCK_ELF))
        # the imported API remains resolvable as an API, keyed by its relocation slot
        self.assertTrue(resolver.is_active())
        self.assertEqual(resolver.getApi(0x4000), (None, "printf"))
        self.assertEqual(resolver.getApi(0x1000), (None, None))

    def test_api_resolver_resolves_imports_for_buffer_elf(self):
        # memory-dump / raw-buffer ELF inputs (is_buffer=True) must still get imported APIs;
        # this is the path that previously relied on ElfSymbolProvider holding relocation names.
        resolver = ElfApiResolver(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            resolver.update(SimpleNamespace(is_buffer=True, getLiefBinary=lambda: MOCK_ELF))
        self.assertEqual(resolver.getApi(0x4000), (None, "printf"))

    def test_api_resolver_inactive_for_non_elf_buffer(self):
        # raw shellcode (non-ELF) buffers have no ELF relocations and stay unresolved
        resolver = ElfApiResolver(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            resolver.update(SimpleNamespace(is_buffer=True, getLiefBinary=lambda: object()))
        self.assertFalse(resolver.is_active())

    def test_api_resolver_clears_stale_imports_on_non_elf_update(self):
        resolver = ElfApiResolver(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            resolver.update(_binary_info(MOCK_ELF))
        self.assertEqual(resolver.getApi(0x4000), (None, "printf"))
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            resolver.update(SimpleNamespace(is_buffer=True, getLiefBinary=lambda: object()))
        self.assertFalse(resolver.is_active())
        self.assertEqual(resolver.getApi(0x4000), (None, None))

    def test_symbol_provider_inactive_for_non_elf(self):
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            provider.update(SimpleNamespace(is_buffer=False, getLiefBinary=lambda: object()))
        self.assertFalse(provider.is_active())

    def test_parse_imports_matches_api_resolver_relocation_slots(self):
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            imports = provider.parseImports(MOCK_ELF)
        self.assertEqual(imports, {0x4000: (None, "printf")})

    def test_parse_imports_handles_missing_symbol_version_auxiliary(self):
        imported = _MockSymbol("puts", value=0, imported=True)
        imported.has_version = True
        imported.symbol_version = SimpleNamespace(
            has_auxiliary_version=True,
            symbol_version_auxiliary=None,
        )
        elf = _MockElfBinary(
            exported_functions=[],
            symtab_symbols=[],
            dynamic_symbols=[imported],
            relocations=[_MockReloc(0x5000, imported)],
            entrypoint=0,
        )
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            imports = provider.parseImports(elf)
        self.assertEqual(imports, {0x5000: (None, "puts")})

    def test_collect_symbols_merges_symtab_dynamic_and_exports(self):
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            symbols = provider.collectSymbols(MOCK_ELF)
        self.assertEqual(symbols[0x1000], "exported_func")
        self.assertEqual(symbols[0x2000], "local_func")
        self.assertEqual(symbols[0x3000], "dyn_defined")
        self.assertNotIn("printf", symbols.values())
        self.assertNotIn(0x4000, symbols)

    def test_undefined_plt_symbol_is_not_a_defined_function_label(self):
        plt_import = _MockSymbol("malloc", value=0x405780, imported=False, shndx=0)
        elf = _MockElfBinary(
            exported_functions=[],
            symtab_symbols=[],
            dynamic_symbols=[plt_import],
            relocations=[],
            entrypoint=0,
        )
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            provider.update(_binary_info(elf))
            symbols = provider.collectSymbols(elf)
        self.assertNotIn(0x405780, provider.getFunctionSymbols())
        self.assertNotIn(0x405780, symbols)

    def test_exported_data_symbols_are_recovered_without_becoming_function_labels(self):
        data_export = _MockSymbol("_ZTV1A", value=0x3500, is_function=False, shndx=7)
        function_export = _MockSymbol("_Z3foov", value=0x3600, shndx=8)
        elf = _MockElfBinary(
            exported_functions=[_MockExport("_Z3foov", 0x3600)],
            symtab_symbols=[],
            dynamic_symbols=[data_export, function_export],
            relocations=[],
            entrypoint=0,
        )
        provider = ElfSymbolProvider(None)
        with (
            mock.patch("lief.ELF.Binary", _MockElfBinary),
            mock.patch(
                "smda.common.labelprovider.ElfSymbolProvider.demangle_itanium_symbol",
                side_effect={"_ZTV1A": "vtable for A", "_Z3foov": "foo()"}.get,
            ),
        ):
            exported_symbols = provider.parseExportedSymbols(elf)
            provider.update(_binary_info(elf))
        self.assertEqual(exported_symbols, {0x3500: "vtable for A", 0x3600: "foo()"})
        self.assertEqual(provider.getFunctionSymbols()[0x3600], "foo()")
        self.assertNotIn(0x3500, provider.getFunctionSymbols())

    def test_malformed_elf_symbol_names_are_skipped_without_aborting_collection(self):
        malformed_export = _MalformedNameSymbol(address=0x3400, value=0x3400, shndx=7)
        malformed_import = _MalformedNameSymbol(imported=True, is_function=True)
        valid_export = _MockSymbol("_Z3foov", value=0x3600, shndx=8)
        elf = _MockElfBinary(
            exported_functions=[malformed_export, _MockExport("_Z3foov", 0x3600)],
            symtab_symbols=[malformed_export, valid_export],
            dynamic_symbols=[malformed_export, valid_export, malformed_import],
            relocations=[_MockReloc(0x4000, malformed_import)],
            entrypoint=0,
        )
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            self.assertEqual(provider.parseExports(elf), {0x3600: "foo()"})
            self.assertEqual(provider.parseExportedSymbols(elf), {0x3600: "foo()"})
            self.assertEqual(provider.parseSymbols(elf.symtab_symbols), {0x3600: "foo()"})
            self.assertEqual(provider.parseImports(elf), {})

    def test_elf_exports_and_imports_use_itanium_demangling(self):
        imported = _MockSymbol("_Z3barv", imported=True)
        elf = _MockElfBinary(
            exported_functions=[_MockExport("_Z3foov", 0x1000)],
            symtab_symbols=[],
            dynamic_symbols=[imported],
            relocations=[_MockReloc(0x4000, imported)],
            entrypoint=0,
        )
        provider = ElfSymbolProvider(None)
        with (
            mock.patch("lief.ELF.Binary", _MockElfBinary),
            mock.patch(
                "smda.common.labelprovider.ElfSymbolProvider.demangle_itanium_symbol",
                side_effect={"_Z3foov": "foo()"}.get,
            ),
            mock.patch(
                "smda.common.labelprovider.import_parsers.demangle_itanium_symbol",
                side_effect={"_Z3barv": "bar()"}.get,
            ),
        ):
            self.assertEqual(provider.parseExports(elf), {0x1000: "foo()"})
            self.assertEqual(provider.parseImports(elf), {0x4000: (None, "bar()")})

    def test_binary_info_elf_imported_functions_use_relocation_slots(self):
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=MOCK_ELF),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            imported = binary_info.getImportedFunctions()
        self.assertEqual(imported, {0x4000: (None, "printf")})

    def test_binary_info_elf_symbols_merge_symtab_sources(self):
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=MOCK_ELF),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            symbols = binary_info.getSymbols()
        self.assertEqual(symbols[0x2000], "local_func")
        self.assertNotIn(0x4000, symbols)

    def test_binary_info_elf_exported_symbols_include_data_exports(self):
        data_export = _MockSymbol("exported_data", value=0x3700, is_function=False, shndx=7)
        elf = _MockElfBinary(
            exported_functions=[_MockExport("exported_func", 0x1000)],
            symtab_symbols=[],
            dynamic_symbols=[data_export],
            relocations=[],
            entrypoint=0,
        )
        binary_info = BinaryInfo(b"")
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=elf),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            self.assertEqual(binary_info.getExportedSymbols(), {0x3700: "exported_data"})
            self.assertNotIn(0x3700, binary_info.getSymbols())

    def test_non_elf_exported_symbols_do_not_alias_exported_functions(self):
        exported_functions = {0x1000: "exported_func"}
        binary_info = BinaryInfo(b"")
        binary_info.getLiefBinary = lambda: object()
        binary_info._getLiefType = lambda: "PE"
        binary_info.getExportedFunctions = lambda: exported_functions

        exported_symbols = binary_info.getExportedSymbols()
        exported_symbols[0x2000] = "new_symbol"

        self.assertEqual(exported_functions, {0x1000: "exported_func"})

    def test_binary_info_elf_oep_is_base_relative_offset(self):
        elf = _MockElfBinary(
            exported_functions=[],
            symtab_symbols=[],
            dynamic_symbols=[],
            relocations=[],
            entrypoint=0x400534,
        )
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=elf),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            self.assertEqual(binary_info.getOep(), 0x534)

    def test_binary_info_elf_pie_oep_preserves_base_relative_offset(self):
        elf = _MockElfBinary(
            exported_functions=[],
            symtab_symbols=[],
            dynamic_symbols=[],
            relocations=[],
            entrypoint=0x1050,
        )
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x555555554000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=elf),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            self.assertEqual(binary_info.getOep(), 0x1050)


if __name__ == "__main__":
    unittest.main()
