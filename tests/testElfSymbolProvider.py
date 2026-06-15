import unittest
from types import SimpleNamespace
from unittest import mock

from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider


class _MockExport:
    def __init__(self, name, address):
        self.name = name
        self.address = address


class _MockSymbol:
    def __init__(self, name, value=0, is_function=True, imported=False):
        self.name = name
        self.demangled_name = name
        self.value = value
        self.is_function = is_function
        self.imported = imported
        self.has_version = False


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

    def test_symbol_provider_inactive_for_non_elf(self):
        provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            provider.update(SimpleNamespace(is_buffer=False, getLiefBinary=lambda: object()))
        self.assertFalse(provider.is_active())


if __name__ == "__main__":
    unittest.main()
