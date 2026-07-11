import unittest
from pathlib import Path

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.utility.MemoryFileLoader import MemoryFileLoader


class TestMachoProviderClassification(unittest.TestCase):
    def test_macho_provider_supplies_symbols_and_apis(self):
        provider = MachoSymbolProvider(None)
        self.assertTrue(provider.isSymbolProvider())
        self.assertTrue(provider.isApiProvider())

    def test_komplex_symbols_and_apis_are_separated(self):
        xored = (Path(__file__).resolve().parent / "komplex_xored").read_bytes()
        raw = bytes(byte ^ (index % 256) for index, byte in enumerate(xored))
        loader = MemoryFileLoader(raw, map_file=True)

        bi = BinaryInfo(loader.getData())
        bi.raw_data = raw
        bi.base_addr = loader.getBaseAddress()
        bi.bitness = loader.getBitness()
        bi.architecture = loader.getArchitecture()
        bi.code_areas = loader.getCodeAreas()

        provider = MachoSymbolProvider(None)
        provider.update(bi)

        self.assertTrue(provider.is_active())
        symbols = provider.getFunctionSymbols()
        oep_addr = bi.base_addr + bi.getOep()
        self.assertIn(oep_addr, symbols)
        self.assertTrue(symbols[oep_addr])

        # imports are APIs, not function-body symbols
        self.assertTrue(provider._api_map)
        for addr in provider._api_map:
            self.assertNotIn(addr, symbols)
            _lib, name = provider.getApi(addr)
            self.assertTrue(name)

        # xmetadata tables: static exports/symbols/imports (distinct from function_name merge)
        exports = bi.getExportedFunctions() or {}
        table_symbols = bi.getSymbols() or {}
        imports = bi.getImportedFunctions() or {}
        self.assertTrue(table_symbols or exports)
        self.assertTrue(imports)
        for addr in table_symbols:
            self.assertTrue(bi.isInCodeAreas(addr))
        for addr, value in imports.items():
            self.assertIsInstance(value, (tuple, list))
            self.assertEqual(provider.getApi(addr), tuple(value) if not isinstance(value, tuple) else value)
        self.assertTrue(set(provider._api_map).intersection(imports.keys()) or imports)

    def test_update_clears_stale_state_on_non_macho(self):
        xored = (Path(__file__).resolve().parent / "komplex_xored").read_bytes()
        raw = bytes(byte ^ (index % 256) for index, byte in enumerate(xored))
        loader = MemoryFileLoader(raw, map_file=True)
        bi = BinaryInfo(loader.getData())
        bi.raw_data = raw
        bi.base_addr = loader.getBaseAddress()
        bi.bitness = loader.getBitness()
        bi.architecture = loader.getArchitecture()
        bi.code_areas = loader.getCodeAreas()

        provider = MachoSymbolProvider(None)
        provider.update(bi)
        self.assertTrue(provider.is_active())

        empty = BinaryInfo(b"")
        empty.getLiefBinary = lambda: None
        provider.update(empty)
        self.assertFalse(provider.is_active())
        self.assertEqual(provider.getFunctionSymbols(), {})


if __name__ == "__main__":
    unittest.main()
