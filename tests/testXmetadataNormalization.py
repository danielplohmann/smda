import unittest
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.SmdaReport import SmdaReport
from tests.testElfSymbolProvider import MOCK_ELF, _MockElfBinary
from tests.testPeSymbolProvider import (
    _MockExport,
    _MockImportEntry,
    _MockImportLibrary,
    _MockPeBinary,
    _MockSection,
    _MockSymbol,
)


def _expected_xmetadata_keys():
    return {"exported_functions", "exported_symbols", "imported_functions", "symbols"}


class TestXmetadataShape(unittest.TestCase):
    def test_pe_xmetadata_keys_and_address_convention(self):
        pe_binary = _MockPeBinary(
            imports=[_MockImportLibrary("KERNEL32.dll", [_MockImportEntry("ExitProcess", 0x2000)])],
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
            xmetadata = {
                "exported_functions": binary_info.getExportedFunctions(),
                "exported_symbols": binary_info.getExportedSymbols(),
                "imported_functions": binary_info.getImportedFunctions(),
                "symbols": binary_info.getSymbols(),
            }

        self.assertEqual(set(xmetadata), _expected_xmetadata_keys())
        self.assertIn(0x401000, xmetadata["exported_functions"])
        self.assertIn(0x401000, xmetadata["exported_symbols"])
        self.assertIn(0x401000, xmetadata["symbols"])
        self.assertIn(0x402000, xmetadata["imported_functions"])

    def test_elf_xmetadata_keys_and_overlap_contract(self):
        binary_info = BinaryInfo(b"")
        binary_info.base_addr = 0x400000
        with (
            mock.patch.object(binary_info, "getLiefBinary", return_value=MOCK_ELF),
            mock.patch("lief.ELF.Binary", _MockElfBinary),
        ):
            xmetadata = {
                "exported_functions": binary_info.getExportedFunctions(),
                "exported_symbols": binary_info.getExportedSymbols(),
                "imported_functions": binary_info.getImportedFunctions(),
                "symbols": binary_info.getSymbols(),
            }

        self.assertEqual(set(xmetadata), _expected_xmetadata_keys())
        self.assertEqual(xmetadata["exported_functions"][0x1000], "exported_func")
        self.assertEqual(xmetadata["exported_symbols"][0x3000], "dyn_defined")
        self.assertEqual(xmetadata["symbols"][0x1000], "exported_func")
        self.assertNotIn(0x4000, xmetadata["symbols"])
        self.assertIn(0x4000, xmetadata["imported_functions"])

    def test_provider_collect_symbols_parity(self):
        pe_binary = _MockPeBinary(
            exported_functions=[_MockExport("exported_func", 0x1000)],
            sections=[_MockSection(0x20000000, 0x1000)],
            symbols=[_MockSymbol("local_func", 0x200)],
            imagebase=0x140000000,
        )
        pe_provider = PeSymbolProvider(None)
        elf_provider = ElfSymbolProvider(None)
        with mock.patch("lief.ELF.Binary", _MockElfBinary):
            elf_symbols = elf_provider.collectSymbols(MOCK_ELF)
        pe_symbols = pe_provider.collectSymbols(pe_binary, base_addr=0x400000)
        self.assertIn(0x401000, pe_symbols)
        self.assertIn(0x1000, elf_symbols)


class TestXmetadataRoundtrip(unittest.TestCase):
    def test_smda_report_preserves_xmetadata_dicts(self):
        xmetadata = {
            "exported_functions": {0x401000: "exported_func"},
            "exported_symbols": {0x401000: "exported_func"},
            "imported_functions": {0x402000: ("kernel32.dll", "ExitProcess")},
            "symbols": {0x401000: "exported_func", 0x401200: "local_func"},
        }
        report = SmdaReport()
        report.xmetadata = xmetadata
        report.status = "ok"
        report.architecture = "intel"
        report.base_addr = 0x400000
        report.xcfg = {}

        restored = SmdaReport.fromDict(report.toDict())
        self.assertEqual(restored.xmetadata, xmetadata)
        self.assertEqual(set(restored.xmetadata), _expected_xmetadata_keys())


class TestMachoImportKeyConsistency(unittest.TestCase):
    def test_parse_imports_matches_provider_api_map_keys(self):
        from tests.testMachoSymbolProvider import _binary_info, _load_fixture

        _, raw, loader = _load_fixture("objective-see/bluenoroff")
        binary_info = _binary_info(raw, loader)
        provider = MachoSymbolProvider(None)
        provider._binary_info = binary_info
        provider.update(binary_info)
        imports = provider.parseImports(binary_info.getLiefBinary())
        self.assertEqual(set(imports), set(provider._api_map))
        for slot, entry in imports.items():
            self.assertEqual(provider.getApi(slot), entry)


if __name__ == "__main__":
    unittest.main()
