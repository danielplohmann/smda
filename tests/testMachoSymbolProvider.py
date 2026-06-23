import json
import logging
import unittest
from pathlib import Path
from unittest import mock

from smda.aarch64.AArch64Disassembler import AArch64Disassembler
from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.MachoDemangler import demangle_macho_symbol
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig
from smda.utility.MemoryFileLoader import MemoryFileLoader

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


def _xor_fixture(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _load_fixture(fixture_id):
    manifest = json.loads(MANIFEST_PATH.read_text())
    fixture = next(item for item in manifest["fixtures"] if item["id"] == fixture_id)
    raw = _xor_fixture((CORPUS_DIR / fixture["path"]).read_bytes())
    loader = MemoryFileLoader(raw, map_file=True)
    return fixture, raw, loader


def _binary_info(raw, loader):
    binary_info = BinaryInfo(raw)
    binary_info.base_addr = loader.getBaseAddress()
    binary_info.bitness = loader.getBitness()
    binary_info.architecture = loader.getArchitecture()
    binary_info.code_areas = loader.getCodeAreas()
    binary_info.binary = loader.getData()
    binary_info.binary_size = len(binary_info.binary)
    binary_info.raw_data = raw
    return binary_info


class TestExportAddressNormalization(unittest.TestCase):
    def test_absolute_export_addresses_are_not_double_adjusted(self):
        exports = {0x100003F08: "_main", 0x100000000: "__mh_execute_header"}
        normalized = DisassemblyResult._normalize_export_addresses(exports, 0x100000000)
        self.assertEqual(normalized, {0x100003F08, 0x100000000})

    def test_relative_export_addresses_are_adjusted_to_absolute(self):
        exports = {0x3F08: "_main"}
        normalized = DisassemblyResult._normalize_export_addresses(exports, 0x100000000)
        self.assertEqual(normalized, {0x100003F08})


class TestMachoDemangler(unittest.TestCase):
    def test_demangle_cxx_via_host_tool_when_available(self):
        with mock.patch(
            "smda.common.labelprovider.MachoDemangler._demangle_with_tools",
            return_value="uid()",
        ) as demangle_tools:
            demangle_macho_symbol.cache_clear()
            self.assertEqual(demangle_macho_symbol("__Z3uidv"), "uid()")
            demangle_tools.assert_called_once()

    def test_unknown_symbol_is_left_unchanged(self):
        demangle_macho_symbol.cache_clear()
        self.assertEqual(demangle_macho_symbol("_plain_symbol"), "_plain_symbol")

    def test_swift_demangler_arrow_suffix_is_stripped(self):
        demangle_macho_symbol.cache_clear()
        with mock.patch(
            "smda.common.labelprovider.MachoDemangler._demangle_with_tools",
            return_value="_$s7HLoader4mainyyF ---> HLoader.main() -> ()",
        ):
            self.assertEqual(demangle_macho_symbol("_$s7HLoader4mainyyF"), "HLoader.main() -> ()")


class TestMachoSymbolProviderBehavior(unittest.TestCase):
    def test_collect_symbols_merges_exports_and_symtab(self):
        _, raw, loader = _load_fixture("objective-see/bluenoroff")
        binary_info = _binary_info(raw, loader)
        provider = MachoSymbolProvider(None)
        provider._binary_info = binary_info
        symbols = provider.collectSymbols(binary_info.getLiefBinary())
        exported = provider.parseExports(binary_info.getLiefBinary())
        self.assertIn(0x100003F08, symbols)
        self.assertEqual(symbols[0x100003F08], "_main")
        for addr, name in exported.items():
            self.assertEqual(symbols.get(addr), name)

    def test_xmetadata_symbols_are_filtered_to_code_areas(self):
        _, raw, loader = _load_fixture("objective-see/turtle")
        binary_info = _binary_info(raw, loader)
        symbols = binary_info.getSymbols()
        self.assertTrue(symbols)
        for address in symbols:
            self.assertTrue(binary_info.isInCodeAreas(address), hex(address))

    def test_stub_names_do_not_replace_existing_symtab_names(self):
        _, raw, loader = _load_fixture("objective-see/turtle")
        binary_info = _binary_info(raw, loader)
        provider = MachoSymbolProvider(None)
        provider.update(binary_info)
        self.assertEqual(provider.getSymbol(0x100096320), "_runtime.etext")

    def test_go_provider_parses_macho_pclntab(self):
        _, raw, loader = _load_fixture("objective-see/turtle")
        binary_info = _binary_info(raw, loader)
        provider = GoSymbolProvider(None)
        provider.update(binary_info)
        symbols = provider.getFunctionSymbols()
        self.assertGreater(len(symbols), 1000)
        sample_name = next(iter(symbols.values()))
        self.assertNotIn("·", sample_name)


class TestMachoCorpusIntegration(unittest.TestCase):
    def test_bluenoroff_symbols_exports_and_imports(self):
        _, raw, _loader = _load_fixture("objective-see/bluenoroff")
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleUnmappedBuffer(raw)

        symbols = report.xmetadata.get("symbols", {})
        exported = report.xmetadata.get("exported_functions", {})
        imported = report.xmetadata.get("imported_functions", {})

        self.assertIn(0x100003F08, symbols)
        self.assertEqual(symbols[0x100003F08], "_main")
        self.assertIn(0x100000000, exported)
        self.assertIn(0x100004000, imported)
        self.assertEqual(imported[0x100004000][1], "_getenv")

    def test_bluenoroff_export_addresses_are_not_doubled(self):
        _, raw, loader = _load_fixture("objective-see/bluenoroff")
        binary_info = _binary_info(raw, loader)
        disassembler = AArch64Disassembler(SmdaConfig())
        disassembler.analyzeBuffer(binary_info)
        exports = disassembler.disassembly.exported_functions
        self.assertIn(0x100000000, exports)
        self.assertNotIn(0x200000000, exports)

    def test_kitty_marks_exported_functions(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        _, raw, _loader = _load_fixture("objective-see/kitty")
        report = Disassembler(config).disassembleUnmappedBuffer(raw)
        exported_addresses = set(report.xmetadata.get("exported_functions", {}))
        for function in report.getFunctions():
            if function.offset in exported_addresses:
                self.assertTrue(function.is_exported)

    def test_bluenoroff_records_import_apirefs(self):
        _, raw, loader = _load_fixture("objective-see/bluenoroff")
        binary_info = _binary_info(raw, loader)
        disassembler = AArch64Disassembler(SmdaConfig())
        disassembler.analyzeBuffer(binary_info)
        self.assertGreaterEqual(len(disassembler.disassembly.apis), 1)
        self.assertIn(0x100004000, disassembler.disassembly.apis)

    def test_kitty_cxx_symbols_are_demangled_when_tooling_is_available(self):
        _, raw, loader = _load_fixture("objective-see/kitty")
        binary_info = _binary_info(raw, loader)
        provider = MachoSymbolProvider(None)
        provider._binary_info = binary_info
        symbols = provider.parseSymbols(binary_info.getLiefBinary())
        uid_name = symbols.get(0x10000215C)
        self.assertTrue(uid_name)
        if uid_name != "__Z3uidv":
            self.assertNotIn("__Z", uid_name)


class TestLockBitExportRegression(unittest.TestCase):
    _EXPORT_SLOT = 0x1000061F4
    _EXPORT_NAME = "_CalculateCryptoBlocksShift"

    def test_lockbit_xmetadata_lists_exports(self):
        _, raw, _loader = _load_fixture("objective-see/lockbit")
        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleUnmappedBuffer(raw)
        exported = report.xmetadata.get("exported_functions", {})

        self.assertEqual(len(exported), 469)
        self.assertEqual(exported[self._EXPORT_SLOT], self._EXPORT_NAME)

    def test_lockbit_export_addresses_are_not_doubled(self):
        _, raw, loader = _load_fixture("objective-see/lockbit")
        binary_info = _binary_info(raw, loader)
        disassembler = AArch64Disassembler(SmdaConfig())
        disassembler.analyzeBuffer(binary_info)

        exports = disassembler.disassembly.exported_functions
        self.assertEqual(len(exports), 469)
        self.assertIn(self._EXPORT_SLOT, exports)
        self.assertNotIn(self._EXPORT_SLOT + binary_info.base_addr, exports)

    def test_lockbit_marks_recovered_export_entry_points(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        _, raw, _loader = _load_fixture("objective-see/lockbit")
        report = Disassembler(config).disassembleUnmappedBuffer(raw)
        exported_addresses = set(report.xmetadata.get("exported_functions", {}))

        exported_functions = [function for function in report.getFunctions() if function.offset in exported_addresses]
        self.assertGreaterEqual(len(exported_functions), 200)
        for function in exported_functions:
            with self.subTest(offset=function.offset):
                self.assertTrue(function.is_exported)

        main_export = next(
            (function for function in report.getFunctions() if function.offset == self._EXPORT_SLOT),
            None,
        )
        self.assertIsNotNone(main_export)
        self.assertTrue(main_export.is_exported)
        self.assertEqual(main_export.function_name, self._EXPORT_NAME)


class TestKittyApirefRegression(unittest.TestCase):
    _OBJC_STORE_STRONG_SLOT = 0x100004128
    _CURL_GLOBAL_INIT_SLOT = 0x100004068

    def test_kitty_records_import_slots_in_disassembly(self):
        _, raw, loader = _load_fixture("objective-see/kitty")
        binary_info = _binary_info(raw, loader)
        disassembler = AArch64Disassembler(SmdaConfig())
        disassembler.analyzeBuffer(binary_info)

        apis = disassembler.disassembly.apis
        self.assertGreaterEqual(len(apis), 20)
        self.assertIn(self._OBJC_STORE_STRONG_SLOT, apis)
        self.assertEqual(apis[self._OBJC_STORE_STRONG_SLOT]["api_name"], "_objc_storeStrong")
        self.assertIn("libobjc", apis[self._OBJC_STORE_STRONG_SLOT]["dll_name"])
        self.assertIn(self._CURL_GLOBAL_INIT_SLOT, apis)
        self.assertEqual(apis[self._CURL_GLOBAL_INIT_SLOT]["api_name"], "_curl_global_init")

    def test_kitty_surfaces_apirefs_on_recovered_functions(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        _, raw, _loader = _load_fixture("objective-see/kitty")
        report = Disassembler(config).disassembleUnmappedBuffer(raw)

        functions_with_apirefs = [function for function in report.getFunctions() if function.apirefs]
        self.assertGreaterEqual(len(functions_with_apirefs), 10)
        sample = functions_with_apirefs[0]
        sample_ref = next(iter(sample.apirefs.values()))
        self.assertIn("!", sample_ref)
        self.assertTrue(sample_ref.endswith(sample_ref.split("!")[-1]))


class TestSwiftDemangleCorpusRegression(unittest.TestCase):
    _HLOADER_MAIN_ADDR = 0x100003700
    _HLOADER_MAIN_RAW = "_$s7HLoader4mainyyF"
    _HLOADER_MAIN_DEMANGLED = "HLoader.main() -> ()"

    _JOKERSPY_TYPE_ADDR = 0x10000260C
    _JOKERSPY_TYPE_RAW = "_$s13XProtectCheckAACMa"
    _JOKERSPY_TYPE_DEMANGLED = "type metadata accessor for XProtectCheck.XProtectCheck"

    def _mock_demangle(self, name):
        mapping = {
            self._HLOADER_MAIN_RAW: self._HLOADER_MAIN_DEMANGLED,
            self._JOKERSPY_TYPE_RAW: self._JOKERSPY_TYPE_DEMANGLED,
        }
        return mapping.get(name, name)

    def test_hloader_swift_symbols_use_mocked_demangler_output(self):
        demangle_macho_symbol.cache_clear()
        _, raw, loader = _load_fixture("malpedia/osx.hloader")
        binary_info = _binary_info(raw, loader)

        with mock.patch(
            "smda.common.labelprovider.MachoSymbolProvider.demangle_macho_symbol",
            side_effect=self._mock_demangle,
        ):
            provider = MachoSymbolProvider(None)
            provider._binary_info = binary_info
            symbols = provider.parseSymbols(binary_info.getLiefBinary())

        self.assertEqual(symbols[self._HLOADER_MAIN_ADDR], self._HLOADER_MAIN_DEMANGLED)
        self.assertNotIn("_$s", symbols[self._HLOADER_MAIN_ADDR])

    def test_jokerspy_swift_function_names_use_mocked_demangler_output(self):
        demangle_macho_symbol.cache_clear()
        config = SmdaConfig()
        config.WITH_STRINGS = False
        _, raw, _loader = _load_fixture("objective-see/jokerspy")

        with mock.patch(
            "smda.common.labelprovider.MachoSymbolProvider.demangle_macho_symbol",
            side_effect=self._mock_demangle,
        ):
            report = Disassembler(config).disassembleUnmappedBuffer(raw)

        symbols = report.xmetadata.get("symbols", {})
        self.assertEqual(symbols[self._JOKERSPY_TYPE_ADDR], self._JOKERSPY_TYPE_DEMANGLED)

        typed_function = next(
            (function for function in report.getFunctions() if function.offset == self._JOKERSPY_TYPE_ADDR),
            None,
        )
        self.assertIsNotNone(typed_function)
        self.assertEqual(typed_function.function_name, self._JOKERSPY_TYPE_DEMANGLED)


if __name__ == "__main__":
    unittest.main()
