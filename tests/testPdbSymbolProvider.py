import logging
import os
import tempfile
import unittest

from purepdb import Function

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.Disassembler import Disassembler

BASE_ADDR = 0x400000
FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
PE_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_xored")
PDB_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_pdb_xored")
# entry point and code size of "main::digest" in the i686 fixture
DIGEST_RVA = 0x1000
DIGEST_CODE_SIZE = 299


def decode_fixture(path):
    with open(path, "rb") as fin:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(fin.read()))


class FakePdb:
    def __init__(self, functions):
        self._functions = functions

    def functions(self):
        return self._functions


def make_function(name, rva, code_size=None, source="proc", module=None):
    return Function(
        name=name,
        segment=1,
        offset=rva,
        rva=rva,
        code_size=code_size,
        source=source,
        module=module,
    )


def make_binary_info(file_path, raw_data=b""):
    binary_info = BinaryInfo(b"")
    binary_info.raw_data = raw_data
    binary_info.file_path = file_path
    binary_info.base_addr = BASE_ADDR
    return binary_info


class PdbFragmentAttributionTestSuite(unittest.TestCase):
    def _providerWith(self, functions):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        provider._parseSymbols(FakePdb(functions))
        return provider

    def test_entry_points_are_reported_as_the_pdb_spells_them(self):
        provider = self._providerWith([make_function("?mangled@@YAXXZ", 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "?mangled@@YAXXZ")
        self.assertEqual(provider.getFunctionSymbols(), {BASE_ADDR + 0x1000: "?mangled@@YAXXZ"})
        self.assertTrue(provider.is_active())

    def test_a_fragment_is_labelled_relative_to_its_containing_procedure(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "parent$+0x60")

    def test_a_fragment_label_carries_no_virtual_address(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        label = provider.getSymbol(BASE_ADDR + 0x1060)
        self.assertNotIn(f"{BASE_ADDR + 0x1060:x}", label)
        self.assertNotIn(f"{0x1060:x}", label)

    def test_a_fragment_label_is_independent_of_the_load_address(self):
        labels = []
        for base_addr in (0x400000, 0x10000000):
            provider = PdbSymbolProvider(None)
            provider._base_addr = base_addr
            provider._parseSymbols(FakePdb([make_function("parent", 0x1000, 0x100)]))
            labels.append(provider.getSymbol(base_addr + 0x1060))
        self.assertEqual(labels[0], labels[1])

    def test_an_address_beyond_every_procedure_stays_unnamed(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1100), "")

    def test_an_address_below_every_procedure_stays_unnamed(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x900), "")

    def test_a_fragment_is_attributed_to_the_nearest_enclosing_procedure(self):
        provider = self._providerWith([make_function("first", 0x1000, 0x100), make_function("second", 0x1100, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1180), "second$+0x80")

    def test_an_import_thunk_never_becomes_a_fragment_parent(self):
        provider = self._providerWith(
            [
                make_function(
                    "_FlushFileBuffers@4",
                    0x1000,
                    0x100,
                    source="thunk",
                    module="Import:api-ms-win-core-file-l1-2-1.dll",
                )
            ]
        )
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "_FlushFileBuffers@4")
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "")

    def test_a_procedure_without_a_resolvable_rva_is_skipped(self):
        unresolved = make_function("unresolved", 0x1000, 0x100)
        unresolved.rva = None
        provider = self._providerWith([unresolved])
        self.assertEqual(provider.getFunctionSymbols(), {})
        self.assertFalse(provider.is_active())

    def test_a_public_without_a_code_size_names_only_its_entry_point(self):
        provider = self._providerWith([make_function("stub", 0x1000, None, source="public")])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "stub")
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1004), "")

    def test_the_provider_answers_symbols_but_not_apis(self):
        provider = PdbSymbolProvider(None)
        self.assertTrue(provider.isSymbolProvider())
        self.assertFalse(provider.isApiProvider())
        self.assertEqual(provider.getApi(0x1000), ("", ""))


class PdbUpdateTestSuite(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this class only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _writeFixture(self, name, data):
        path = os.path.join(self.tempdir.name, name)
        with open(path, "wb") as fout:
            fout.write(data)
        return path

    def test_a_pdb_on_disk_is_parsed_into_symbols(self):
        pdb_path = self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(pdb_path))
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA), "main::digest")
        self.assertEqual(
            provider.getSymbol(BASE_ADDR + DIGEST_RVA + DIGEST_CODE_SIZE - 1),
            f"main::digest$+0x{DIGEST_CODE_SIZE - 1:x}",
        )
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA + DIGEST_CODE_SIZE), "")

    def test_a_pdb_already_in_memory_is_parsed_without_reading_the_file(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info("sample.pdb", raw_data=decode_fixture(PDB_FIXTURE)))
        self.assertEqual(provider.getSymbol(BASE_ADDR + DIGEST_RVA), "main::digest")

    def test_a_target_without_a_file_path_yields_no_symbols(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(""))
        self.assertFalse(provider.is_active())

    def test_an_unreadable_file_path_yields_no_symbols(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(os.path.join(self.tempdir.name, "absent.pdb")))
        self.assertFalse(provider.is_active())

    def test_a_truncated_pdb_warns_instead_of_failing_silently(self):
        pdb_path = self._writeFixture("broken.pdb", decode_fixture(PDB_FIXTURE)[:512])
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(pdb_path))
        self.assertIn("Failed parsing PDB", logs.output[0])
        self.assertFalse(provider.is_active())

    def test_an_ignored_sidecar_pdb_warns_instead_of_failing_silently(self):
        self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(exe_path))
        self.assertIn("sample.pdb", logs.output[0])

    def test_a_supplied_file_that_is_not_a_pdb_warns_instead_of_failing_silently(self):
        pdb_path = self._writeFixture("mistyped.pdb", b"MZ" + b"\x00" * 64)
        provider = PdbSymbolProvider(None)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider.update(make_binary_info(pdb_path))
        self.assertIn("is not a PDB file", logs.output[0])

    def test_a_binary_without_a_sidecar_pdb_stays_quiet(self):
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider.update(make_binary_info(exe_path))

    def test_a_sidecar_pdb_that_was_supplied_explicitly_stays_quiet(self):
        pdb_path = self._writeFixture("sample.pdb", decode_fixture(PDB_FIXTURE))
        exe_path = self._writeFixture("sample.exe", decode_fixture(PE_FIXTURE))
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(pdb_path))
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider.update(make_binary_info(exe_path))


class PdbReportIntegrationTestSuite(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.exe_path = os.path.join(self.tempdir.name, "sample.exe")
        self.pdb_path = os.path.join(self.tempdir.name, "sample.pdb")
        with open(self.exe_path, "wb") as fout:
            fout.write(decode_fixture(PE_FIXTURE))
        with open(self.pdb_path, "wb") as fout:
            fout.write(decode_fixture(PDB_FIXTURE))

    def _analyze(self, pdb_path):
        report = Disassembler(backend="intel").disassembleFile(self.exe_path, pdb_path=pdb_path)
        self.assertEqual(report.status, "ok")
        return {function.offset: function.function_name for function in report.getFunctions()}

    def test_a_supplied_pdb_names_the_functions_it_describes(self):
        named = {name for name in self._analyze(self.pdb_path).values() if name}
        self.assertIn("main::digest", named)
        self.assertIn("main::mainCRTStartup", named)

    def test_naming_is_reproducible_across_runs(self):
        self.assertEqual(self._analyze(self.pdb_path), self._analyze(self.pdb_path))

    def test_a_pe_analyzed_without_a_pdb_keeps_its_previous_naming(self):
        os.remove(self.pdb_path)
        named = {name for name in self._analyze("").values() if name}
        self.assertNotIn("main::digest", named)


if __name__ == "__main__":
    unittest.main()
