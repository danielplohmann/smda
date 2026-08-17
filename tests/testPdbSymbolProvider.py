import logging
import os
import tempfile
import unittest
from unittest import mock

from purepdb import Function

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider import PdbSymbolProvider as pdb_module
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider, _demangleSymbolName
from smda.common.labelprovider.rust_demangler import demangle
from smda.Disassembler import Disassembler

BASE_ADDR = 0x400000
FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
PE_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_xored")
PDB_FIXTURE = os.path.join(FIXTURE_DIR, "rust_pe_msvc_i686_pdb_xored")
# entry point and code size of "main::digest" in the i686 fixture
DIGEST_RVA = 0x1000
DIGEST_CODE_SIZE = 299
# read out of real PDBs: the Rust names from a rust-lld/MSVC x64 image, the
# rest from sqlite3 x86/x64. The non-Rust names all begin with "_R", which is
# why the dispatch parses a name before it rewrites it
RUST_MAIN = "_RNvCs8JfRDQSkzJ8_15rust_pe_symbols4main"
RUST_MAIN_DEMANGLED = "rust_pe_symbols::main"
RUST_TRAIT_IMPL = "_RNvXs5_NtNtCslFVcyoAu48q_3std2io5errorNtB5_5ErrorNtNtCs55qC6OcLGgs_4core3fmt7Display3fmt"
RUST_TRAIT_IMPL_DEMANGLED = "<std::io::error::Error as core::fmt::Display>::fmt"
NOT_RUST = ("_RTC_Initialize", "_ReadFile@20", "_RoInitialize@4")
MSVC_PE_FIXTURE = os.path.join(FIXTURE_DIR, "msvc_cxx_pdb_pe_xored")
MSVC_PDB_FIXTURE = os.path.join(FIXTURE_DIR, "msvc_cxx_pdb_xored")
# the two translation units of the x64 fixture: one built with debug info, whose procedure
# records carry the name already undecorated, and one without, which contributes publics only
MSVC_PROC_NAME = "geometry::combine"
MSVC_PROC_RVA = 0x1000
MSVC_PUBLIC = "?measure@text@@YAHPEBDI@Z"
MSVC_PUBLIC_DEMANGLED = "int __cdecl text::measure(char const *, unsigned int)"
MSVC_PUBLIC_RVA = 0x1064
# shapes the demangler declines: a lambda, an RTTI descriptor, and a name truncated past
# its parameter list
MSVC_DECLINED = ("??R<lambda_1>@@QEBA@XZ", "??_R0?AVexception@std@@@8", "?a2@@YAHX")
# a name scoped inside a function reads, which is what a PDB's statics and lambdas look like
MSVC_LOCAL_SCOPE = "?x@?1??f@@YAHXZ@4HA"
MSVC_LOCAL_SCOPE_DEMANGLED = "int `int __cdecl f(void)'::`2'::x"


def decode_fixture(path):
    with open(path, "rb") as fin:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(fin.read()))


class FakeDiagnostics:
    def __init__(self, warnings):
        self.warnings = warnings


class FakePdb:
    def __init__(self, functions, warnings=()):
        self._functions = functions
        self._warnings = list(warnings)

    def functions(self):
        return self._functions

    def diagnose(self):
        return FakeDiagnostics(self._warnings)


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
    def setUp(self):
        # several test modules call logging.disable() at import, which would make assertLogs
        # see no records depending on collection order; lift it for this class only
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

    def _providerWith(self, functions):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        provider._parseSymbols(FakePdb(functions))
        return provider

    def test_an_undecorated_entry_point_is_reported_as_the_pdb_spells_it(self):
        provider = self._providerWith([make_function("_platform_seed", 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "_platform_seed")
        self.assertEqual(provider.getFunctionSymbols(), {BASE_ADDR + 0x1000: "_platform_seed"})
        self.assertTrue(provider.is_active())

    def test_an_msvc_entry_point_is_reported_demangled(self):
        provider = self._providerWith([make_function(MSVC_PUBLIC, 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), MSVC_PUBLIC_DEMANGLED)

    def test_a_fragment_of_an_msvc_procedure_is_labelled_with_the_readable_name(self):
        provider = self._providerWith([make_function(MSVC_PUBLIC, 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), f"{MSVC_PUBLIC_DEMANGLED}$+0x60")

    def test_a_fragment_of_a_declined_msvc_procedure_keeps_the_decorated_parent(self):
        provider = self._providerWith([make_function("?a2@@YAHX", 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), "?a2@@YAHX$+0x60")

    def test_a_rust_entry_point_is_reported_demangled(self):
        provider = self._providerWith([make_function(RUST_MAIN, 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), RUST_MAIN_DEMANGLED)

    def test_a_fragment_of_a_rust_procedure_is_labelled_with_the_readable_name(self):
        provider = self._providerWith([make_function(RUST_MAIN, 0x1000, 0x100)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1060), f"{RUST_MAIN_DEMANGLED}$+0x60")

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

    def test_a_name_holding_a_control_character_is_skipped(self):
        provider = self._providerWith(
            [make_function("clean", 0x1000, 0x40), make_function("bell\x07name", 0x2000, 0x40)]
        )
        self.assertEqual(provider.getFunctionSymbols(), {BASE_ADDR + 0x1000: "clean"})
        # nor may it become a fragment parent, which would carry the byte into every label
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x2010), "")

    def test_a_non_ascii_name_is_kept(self):
        # a demangled Rust identifier is legitimately non-ASCII; only control bytes are refused
        provider = self._providerWith([make_function("hello::wörld", 0x1000, 0x40)])
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), "hello::wörld")

    def test_an_empty_name_is_skipped(self):
        provider = self._providerWith([make_function("", 0x1000, 0x40)])
        self.assertEqual(provider.getFunctionSymbols(), {})

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

    def _warnFor(self, functions, warnings=()):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        pdb = FakePdb(functions, warnings)
        provider._parseSymbols(pdb)
        with self.assertLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING) as logs:
            provider._warnAboutThinPdb("sample.pdb", pdb)
        return logs.output[0]

    def test_a_pdb_that_parses_but_resolves_no_address_warns(self):
        unresolved = make_function("unresolved", 0x1000, 0x100)
        unresolved.rva = None
        message = self._warnFor([unresolved], ["no section-header stream, every rva is None"])
        self.assertIn("no usable symbols", message)
        self.assertIn("no section-header stream", message)

    def test_a_pdb_without_procedure_records_warns_that_fragments_are_unavailable(self):
        message = self._warnFor([make_function("stub", 0x1000, None, source="public")])
        self.assertIn("no procedure records", message)

    def test_a_pdb_with_procedures_and_symbols_stays_quiet(self):
        provider = self._providerWith([make_function("parent", 0x1000, 0x100)])
        with self.assertNoLogs("smda.common.labelprovider.PdbSymbolProvider", level=logging.WARNING):
            provider._warnAboutThinPdb("sample.pdb", FakePdb([]))

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


class PdbSymbolDemanglingTestSuite(unittest.TestCase):
    def test_rust_v0_names_are_demangled(self):
        self.assertEqual(_demangleSymbolName(RUST_MAIN), RUST_MAIN_DEMANGLED)
        self.assertEqual(_demangleSymbolName(RUST_TRAIT_IMPL), RUST_TRAIT_IMPL_DEMANGLED)

    def test_names_that_only_look_rust_are_left_alone(self):
        for name in NOT_RUST:
            self.assertEqual(_demangleSymbolName(name), name)

    def test_a_cxx_itanium_name_without_a_rust_hash_is_not_claimed(self):
        self.assertEqual(_demangleSymbolName("_ZN4test4funcEv"), "_ZN4test4funcEv")

    def test_a_legacy_name_that_is_only_a_hash_keeps_its_original_spelling(self):
        name = "_ZN17h0000000000000000E"
        self.assertEqual(demangle(name), "")
        self.assertEqual(_demangleSymbolName(name), name)

    def test_an_msvc_decorated_name_is_demangled(self):
        self.assertEqual(_demangleSymbolName(MSVC_PUBLIC), MSVC_PUBLIC_DEMANGLED)
        self.assertEqual(_demangleSymbolName("?mangled@@YAXXZ"), "void __cdecl mangled(void)")

    def test_an_msvc_name_the_demangler_declines_keeps_its_decorated_spelling(self):
        for name in MSVC_DECLINED:
            self.assertEqual(_demangleSymbolName(name), name)

    def test_a_name_scoped_inside_a_function_is_demangled(self):
        # a PDB carries these by the hundred: every function-local static and lambda
        self.assertEqual(_demangleSymbolName(MSVC_LOCAL_SCOPE), MSVC_LOCAL_SCOPE_DEMANGLED)

    def test_a_name_that_only_looks_msvc_is_left_alone(self):
        for name in ("?", "?????", "?not a symbol"):
            self.assertEqual(_demangleSymbolName(name), name)

    def test_an_unexpected_demangler_failure_keeps_the_original_name(self):
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=RecursionError):
            self.assertEqual(_demangleSymbolName(RUST_MAIN), RUST_MAIN)

    def test_an_operational_exception_still_propagates(self):
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=MemoryError):
            self.assertRaises(MemoryError, _demangleSymbolName, RUST_MAIN)

    def test_one_undemanglable_name_does_not_cost_the_other_symbols(self):
        provider = PdbSymbolProvider(None)
        provider._base_addr = BASE_ADDR
        functions = [make_function(RUST_MAIN, 0x1000, 0x40), make_function(RUST_MAIN, 0x2000, 0x40)]
        with mock.patch.object(pdb_module, "is_rust_language_evidence", side_effect=RecursionError):
            provider._parseSymbols(FakePdb(functions))
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x1000), RUST_MAIN)
        self.assertEqual(provider.getSymbol(BASE_ADDR + 0x2000), RUST_MAIN)


class MsvcPdbFixtureTestSuite(unittest.TestCase):
    """The x64 fixture pair is a clang-cl/lld-link DLL built from two translation units, one
    compiled with /Z7 and one without, so the PDB carries both name shapes a real MSVC build
    produces: procedure records that already spell the name, and decorated publics."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.exe_path = os.path.join(self.tempdir.name, "sample.exe")
        self.pdb_path = os.path.join(self.tempdir.name, "sample.pdb")
        for path, fixture in ((self.exe_path, MSVC_PE_FIXTURE), (self.pdb_path, MSVC_PDB_FIXTURE)):
            with open(path, "wb") as fout:
                fout.write(decode_fixture(fixture))

    def _provider(self):
        provider = PdbSymbolProvider(None)
        provider.update(make_binary_info(self.pdb_path))
        return provider

    def test_a_decorated_public_is_reported_as_a_signature(self):
        self.assertEqual(self._provider().getSymbol(BASE_ADDR + MSVC_PUBLIC_RVA), MSVC_PUBLIC_DEMANGLED)

    def test_a_procedure_record_name_is_reported_as_the_pdb_spells_it(self):
        self.assertEqual(self._provider().getSymbol(BASE_ADDR + MSVC_PROC_RVA), MSVC_PROC_NAME)

    def test_no_reported_name_stays_decorated(self):
        names = self._provider().getFunctionSymbols().values()
        self.assertTrue(names)
        self.assertEqual([name for name in names if name.startswith("?")], [])

    def test_a_supplied_pdb_names_the_functions_it_describes(self):
        report = Disassembler(backend="intel").disassembleFile(self.exe_path, pdb_path=self.pdb_path)
        self.assertEqual(report.status, "ok")
        named = {function.function_name for function in report.getFunctions()}
        self.assertIn(MSVC_PUBLIC_DEMANGLED, named)
        self.assertIn(MSVC_PROC_NAME, named)


if __name__ == "__main__":
    unittest.main()
