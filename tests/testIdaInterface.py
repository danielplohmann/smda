import types
import unittest
from unittest import mock

from smda.ida import IdaDomainInterface as ida_domain_backend
from smda.ida import IdaInterface as ida_compatibility
from smda.ida.IdaDomainInterface import IdaDomainInterface
from smda.ida.IdaIdapythonInterface import Ida73Interface, Ida74Interface, Ida85Interface


class TestIdaBackendSelection(unittest.TestCase):
    def tearDown(self):
        ida_compatibility.IdaInterface.instance = None

    def test_legacy_sdk_boundaries(self):
        self.assertIs(ida_compatibility._selectBackend(739), Ida73Interface)
        self.assertIs(ida_compatibility._selectBackend(740), Ida74Interface)
        self.assertIs(ida_compatibility._selectBackend(849), Ida74Interface)
        self.assertIs(ida_compatibility._selectBackend(850), Ida85Interface)
        self.assertIs(ida_compatibility._selectBackend(900), Ida85Interface)

    def test_domain_is_preferred_only_for_supported_sdk_versions(self):
        class DomainBackend:
            pass

        self.assertIs(ida_compatibility._selectBackend(900, DomainBackend), Ida85Interface)
        self.assertIs(ida_compatibility._selectBackend(910, DomainBackend), DomainBackend)
        self.assertIs(ida_compatibility._selectBackend(940, DomainBackend), DomainBackend)

    def test_new_ida_falls_back_to_idapython_without_domain(self):
        self.assertIs(ida_compatibility._selectBackend(910), Ida85Interface)
        self.assertIs(ida_compatibility._selectBackend(940), Ida85Interface)

    def test_invalid_sdk_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported IDA SDK version"):
            ida_compatibility._selectBackend("940")

    def test_facade_uses_domain_when_available(self):
        class DomainBackend:
            pass

        with (
            mock.patch.object(ida_compatibility, "getIdaSdkVersion", return_value=940),
            mock.patch.object(ida_compatibility, "_getDomainInterface", return_value=DomainBackend),
        ):
            interface = ida_compatibility.IdaInterface()
        self.assertIsInstance(interface.instance, DomainBackend)

    def test_facade_does_not_probe_domain_on_older_ida(self):
        with (
            mock.patch.object(ida_compatibility, "getIdaSdkVersion", return_value=850),
            mock.patch.object(ida_compatibility, "_getDomainInterface") as get_domain,
            mock.patch.object(ida_compatibility, "_selectBackend", return_value=mock.Mock),
        ):
            ida_compatibility.IdaInterface()
        get_domain.assert_not_called()

    def test_domain_probe_does_not_import_optional_package(self):
        with (
            mock.patch.object(ida_compatibility.importlib.util, "find_spec", return_value=object()),
            mock.patch.object(ida_domain_backend.importlib, "import_module") as import_module,
        ):
            self.assertIs(ida_compatibility._getDomainInterface(), IdaDomainInterface)
        import_module.assert_not_called()

    def test_domain_probe_returns_none_when_package_is_missing(self):
        with mock.patch.object(ida_compatibility.importlib.util, "find_spec", return_value=None):
            self.assertIsNone(ida_compatibility._getDomainInterface())

    def test_facade_falls_back_when_domain_cannot_initialize(self):
        domain_backend = mock.Mock(side_effect=ida_domain_backend.IdaDomainUnavailableError("domain unavailable"))
        legacy_backend = mock.Mock()
        with (
            mock.patch.object(ida_compatibility, "getIdaSdkVersion", return_value=940),
            mock.patch.object(ida_compatibility, "_getDomainInterface", return_value=domain_backend),
            mock.patch.object(ida_compatibility, "_selectBackend", side_effect=[domain_backend, legacy_backend]),
        ):
            ida_compatibility.IdaInterface()
        legacy_backend.assert_called_once_with()

    def test_facade_does_not_hide_unrelated_domain_import_errors(self):
        domain_backend = mock.Mock(side_effect=ImportError("database failure"))
        with (
            mock.patch.object(ida_compatibility, "getIdaSdkVersion", return_value=940),
            mock.patch.object(ida_compatibility, "_getDomainInterface", return_value=domain_backend),
            mock.patch.object(ida_compatibility, "_selectBackend", return_value=domain_backend),
            self.assertRaisesRegex(ImportError, "database failure"),
        ):
            ida_compatibility.IdaInterface()

    def test_headless_export_has_clear_optional_dependency_error(self):
        with (
            mock.patch.object(ida_compatibility, "_getDomainInterface", return_value=None),
            self.assertRaisesRegex(ImportError, r'pip install "smda\[ida\]"'),
        ):
            ida_compatibility.IdaInterface.fromPath("sample.i64")

    def test_lazy_domain_import_has_clear_optional_dependency_error(self):
        with (
            mock.patch.object(ida_domain_backend.importlib, "import_module", side_effect=ImportError),
            self.assertRaisesRegex(ImportError, r'pip install "smda\[ida\]"'),
        ):
            ida_domain_backend._getDatabaseClass()

    def test_headless_export_owns_and_closes_database(self):
        database = _FakeDatabase()
        database_factory = mock.Mock()
        database_factory.open.return_value = database
        with (
            mock.patch.object(ida_compatibility, "_getDomainInterface", return_value=IdaDomainInterface),
            mock.patch.object(ida_domain_backend, "_getDatabaseClass", return_value=database_factory),
        ):
            interface = ida_compatibility.IdaInterface.fromPath("sample.i64", save_on_close=False)
        database_factory.open.assert_called_once_with(path="sample.i64", save_on_close=False)
        interface.close()
        self.assertTrue(database.closed)


class _FakeImports:
    def get_all_imports(self):
        return iter(
            [
                types.SimpleNamespace(address=0x1000, name="CreateFileW", ordinal=1, module_name="kernel32.dll"),
                types.SimpleNamespace(address=0x2000, name=None, ordinal=7, module_name="test.dll"),
                types.SimpleNamespace(address=0x3000, name="symbol", ordinal=0, module_name=""),
            ]
        )


class _FakeFunctions:
    def __init__(self):
        self.function = types.SimpleNamespace(start_ea=0x1000)

    def get_all(self):
        return iter([self.function])

    def get_at(self, offset):
        return self.function if offset == self.function.start_ea else None

    def get_flowchart(self, function):
        instruction = types.SimpleNamespace(ea=0x1000)
        block = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004, get_instructions=lambda: iter([instruction]))
        return iter([block])

    def get_name(self, function):
        return "named_function"

    def create(self, instruction):
        return instruction == 0x1000


class _FakeSegments:
    def __init__(self):
        self.code = types.SimpleNamespace(start_ea=0x12345, end_ea=0x12349, name="text")

    def get_all(self):
        return iter([self.code])

    def get_at(self, offset):
        return self.code if self.code.start_ea <= offset < self.code.end_ea else None

    def get_bitness(self, segment):
        return 64

    def get_size(self, segment):
        return segment.end_ea - segment.start_ea

    def get_name(self, segment):
        return segment.name


class _FakeDatabase:
    def __init__(self, architecture="metapc", bitness=64):
        self.architecture = architecture
        self.bitness = bitness
        self.minimum_ea = 0x1000
        self.path = "/tmp/input.bin"
        self.functions = _FakeFunctions()
        self.segments = _FakeSegments()
        self.imports = _FakeImports()
        self.instructions = types.SimpleNamespace(
            get_at=lambda offset: types.SimpleNamespace(size=4) if offset == 0x1000 else None
        )
        self.bytes = types.SimpleNamespace(get_bytes_at=lambda offset, size: b"\x90" * size)
        self.xrefs = types.SimpleNamespace(
            code_refs_to_ea=lambda offset, flow=True: iter([0x900]),
            code_refs_from_ea=lambda offset, flow=True: iter([0x1100]),
        )
        self.names = types.SimpleNamespace(
            get_demangled_name=lambda offset: "demangled",
            set_name=lambda address, name: bool(name),
        )
        self.closed = False

    def close(self):
        self.closed = True


class TestIdaDomainInterface(unittest.TestCase):
    def test_domain_uses_high_level_entities(self):
        interface = IdaDomainInterface(database=_FakeDatabase())
        self.assertEqual(interface.getArchitecture(), "intel")
        self.assertEqual(interface.getBitness(), 64)
        self.assertEqual(interface.getFunctions(), [0x1000])
        self.assertEqual(interface.getBlocks(0x1000), [[0x1000]])
        self.assertEqual(interface.getInstructionBytes(0x1000), b"\x90\x90\x90\x90")
        self.assertEqual(interface.getInstructionBytes(0x2000), b"")
        self.assertEqual(interface.getCodeInRefs(0x1000), [(0x900, 0x1000)])
        self.assertEqual(interface.getCodeOutRefs(0x1000), [(0x1000, 0x1100)])
        self.assertEqual(interface.getFunctionSymbols(), {0x1000: "named_function"})
        self.assertEqual(interface.getBaseAddr(), 0x10000)
        self.assertEqual(interface.getBinary(), b"\x90\x90\x90\x90")

    def test_domain_maps_aarch64_and_rejects_arm32(self):
        self.assertEqual(IdaDomainInterface(database=_FakeDatabase("ARM", 64)).getArchitecture(), "aarch64")
        self.assertEqual(IdaDomainInterface(database=_FakeDatabase("aarch64", 64)).getArchitecture(), "aarch64")
        with self.assertRaisesRegex(ValueError, r"Unsupported Architecture: ARM \(32bit\)"):
            IdaDomainInterface(database=_FakeDatabase("ARM", 32)).getArchitecture()

    def test_domain_import_map_preserves_named_and_ordinal_imports(self):
        interface = IdaDomainInterface(database=_FakeDatabase())
        self.assertEqual(
            interface.getApiMap(),
            {
                0x1000: "kernel32.dll!CreateFileW",
                0x2000: "test.dll!#7",
                0x3000: "symbol",
            },
        )

    def test_injected_database_is_not_closed(self):
        database = _FakeDatabase()
        interface = IdaDomainInterface(database=database)
        interface.close()
        self.assertFalse(database.closed)


if __name__ == "__main__":
    unittest.main()
