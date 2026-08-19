import logging
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import lief

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider import import_parsers
from smda.common.labelprovider.import_parsers import (
    parse_elf_relocation_imports,
    parse_macho_bindings,
    parse_pe_delay_imports,
    parse_pe_imports,
)
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider
from smda.common.LanguageAnalyzer import LanguageAnalyzer
from smda.utility.lief_helper import lief_name
from smda.utility.PeFileLoader import PeFileLoader

logging.disable(logging.CRITICAL)

FIXTURE_DIR = Path(__file__).resolve().parent
UNDECODABLE = b"\xff\xfe\x80\x81name"


def _decode(path):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(path.read_bytes()))


class _FakeElfBinary:
    def __init__(self, relocations):
        self.relocations = relocations


class _FakeMachoBinary:
    def __init__(self, bindings):
        self.bindings = bindings


def _patched_lief():
    return SimpleNamespace(
        ELF=SimpleNamespace(Binary=_FakeElfBinary),
        MachO=SimpleNamespace(Binary=_FakeMachoBinary),
        PE=lief.PE,
    )


class _RaisingName:
    @property
    def name(self):
        raise UnicodeDecodeError("utf-32-le", b"\x00\x00\x00\x00", 0, 4, "out of range")


class LiefNameHelperTest(unittest.TestCase):
    def testTextNamePassesThrough(self):
        self.assertEqual(lief_name(SimpleNamespace(name="main")), "main")

    def testUndecodableNameBecomesEmpty(self):
        self.assertEqual(lief_name(SimpleNamespace(name=UNDECODABLE)), "")

    def testMissingAttributeBecomesEmpty(self):
        self.assertEqual(lief_name(SimpleNamespace()), "")

    def testRaisingAttributeBecomesEmpty(self):
        self.assertEqual(lief_name(_RaisingName()), "")

    def testAlternateAttributeIsRead(self):
        symbol = SimpleNamespace(name="_ZN3foo3barE", demangled_name="foo::bar")
        self.assertEqual(lief_name(symbol, "demangled_name"), "foo::bar")


class MappedPeSymbolNameTest(unittest.TestCase):
    """A PE read as a memory image is what makes lief hand back bytes: the COFF
    symbol table is located by a file offset, so a mapped image reads it from
    unrelated bytes."""

    @classmethod
    def setUpClass(cls):
        cls.mapped = PeFileLoader.mapBinary(_decode(FIXTURE_DIR / "rust_pe_gnu_xored"))
        cls.parsed = lief.PE.parse(cls.mapped)

    def testMappedImageYieldsBothNameKinds(self):
        name_types = {type(symbol.name).__name__ for symbol in self.parsed.symbols}
        self.assertIn("bytes", name_types)
        self.assertIn("str", name_types)

    def testLanguageAnalyzerSurvivesUndecodableSymbolNames(self):
        binary_info = BinaryInfo(self.mapped)
        binary_info.raw_data = self.mapped
        binary_info.base_addr = 0x140000000
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        analyzer = LanguageAnalyzer(SimpleNamespace(binary_info=binary_info))
        score, count = analyzer.getCppSymbolScore()
        self.assertIsInstance(score, float)
        self.assertIsInstance(count, int)

    def testPeSymbolProviderSurvivesMappedCoffTable(self):
        symbols = PeSymbolProvider(None).parseSymbols(self.parsed, 0x140000000)
        self.assertIsInstance(symbols, dict)
        self.assertTrue(all(isinstance(name, str) for name in symbols.values()))


class ProviderNameNormalizationTest(unittest.TestCase):
    def testPeExportWithUndecodableNameIsSkipped(self):
        export = SimpleNamespace(
            entries=[
                SimpleNamespace(name=UNDECODABLE, address=0x1000, is_extern=False, is_forwarded=False),
                SimpleNamespace(name="ok_export", address=0x2000, is_extern=False, is_forwarded=False),
            ]
        )
        binary = SimpleNamespace(get_export=lambda: export, imagebase=0x400000)
        self.assertEqual(PeSymbolProvider(None).parseExports(binary, 0x400000), {0x402000: "ok_export"})

    def testPeCoffSymbolWithUndecodableNameIsSkipped(self):
        binary = SimpleNamespace(
            sections=[SimpleNamespace(virtual_address=0x1000)],
            symbols=[
                SimpleNamespace(
                    name=UNDECODABLE, value=0x10, section_idx=1, complex_type=SimpleNamespace(name="FUNCTION")
                ),
                SimpleNamespace(name="named", value=0x20, section_idx=1, complex_type=SimpleNamespace(name="FUNCTION")),
            ],
            imagebase=0x400000,
        )
        self.assertEqual(PeSymbolProvider(None).parseSymbols(binary, 0x400000), {0x401020: "named"})

    def testPeImportWithUndecodableNameFallsBackToOrdinal(self):
        library = SimpleNamespace(
            name=UNDECODABLE,
            entries=[
                SimpleNamespace(name=UNDECODABLE, iat_address=0x100, is_ordinal=True, ordinal=7),
                SimpleNamespace(name="CreateFileW", iat_address=0x108, is_ordinal=False, ordinal=0),
            ],
        )
        imports = parse_pe_imports(SimpleNamespace(imports=[library], imagebase=0x400000), 0x400000)
        self.assertEqual(imports[0x400100], ("", "#7"))
        self.assertEqual(imports[0x400108], ("", "CreateFileW"))

    def testPeDelayImportWithUndecodableNameFallsBackToOrdinal(self):
        delay = SimpleNamespace(
            name=UNDECODABLE,
            iat=0x200,
            entries=[
                SimpleNamespace(name=UNDECODABLE, is_ordinal=True, ordinal=3),
                SimpleNamespace(name="SomeApi", is_ordinal=False, ordinal=0),
            ],
        )
        binary = SimpleNamespace(
            delay_imports=[delay],
            has_delay_imports=True,
            optional_header=SimpleNamespace(magic=lief.PE.PE_TYPE.PE32_PLUS),
            imagebase=0x400000,
        )
        imports = parse_pe_delay_imports(binary, 0x400000)
        self.assertEqual(imports[0x400200], ("", "#3"))
        self.assertEqual(imports[0x400208], ("", "SomeApi"))

    @staticmethod
    def _elf_relocation(name, address, version_name=None):
        auxiliary = SimpleNamespace(name=version_name) if version_name is not None else None
        symbol = SimpleNamespace(
            name=name,
            imported=True,
            is_function=True,
            has_version=auxiliary is not None,
            symbol_version=(
                SimpleNamespace(has_auxiliary_version=True, symbol_version_auxiliary=auxiliary)
                if auxiliary is not None
                else None
            ),
        )
        return SimpleNamespace(has_symbol=True, symbol=symbol, address=address)

    def testElfRelocationImportNamesAreNormalized(self):
        parsed = _FakeElfBinary(
            [
                self._elf_relocation(UNDECODABLE, 0x1000),
                self._elf_relocation("puts", 0x1008, version_name=UNDECODABLE),
                self._elf_relocation("printf", 0x1010, version_name="GLIBC_2.2.5"),
            ]
        )
        with mock.patch.object(import_parsers, "lief", _patched_lief()):
            imports = parse_elf_relocation_imports(parsed)
        self.assertNotIn(0x1000, imports)
        self.assertEqual(imports[0x1008], (None, "puts"))
        self.assertEqual(imports[0x1010], ("GLIBC_2.2.5", "printf"))

    def testMachoBindingNamesAreNormalized(self):
        parsed = _FakeMachoBinary(
            [
                SimpleNamespace(
                    address=0x1000,
                    has_symbol=True,
                    symbol=SimpleNamespace(name=UNDECODABLE),
                    has_library=False,
                    library=None,
                ),
                SimpleNamespace(
                    address=0x1008,
                    has_symbol=True,
                    symbol=SimpleNamespace(name="_malloc"),
                    has_library=True,
                    library=SimpleNamespace(name="/usr/lib/libSystem.B.dylib"),
                ),
            ]
        )
        with mock.patch.object(import_parsers, "lief", _patched_lief()):
            imports = parse_macho_bindings(parsed, adjustment=0x10)
        self.assertNotIn(0x1010, imports)
        self.assertEqual(imports[0x1018], ("/usr/lib/libsystem.b.dylib", "_malloc"))

    def testMachoSymbolProviderNormalizesBothNameSlots(self):
        self.assertEqual(MachoSymbolProvider._get_symbol_name(SimpleNamespace(name=UNDECODABLE)), "")
        self.assertEqual(MachoSymbolProvider._format_symbol_name(SimpleNamespace(name=UNDECODABLE)), "")
        named = SimpleNamespace(name="_start", demangled_name=UNDECODABLE)
        self.assertEqual(MachoSymbolProvider._format_symbol_name(named), "_start")

    def testRustProviderSkipsUndecodableSymbols(self):
        provider = RustSymbolProvider(None)
        recovered = provider._parse_lief_symbols(
            [
                SimpleNamespace(name=UNDECODABLE, is_function=True, value=0x1000, shndx=1, imported=False),
                SimpleNamespace(name="_RNvC4main3foo", is_function=True, value=0x2000, shndx=1, imported=False),
            ]
        )
        self.assertNotIn(0x1000, recovered)
        self.assertIn(0x2000, recovered)


class CodeSectionNameTest(unittest.TestCase):
    def testUndecodableSectionNameBecomesEmptyString(self):
        binary_info = BinaryInfo(b"MZ")
        binary_info.base_addr = 0x400000
        binary_info._lief_binary = SimpleNamespace(
            sections=[
                SimpleNamespace(name=UNDECODABLE, virtual_address=0x1000, virtual_size=0x1000, sizeof_raw_data=0x1000)
            ]
        )
        binary_info._lief_type = "PE"
        binary_info._symbol_provider = PeSymbolProvider(None)
        self.assertEqual([entry[0] for entry in binary_info.getSections()], [""])


if __name__ == "__main__":
    unittest.main()
