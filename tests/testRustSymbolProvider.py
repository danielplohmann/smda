import unittest
from concurrent.futures import ThreadPoolExecutor

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.rust_demangler import demangle
from smda.common.labelprovider.rust_demangler.rust import TypeNotFoundError
from smda.common.labelprovider.rust_demangler.rust_v0 import (
    Printer,
    UnableTov0Demangle,
)
from smda.common.labelprovider.rust_demangler.utils import remove_bad_spaces
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider


class MockSymbol:
    def __init__(self, name, value, is_function=True, demangled_name=None):
        self.name = name
        self.value = value
        self.is_function = is_function
        self._demangled_name = demangled_name
        self.complex_type = type("obj", (object,), {"name": "FUNCTION"})

    @property
    def demangled_name(self):
        if self._demangled_name is None:
            raise AttributeError("No demangled name available")
        return self._demangled_name


class MockLiefBinary:
    def __init__(self, symbols, exported_functions=None):
        self.header = type("obj", (object,), {"entrypoint": 0})
        self.exported_functions = exported_functions if exported_functions else []
        self.symtab_symbols = symbols
        self.dynamic_symbols = []
        self.relocations = []
        self.imagebase = 0x400000
        self.sections = []
        self.symbols = symbols
        self.imports = []


class MockSection:
    def __init__(self, characteristics, virtual_address):
        self.characteristics = characteristics
        self.virtual_address = virtual_address


class MockExport:
    def __init__(self, name, address):
        self.name = name
        self.address = address


class TestRustDemangler(unittest.TestCase):
    """Tests for the rust_demangler module directly."""

    def test_direct_demangling_legacy(self):
        """Test legacy Rust symbol demangling."""
        mangled = "_ZN3foo3barE"
        expected = "foo::bar"
        self.assertEqual(demangle(mangled), expected)

    def test_direct_demangling_v0(self):
        """Test v0 Rust symbol demangling."""
        mangled = "_RNvC6_123foo3bar"
        expected = "123foo::bar"
        self.assertEqual(demangle(mangled), expected)

    def test_demangling_with_double_underscore_prefix(self):
        """Test demangling with __ prefix variants."""
        # Some platforms (like macOS) use __ prefix
        mangled_legacy = "__ZN3foo3barE"
        mangled_v0 = "__RNvC6_123foo3bar"
        self.assertEqual(demangle(mangled_legacy), "foo::bar")
        self.assertEqual(demangle(mangled_v0), "123foo::bar")

    def test_demangling_rejects_bare_prefixes(self):
        """Test that bare 'R' and 'ZN' prefixes are rejected."""
        # These should raise TypeNotFoundError as they are too broad
        with self.assertRaises(TypeNotFoundError):
            demangle("ZN3foo3barE")
        with self.assertRaises(TypeNotFoundError):
            demangle("RNvC6_123foo3bar")

    def test_legacy_strict_hash(self):
        """Test that hash segments are properly handled in legacy symbols."""
        # Strict hash checking: 17h + 16 hex digits
        valid_hash = "_ZN3foo3bar17h0123456789abcdefE"
        expected = "foo::bar"
        self.assertEqual(demangle(valid_hash), expected)

    def test_v0_suffix_not_retained_between_calls(self):
        """Test that suffix state is not retained between demangle calls.

        Regression test: The global _demangler instance was retaining self.suffix
        across calls, causing symbols without dots to get stale suffixes appended.
        """
        # First demangle a symbol that would have a suffix (contains .llvm.)
        # Note: .llvm. suffix gets stripped during processing
        symbol_with_suffix = "_RNvC3foo3bar.llvm.1234567890abcdef"
        _result1 = demangle(symbol_with_suffix)  # noqa: F841

        # Now demangle a symbol WITHOUT any suffix
        symbol_without_suffix = "_RNvC6_123foo3bar"
        result2 = demangle(symbol_without_suffix)

        # The second result should NOT have any suffix from the first call
        self.assertEqual(result2, "123foo::bar")
        self.assertNotIn(".llvm.", result2)

    def test_v0_lifetime_letter_mapping(self):
        """Ensure lifetime indexes map to alphabet letters starting at 'a'."""

        printer = Printer(None, "", bound=1)
        printer.print_lifetime_from_index(1)
        self.assertEqual(printer.out, "'a")

        printer = Printer(None, "", bound=3)
        printer.print_lifetime_from_index(2)
        self.assertEqual(printer.out, "'b")

    def test_v0_lifetime_invalid_depth_raises(self):
        """Invalid lifetime depths should raise demangling errors."""

        printer = Printer(None, "", bound=0)
        with self.assertRaises(UnableTov0Demangle):
            printer.print_lifetime_from_index(2)

    def test_demangle_thread_safety(self):
        """Demangling should be safe when run concurrently."""

        symbols = [
            "_RNvC3foo3bar.llvm.1234567890abcdef",
            "_RNvC6_123foo3bar",
            "__RNvC6_123foo3bar",
            "_ZN3foo3barE",
        ]

        expected = [
            "foo::bar",
            "123foo::bar",
            "123foo::bar",
            "foo::bar",
        ]

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(demangle, symbols * 5))

        self.assertEqual(results, expected * 5)


class TestRustSymbolProvider(unittest.TestCase):
    """Tests for the RustSymbolProvider class."""

    def test_rust_symbol_provider_elf_logic(self):
        """Test that RustSymbolProvider correctly parses and demangles Rust symbols."""
        provider = RustSymbolProvider(None)

        sym_legacy = MockSymbol("_ZN3foo3barE", 0x1000)
        sym_v0 = MockSymbol("_RNvC6_123foo3bar", 0x2000)
        sym_normal = MockSymbol("main", 0x3000)

        symbols = [sym_legacy, sym_v0, sym_normal]

        results = provider._parse_lief_symbols(symbols)

        self.assertEqual(results[0x1000], "foo::bar")
        self.assertEqual(results[0x2000], "123foo::bar")
        # Non-Rust symbols should not be included
        self.assertNotIn(0x3000, results)

    def test_is_rust_symbol_detection(self):
        """Test _is_rust_symbol correctly identifies Rust mangled symbols."""
        provider = RustSymbolProvider(None)

        # Valid Rust prefixes
        self.assertTrue(provider._is_rust_symbol("_ZN3foo3barE"))
        self.assertTrue(provider._is_rust_symbol("_RNvC6_123foo3bar"))
        self.assertTrue(provider._is_rust_symbol("__ZN3foo3barE"))
        self.assertTrue(provider._is_rust_symbol("__RNvC6_123foo3bar"))

        # Invalid/too broad prefixes (bare R and ZN) should NOT be detected
        self.assertFalse(provider._is_rust_symbol("ZN3foo3barE"))
        self.assertFalse(provider._is_rust_symbol("RNvC6_123foo3bar"))

        # Normal symbols
        self.assertFalse(provider._is_rust_symbol("main"))
        self.assertFalse(provider._is_rust_symbol("printf"))
        self.assertFalse(provider._is_rust_symbol("_start"))

    def test_is_api_provider(self):
        """Test that RustSymbolProvider correctly reports it is not an API provider."""
        provider = RustSymbolProvider(None)
        self.assertFalse(provider.isApiProvider())
        self.assertEqual(provider.getApi(0x1000), ("", ""))

    def test_is_symbol_provider(self):
        """Test that RustSymbolProvider correctly reports it is a symbol provider."""
        provider = RustSymbolProvider(None)
        self.assertTrue(provider.isSymbolProvider())

    def test_detection_logic(self):
        """Test Rust binary detection based on signatures."""
        provider = RustSymbolProvider(None)

        # Binary with Rust signature
        bi = BinaryInfo(b"some code... /rustc/ ... more code")
        self.assertTrue(provider.is_rust_binary(bi))

        # Binary with RUST_BACKTRACE signature
        bi2 = BinaryInfo(b"RUST_BACKTRACE=1 some more data")
        self.assertTrue(provider.is_rust_binary(bi2))

        # Binary with RUST_MIN_STACK signature
        bi3 = BinaryInfo(b"RUST_MIN_STACK data here")
        self.assertTrue(provider.is_rust_binary(bi3))

        # Non-Rust binary
        bi4 = BinaryInfo(b"random binary data without rust markers")
        self.assertFalse(provider.is_rust_binary(bi4))


class TestElfSymbolProviderWithoutRustDemangling(unittest.TestCase):
    """Tests to verify ElfSymbolProvider no longer performs Rust demangling."""

    def test_elf_symbol_provider_returns_raw_rust_names(self):
        """Test that ElfSymbolProvider returns raw names (no Rust demangling)."""
        provider = ElfSymbolProvider(None)

        # Rust symbols should be returned as-is (raw names)
        sym_legacy = MockSymbol("_ZN3foo3barE", 0x1000)
        sym_v0 = MockSymbol("_RNvC6_123foo3bar", 0x2000)
        sym_normal = MockSymbol("main", 0x3000)

        symbols = [sym_legacy, sym_v0, sym_normal]

        results = provider.parseSymbols(symbols)

        # Raw Rust names should be preserved (no demangling)
        self.assertEqual(results[0x1000], "_ZN3foo3barE")
        self.assertEqual(results[0x2000], "_RNvC6_123foo3bar")
        self.assertEqual(results[0x3000], "main")


class TestPeSymbolProviderWithoutRustDemangling(unittest.TestCase):
    """Tests to verify PeSymbolProvider no longer performs Rust demangling."""

    def test_pe_symbol_provider_returns_raw_rust_names(self):
        """Test that PeSymbolProvider returns raw names (no Rust demangling)."""
        provider = PeSymbolProvider(None)

        # Test exports - should return raw names
        exp_legacy = MockExport("_ZN3foo3barE", 0x1000)
        exp_v0 = MockExport("_RNvC6_123foo3bar", 0x2000)
        exp_normal = MockExport("ExportedFunc", 0x3000)

        mock_binary = MockLiefBinary([], exported_functions=[exp_legacy, exp_v0, exp_normal])

        results = provider.parseExports(mock_binary)

        # PeSymbolProvider adds imagebase (0x400000) + address
        # Raw Rust names should be preserved (no demangling)
        self.assertEqual(results[0x401000], "_ZN3foo3barE")
        self.assertEqual(results[0x402000], "_RNvC6_123foo3bar")
        self.assertEqual(results[0x403000], "ExportedFunc")


class TestUtilityFunctions(unittest.TestCase):
    """Tests for utility functions."""

    def test_space_cleanup(self):
        """Test remove_bad_spaces utility function."""
        # Inner spaces removed
        self.assertEqual(remove_bad_spaces("Vec< T >"), "Vec<T>")
        # Separating space becomes underscore
        self.assertEqual(remove_bad_spaces("Foo< Bar Baz >"), "Foo<Bar_Baz>")


if __name__ == "__main__":
    unittest.main()
