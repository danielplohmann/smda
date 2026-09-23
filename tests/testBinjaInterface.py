import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from smda.binja.BinjaInterface import BinjaInterface


class _FakeBlock:
    def __init__(self, start, lengths, successors=()):
        self.start = start
        self._lengths = lengths
        self.outgoing_edges = [SimpleNamespace(target=SimpleNamespace(start=target)) for target in successors]

    def __iter__(self):
        return iter([([], length) for length in self._lengths])


class _FakeFunction:
    def __init__(self, start, name, blocks, call_sites=()):
        self.start = start
        self.name = name
        self.symbol = SimpleNamespace(raw_name=name)
        self.basic_blocks = blocks
        self.call_sites = [SimpleNamespace(address=address) for address in call_sites]


class _FakeBinaryView:
    """x64 image at 0x401000: main() calls helper(), helper() returns, both as straight-line blocks."""

    CODE = {
        0x401000: bytes.fromhex("e805000000"),
        0x401005: bytes.fromhex("c3"),
        0x40100A: bytes.fromhex("31c0"),
        0x40100C: bytes.fromhex("c3"),
    }

    def __init__(self, arch_name="x86_64"):
        self.arch = SimpleNamespace(name=arch_name, address_size=8)
        self.functions = [
            _FakeFunction(0x401000, "main", [_FakeBlock(0x401000, [5, 1])], call_sites=[0x401000]),
            _FakeFunction(0x40100A, "sub_40100a", [_FakeBlock(0x40100A, [2, 1])]),
        ]
        self.file = SimpleNamespace(original_filename="/tmp/sample.exe", filename="/tmp/sample.bndb")
        self.segments = [
            SimpleNamespace(start=0x401000, end=0x401010, data_length=0x10),
            SimpleNamespace(start=0x402000, end=0x402008, data_length=8),
        ]
        self.calls = 0

    def get_function_at(self, offset):
        return next((function for function in self.functions if function.start == offset), None)

    def get_instruction_length(self, offset):
        return len(self.CODE.get(offset, b""))

    def read(self, offset, length):
        if offset == 0x402000:
            return b"\x11" * length
        image = b"".join(self.CODE[address] for address in sorted(self.CODE))
        start = offset - 0x401000
        return image[start : start + length].ljust(length, b"\x00")

    def get_callees(self, address, func=None):
        self.calls += 1
        return [0x40100A] if address == 0x401000 else []

    def get_symbols(self):
        return [
            SimpleNamespace(
                type=SimpleNamespace(name="ImportAddressSymbol"),
                address=0x402000,
                raw_name="ExitProcess",
                namespace="KERNEL32.dll",
            ),
            SimpleNamespace(
                type=SimpleNamespace(name="ImportedFunctionSymbol"),
                address=0x402008,
                raw_name="__libc_start_main",
                namespace="BNINTERNALNAMESPACE",
            ),
            SimpleNamespace(
                type=SimpleNamespace(name="FunctionSymbol"), address=0x401000, raw_name="main", namespace=None
            ),
        ]

    def get_sections_at(self, offset):
        return [SimpleNamespace(name=".text")]


class BinjaInterfaceTest(unittest.TestCase):
    def setUp(self):
        self.bv = _FakeBinaryView()
        self.interface = BinjaInterface(self.bv)

    def test_architecture_and_bitness(self):
        self.assertEqual(self.interface.getArchitecture(), "intel")
        self.assertEqual(self.interface.getBitness(), 64)
        self.assertEqual(BinjaInterface(_FakeBinaryView("aarch64")).getArchitecture(), "aarch64")
        with self.assertRaises(ValueError):
            BinjaInterface(_FakeBinaryView("mips32")).getArchitecture()

    def test_functions_and_blocks(self):
        self.assertEqual(self.interface.getFunctions(), [0x401000, 0x40100A])
        self.assertEqual(self.interface.getBlocks(0x401000), [[0x401000, 0x401005]])
        self.assertEqual(self.interface.getBlocks(0x401234), [])
        self.assertEqual(self.interface.getInstructionBytes(0x401000), bytes.fromhex("e805000000"))
        self.assertEqual(self.interface.getInstructionBytes(0x401234), b"")

    def test_code_refs_are_fallthrough_and_calls(self):
        self.assertEqual(self.interface.getCodeOutRefs(0x401000), [(0x401000, 0x401005), (0x401000, 0x40100A)])
        self.assertEqual(self.interface.getCodeOutRefs(0x401005), [])
        self.assertEqual(self.interface.getCodeInRefs(0x40100A), [(0x401000, 0x40100A)])
        self.interface.getCodeOutRefs(0x40100A)
        self.assertEqual(self.bv.calls, 1)

    def test_block_successors_are_edges_from_the_last_instruction(self):
        self.bv.functions[1].basic_blocks = [
            _FakeBlock(0x40100A, [2], successors=[0x40100C]),
            _FakeBlock(0x40100C, [1]),
        ]
        self.assertEqual(self.interface.getCodeOutRefs(0x40100A), [(0x40100A, 0x40100C)])
        self.assertEqual(self.interface.getBlocks(0x40100A), [[0x40100A], [0x40100C]])

    def test_function_symbols_skip_auto_names(self):
        self.bv.functions.append(_FakeFunction(0x401020, "j_sub_40100a", [_FakeBlock(0x401020, [5])]))
        self.assertEqual(self.interface.getFunctionSymbols(), {0x401000: "main"})

    def test_function_symbols_demangle_through_one_config(self):
        self.bv.functions[0].symbol.raw_name = "_Z4mainv"
        demangle_any = mock.Mock(
            side_effect=lambda raw_name, config: SimpleNamespace(name="main()") if raw_name == "_Z4mainv" else None
        )
        binaryninja = types.SimpleNamespace(
            DemanglerConfig=SimpleNamespace(for_binary_view=mock.Mock(return_value="config")), demangle_any=demangle_any
        )
        with mock.patch.dict(sys.modules, {"binaryninja": binaryninja}):
            self.assertEqual(self.interface.getFunctionSymbols(demangle=True), {0x401000: "main()"})
        binaryninja.DemanglerConfig.for_binary_view.assert_called_once_with(self.bv)
        demangle_any.assert_any_call("_Z4mainv", "config")

    def test_image_never_grows_past_the_last_segment(self):
        self.bv.segments[1].data_length = 0x100
        self.assertEqual(len(self.interface.getBinary()), 0x2008)

    def test_image_is_page_aligned_and_zero_filled(self):
        self.assertEqual(self.interface.getBaseAddr(), 0x400000)
        image = self.interface.getBinary()
        self.assertEqual(len(image), 0x2008)
        self.assertEqual(image[:0x1000], b"\x00" * 0x1000)
        self.assertEqual(image[0x1000:0x1009], bytes.fromhex("e805000000c331c0c3"))
        self.assertEqual(image[0x2000:], b"\x11" * 8)

    def test_empty_view(self):
        self.bv.segments = []
        self.assertEqual(self.interface.getBaseAddr(), 0)
        self.assertEqual(self.interface.getBinary(), b"")

    def test_api_map_prefixes_the_module(self):
        self.assertEqual(
            self.interface.getApiMap(), {0x402000: "KERNEL32.dll!ExitProcess", 0x402008: "__libc_start_main"}
        )

    def test_external_functions_live_in_synthetic_sections(self):
        self.assertFalse(self.interface.isExternalFunction(0x401000))
        self.bv.get_sections_at = lambda offset: [SimpleNamespace(name=".extern")]
        self.assertTrue(self.interface.isExternalFunction(0x401000))


class BinjaInterfaceWriteTest(unittest.TestCase):
    def setUp(self):
        self.bv = _FakeBinaryView()
        self.bv.create_user_function = mock.Mock(return_value=object())
        self.bv.define_user_symbol = mock.Mock()
        self.interface = BinjaInterface(self.bv)

    def test_file_path_is_the_open_file(self):
        self.assertEqual(self.interface.getFilePath(), "/tmp/sample.bndb")
        self.bv.file.filename = ""
        self.assertEqual(self.interface.getFilePath(), "/tmp/sample.exe")

    def test_make_function_only_creates_missing_functions(self):
        self.assertFalse(self.interface.makeFunction(0x401000))
        self.bv.create_user_function.assert_not_called()
        self.interface.getCodeOutRefs(0x401000)
        self.assertTrue(self.interface.makeFunction(0x401020))
        self.bv.create_user_function.assert_called_once_with(0x401020)
        self.assertIsNone(self.interface._code_refs)
        self.bv.create_user_function.return_value = None
        self.assertFalse(self.interface.makeFunction(0x401030))

    def test_make_name_only_replaces_default_names(self):
        symbol = mock.Mock(return_value="symbol")
        with mock.patch.dict(sys.modules, {"binaryninja": types.SimpleNamespace(Symbol=symbol)}):
            self.assertFalse(self.interface.makeName(0x401000, "entry"))
            self.assertTrue(self.interface.makeName(0x40100A, "helper"))
            self.assertTrue(self.interface.makeName(0x401020, "new"))
        symbol.assert_has_calls(
            [mock.call("FunctionSymbol", 0x40100A, "helper"), mock.call("FunctionSymbol", 0x401020, "new")]
        )
        self.assertEqual(self.bv.define_user_symbol.call_count, 2)
