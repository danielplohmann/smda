import logging
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from smda.binja.BinjaInterface import BinjaInterface
from smda.SmdaConfig import SmdaConfig


class _FakeBlock:
    def __init__(self, start, lengths, successors=(), arch="block-arch", invalid=False):
        self.start = start
        self.end = start + sum(lengths)
        self.arch = arch
        self.has_invalid_instructions = invalid
        self.outgoing_edges = [SimpleNamespace(target=SimpleNamespace(start=target)) for target in successors]

    def __iter__(self):
        raise AssertionError("rendering instruction text is the cost this interface avoids")


class _FakeFunction:
    def __init__(self, start, name, blocks, call_sites=(), arch="block-arch"):
        self.start = start
        self.arch = arch
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
        self.length_queries = []

    def get_function_at(self, offset, plat=None):
        return next((function for function in self.functions if function.start == offset), None)

    def get_instruction_length(self, offset, arch=None):
        self.length_queries.append((offset, arch))
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
        self.assertEqual(BinjaInterface(_FakeBinaryView("armv7")).getArchitecture(), "arm")
        self.assertEqual(BinjaInterface(_FakeBinaryView("thumb2")).getArchitecture(), "arm")
        for unsupported in ("mips32", "armv7eb", "thumb2eb"):
            with self.assertRaises(ValueError):
                BinjaInterface(_FakeBinaryView(unsupported)).getArchitecture()

    def test_functions_and_blocks(self):
        self.assertEqual(self.interface.getFunctions(), [0x401000, 0x40100A])
        self.assertEqual(self.interface.getBlocks(0x401000), [[0x401000, 0x401005]])
        self.assertEqual(self.interface.getBlocks(0x401234), [])
        self.assertEqual(self.interface.getInstructionBytes(0x401000), bytes.fromhex("e805000000"))
        self.assertEqual(self.interface.getInstructionBytes(0x401234), b"")

    def test_blocks_are_decoded_once_with_the_block_architecture(self):
        self.interface.getBlocks(0x401000)
        self.interface.getCodeOutRefs(0x401000)
        self.assertEqual(
            [query for query in self.bv.length_queries if query[0] < 0x40100A].count((0x401000, "block-arch")), 1
        )
        self.assertEqual(self.bv.length_queries.count((0x401005, "block-arch")), 1)

    def test_instruction_bytes_come_from_the_decoded_block(self):
        self.interface.getBlocks(0x401000)
        self.bv.length_queries.clear()
        self.assertEqual(self.interface.getInstructionBytes(0x401005), b"\xc3")
        self.assertEqual(self.bv.length_queries, [])

    def test_zero_length_instruction_ends_the_block(self):
        self.bv.functions[1].basic_blocks = [_FakeBlock(0x40100A, [2, 1, 4])]
        self.bv.CODE = {**self.bv.CODE, 0x40100D: b""}
        self.assertEqual(self.interface.getBlocks(0x40100A), [[0x40100A, 0x40100C]])

    def test_instruction_crossing_the_block_end_is_listed_and_read_with_the_block_architecture(self):
        self.bv.functions[0].basic_blocks = [_FakeBlock(0x401000, [3])]
        self.assertEqual(self.interface.getBlocks(0x401000), [[0x401000]])
        self.bv.length_queries.clear()
        self.assertEqual(self.interface.getInstructionBytes(0x401000), bytes.fromhex("e805000000"))
        self.assertEqual(self.bv.length_queries, [(0x401000, "block-arch")])

    def test_short_block_read_leaves_instructions_uncached(self):
        read = self.bv.read
        self.bv.read = lambda offset, length: read(offset, length)[:1]
        self.assertEqual(self.interface.getBlocks(0x401000), [[0x401000, 0x401005]])
        self.bv.read = read
        self.bv.length_queries.clear()
        self.assertEqual(self.interface.getInstructionBytes(0x401000), bytes.fromhex("e805000000"))
        self.assertEqual(self.interface.getInstructionBytes(0x401005), b"\xc3")
        self.assertEqual(self.bv.length_queries, [(0x401000, "block-arch"), (0x401005, "block-arch")])

    def test_make_function_drops_decoded_blocks(self):
        self.bv.create_user_function = lambda offset, platform: object()
        self.interface.getBlocks(0x40100A)
        self.bv.CODE = {**self.bv.CODE, 0x40100A: b"\x90", 0x40100B: b"\x31\xc0"}
        self.assertEqual(self.interface.getBlocks(0x40100A), [[0x40100A, 0x40100C]])
        self.assertTrue(self.interface.makeFunction(0x401020))
        self.assertEqual(self.interface.getBlocks(0x40100A), [[0x40100A, 0x40100B]])

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

    def test_image_is_capped_at_max_image_size(self):
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)
        self.bv.segments.append(SimpleNamespace(start=0x7FF000000000, end=0x7FF000000010, data_length=0x10))
        with (
            mock.patch.object(SmdaConfig, "MAX_IMAGE_SIZE", 0x3000),
            self.assertLogs("smda.export.segment_mapping", level="WARNING"),
        ):
            image = self.interface.getBinary()
        self.assertEqual(len(image), 0x3000)
        self.assertEqual(image[0x1000:0x1009], bytes.fromhex("e805000000c331c0c3"))
        self.assertEqual(image[0x2000:0x2008], b"\x11" * 8)

    def test_unbacked_segment_tail_is_zero_filled(self):
        self.bv.segments[1].data_length = 4
        image = self.interface.getBinary()
        self.assertEqual(len(image), 0x2008)
        self.assertEqual(image[0x2000:], b"\x11" * 4 + b"\x00" * 4)

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


class _FakeArch:
    def __init__(self, name):
        self.name = name


A32 = _FakeArch("armv7")
T32 = _FakeArch("thumb2")


class _FakeArmBinaryView(_FakeBinaryView):
    """ARM image at 0x10000: arm_main() (A32) calls thumb_helper() (T32), which branches into an A32
    PLT entry, and Binary Ninja also defined an A32 function over thumb_helper's start."""

    # A32 mov r0, #1; bx lr | T32 movs r0, #1; bx lr | A32 bx lr
    IMAGE = bytes.fromhex("0100a0e3 1eff2fe1" + "00" * 8 + "0120 7047" + "00" * 12 + "1eff2fe1")
    T32_LENGTHS = {0x10010: 2, 0x10012: 2}

    def __init__(self):
        super().__init__("armv7")
        self.arch.address_size = 4
        self.platform = mock.Mock()
        self.platform.get_associated_platform_by_address.side_effect = lambda address: (
            "thumb2-platform" if address & 1 else "armv7-platform",
            address & ~1,
        )
        self.functions = [
            _FakeFunction(0x10000, "arm_main", [_FakeBlock(0x10000, [4, 4], arch=A32)], call_sites=[0x10000], arch=A32),
            _FakeFunction(0x10010, "sub_10010", [_FakeBlock(0x10010, [4], arch=A32, invalid=True)], arch=A32),
            _FakeFunction(
                0x10010,
                "thumb_helper",
                [_FakeBlock(0x10010, [2, 2], successors=[0x10020], arch=T32), _FakeBlock(0x10020, [4], arch=A32)],
                arch=T32,
            ),
        ]
        self.segments = [SimpleNamespace(start=0x10000, end=0x10000 + len(self.IMAGE), data_length=len(self.IMAGE))]

    def get_function_at(self, offset, plat=None):
        return next(
            (
                function
                for function in self.functions
                if function.start == offset and plat in (None, f"{function.arch.name}-platform")
            ),
            None,
        )

    def get_instruction_length(self, offset, arch=None):
        self.length_queries.append((offset, arch))
        return 4 if arch is A32 else self.T32_LENGTHS.get(offset, 0)

    def read(self, offset, length):
        return self.IMAGE[offset - 0x10000 : offset - 0x10000 + length].ljust(length, b"\x00")

    def get_callees(self, address, func=None):
        return [0x10010] if address == 0x10000 else []

    def get_code_refs(self, address):
        return [SimpleNamespace(address=0x10000)] if address in (0x10000, 0x10010) else []

    def get_symbols(self):
        return []

    def overlap(self):
        """A32 mov r0, r0; vhadd.s8 d18, d0, d1; ... from 0x10000, overlapped by T32 movs r0, #1;
        movw r0, #0; bx lr from 0x10004."""
        self.IMAGE = bytes.fromhex("0000a0e1 012040f2 00007047")
        self.T32_LENGTHS = {0x10004: 2, 0x10006: 4, 0x1000A: 2}
        self.segments = [SimpleNamespace(start=0x10000, end=0x1000C, data_length=0xC)]
        self.functions = [
            _FakeFunction(0x10000, "sub_10000", [_FakeBlock(0x10000, [4, 4, 4], arch=A32)], arch=A32),
            _FakeFunction(0x10004, "sub_10004", [_FakeBlock(0x10004, [2, 4, 2], arch=T32)], arch=T32),
        ]
        return self


class BinjaInterfaceArmTest(unittest.TestCase):
    def setUp(self):
        self.bv = _FakeArmBinaryView()
        self.interface = BinjaInterface(self.bv)

    def test_architecture_and_bitness(self):
        self.assertEqual(self.interface.getArchitecture(), "arm")
        self.assertEqual(self.interface.getBitness(), 32)

    def test_a_start_defined_in_both_instruction_sets_is_the_valid_one(self):
        self.assertEqual(self.interface.getFunctions(), [0x10000, 0x10010])
        self.assertFalse(self.interface.isThumb(0x10000))
        self.assertTrue(self.interface.isThumb(0x10010))
        self.assertFalse(self.interface.isThumb(0x10030))

    def test_function_symbols_skip_a_rejected_duplicate(self):
        self.bv.functions.append(
            _FakeFunction(0x10010, "wrong_name", [_FakeBlock(0x10010, [4], arch=A32, invalid=True)], arch=A32)
        )
        self.bv.functions[1].name = "also_wrong"
        self.assertEqual(self.interface.getFunctionSymbols(), {0x10000: "arm_main", 0x10010: "thumb_helper"})

    def test_overlapping_functions_in_the_other_instruction_set_keep_the_earlier_start_on_a_tie(self):
        self.bv.overlap()
        self.assertEqual(self.interface.getFunctions(), [0x10000])
        self.assertEqual(self.interface.getBlocks(0x10000), [[0x10000, 0x10004, 0x10008]])
        self.assertEqual(self.interface.getInstructionBytes(0x10004), bytes.fromhex("012040f2"))
        self.assertEqual(self.interface.getCodeOutRefs(0x10004), [(0x10004, 0x10008)])

    def test_overlapping_functions_in_the_other_instruction_set_keep_the_referenced_one(self):
        self.bv.overlap()
        self.bv.get_code_refs = lambda address: [SimpleNamespace(address=0x20000)] if address == 0x10004 else []
        self.assertEqual(self.interface.getFunctions(), [0x10004])
        self.assertTrue(self.interface.isThumb(0x10004))
        self.assertEqual(self.interface.getCodeOutRefs(0x10004), [(0x10004, 0x10006)])
        self.assertEqual(self.interface.getCodeInRefs(0x10004), [])

    def test_a_function_rejected_only_by_a_rejected_rival_is_kept(self):
        # A32 a and c each overlap T32 b, not each other; c outranks b, which outranks a
        self.bv.functions = [
            _FakeFunction(0x10000, "a", [_FakeBlock(0x10000, [4, 4], arch=A32)], arch=A32),
            _FakeFunction(0x10004, "b", [_FakeBlock(0x10004, [2, 4, 2], arch=T32)], arch=T32),
            _FakeFunction(0x10008, "c", [_FakeBlock(0x10008, [4, 4], arch=A32)], arch=A32),
        ]
        references = {0x10004: 1, 0x10008: 2}
        self.bv.get_code_refs = lambda address: [SimpleNamespace(address=0)] * references.get(address, 0)
        self.assertEqual(self.interface.getFunctions(), [0x10000, 0x10008])
        self.assertEqual(self.interface.getFunctionSymbols(), {0x10000: "a", 0x10008: "c"})

    def test_blocks_in_the_other_instruction_set_add_no_code_refs(self):
        # thumb_helper's A32 PLT block at 0x10020 continues to 0x10030; a T32 function also starts there
        self.bv.functions[2].basic_blocks[1] = _FakeBlock(0x10020, [4], successors=[0x10030], arch=A32)
        self.bv.functions.append(
            _FakeFunction(0x10020, "thumb_tail", [_FakeBlock(0x10020, [2, 2], arch=T32)], arch=T32)
        )
        self.bv.T32_LENGTHS = {**self.bv.T32_LENGTHS, 0x10020: 2, 0x10022: 2}
        self.assertEqual(self.interface.getFunctions(), [0x10000, 0x10010, 0x10020])
        self.assertEqual(self.interface.getBlocks(0x10020), [[0x10020, 0x10022]])
        self.assertEqual(self.interface.getCodeOutRefs(0x10020), [(0x10020, 0x10022)])
        self.assertEqual(self.interface.getCodeInRefs(0x10030), [])

    def test_blocks_in_the_other_instruction_set_are_left_out(self):
        self.assertEqual(self.interface.getBlocks(0x10010), [[0x10010, 0x10012]])
        self.assertEqual(self.interface.getInstructionBytes(0x10012), bytes.fromhex("7047"))
        self.assertEqual(self.interface.getCodeOutRefs(0x10012), [(0x10012, 0x10020)])

    def test_make_function_picks_the_instruction_set(self):
        self.bv.create_user_function = mock.Mock(return_value=object())
        self.assertTrue(self.interface.makeFunction(0x10040, thumb=True))
        self.assertTrue(self.interface.makeFunction(0x10051))
        self.assertTrue(self.interface.makeFunction(0x10060))
        self.assertFalse(self.interface.makeFunction(0x10011))
        self.assertFalse(self.interface.makeFunction(0x10000))
        self.bv.create_user_function.assert_has_calls(
            [
                mock.call(0x10040, "thumb2-platform"),
                mock.call(0x10050, "thumb2-platform"),
                mock.call(0x10060, "armv7-platform"),
            ]
        )
        self.assertEqual(self.bv.create_user_function.call_count, 3)

    def test_make_function_adds_the_other_instruction_set_at_a_start(self):
        self.bv.create_user_function = mock.Mock(return_value=object())
        self.assertTrue(self.interface.makeFunction(0x10000, thumb=True))
        self.bv.create_user_function.assert_called_once_with(0x10000, "thumb2-platform")

    def test_make_name_drops_the_thumb_bit(self):
        self.bv.define_user_symbol = mock.Mock()
        symbol = mock.Mock(return_value="symbol")
        with mock.patch.dict(sys.modules, {"binaryninja": types.SimpleNamespace(Symbol=symbol)}):
            self.assertTrue(self.interface.makeName(0x10041, "helper"))
        symbol.assert_called_once_with("FunctionSymbol", 0x10040, "helper")


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
        self.bv.create_user_function.assert_called_once_with(0x401020, None)
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
