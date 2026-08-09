import pathlib
import struct
import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider


def _build_truncated_pclntab_116_64():
    buf = bytearray(0xC0)
    buf[0:4] = struct.pack("<I", 0xFFFFFFFA)
    buf[4:6] = b"\x00\x00"
    buf[6] = 1
    buf[7] = 8
    fields = [2, 0, 0x80, 0, 0, 0, 0x90]
    buf[8 : 8 + 56] = struct.pack("<7Q", *fields)
    buf[0x80:0x90] = b"main.f\x00main.g\x00\x00\x00"
    buf[0x90:0x98] = struct.pack("<Q", 0x100)
    buf[0x98:0xA0] = struct.pack("<Q", 0)
    buf[0xA0:0xA8] = struct.pack("<Q", 0x200)
    buf[0xA8:0xB0] = struct.pack("<Q", 0)
    buf[0xB0:0xB4] = struct.pack("<I", 0x100)
    buf[0xB4:0xB8] = b"\x00" * 4
    buf[0xB8:0xBC] = struct.pack("<I", 0)
    buf[0xBC:0xC0] = struct.pack("<I", 0xDEAD)
    return bytes(buf)


class TestGoSymbolProvider(unittest.TestCase):
    def test_truncated_pclntab_yields_partial_symbols(self):
        provider = GoSymbolProvider(None)
        binary = _build_truncated_pclntab_116_64()
        result = provider._parse_pclntab(0, binary)
        self.assertEqual(result, {0x100: "main.f"})


class TestPcLntabOffsetValidation(unittest.TestCase):
    def test_a_candidate_offset_without_a_header_falls_back_to_the_scan(self):
        provider = GoSymbolProvider(None)
        header = b"\xfb\xff\xff\xff\x00\x00\x01\x08"
        binary = b"\x00" * 0x40 + header + b"\x00" * 0x40

        class _StubBinaryInfo:
            pass

        binary_info = _StubBinaryInfo()
        binary_info.binary = binary
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.getLiefBinary = lambda: None

        self.assertEqual(provider.getPcLntabOffset(binary_info), 0x40)
        self.assertEqual(provider._readPcLntabHeader(binary, 0x40)["version"], "1.12")
        self.assertIsNone(provider._readPcLntabHeader(binary, 0x10))

    def test_truncated_function_table_stops_instead_of_raising(self):
        provider = GoSymbolProvider(None)
        header = b"\xfb\xff\xff\xff\x00\x00\x01\x08"
        # claims 64 functions but carries no table bytes at all
        binary = header + struct.pack("<Q", 64) + b"\x00" * 8

        self.assertEqual(provider._parse_pclntab(0, binary), {})


def _pclntab(magic, fields, table_bytes=b"", buffer_len=0x100):
    """Header plus the field block each version reads, with a deliberately short table."""
    buf = bytearray(buffer_len)
    buf[0:4] = struct.pack("<I", magic)
    buf[4:6] = b"\x00\x00"
    buf[6] = 1
    buf[7] = 8
    buf[8 : 8 + 8 * len(fields)] = struct.pack("<" + "Q" * len(fields), *fields)
    if table_bytes:
        buf[0x80 : 0x80 + len(table_bytes)] = table_bytes
    return bytes(buf)


class TestTruncatedPcLntabTables(unittest.TestCase):
    def test_a_truncated_116_table_stops_instead_of_raising(self):
        # 64 claimed functions, table starts 8 bytes before the end of the buffer
        binary = _pclntab(0xFFFFFFFA, [64, 0, 0x80, 0, 0, 0, 0xF8])

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {})

    def test_a_truncated_118_table_stops_instead_of_raising(self):
        binary = _pclntab(0xFFFFFFF0, [64, 0, 0, 0x80, 0, 0, 0, 0xFC])

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {})

    def test_a_112_entry_whose_func_info_runs_past_the_buffer_is_skipped(self):
        # one function whose func-info offset points at the last 8 bytes, so the name
        # offset read at info_offset + 8 would run past the end
        buf = bytearray(0x100)
        buf[0:4] = struct.pack("<I", 0xFFFFFFFB)
        buf[4:6] = b"\x00\x00"
        buf[6] = 1
        buf[7] = 8
        buf[8:12] = struct.pack("<I", 1)
        buf[16:24] = struct.pack("<Q", 0x1000)
        buf[24:32] = struct.pack("<Q", 0xF8)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, bytes(buf)), {})


class TestPcLntabHeaderBounds(unittest.TestCase):
    def test_an_offset_past_the_buffer_has_no_header(self):
        binary = b"\xfb\xff\xff\xff\x00\x00\x01\x08" + b"\x00" * 8

        self.assertIsNone(GoSymbolProvider._readPcLntabHeader(binary, len(binary)))
        self.assertIsNone(GoSymbolProvider._readPcLntabHeader(binary, len(binary) - 4))
        self.assertIsNone(GoSymbolProvider._readPcLntabHeader(binary, -1))

    def test_a_well_formed_112_entry_still_resolves_its_name(self):
        buf = bytearray(0x100)
        buf[0:4] = struct.pack("<I", 0xFFFFFFFB)
        buf[4:6] = b"\x00\x00"
        buf[6] = 1
        buf[7] = 8
        buf[8:12] = struct.pack("<I", 1)
        buf[16:24] = struct.pack("<Q", 0x2000)
        buf[24:32] = struct.pack("<Q", 0x40)
        buf[0x48:0x50] = struct.pack("<Q", 0x80)
        buf[0x80:0x8A] = b"main.main\x00"

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, bytes(buf)), {0x2000: "main.main"})


class TestBigEndianPcLntab(unittest.TestCase):
    """Offset discovery accepts either byte order, so the parser has to as well."""

    @staticmethod
    def _table_112(endianness):
        buf = bytearray(0x100)
        buf[0:4] = struct.pack(endianness + "I", 0xFFFFFFFB)
        buf[4:6] = b"\x00\x00"
        buf[6] = 1
        buf[7] = 8
        buf[8:12] = struct.pack(endianness + "I", 1)
        buf[16:24] = struct.pack(endianness + "Q", 0x2000)
        buf[24:32] = struct.pack(endianness + "Q", 0x40)
        buf[0x48:0x50] = struct.pack(endianness + "Q", 0x80)
        buf[0x80:0x8A] = b"main.main\x00"
        return bytes(buf)

    @staticmethod
    def _table_120(endianness):
        buf = bytearray(0x200)
        buf[0:4] = struct.pack(endianness + "I", 0xFFFFFFF1)
        buf[4:6] = b"\x00\x00"
        buf[6] = 1
        buf[7] = 8
        fields = (1, 0, 0x1000, 0x100, 0, 0, 0, 0x80)
        buf[8:72] = struct.pack(endianness + "Q" * 8, *fields)
        buf[0x80:0x84] = struct.pack(endianness + "I", 0x2000)
        buf[0x88:0x8C] = struct.pack(endianness + "I", 0x2000)
        buf[0x8C:0x90] = struct.pack(endianness + "I", 0x40)
        buf[0x140:0x14A] = b"main.main\x00"
        return bytes(buf)

    def test_both_byte_orders_recover_the_same_symbols(self):
        for name, builder, expected in (
            ("1.12", self._table_112, {0x2000: "main.main"}),
            ("1.20", self._table_120, {0x3000: "main.main"}),
        ):
            for endianness in ("<", ">"):
                with self.subTest(version=name, endianness=endianness):
                    binary = builder(endianness)
                    self.assertIsNotNone(GoSymbolProvider._readPcLntabHeader(binary, 0))
                    self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), expected)

    def test_an_unknown_marker_is_still_rejected(self):
        binary = struct.pack("<I", 0xFFFFFFEE) + b"\x00\x00\x01\x08" + b"\x00" * 0x40

        with self.assertRaises(ValueError):
            GoSymbolProvider(None)._parse_pclntab(0, binary)


def _table_116_64(endianness, text_base, name_bytes=b"main.main\x00"):
    """A 1.16 table with one function, whose _func opens with a pointer-wide entry address."""
    buf = bytearray(0x200)
    buf[0:4] = struct.pack(endianness + "I", 0xFFFFFFFA)
    buf[4:6] = b"\x00\x00"
    buf[6] = 1
    buf[7] = 8
    # nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
    buf[8:64] = struct.pack(endianness + "Q" * 7, 1, 0, 0x40, 0, 0, 0, 0x80)
    # a decoy at name offset 0, so reading the wrong field (or none) cannot pass by accident
    buf[0x40:0x48] = b"decoy\x00\x00\x00"
    buf[0x48 : 0x48 + len(name_bytes)] = name_bytes
    # functab: entry address, then the offset of its _func
    buf[0x80:0x88] = struct.pack(endianness + "Q", text_base)
    buf[0x88:0x90] = struct.pack(endianness + "Q", 0x10)
    # _func: the same entry address, pointer-wide, then a uint32 name offset
    buf[0x90:0x98] = struct.pack(endianness + "Q", text_base)
    buf[0x98:0x9C] = struct.pack(endianness + "I", 8)
    return bytes(buf)


class TestPcLntab116EntryWidth(unittest.TestCase):
    """A 1.16 _func entry is pointer-wide; reading half of it matches the wrong bytes."""

    def test_a_text_base_above_four_gigabytes_still_resolves(self):
        # a 64-bit Mach-O image is based at 0x100000000, so the entry does not fit in 32 bits
        binary = _table_116_64("<", 0x100001000)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {0x100001000: "main.main"})

    def test_a_big_endian_table_resolves_the_name_and_not_a_neighbouring_field(self):
        binary = _table_116_64(">", 0x400000)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {0x400000: "main.main"})

    def test_a_middle_dot_is_rendered_the_way_go_renders_it(self):
        # debug/gosym maps U+00B7 to a period; compiler-generated wrappers carry it
        binary = _table_116_64("<", 0x400000, name_bytes="main.run·dwrap·1\x00".encode())

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {0x400000: "main.run.dwrap.1"})


def _table_118_or_120(magic, text_start_field, name_bytes=b"main.main\x00"):
    """A 1.18/1.20 table with one function, whose entry is an offset from the text start."""
    buf = bytearray(0x200)
    buf[0:4] = struct.pack("<I", magic)
    buf[4:6] = b"\x00\x00"
    buf[6] = 1
    buf[7] = 8
    # nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
    # the eight-quadword field block runs to 0x48, so the name table has to start past it
    buf[8:72] = struct.pack("<8Q", 1, 0, text_start_field, 0xC0, 0, 0, 0, 0x80)
    buf[0xC0:0xC8] = b"decoy\x00\x00\x00"
    buf[0xC8 : 0xC8 + len(name_bytes)] = name_bytes
    # functab: entry offset, then the offset of its _func
    buf[0x80:0x84] = struct.pack("<I", 0x1000)
    buf[0x88:0x8C] = struct.pack("<I", 0x1000)
    buf[0x8C:0x90] = struct.pack("<I", 8)
    return bytes(buf)


class TestPcLntabTextStart(unittest.TestCase):
    """Go stopped maintaining the header's text start, so the container has to supply it."""

    def test_a_supplied_text_start_wins_over_the_header_field(self):
        # an externally linked build leaves the header field at 0 and its entries relative
        binary = _table_118_or_120(0xFFFFFFF1, 0)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {0x1000: "main.main"})
        self.assertEqual(
            GoSymbolProvider(None)._parse_pclntab(0, binary, 0x100001B30),
            {0x100002B30: "main.main"},
        )

    def test_the_header_field_is_still_used_when_the_container_offers_nothing(self):
        binary = _table_118_or_120(0xFFFFFFF0, 0x400000)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary), {0x401000: "main.main"})

    def test_a_supplied_text_start_of_zero_is_honoured_rather_than_treated_as_absent(self):
        binary = _table_118_or_120(0xFFFFFFF1, 0x400000)

        self.assertEqual(GoSymbolProvider(None)._parse_pclntab(0, binary, 0), {0x1000: "main.main"})


def _fixture(name):
    raw = (pathlib.Path(__file__).resolve().parent / name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class TestTextStartSources(unittest.TestCase):
    """Where the text start comes from when no runtime.text symbol is available."""

    def test_an_elf_falls_back_to_its_text_section(self):
        binary_info = BinaryInfo(_fixture("bashlite_xored"))

        self.assertEqual(GoSymbolProvider(None).getTextStart(binary_info), 0x400100)

    def test_a_pe_section_address_is_lifted_by_the_image_base(self):
        # LIEF reports a PE section address as an RVA, unlike ELF and Mach-O
        binary_info = BinaryInfo(_fixture("pe_export_label_test_xored"))
        lief_binary = binary_info.getLiefBinary()

        text_start = GoSymbolProvider(None).getTextStart(binary_info)

        self.assertEqual(text_start, lief_binary.get_section(".text").virtual_address + lief_binary.imagebase)

    def test_a_container_without_a_text_section_offers_nothing(self):
        stub = SimpleNamespace(
            getLiefBinary=lambda: SimpleNamespace(symbols=[], get_section=lambda name: None),
            bitness=64,
            architecture="intel",
        )

        self.assertIsNone(GoSymbolProvider(None).getTextStart(stub))

    def test_a_container_that_cannot_be_read_offers_nothing(self):
        def _explode():
            raise ValueError("unreadable container")

        stub = SimpleNamespace(getLiefBinary=_explode, bitness=64, architecture="intel")

        self.assertIsNone(GoSymbolProvider(None).getTextStart(stub))


class TestPcLntabBitnessMarker(unittest.TestCase):
    def test_an_unrecognized_pointer_size_is_rejected(self):
        binary = bytearray(_table_116_64("<", 0x400000))
        binary[7] = 2

        with self.assertRaises(ValueError):
            GoSymbolProvider(None)._parse_pclntab(0, bytes(binary))


class TestGoProviderCapabilities(unittest.TestCase):
    def test_a_symbol_only_provider_resolves_no_api(self):
        # the dispatcher never asks, because isApiProvider is False, but the pair it would
        # get has to be the empty one every other provider returns for "not mine"
        provider = GoSymbolProvider(None)

        self.assertFalse(provider.isApiProvider())
        self.assertTrue(provider.isSymbolProvider())
        self.assertEqual(provider.getApi(0x401000), ("", ""))


if __name__ == "__main__":
    unittest.main()
