import struct
import unittest

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


if __name__ == "__main__":
    unittest.main()
