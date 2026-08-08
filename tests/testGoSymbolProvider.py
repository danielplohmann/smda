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


if __name__ == "__main__":
    unittest.main()
