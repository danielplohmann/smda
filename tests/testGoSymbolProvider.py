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


if __name__ == "__main__":
    unittest.main()
