import struct
import threading
import unittest

from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider

KB_MAGIC = b"IDR Knowledge Base File"
BASE_ADDR = 0x400000


def build_valid_kb(module_names, functions):
    """functions: list of (mod_id, name, dump bytes)."""
    buf = bytearray(KB_MAGIC)
    module_offsets = {}
    for mod_id, name in module_names.items():
        module_offsets[mod_id] = len(buf)
        buf += struct.pack("<H", mod_id)
        buf += struct.pack("<H", len(name)) + name.encode()
    function_offsets = []
    expected_symbols = {}
    for mod_id, name, dump in functions:
        function_offsets.append(len(buf))
        buf += struct.pack("<H", mod_id)
        buf += struct.pack("<H", len(name)) + name.encode()
        buf += b"\x00" * 9
        buf += struct.pack("<H", 0)
        buf += b"\x00" * 5
        buf += struct.pack("<I", len(dump))
        buf += b"\x00" * 4
        expected_symbols[BASE_ADDR + len(buf)] = name
        buf += dump
        buf += b"\x00" * len(dump)
    table_off = len(buf)
    tbl = struct.pack("<I", len(module_names)) + b"\x00" * 4
    for mod_id in module_names:
        tbl += struct.pack("<I", module_offsets[mod_id])
        tbl += struct.pack("<I", 0)
        tbl += struct.pack("<I", mod_id)
        tbl += struct.pack("<I", 0)
    tbl += (struct.pack("<I", 0) + b"\x00" * 4) * 4
    tbl += struct.pack("<I", len(function_offsets)) + b"\x00" * 4
    for fun_off in function_offsets:
        tbl += struct.pack("<I", fun_off) + b"\x00" * 12
    buf += tbl
    buf += struct.pack("<I", table_off)
    return bytes(buf), expected_symbols


class DelphiKbSymbolProviderTestSuite(unittest.TestCase):
    def setUp(self):
        self.provider = DelphiKbSymbolProvider(None)

    def test_valid_kb_still_parses_symbols(self):
        kb, expected = build_valid_kb(
            {1: "System", 2: "SysUtils"},
            [(1, "TObject.Create", b"\x55\x8b\xec\xc3"), (2, "Trim", b"\x33\xc0\xc3\x90")],
        )
        symbols = self.provider.parseKbBuffer(kb, BASE_ADDR)
        self.assertEqual(symbols, expected)

    def test_huge_declared_table_counts_are_bounded(self):
        kb = KB_MAGIC + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4 + struct.pack("<I", len(KB_MAGIC))
        worker_result = {}

        def parse():
            worker_result["symbols"] = self.provider.parseKbBuffer(kb, BASE_ADDR)

        worker = threading.Thread(target=parse, daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive(), "parseKbBuffer did not terminate on a bogus 32-bit table count")
        self.assertEqual(worker_result["symbols"], {})

    def test_unknown_module_id_does_not_raise(self):
        buf = bytearray(KB_MAGIC)
        fun_rec_off = len(buf)
        buf += struct.pack("<H", 0x4141)
        buf += struct.pack("<H", 3) + b"fun"
        buf += b"\x00" * 9
        buf += struct.pack("<H", 0)
        buf += b"\x00" * 5
        buf += struct.pack("<I", 0)
        buf += b"\x00" * 4
        table_off = len(buf)
        tbl = struct.pack("<I", 0) + b"\x00" * 4
        tbl += (struct.pack("<I", 0) + b"\x00" * 4) * 4
        tbl += struct.pack("<I", 1) + b"\x00" * 4
        tbl += struct.pack("<I", fun_rec_off) + b"\x00" * 12
        buf += tbl + struct.pack("<I", table_off)
        symbols = self.provider.parseKbBuffer(bytes(buf), BASE_ADDR)
        self.assertEqual(len(symbols), 1)

    def test_non_utf8_names_do_not_raise(self):
        buf = bytearray(KB_MAGIC)
        mod_rec_off = len(buf)
        buf += struct.pack("<H", 1)
        buf += struct.pack("<H", 2) + b"\xff\xfe"
        table_off = len(buf)
        tbl = struct.pack("<I", 1) + b"\x00" * 4
        tbl += struct.pack("<I", mod_rec_off) + struct.pack("<I", 0) + struct.pack("<I", 1) + struct.pack("<I", 0)
        tbl += (struct.pack("<I", 0) + b"\x00" * 4) * 4
        tbl += struct.pack("<I", 0) + b"\x00" * 4
        buf += tbl + struct.pack("<I", table_off)
        symbols = self.provider.parseKbBuffer(bytes(buf), BASE_ADDR)
        self.assertEqual(symbols, {})


if __name__ == "__main__":
    unittest.main()
