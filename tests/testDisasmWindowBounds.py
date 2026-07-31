import types
import unittest

from smda.common.RecursiveDisassembler import RecursiveDisassembler


def _stub(base_addr, binary, max_instruction_size=15):
    return types.SimpleNamespace(
        disassembly=types.SimpleNamespace(binary_info=types.SimpleNamespace(base_addr=base_addr, binary=binary)),
        backend=types.SimpleNamespace(max_instruction_size=max_instruction_size),
    )


class TestDisasmWindowBounds(unittest.TestCase):
    def test_target_below_base_addr_yields_no_bytes(self):
        # a negative relative offset smaller than the image wrapped to the tail of the image, so
        # bytes from an unrelated location were decoded and booked as if they lived at the target.
        stub = _stub(0x400000, b"\x90" * 0x100 + b"\xcc" * 0x10)
        self.assertEqual(RecursiveDisassembler._getDisasmWindowBuffer(stub, 0x3FFFF0), b"")

    def test_target_past_image_end_yields_no_bytes(self):
        stub = _stub(0x400000, b"\x90" * 0x100)
        self.assertEqual(RecursiveDisassembler._getDisasmWindowBuffer(stub, 0x400100), b"")

    def test_in_image_target_still_yields_the_window(self):
        stub = _stub(0x400000, b"\x90" * 0x100)
        self.assertEqual(RecursiveDisassembler._getDisasmWindowBuffer(stub, 0x400010), b"\x90" * 15)


if __name__ == "__main__":
    unittest.main()
