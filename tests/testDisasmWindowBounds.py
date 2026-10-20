import types
import unittest
from unittest.mock import patch

from smda.common.RecursiveDisassembler import RecursiveDisassembler
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


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

    def test_block_decode_preserves_architecture_windows_across_refills(self):
        cases = (
            ("arm", 32, "10402de9", "010080e2", "1080bde8", 32),
            ("aarch64", 64, "fd7bbfa9fd030091", "00040091", "fd7bc1a8c0035fd6", 32),
            ("intel", 32, "5589e5", "40", "5dc3", 30),
            ("intel", 64, "554889e5", "48ffc0", "5dc3", 30),
        )
        for architecture, bitness, prologue, body, epilogue, window in cases:
            with self.subTest(architecture=architecture, bitness=bitness):
                binary = bytes.fromhex(prologue) + bytes.fromhex(body) * 64 + bytes.fromhex(epilogue)
                config = SmdaConfig()
                config.TIMEOUT = 5
                disassembler = Disassembler(config, backend=architecture)
                engine = disassembler.disassembler
                with patch.object(engine, "_getDisasmWindowBuffer", wraps=engine._getDisasmWindowBuffer) as decode:
                    report = disassembler.disassembleBuffer(binary, 0x10000, bitness=bitness)
                self.assertEqual(report.status, "ok")
                self.assertIsNotNone(report.getFunction(0x10000))
                block_windows = [call.kwargs["size"] for call in decode.call_args_list if "size" in call.kwargs]
                self.assertGreater(len(block_windows), 1)
                self.assertEqual(set(block_windows), {window})


if __name__ == "__main__":
    unittest.main()
