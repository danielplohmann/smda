import struct
import unittest

from smda.Disassembler import Disassembler
from smda.intel.IntelDisassembler import IntelDisassembler


def build_delphi_kb_with_unknown_module_id():
    buf = bytearray(b"IDR Knowledge Base File")
    fun_rec_off = len(buf)
    rec = struct.pack("<H", 0x4141)
    rec += struct.pack("<H", 3) + b"fun"
    rec += b"\x00" * 9
    rec += struct.pack("<H", 0)
    rec += b"\x00" * 5
    rec += struct.pack("<I", 0)
    rec += b"\x00" * 4
    buf += rec
    table_off = len(buf)
    tbl = struct.pack("<I", 0)
    tbl += b"\x00" * 4
    tbl += (struct.pack("<I", 0) + b"\x00" * 4) * 4
    tbl += struct.pack("<I", 1)
    tbl += b"\x00" * 4
    tbl += struct.pack("<I", fun_rec_off)
    buf += tbl
    buf += struct.pack("<I", table_off)
    return bytes(buf)


class CrashingProvider:
    def __init__(self, exception):
        self._exception = exception

    def update(self, binary_info):
        raise self._exception

    def isApiProvider(self):
        return False

    def isSymbolProvider(self):
        return True

    def is_active(self):
        return False

    def getSymbol(self, address):
        return ""

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")


class LabelProviderBoundaryTestSuite(unittest.TestCase):
    """A crashing label provider must degrade to zero symbols, not abort the run."""

    TINY_X86_FUNCTION = b"\x55\x8b\xec\x33\xc0\x5d\xc3"

    def _disassembleWithProvider(self, provider):
        disassembler = Disassembler(backend="intel")
        disassembler.disassembler.label_providers.insert(0, provider)
        return disassembler.disassembleBuffer(self.TINY_X86_FUNCTION, 0x1000)

    def test_operational_provider_crash_degrades_to_no_symbols(self):
        for exception in (ValueError("bad parse"), KeyError(0x4141), RecursionError("too deep")):
            with self.subTest(exception=exception.__class__.__name__):
                report = self._disassembleWithProvider(CrashingProvider(exception))
                self.assertEqual(report.status, "ok")
                self.assertEqual(report.num_functions, 1)

    def test_non_operational_provider_crash_still_bubbles_up(self):
        disassembler = IntelDisassembler(Disassembler().config)
        disassembler.label_providers.insert(0, CrashingProvider(MemoryError("oom")))
        with self.assertRaises(MemoryError):
            disassembler._updateLabelProviders(None)

    def test_malformed_delphi_kb_input_does_not_abort_run(self):
        report = Disassembler().disassembleUnmappedBuffer(build_delphi_kb_with_unknown_module_id())
        self.assertEqual(report.status, "ok")


if __name__ == "__main__":
    unittest.main()
