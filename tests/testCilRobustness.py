import unittest
from pathlib import Path
from unittest import mock

import pefile

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


def _load_njrat():
    """Return the decrypted njrat .NET fixture (64 methods)."""
    raw = (Path(__file__).resolve().parent / "njrat_xored").read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class CilRobustnessTestSuite(unittest.TestCase):
    def test_malformed_method_body_row_does_not_abort_analysis(self):
        # DnfileMethodBodyReader.__init__ evaluates pe.get_offset_from_rva(row.Rva)
        # before any method-body parsing; a crafted MethodDef row (e.g. Rva == 0
        # resolving to the out-of-image offset sentinel) used to raise pefile.
        # PEFormatError, which the only MethodBodyFormatError handler could not
        # catch, aborting every other method's recovery.
        import smda.cil.CilDisassembler as cil_module

        real_init = cil_module.DnfileMethodBodyReader.__init__
        calls = {"n": 0}

        def flaky_init(self, pe, row):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise pefile.PEFormatError("simulated out-of-image RVA")
            return real_init(self, pe, row)

        with mock.patch.object(cil_module.DnfileMethodBodyReader, "__init__", flaky_init):
            report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(_load_njrat())

        self.assertEqual(report.status, "ok")
        self.assertGreaterEqual(report.num_functions, 60, "later methods must still be recovered")

    def test_missing_us_stream_does_not_abort_analysis(self):
        # dnfile only materializes pe.net.user_strings when a stream literally named
        # "#US" exists; read_dotnet_user_string used to dereference None, raising
        # AttributeError from inside format_operand and aborting the whole run.
        njrat = bytearray(_load_njrat())
        us_offset = njrat.find(b"#US\x00")
        self.assertGreaterEqual(us_offset, 0)
        njrat[us_offset : us_offset + 4] = b"#QQ\x00"

        report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(bytes(njrat))

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.num_functions, 64)


if __name__ == "__main__":
    unittest.main()
