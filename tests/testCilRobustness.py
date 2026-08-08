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


class CilMetadataSignatureTestSuite(unittest.TestCase):
    def test_a_corrupted_metadata_signature_reports_no_methods_instead_of_raising(self):
        # dnfile leaves pe.net without tables when the "BSJB" signature is unreadable; the
        # symbol provider already degrades on that, and the disassembler must too
        njrat = bytearray(_load_njrat())
        signature_at = njrat.find(b"BSJB")
        self.assertNotEqual(signature_at, -1)
        njrat[signature_at : signature_at + 4] = b"XXXX"

        report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(bytes(njrat))

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.num_functions, 0)


class CilLeafFunctionTestSuite(unittest.TestCase):
    def test_a_method_that_calls_is_not_reported_as_a_leaf(self):
        report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(_load_njrat())

        self.assertEqual(report.num_functions, 64)
        self.assertLess(report.statistics.num_leaf_functions, report.num_functions)


class CilSymbolAmbiguityTestSuite(unittest.TestCase):
    def test_a_name_shared_by_several_methods_resolves_to_none(self):
        from smda.common.labelprovider.CilSymbolProvider import CilSymbolProvider

        provider = CilSymbolProvider(SmdaConfig())
        provider._addr_to_func_symbols = {0x100: ".ctor", 0x200: ".ctor", 0x300: "Send"}
        provider._func_symbol_to_addr = {".ctor": 0x100, "Send": 0x300}
        provider._ambiguous_func_symbols = {".ctor"}

        self.assertIsNone(provider.getAddress(".ctor"))
        self.assertEqual(provider.getAddress("Send"), 0x300)

    def test_repeated_names_are_recorded_as_ambiguous_while_parsing(self):
        njrat = _load_njrat()
        from smda.common.BinaryInfo import BinaryInfo
        from smda.common.labelprovider.CilSymbolProvider import CilSymbolProvider

        binary_info = BinaryInfo(njrat)
        binary_info.raw_data = njrat
        provider = CilSymbolProvider(SmdaConfig())
        provider.update(binary_info)

        self.assertIn(".ctor", provider._ambiguous_func_symbols)
        self.assertIsNone(provider.getAddress(".ctor"))


if __name__ == "__main__":
    unittest.main()
