import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyze import hasPeSignature, shouldParseHeader
from smda.Disassembler import Disassembler
from smda.utility.FileLoader import FileLoader

PE_FIXTURE = "cutwail_xored"
ELF_FIXTURE = "mirai_x64_xored"
DEX_FIXTURE = "blockblast_classes_xored"
DUMP_FIXTURE = "asprox_0x008D0000_xored"


def _load_xored_fixture(fixture_name):
    data = (Path(__file__).resolve().parent / fixture_name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _args(parse_header=False, base_addr="", oep="", input_path="sample.bin"):
    return Namespace(parse_header=parse_header, base_addr=base_addr, oep=oep, input_path=input_path)


class AnalyzeCliRoutingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe = _load_xored_fixture(PE_FIXTURE)
        cls.elf = _load_xored_fixture(ELF_FIXTURE)
        cls.dex = _load_xored_fixture(DEX_FIXTURE)
        cls.dump = _load_xored_fixture(DUMP_FIXTURE)

    def test_recognized_containers_select_header_parsing(self):
        for buffer in (self.pe, self.elf, self.dex):
            self.assertTrue(shouldParseHeader(buffer, _args()))

    def test_unrecognized_buffer_falls_back_to_raw_mode(self):
        self.assertFalse(shouldParseHeader(self.dump, _args()))
        self.assertFalse(shouldParseHeader(b"", _args()))

    def test_mz_without_pe_signature_stays_raw(self):
        shellcode = b"MZ" + bytes.fromhex("e800000000") + b"\x90" * 0x100
        self.assertFalse(shouldParseHeader(shellcode, _args()))
        self.assertFalse(shouldParseHeader(b"MZ\x90\x90", _args()))
        far_lfanew = bytearray(self.pe[:0x200])
        far_lfanew[0x3C:0x40] = (0x10000).to_bytes(4, "little")
        self.assertFalse(shouldParseHeader(bytes(far_lfanew), _args()))

    def test_pe_signature_is_read_at_e_lfanew(self):
        self.assertTrue(hasPeSignature(self.pe))
        self.assertTrue(shouldParseHeader(self.pe[:0x400], _args()))

    def test_explicit_base_addr_or_oep_forces_raw_mode(self):
        self.assertFalse(shouldParseHeader(self.pe, _args(base_addr="0x400000")))
        self.assertFalse(shouldParseHeader(self.elf, _args(oep="0x1000")))

    def test_header_path_reuses_the_buffer_the_cli_already_read(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.bin"
            path.write_bytes(self.elf)
            with mock.patch.object(
                FileLoader, "_loadRawFileContent", side_effect=AssertionError("file re-read")
            ) as no_reread:
                report = Disassembler().disassembleFile(str(path), buffer=self.elf)
            self.assertEqual(no_reread.call_count, 0)
        self.assertEqual(report.architecture, "intel")
        self.assertTrue(report.getFunctions())

    def test_base_addr_in_file_name_forces_raw_mode(self):
        for name in ("x_0x00400000", "/dumps/x_0x00400000", "x_0x00007FF6A1B20000.bin"):
            self.assertFalse(shouldParseHeader(self.pe, _args(input_path=name)))

    def test_file_name_without_base_addr_still_auto_detects(self):
        for name in ("sample.bin", "x_0x400000", "0x00400000"):
            self.assertTrue(shouldParseHeader(self.pe, _args(input_path=name)))

    def test_parse_header_flag_wins_over_explicit_mapping_args(self):
        self.assertTrue(shouldParseHeader(self.dump, _args(parse_header=True)))
        self.assertTrue(shouldParseHeader(self.pe, _args(parse_header=True, base_addr="0x400000")))
        self.assertTrue(shouldParseHeader(self.pe, _args(parse_header=True, input_path="x_0x00400000")))


if __name__ == "__main__":
    unittest.main()
