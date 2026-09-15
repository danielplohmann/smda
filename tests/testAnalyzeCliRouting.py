import sys
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyze import shouldParseHeader

PE_FIXTURE = "cutwail_xored"
ELF_FIXTURE = "mirai_x64_xored"
DEX_FIXTURE = "blockblast_classes_xored"
DUMP_FIXTURE = "asprox_0x008D0000_xored"


def _load_xored_fixture(fixture_name):
    data = (Path(__file__).resolve().parent / fixture_name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _args(parse_header=False, base_addr="", oep=""):
    return Namespace(parse_header=parse_header, base_addr=base_addr, oep=oep)


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

    def test_explicit_base_addr_or_oep_forces_raw_mode(self):
        self.assertFalse(shouldParseHeader(self.pe, _args(base_addr="0x400000")))
        self.assertFalse(shouldParseHeader(self.elf, _args(oep="0x1000")))

    def test_parse_header_flag_wins_over_explicit_mapping_args(self):
        self.assertTrue(shouldParseHeader(self.dump, _args(parse_header=True)))
        self.assertTrue(shouldParseHeader(self.pe, _args(parse_header=True, base_addr="0x400000")))


if __name__ == "__main__":
    unittest.main()
