import unittest
from pathlib import Path
from types import SimpleNamespace

from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader


class TestElfFileLoader(unittest.TestCase):
    def _load_fixture(self, fixture_name):
        xored = (Path(__file__).resolve().parent / fixture_name).read_bytes()
        return bytes(byte ^ (index % 256) for index, byte in enumerate(xored))

    def test_real_elf_loader_metadata_and_code_areas(self):
        raw = self._load_fixture("bashlite_xored")
        loader = MemoryFileLoader(raw, map_file=True)

        self.assertTrue(ElfFileLoader.isCompatible(raw))
        self.assertEqual(loader.getArchitecture(), "intel")
        self.assertEqual(loader.getBitness(), 64)
        self.assertTrue(loader.getHasBackend())
        self.assertTrue(ElfFileLoader.getHasBackend(raw))
        self.assertTrue(loader.getCodeAreas())
        self.assertTrue(loader.getData())

    def test_plt_ranges_include_all_supported_section_names(self):
        sections = [
            SimpleNamespace(name=".plt", virtual_address=0x1000, size=0x20),
            SimpleNamespace(name=".plt.sec", virtual_address=0x2000, size=0x30),
            SimpleNamespace(name=".text", virtual_address=0x3000, size=0x40),
        ]

        self.assertEqual(
            ElfFileLoader.getPltRanges(b"", parsed=SimpleNamespace(sections=sections)),
            [(0x1000, 0x1020), (0x2000, 0x2030)],
        )

    def test_got_bases_prefer_got_plt_before_got(self):
        sections = [
            SimpleNamespace(name=".got", virtual_address=0x3000),
            SimpleNamespace(name=".got.plt", virtual_address=0x4000),
        ]

        self.assertEqual(
            ElfFileLoader.getGotBases(b"", parsed=SimpleNamespace(sections=sections)),
            [0x4000, 0x3000],
        )


if __name__ == "__main__":
    unittest.main()
