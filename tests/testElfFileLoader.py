import unittest
from pathlib import Path
from types import SimpleNamespace

import lief

from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader


class _HashableNamespace(SimpleNamespace):
    # ElfFileLoader's internal helpers (_calculate_base_address, _get_boundaries,
    # _get_sorted_sections) are @lru_cache-decorated on the parsed elffile object.
    # Plain SimpleNamespace defines __eq__ (structural), which makes it unhashable
    # by default; give mocked "parsed" ELF objects identity-based hashing instead.
    def __hash__(self):
        return id(self)


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

    def test_invalid_abi_does_not_depend_on_removed_lief_exception(self):
        class InvalidAbi:
            @property
            def name(self):
                raise ValueError("invalid ABI")

        parsed = SimpleNamespace(header=SimpleNamespace(identity_os_abi=InvalidAbi()))

        self.assertEqual(ElfFileLoader.getAbi(b"", parsed=parsed), "")
        self.assertEqual(
            ElfFileLoader.getAbi(b"", parsed=SimpleNamespace(header=SimpleNamespace(identity_os_abi=110))), ""
        )

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

    def test_code_areas_use_segment_execute_flag_not_readable_flag(self):
        # PF_R|PF_W = 6 (readable+writable, NOT executable). Under the old bug
        # (segment flags tested against Section.FLAGS.EXECINSTR == 4), 6 & 4 == 4
        # is truthy, so this would have been misclassified as a code area.
        rw_segment = SimpleNamespace(
            virtual_address=0x1000,
            virtual_size=0x1000,
            physical_size=0x1000,
            alignment=0,
            flags=SimpleNamespace(value=6),
        )
        # PF_R|PF_X = 5, genuinely executable.
        rx_segment = SimpleNamespace(
            virtual_address=0x5000,
            virtual_size=0x1000,
            physical_size=0x1000,
            alignment=0,
            flags=SimpleNamespace(value=5),
        )
        parsed = SimpleNamespace(sections=[], segments=[rw_segment, rx_segment])

        code_areas = ElfFileLoader.getCodeAreas(b"", parsed=parsed)

        self.assertEqual(code_areas, [[0x5000, 0x6000]])

    def test_code_areas_zero_section_alignment_does_not_raise(self):
        section = SimpleNamespace(
            virtual_address=0x1000,
            size=10,
            alignment=0,
            flags=lief.ELF.Section.FLAGS.EXECINSTR.value,
            file_offset=0,
            offset=0,
            content=b"",
        )
        parsed = SimpleNamespace(sections=[section], segments=[])

        code_areas = ElfFileLoader.getCodeAreas(b"", parsed=parsed)

        self.assertEqual(code_areas, [[0x1000, 0x100A]])

    def test_map_binary_clamps_header_copy_to_actual_file_length(self):
        section = SimpleNamespace(
            virtual_address=0x2000,
            size=0x100,
            alignment=0,
            flags=0,
            file_offset=0x500,
            offset=0x2000,  # == virtual_address, so the computed base address is 0
            content=b"\x11" * 0x100,
        )
        parsed = _HashableNamespace(sections=[section], segments=[])
        # min_raw_offset (0x500) is far beyond the length of this truncated
        # raw file, so the header-copy slice must be clamped to len(binary)
        # rather than shrinking mapped_binary via a length-mismatched
        # slice assignment.
        truncated_binary = b"\x00" * 0x10

        mapped = ElfFileLoader.mapBinary(truncated_binary, parsed=parsed)

        expected_len = 0x3000  # align(0x2100, 0x1000)
        self.assertEqual(len(mapped), expected_len)

    def test_map_binary_clamps_segment_physical_size_to_buffer_capacity(self):
        segment = SimpleNamespace(
            virtual_address=0x1FF0,
            virtual_size=0x10,
            physical_size=0x500,
            alignment=0,
            file_offset=0,
            content=b"\x33" * 0x500,
        )
        parsed = _HashableNamespace(sections=[], segments=[segment])

        mapped = ElfFileLoader.mapBinary(b"", parsed=parsed)

        expected_len = 0x2000  # align(0x2000, 0x1000)
        self.assertEqual(len(mapped), expected_len)
        # only the bytes that actually fit in the buffer's remaining capacity
        # (0x2000 - 0x1FF0 == 0x10) should have been copied
        self.assertEqual(mapped[0x1FF0:0x2000], b"\x33" * 0x10)

    def test_map_binary_skips_sections_below_the_base_address(self):
        # the section at 0x8000 (offset 0) fixes the computed base address at 0x8000;
        # the second section's own base candidate is negative and therefore filtered,
        # so it survives to _map_sections with rva == -0x100. An unguarded negative
        # slice start wraps to the end of the buffer and the length-mismatched slice
        # assignment then *inserts* the section's bytes, growing mapped_binary and
        # desynchronizing every later VA->offset translation.
        anchor = SimpleNamespace(
            virtual_address=0x8000,
            size=0x100,
            alignment=0,
            flags=0,
            file_offset=0,
            offset=0,
            content=b"\x11" * 0x100,
        )
        below_base = SimpleNamespace(
            virtual_address=0x7F00,
            size=0x200,
            alignment=0,
            flags=0,
            file_offset=0x8000,
            offset=0x8000,
            content=b"\x22" * 0x200,
        )
        parsed = _HashableNamespace(sections=[anchor, below_base], segments=[])

        mapped = ElfFileLoader.mapBinary(b"", parsed=parsed)

        self.assertEqual(len(mapped), 0x1000)  # align(0x100, 0x1000), not grown to 0x1200
        self.assertNotIn(b"\x22", mapped)

    def test_map_binary_clamps_section_size_to_buffer_capacity(self):
        section = SimpleNamespace(
            virtual_address=0x1FF0,
            size=0x500,
            alignment=0,
            flags=0,
            file_offset=0,
            offset=0x1FF0,  # keeps the computed base address at 0
            content=b"\x44" * 0x500,
        )
        parsed = _HashableNamespace(sections=[section], segments=[])

        mapped = ElfFileLoader.mapBinary(b"", parsed=parsed)

        expected_len = 0x3000  # align(0x24F0, 0x1000)
        self.assertEqual(len(mapped), expected_len)
        self.assertEqual(mapped[0x1FF0 : 0x1FF0 + 0x500], b"\x44" * 0x500)


if __name__ == "__main__":
    unittest.main()
