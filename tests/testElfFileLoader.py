import random
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

import lief

from smda.Disassembler import Disassembler
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader

HEADER_SEGMENT_FIXTURE = "elf_header_segment_aarch64_xored"


class _HashableNamespace(SimpleNamespace):
    # ElfFileLoader's internal helpers (_calculate_base_address, _get_boundaries,
    # _get_sorted_sections) are @lru_cache-decorated on the parsed elffile object.
    # Plain SimpleNamespace defines __eq__ (structural), which makes it unhashable
    # by default; give mocked "parsed" ELF objects identity-based hashing instead.
    def __hash__(self):
        return id(self)


def _strip_section_headers(raw):
    # zero e_shoff, e_shentsize, e_shnum and e_shstrndx, as UPX leaves them
    stripped = bytearray(raw)
    endian = "<" if raw[5] == 1 else ">"
    if raw[4] == 2:
        struct.pack_into(endian + "Q", stripped, 0x28, 0)
        struct.pack_into(endian + "HHH", stripped, 0x3A, 0, 0, 0)
    else:
        struct.pack_into(endian + "I", stripped, 0x20, 0)
        struct.pack_into(endian + "HHH", stripped, 0x2E, 0, 0, 0)
    return bytes(stripped)


class TestElfFileLoader(unittest.TestCase):
    def _load_fixture(self, fixture_name):
        xored = (Path(__file__).resolve().parent / fixture_name).read_bytes()
        return bytes(byte ^ (index % 256) for index, byte in enumerate(xored))

    def test_base_address_without_sections_comes_from_pt_load(self):
        def segment(segment_type, virtual_address, file_offset):
            return SimpleNamespace(type=segment_type, virtual_address=virtual_address, file_offset=file_offset)

        load, phdr, stack = (lief.ELF.Segment.TYPE.LOAD, lief.ELF.Segment.TYPE.PHDR, lief.ELF.Segment.TYPE.GNU_STACK)
        for segments, expected in (
            # only PT_LOAD counts: PT_PHDR would give 0x8000 and PT_GNU_STACK 0
            (
                [
                    segment(phdr, 0x8034, 0x34),
                    segment(load, 0x200B4, 0xB4),
                    segment(load, 0x10000, 0),
                    segment(stack, 0, 0),
                ],
                0x10000,
            ),
            # position-independent
            ([segment(load, 0, 0), segment(load, 0x1DB0, 0xDB0)], 0),
            # same rule as for sections: where file offset 0 would be mapped
            ([segment(load, 0x10000, 0x94)], 0xFF6C),
            ([segment(load, 0x10, 0x94)], 0),
        ):
            with self.subTest(expected=hex(expected)):
                parsed = _HashableNamespace(sections=[], segments=segments)
                self.assertEqual(ElfFileLoader.getBaseAddress(b"", parsed=parsed), expected)

    def test_base_address_covers_a_header_segment_without_sections(self):
        def load(virtual_address, file_offset, virtual_size):
            return SimpleNamespace(
                type=lief.ELF.Segment.TYPE.LOAD,
                virtual_address=virtual_address,
                file_offset=file_offset,
                virtual_size=virtual_size,
            )

        text = SimpleNamespace(virtual_address=0x200B4, offset=0xB4, size=0x78)
        for segments, expected in (
            # the header segment ends one 64 KiB page below .text, as a linker lays it out
            ([load(0x10000, 0, 0xB4), load(0x200B4, 0xB4, 0x78)], 0x10000),
            # further away it is not adjacent to the image, keep the section base
            ([load(0x0, 0, 0xB4), load(0x200B4, 0xB4, 0x78)], 0x20000),
            # a PT_LOAD that does not map the header is not considered
            ([load(0x10000, 0x10, 0xB4), load(0x200B4, 0xB4, 0x78)], 0x20000),
        ):
            with self.subTest(expected=hex(expected)):
                parsed = _HashableNamespace(sections=[text], segments=segments)
                self.assertEqual(ElfFileLoader.getBaseAddress(b"", parsed=parsed), expected)

    def test_header_segment_without_sections_is_mapped(self):
        # AArch64 ELF whose first PT_LOAD holds only the ELF and program headers, built with
        #   clang --target=aarch64-linux-gnu -O1 -ffreestanding -nostdlib -static -fuse-ld=lld -Wl,--build-id=none
        # from three small functions, then llvm-strip (clang/lld 18.1.3); with no build-id note
        # and no .rodata, no section lands in that segment
        raw = self._load_fixture(HEADER_SEGMENT_FIXTURE)
        loader = MemoryFileLoader(raw, map_file=True)

        self.assertEqual(loader.getBaseAddress(), 0x200000)
        self.assertEqual(loader.getData()[:4], b"\x7fELF")
        report = Disassembler().disassembleBuffer(loader.getData(), loader.getBaseAddress())
        self.assertEqual(report.architecture, "aarch64")
        # a buffer carries no entry point, so it finds the functions the file does, less the entry
        buffer_functions = {function.offset for function in report.getFunctions()}
        file_functions = {function.offset for function in Disassembler().disassembleUnmappedBuffer(raw).getFunctions()}
        self.assertTrue(buffer_functions)
        self.assertLessEqual(buffer_functions, file_functions)

    def test_sectionless_elf_maps_like_its_sectioned_original(self):
        for fixture_name in ("bashlite_xored", "mirai_i386_xored", "aarch64_static_xored", "mirai_m68k_xored"):
            with self.subTest(fixture=fixture_name):
                raw = self._load_fixture(fixture_name)
                sectioned = MemoryFileLoader(raw, map_file=True)
                sectionless = MemoryFileLoader(_strip_section_headers(raw), map_file=True)

                self.assertEqual(sectionless.getBaseAddress(), sectioned.getBaseAddress())
                self.assertEqual(len(sectionless.getData()), len(sectioned.getData()))
                self.assertEqual(sectionless.getData()[:4], b"\x7fELF")
                self.assertTrue(sectionless.getCodeAreas())

    def test_sectionless_elf_disassembles_at_its_load_address(self):
        raw = self._load_fixture("elf_ehframe_hdr_x64_xored")
        stripped = _strip_section_headers(raw)
        self.assertEqual(ElfFileLoader.getPltRanges(stripped), [])
        self.assertEqual(ElfFileLoader.getGotBases(stripped), [])

        sectioned = Disassembler().disassembleUnmappedBuffer(raw)
        report = Disassembler().disassembleUnmappedBuffer(stripped)

        self.assertEqual(report.status, "ok")
        self.assertEqual(report.base_addr, 0x400000)
        self.assertEqual(
            sorted(function.offset for function in report.getFunctions()),
            sorted(function.offset for function in sectioned.getFunctions()),
        )

    def test_sectionless_elf_with_corrupt_program_headers_gives_an_error_report(self):
        stripped = bytearray(_strip_section_headers(self._load_fixture("bashlite_xored")))
        phoff, phnum = struct.unpack_from("<Q", stripped, 0x20)[0], struct.unpack_from("<H", stripped, 0x38)[0]
        stripped[phoff : phoff + 56 * phnum] = random.Random(1).randbytes(56 * phnum)

        report = Disassembler().disassembleUnmappedBuffer(bytes(stripped))

        self.assertEqual(report.status, "error")

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

    def test_code_areas_skip_zero_width_section_and_segment(self):
        # A zero-size executable section/segment produced a degenerate [start, start]
        # area. mergeCodeAreas keeps it, so code_areas is non-empty and both
        # isInCodeAreas and _passesCodeFilter switch from their "no code areas, assume
        # the whole image" fallback to a filter that rejects every address.
        empty_section = SimpleNamespace(
            virtual_address=0x1000,
            size=0,
            alignment=0,
            flags=lief.ELF.Section.FLAGS.EXECINSTR.value,
            file_offset=0,
            offset=0,
            content=b"",
        )
        empty_segment = SimpleNamespace(
            virtual_address=0x8000,
            virtual_size=0,
            physical_size=0,
            alignment=0,
            flags=SimpleNamespace(value=5),
        )
        parsed = SimpleNamespace(sections=[empty_section], segments=[empty_segment])

        self.assertEqual(ElfFileLoader.getCodeAreas(b"", parsed=parsed), [])

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
            type=lief.ELF.Segment.TYPE.LOAD,
            virtual_address=0x1000,  # the only PT_LOAD, so the computed base address is 0x1000
            virtual_size=0x10,
            physical_size=0x1500,
            alignment=0,
            file_offset=0,
            content=b"\x33" * 0x1500,
        )
        parsed = _HashableNamespace(sections=[], segments=[segment])

        mapped = ElfFileLoader.mapBinary(b"", parsed=parsed)

        expected_len = 0x1000  # align(0x10, 0x1000)
        self.assertEqual(len(mapped), expected_len)
        # only the bytes that actually fit in the buffer's capacity should have been copied
        self.assertEqual(mapped, b"\x33" * 0x1000)

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
