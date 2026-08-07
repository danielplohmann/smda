import struct
import unittest
from types import SimpleNamespace

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64FunctionCandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.SmdaConfig import SmdaConfig
from smda.utility.PeFileLoader import PeFileLoader


class PeFileLoaderTestSuite(unittest.TestCase):
    @staticmethod
    def _minimal_pe_header(machine_type):
        pe_offset = 0x80
        binary = bytearray(pe_offset + 0x40)
        binary[:2] = b"MZ"
        binary[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        binary[pe_offset + 4 : pe_offset + 6] = machine_type.to_bytes(2, "little")
        return bytes(binary)

    def test_arm64_pe_header_reports_aarch64_64bit(self):
        binary = self._minimal_pe_header(0xAA64)

        self.assertTrue(PeFileLoader.isCompatible(binary))
        self.assertTrue(PeFileLoader.checkPe(binary))
        self.assertEqual(PeFileLoader.getArchitecture(binary, parsed=None), "aarch64")
        self.assertEqual(PeFileLoader.getBitness(binary), 64)

    def test_machine_type_requires_valid_pe_signature(self):
        binary = bytearray(self._minimal_pe_header(0xAA64))
        binary[0x80:0x84] = b"PX\x00\x00"

        self.assertEqual(PeFileLoader.getMachineType(bytes(binary)), 0)
        self.assertFalse(PeFileLoader.checkPe(bytes(binary)))
        self.assertEqual(PeFileLoader.getArchitecture(bytes(binary), parsed=None), "")
        self.assertEqual(PeFileLoader.getBitness(bytes(binary)), 0)

    def test_pe_offset_uses_full_four_byte_e_lfanew(self):
        pe_offset = 0x180
        binary = bytearray(pe_offset + 0x40)
        binary[:2] = b"MZ"
        binary[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        binary[pe_offset + 4 : pe_offset + 6] = (0xAA64).to_bytes(2, "little")

        self.assertEqual(PeFileLoader.getPeOffset(bytes(binary)), pe_offset)
        self.assertEqual(PeFileLoader.getMachineType(bytes(binary)), 0xAA64)

    @staticmethod
    def _build_pe_with_section(
        total_len, virt_size, virt_offset, raw_size, raw_offset, machine_type=0x14C, num_sections=1
    ):
        pe_offset = 0x80
        optional_header_size = 0xF8
        binary = bytearray(total_len)
        binary[:2] = b"MZ"
        binary[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        binary[pe_offset + 4 : pe_offset + 6] = machine_type.to_bytes(2, "little")
        binary[pe_offset + 6 : pe_offset + 8] = num_sections.to_bytes(2, "little")
        section_offset = pe_offset + optional_header_size
        slice_start = section_offset + 0x8
        binary[slice_start : slice_start + 4] = virt_size.to_bytes(4, "little")
        binary[slice_start + 4 : slice_start + 8] = virt_offset.to_bytes(4, "little")
        binary[slice_start + 8 : slice_start + 12] = raw_size.to_bytes(4, "little")
        binary[slice_start + 12 : slice_start + 16] = raw_offset.to_bytes(4, "little")
        return bytes(binary)

    def test_mapBinary_clamps_truncated_section_raw_copy(self):
        # raw_offset + raw_size extends past the actual (truncated) byte-length of the binary;
        # mapBinary() must not let the length-mismatched RHS slice shrink mapped_binary.
        virt_offset = 0x2000
        virt_size = 0x1000
        raw_size = 0x1000
        raw_offset = 0x1A0
        total_len = 0x1F0
        binary = self._build_pe_with_section(total_len, virt_size, virt_offset, raw_size, raw_offset)

        mapped = PeFileLoader.mapBinary(binary)

        expected_len = max(virt_size + virt_offset, raw_size + virt_offset)
        self.assertEqual(len(mapped), expected_len)

        available = total_len - raw_offset
        self.assertEqual(mapped[virt_offset : virt_offset + available], binary[raw_offset : raw_offset + available])
        self.assertEqual(mapped[virt_offset + available : virt_offset + raw_size], b"\x00" * (raw_size - available))

    def test_mapBinary_clamps_header_copy_to_truncated_binary(self):
        # min_raw_section_offset (0x300) exceeds the actual (truncated) raw binary length (0x200);
        # mapBinary() must not let the length-mismatched header-copy slice shrink mapped_binary.
        virt_offset = 0x1000
        virt_size = 0x100
        raw_size = 0
        raw_offset = 0x300
        total_len = 0x200
        binary = self._build_pe_with_section(total_len, virt_size, virt_offset, raw_size, raw_offset)

        mapped = PeFileLoader.mapBinary(binary)

        expected_len = max(virt_size + virt_offset, raw_size + virt_offset)
        self.assertEqual(len(mapped), expected_len)
        self.assertEqual(mapped[0:total_len], binary[0:total_len])

    def test_map_binary_returns_empty_for_malformed_mz_without_sections(self):
        # isCompatible() only checks the "MZ" magic, so a DOS-stub-only file reaches
        # mapBinary. It has no usable section data, which used to raise
        # ValueError("PE file larger than MAX_IMAGE_SIZE") - a message stating the
        # opposite of the actual condition, and uncaught on the FileLoader path, so a
        # single malformed MZ file aborted analysis of a whole directory. ELF and Mach-O
        # both return b"" for the analogous case.
        binary = bytearray(b"MZ" + b"\x00" * 0x3E)
        binary[0x3C:0x40] = struct.pack("<I", 0x40)  # e_lfanew pointing past the stub

        self.assertTrue(PeFileLoader.isCompatible(bytes(binary)))
        self.assertEqual(PeFileLoader.mapBinary(bytes(binary)), b"")

    def test_map_binary_still_raises_for_oversized_image(self):
        # the MAX_IMAGE_SIZE guard must remain intact for a genuinely oversized image
        pe_offset = 0x40
        binary = bytearray(b"MZ" + b"\x00" * (pe_offset + 0xF8 + 0x28))
        binary[0x3C:0x40] = struct.pack("<I", pe_offset)
        binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        binary[pe_offset + 4 : pe_offset + 6] = struct.pack("<H", 0x014C)  # i386
        binary[pe_offset + 6 : pe_offset + 8] = struct.pack("<H", 1)  # one section
        section = pe_offset + 0xF8
        # virt_size + virt_offset well beyond MAX_IMAGE_SIZE
        binary[section + 0x8 : section + 0x18] = struct.pack("IIII", SmdaConfig.MAX_IMAGE_SIZE, 0x1000, 0, 0x200)

        with self.assertRaises(ValueError):
            PeFileLoader.mapBinary(bytes(binary))

    def test_mapBinary_header_copy_respects_section_at_offset_0x200(self):
        # A section with PointerToRawData == 0x200 is the most common PE layout. The
        # raw_offset `> 0x200` floor skipped exactly this value, so the 0xFFFFFFFF
        # sentinel survived and the whole raw file (including section payload bytes)
        # was copied into the RVA-0 header region up to the first section's VA.
        virt_offset = 0x1000
        virt_size = 0x100
        raw_size = 0x100
        raw_offset = 0x200
        total_len = 0x400
        binary = self._build_pe_with_section(total_len, virt_size, virt_offset, raw_size, raw_offset)
        binary = bytearray(binary)
        for i in range(raw_size):
            binary[raw_offset + i] = 0x90

        mapped = PeFileLoader.mapBinary(bytes(binary))

        self.assertEqual(mapped[0:0x200], bytes(binary)[0:0x200])
        # the header gap between SizeOfHeaders and the section VA must stay zero-filled,
        # not echo raw section content
        self.assertEqual(mapped[0x200:0x1000], b"\x00" * (0x1000 - 0x200))
        self.assertEqual(mapped[0x1000:0x1100], bytes(binary)[0x200:0x300])

    @staticmethod
    def _build_pe_with_zero_virtual_size_exec_section():
        pe = 0x80
        binary = bytearray(0x240)
        binary[:2] = b"MZ"
        binary[0x3C:0x40] = pe.to_bytes(4, "little")
        binary[pe : pe + 4] = b"PE\x00\x00"
        binary[pe + 4 : pe + 6] = (0x14C).to_bytes(2, "little")
        binary[pe + 6 : pe + 8] = (1).to_bytes(2, "little")
        binary[pe + 20 : pe + 22] = (0xE0).to_bytes(2, "little")  # SizeOfOptionalHeader
        binary[pe + 22 : pe + 24] = (0x0102).to_bytes(2, "little")
        binary[pe + 24 : pe + 26] = (0x10B).to_bytes(2, "little")  # PE32 magic
        section = pe + 4 + 20 + 0xE0
        binary[section : section + 8] = b".text\x00\x00"
        binary[section + 8 : section + 12] = (0).to_bytes(4, "little")  # VirtualSize
        binary[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
        binary[section + 16 : section + 20] = (0x2A0).to_bytes(4, "little")  # SizeOfRawData
        binary[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
        binary[section + 36 : section + 40] = (0x60000020 | 0x20000000).to_bytes(4, "little")
        return bytes(binary)

    def test_getCodeAreas_recovers_executable_extent_from_raw_size_when_virtual_size_is_zero(self):
        # MEM_EXECUTE section with VirtualSize == 0 produced a zero-width code area that
        # rejected every address, silently losing all functions. mapBinary folds raw_size
        # into the virtual extent, so the code gate must do the same and round up.
        binary = self._build_pe_with_zero_virtual_size_exec_section()

        code_areas = PeFileLoader.getCodeAreas(binary)

        base = PeFileLoader.getBaseAddress(binary)
        self.assertEqual(code_areas, [[base + 0x1000, base + 0x1000 + 0x1000]])

    def test_getSections_recovers_extent_from_raw_size_when_virtual_size_is_zero(self):
        # same class as getCodeAreas: a zero VirtualSize yielded a zero-width section
        # range, so no address ever resolved to the section's name
        binary = self._build_pe_with_zero_virtual_size_exec_section()
        binary_info = BinaryInfo(binary)
        binary_info.base_addr = PeFileLoader.getBaseAddress(binary)

        sections = {name: (start, end) for name, start, end in binary_info.getSections()}

        base = binary_info.base_addr
        self.assertEqual(sections[".text"], (base + 0x1000, base + 0x1000 + 0x1000))

    def test_aarch64_pe_exec_section_ranges_survive_zero_virtual_size(self):
        # the AArch64 candidate manager dropped such a section from its executable
        # ranges entirely, rejecting every pointer target inside it
        binary = self._build_pe_with_zero_virtual_size_exec_section()
        base = PeFileLoader.getBaseAddress(binary)
        parsed = PeFileLoader.parseBinary(binary)

        ranges = AArch64FunctionCandidateManager._peExecutableSectionRanges(parsed, base)

        self.assertEqual(ranges, [(base + 0x1000, base + 0x1000 + 0x2A0)])

    def test_aarch64_pe_exec_section_ranges_skip_a_wholly_empty_section(self):
        # neither VirtualSize nor SizeOfRawData gives an extent, so there is nothing
        # to constrain pointer targets with and no range may be emitted
        section = SimpleNamespace(
            characteristics=0x20000020,
            virtual_address=0x1000,
            virtual_size=0,
            sizeof_raw_data=0,
        )
        parsed = SimpleNamespace(sections=[section])

        ranges = AArch64FunctionCandidateManager._peExecutableSectionRanges(parsed, 0x400000)

        self.assertEqual(ranges, [])

    def test_mergeCodeAreas(self):
        test_cases = [
            ("Overlapping intervals", [[1, 5], [3, 7], [8, 12]], [[1, 7], [8, 12]]),
            ("Contiguous intervals", [[1, 5], [5, 10], [10, 15]], [[1, 15]]),
            ("Unsorted contiguous intervals", [[10, 15], [1, 5], [5, 10]], [[1, 15]]),
            ("Separated intervals", [[1, 5], [6, 10], [11, 15]], [[1, 5], [6, 10], [11, 15]]),
            ("Empty list", [], []),
            ("Single interval", [[1, 5]], [[1, 5]]),
            ("Mixed intervals", [[1, 5], [5, 10], [11, 15], [15, 20]], [[1, 10], [11, 20]]),
        ]

        for name, intervals, expected in test_cases:
            with self.subTest(msg=name):
                self.assertEqual(PeFileLoader.mergeCodeAreas(intervals), expected)


if __name__ == "__main__":
    unittest.main()
