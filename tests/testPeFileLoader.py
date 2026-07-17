import unittest

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
