import unittest

from smda.utility.PeFileLoader import PeFileLoader


class PeFileLoaderTestSuite(unittest.TestCase):
    @staticmethod
    def _minimal_pe_header(machine_type):
        pe_offset = 0x80
        binary = bytearray(pe_offset + 0x40)
        binary[:2] = b"MZ"
        binary[0x3C:0x3E] = pe_offset.to_bytes(2, "little")
        binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        binary[pe_offset + 4 : pe_offset + 6] = machine_type.to_bytes(2, "little")
        return bytes(binary)

    def test_arm64_pe_header_reports_aarch64_64bit(self):
        binary = self._minimal_pe_header(0xAA64)

        self.assertTrue(PeFileLoader.isCompatible(binary))
        self.assertTrue(PeFileLoader.checkPe(binary))
        self.assertEqual(PeFileLoader.getArchitecture(binary, parsed=None), "aarch64")
        self.assertEqual(PeFileLoader.getBitness(binary), 64)

    def test_mergeCodeAreas(self):
        test_cases = [
            ("Overlapping intervals", [[1, 5], [3, 7], [8, 12]], [[1, 5], [3, 7], [8, 12]]),
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
