import re
import struct
import unittest
from unittest import mock

from smda.intel.BitnessAnalyzer import BitnessAnalyzer


class TestBitnessAnalyzer(unittest.TestCase):
    def test_determine_bitness_scans_call_opcodes_once(self):
        binary = bytearray(16)
        binary[0] = 0xE8
        binary[1:5] = struct.pack("i", 5)
        binary[10] = 0x48
        original_finditer = re.finditer
        finditer_calls = []

        def counting_finditer(pattern, subject):
            finditer_calls.append((pattern, subject))
            return original_finditer(pattern, subject)

        with mock.patch("smda.intel.BitnessAnalyzer.re.finditer", side_effect=counting_finditer):
            bitness = BitnessAnalyzer().determineBitness(bytes(binary))

        self.assertEqual(bitness, 64)
        self.assertEqual(finditer_calls, [(b"\xe8", bytes(binary))])


if __name__ == "__main__":
    unittest.main()
