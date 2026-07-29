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

    def test_call_occupying_exact_final_five_bytes_is_scored(self):
        # the only scoring evidence is a 5-byte E8 rel32 occupying exactly the
        # last 5 bytes, targeting a 64-bit-typical first byte (0x48)
        binary = b"\x00\x48" + b"\x00" * 9 + b"\xe8" + struct.pack("<i", 1 - 16)

        bitness = BitnessAnalyzer().determineBitness(binary)

        self.assertEqual(bitness, 64)


if __name__ == "__main__":
    unittest.main()
