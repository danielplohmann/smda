import unittest

from smda.common.labelprovider.OrdinalHelper import OrdinalHelper
from smda.intel.definitions import GAP_SEQUENCES


class TestDefinitionsExpansion(unittest.TestCase):
    def test_gap_sequences(self):
        expected_sequences = [
            (2, b"\xeb\x00"),  # jmp $+2 (NOP-equivalent padding)
            (2, b"\x89\xc0"),  # mov eax, eax
            (2, b"\x8b\xc9"),  # mov ecx, ecx
            (2, b"\x8b\xd2"),  # mov edx, edx
            (2, b"\x8b\xdb"),  # mov ebx, ebx
            (2, b"\x8b\xf6"),  # mov esi, esi
            (3, b"\x8d\x24\x24"),  # lea esp, [esp] (fixed from incorrect \x8d\x64\x24)
            (4, b"\x8d\x64\x24\x00"),  # lea esp, [esp+0]
            (5, b"\x66\x0f\x1f\x40\x00"),  # multi-byte NOP (operand-size prefix)
            (6, b"\x8d\xbf\x00\x00\x00\x00"),  # lea edi, [edi]
        ]

        for length, seq in expected_sequences:
            self.assertIn(
                seq, GAP_SEQUENCES[length], f"Sequence {seq.hex()} of length {length} not found in GAP_SEQUENCES"
            )

    def test_no_rex_sequences_in_shared_dict(self):
        # REX-prefixed (0x48) sequences must not be in the shared dict:
        # in 32-bit mode 0x48 is "dec eax", making these non-NOP sequences.
        rex_sequences = [
            b"\x48\x8b\xc0",
            b"\x48\x89\xc0",
            b"\x48\x8d\x00",
            b"\x48\x8d\x40\x00",
            b"\x48\x0f\x1f\x40\x00",
            b"\x48\x8d\x64\x24\x00",
        ]
        for seq in rex_sequences:
            length = len(seq)
            self.assertNotIn(
                seq, GAP_SEQUENCES[length], f"REX sequence {seq.hex()} should not be in shared GAP_SEQUENCES"
            )

    def test_ordinal_expansion(self):
        # Test new oleaut32.dll ordinals
        self.assertEqual(OrdinalHelper.resolveOrdinal("oleaut32.dll", 6), "SysFreeString")
        self.assertEqual(OrdinalHelper.resolveOrdinal("oleaut32.dll", 2), "SysAllocString")
        self.assertEqual(OrdinalHelper.resolveOrdinal("oleaut32.dll", 149), "SysStringByteLen")
        # Case insensitivity
        self.assertEqual(OrdinalHelper.resolveOrdinal("OLEAUT32.DLL", 144), "DllCanUnloadNow")
        # Existing ws2_32.dll entries still resolve
        self.assertEqual(OrdinalHelper.resolveOrdinal("ws2_32.dll", 23), "socket")


if __name__ == "__main__":
    unittest.main()
