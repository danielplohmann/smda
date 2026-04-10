import unittest
from smda.intel.definitions import GAP_SEQUENCES, COMMON_API_CALLS
from smda.common.labelprovider.OrdinalHelper import OrdinalHelper

class TestDefinitionsExpansion(unittest.TestCase):

    def test_common_api_calls(self):
        # Check that the list exists and contains a sample of expected APIs
        self.assertTrue(len(COMMON_API_CALLS) > 0)
        self.assertIn("GetSystemTimeAsFileTime", COMMON_API_CALLS)
        self.assertIn("LoadLibraryExW", COMMON_API_CALLS)

    def test_gap_sequences(self):
        # Universal and 64-bit sequences
        expected_sequences = [
            (2, b"\xeb\x00"),  # short jmp
            (2, b"\x89\xc0"),  # mov eax, eax
            (3, b"\x48\x8b\xc0"),  # mov rax, rax (64-bit)
            (3, b"\x8d\x24\x24"),  # lea esp, [esp] (bug fix)
            (4, b"\x8d\x64\x24\x00"),  # lea esp, [esp+0]
            (5, b"\x48\x0f\x1f\x40\x00"),  # multi-byte NOP (64-bit)
            (6, b"\x8d\xbf\x00\x00\x00\x00"),  # lea edi, [edi]
        ]

        for length, seq in expected_sequences:
            self.assertIn(seq, GAP_SEQUENCES[length], f"Sequence {seq.hex()} of length {length} not found in GAP_SEQUENCES")

    def test_ordinal_expansion(self):
        # Test new ordinals
        self.assertEqual(OrdinalHelper.resolveOrdinal("ole32.dll", 101), "CoTaskMemAlloc")
        self.assertEqual(OrdinalHelper.resolveOrdinal("oleaut32.dll", 6), "SysFreeString")
        self.assertEqual(OrdinalHelper.resolveOrdinal("mfc42.dll", 1), "DllGetClassObject")
        # Case insensitivity
        self.assertEqual(OrdinalHelper.resolveOrdinal("OLEAUT32.DLL", 144), "DllCanUnloadNow")

if __name__ == "__main__":
    unittest.main()
