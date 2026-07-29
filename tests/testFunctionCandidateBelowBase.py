import types
import unittest

from smda.common.FunctionCandidate import FunctionCandidate


class TestFunctionCandidateBelowBase(unittest.TestCase):
    def test_function_candidate_below_base_addr_has_empty_bytes(self):
        # 32: a candidate below base_addr made rel_start_addr negative, so the slice wrapped to
        # the end of the mapped image and scored an unrelated window. It must yield no bytes.
        binary_info = types.SimpleNamespace(bitness=32, base_addr=0x1000, binary=b"\x55\x8b\xec" * 1024)
        candidate = FunctionCandidate(binary_info, 0x500)
        self.assertEqual(candidate.bytes, b"")


if __name__ == "__main__":
    unittest.main()
