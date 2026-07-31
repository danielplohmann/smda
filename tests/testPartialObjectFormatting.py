import unittest

from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyResult import DisassemblyResult


class TestPartialObjectFormatting(unittest.TestCase):
    """Display helpers must not raise on partially-populated objects; every offset-like field
    on these models is nullable, so formatting it as an integer crashed."""

    def test_function_str(self):
        self.assertIn("0x????????", str(SmdaFunction()))

    def test_instruction_str(self):
        self.assertIn("0x????????", str(SmdaInstruction()))

    def test_basic_block_str(self):
        self.assertIn("0x????????", str(SmdaBasicBlock([])))

    def test_report_str(self):
        self.assertIn("0x????????", str(SmdaReport()))

    def test_report_str_for_error_status(self):
        report = SmdaReport()
        report.status = "error"
        report.message = "boom"
        self.assertIn("boom", str(report))

    def test_pic_hash_helpers_tolerate_missing_hash(self):
        function = SmdaFunction()
        self.assertIsNone(function.getPicHashAsLong())
        self.assertIsNone(function.getPicHashAsHex())


class TestApiRefInitialization(unittest.TestCase):
    def test_api_refs_are_initialized_once_and_invalidated_on_new_reference(self):
        result = DisassemblyResult()
        result.functions[0x1000] = [[(0x1000, 2, "call", "0x2000", b"\xff\xd0")]]
        # a binary with zero APIs must not re-walk the (empty) API table on every call
        self.assertEqual({}, result.getApiRefs(0x1000))
        self.assertTrue(result._api_refs_initialized)

        result.addApiReference(0x2000, 0x1000, "kernel32.dll", "Sleep")
        self.assertFalse(result._api_refs_initialized)
        self.assertEqual({0x1000: "kernel32.dll!Sleep"}, result.getApiRefs(0x1000))


if __name__ == "__main__":
    unittest.main()
