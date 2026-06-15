import hashlib
import struct
import unittest

from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport


class TestCommonModels(unittest.TestCase):
    def test_empty_basic_block_string_is_safe(self):
        self.assertEqual(str(SmdaBasicBlock([])), "0x????????: (   0)")

    def test_report_without_disassembly_has_empty_cfg(self):
        # reports built without a disassembly (e.g. controlled error reports
        # for unsupported architectures) must expose an empty CFG, not crash
        report = SmdaReport()
        self.assertEqual(report.num_functions, 0)
        self.assertIsNone(report.getFunction(0x1000))
        self.assertEqual(list(report.getFunctions()), [])

    def test_report_without_disassembly_serializes(self):
        # such a report must also survive toDict() (no xmetadata/timestamp crash)
        report_dict = SmdaReport().toDict()
        self.assertEqual(report_dict["xcfg"], {})
        self.assertEqual(report_dict["xmetadata"], {})
        self.assertEqual(report_dict["timestamp"], "")
        # and round-trip back through fromDict without a strptime("") crash
        restored = SmdaReport.fromDict(report_dict)
        self.assertIsNone(restored.timestamp)
        self.assertEqual(restored.num_functions, 0)

    def test_function_hash_helpers_use_little_endian(self):
        function = SmdaFunction()
        function.pic_hash = 0x0102030405060708
        function.getPicHashSequence = lambda binary_info: b"pic-sequence"
        function.getOpcHashSequence = lambda: b"opc-sequence"

        self.assertEqual(function.getPicHashAsHex(), struct.pack("<Q", function.pic_hash).hex())
        self.assertEqual(
            function.getPicHash(None),
            struct.unpack("<Q", hashlib.sha256(b"pic-sequence").digest()[:8])[0],
        )
        self.assertEqual(
            function.getOpcHash(),
            struct.unpack("<Q", hashlib.sha256(b"opc-sequence").digest()[:8])[0],
        )


if __name__ == "__main__":
    unittest.main()
