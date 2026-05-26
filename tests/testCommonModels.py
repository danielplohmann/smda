import hashlib
import struct
import unittest

from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import SmdaFunction


class TestCommonModels(unittest.TestCase):
    def test_empty_basic_block_string_is_safe(self):
        self.assertEqual(str(SmdaBasicBlock([])), "0x????????: (   0)")

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
