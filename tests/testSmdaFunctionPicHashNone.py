import struct
import unittest

from smda.common.SmdaFunction import SmdaFunction


class TestSmdaFunctionPicHashNone(unittest.TestCase):
    def test_getPicHashAsHex_returns_none_when_unset(self):
        # 36 (sub-item): getPicHashAsHex raised struct.error on pic_hash is None (the class
        # default when CALCULATE_HASHING is off); the sibling getPicHashAsLong returns None.
        function = SmdaFunction()
        function.pic_hash = None
        self.assertIsNone(function.getPicHashAsHex())
        function.pic_hash = 0x0102030405060708
        self.assertEqual(function.getPicHashAsHex(), struct.pack("<Q", function.pic_hash).hex())


if __name__ == "__main__":
    unittest.main()
