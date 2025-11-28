import unittest

from smda.utility.PeFileLoader import PeFileLoader


class PeFileLoaderTestSuite(unittest.TestCase):
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
