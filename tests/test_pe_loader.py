
import unittest

from smda.utility.PeFileLoader import PeFileLoader

class PeFileLoaderTestSuite(unittest.TestCase):

    def test_mergeCodeAreas(self):
        # Test case 1: Overlapping intervals
        intervals1 = [[1, 5], [3, 7], [8, 12]]
        expected1 = [[1, 5], [3, 7], [8, 12]]
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals1), expected1)

        # Test case 2: Contiguous intervals
        intervals2 = [[1, 5], [5, 10], [10, 15]]
        expected2 = [[1, 15]]
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals2), expected2)

        # Test case 3: Separated intervals
        intervals3 = [[1, 5], [6, 10], [11, 15]]
        expected3 = [[1, 5], [6, 10], [11, 15]]
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals3), expected3)

        # Test case 4: Empty list
        intervals4 = []
        expected4 = []
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals4), expected4)

        # Test case 5: Single interval
        intervals5 = [[1, 5]]
        expected5 = [[1, 5]]
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals5), expected5)

        # Test case 6: Mixed intervals
        intervals6 = [[1, 5], [5, 10], [11, 15], [15, 20]]
        expected6 = [[1, 10], [11, 20]]
        self.assertEqual(PeFileLoader.mergeCodeAreas(intervals6), expected6)

if __name__ == '__main__':
    unittest.main()
