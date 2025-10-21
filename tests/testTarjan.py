#!/usr/bin/python

import logging
import unittest

from smda.common.Tarjan import Tarjan

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class TarjanTestSuite(unittest.TestCase):
    """Provoke recursion"""

    def testInstructionEscaping(self):
        test_data = {i: [] for i in range(1000)}
        for i in range(1, 1000):
            for j in range(i + 1, 1000, 1):
                test_data[i].append(j)
        test_data[1000] = []

        tarjan = Tarjan(test_data)
        tarjan.calculateScc()
        sccs = tarjan.getResult()
        self.assertEqual(1001, len(sccs))


if __name__ == "__main__":
    unittest.main()
