#!/usr/bin/python

import logging
import os
import unittest

from smda.common.Tarjan import Tarjan

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class TarjanTestSuite(unittest.TestCase):
    """Provoke recursion"""

    def testInstructionEscaping(self):
        test_data = {i: [] for i in range(10000)}
        for i in range(1, 10000):
            for j in range(i + 1, 10000, 1):
                test_data[i].append(j)
        test_data[10000] = []

        tarjan = Tarjan(test_data)
        tarjan.calculateScc()
        sccs = tarjan.getResult()
        self.assertEqual(10001, len(sccs))


if __name__ == '__main__':
    unittest.main()
