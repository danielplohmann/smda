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

    def testSingleNodeGraphsYieldOneComponent(self):
        """SmdaFunction._calculateSccs returns [[key]] for these without running Tarjan."""
        for graph in ({0x100: []}, {0x100: [0x100]}):
            with self.subTest(graph=graph):
                tarjan = Tarjan(graph)
                tarjan.calculateScc()
                self.assertEqual([[0x100]], tarjan.getResult())


if __name__ == "__main__":
    unittest.main()
