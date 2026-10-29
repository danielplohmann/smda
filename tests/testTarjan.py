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

    def testClosureHandlesSuccessorOnlyVertex(self):
        """Vertices that are only successors have no key in the graph (#411)."""
        closure = Tarjan({1: [2], 3: [1, 4], 4: [3]}).closure()
        self.assertEqual({1, 2, 3, 4}, set(closure))
        self.assertEqual((), closure[2])
        self.assertEqual({2}, set(closure[1]))
        self.assertEqual({1, 2, 3, 4}, set(closure[3]))
        self.assertEqual({1, 2, 3, 4}, set(closure[4]))


if __name__ == "__main__":
    unittest.main()
