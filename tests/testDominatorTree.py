#!/usr/bin/python

import logging
import unittest

from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class DominatorTreeTestSuite(unittest.TestCase):
    """Regression coverage for get_nesting_depth's recursion-limit robustness."""

    def testNestingDepthUnchangedOnShallowTree(self):
        # Pin against the module's own self-test fixture (test_data[0] in the
        # __main__ block) so the iterative rewrite of maximum_costs is proven
        # to be behavior-preserving on a normal, shallow dominator tree.
        smda = {
            10208: [10229],
            10229: [10240, 10253],
            10240: [10244, 10246],
            10244: [10246],
            10246: [10240, 10253],
            10253: [10229, 10261],
        }
        fixed_smda = {}
        for key, values in smda.items():
            fixed_smda[key] = values
            for value in values:
                if value not in fixed_smda:
                    fixed_smda[value] = []

        dt = build_dominator_tree(smda, 10208)
        nd = get_nesting_depth(fixed_smda, dt, 10208)

        self.assertEqual(
            dt,
            {
                10240: [10244, 10246],
                10229: [10240, 10253],
                10253: [10261],
                10208: [10229],
            },
        )
        self.assertEqual(nd, 3)

    def testNestingDepthSurvivesDeepDominatorChain(self):
        # A long, degenerate single-successor dominator-tree chain (as could
        # arise from obfuscated/generated code) used to blow past Python's
        # default recursion limit inside maximum_costs' recursive helper.
        # The RecursionError was swallowed by get_nesting_depth's blanket
        # except-Exception handler, silently returning 0 instead of the
        # correct depth. The iterative post-order rewrite must handle this
        # without raising and without losing the real depth value.
        chain_length = 2000

        # Every node 0..chain_length-1 has out-degree 2 in the graph (branch
        # to the next node plus a shared "sink"), so every node in
        # 1..chain_length plus "sink" is a "significant_node" and thus
        # contributes 1 to the nesting-depth cost -- node 0 alone does not.
        # This makes the expected total nesting depth exactly chain_length.
        graph = {i: [i + 1, "sink"] for i in range(chain_length)}
        graph["sink"] = []

        domtree = {i: [i + 1] for i in range(chain_length)}
        domtree[chain_length] = []

        nd = get_nesting_depth(graph, domtree, 0)

        self.assertEqual(nd, chain_length)
        self.assertNotEqual(nd, 0)


if __name__ == "__main__":
    unittest.main()
