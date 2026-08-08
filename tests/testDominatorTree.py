import random
import unittest

from smda.common.DominatorTree import build_dominator_tree, fix_graph


def _bruteforce_idoms(G, r):
    nodes = set()
    for k, vs in G.items():
        nodes.add(k)
        nodes.update(vs)
    reachable = {r}
    frontier = [r]
    while frontier:
        nxt = []
        for n in frontier:
            for s in G.get(n, []):
                if s not in reachable:
                    reachable.add(s)
                    nxt.append(s)
        frontier = nxt
    preds_of = {n: [] for n in reachable}
    for k, vs in G.items():
        if k not in reachable:
            continue
        for v in vs:
            if v in reachable:
                preds_of[v].append(k)
    D = {r: {r}}
    for n in reachable - {r}:
        D[n] = set(reachable)
    while True:
        changed = False
        for n in reachable - {r}:
            preds = preds_of[n]
            inter = set.intersection(*[D[p] for p in preds]) if preds else set()
            new = {n} | inter
            if new != D[n]:
                D[n] = new
                changed = True
        if not changed:
            break
    idom = {}
    for n in reachable - {r}:
        proper = D[n] - {n}
        if not proper:
            continue
        idom[n] = max(proper, key=lambda x: len(D[x]))
    return idom


def _inverted_idoms(idom):
    inv = {}
    for child, parent in idom.items():
        inv.setdefault(parent, []).append(child)
    return inv


class TestDominatorTree(unittest.TestCase):
    def test_existing_fixtures(self):
        cases = [
            {
                10208: [10229],
                10229: [10240, 10253],
                10240: [10244, 10246],
                10244: [10246],
                10246: [10240, 10253],
                10253: [10229, 10261],
            },
            {1: [2], 2: [3, 4, 6], 3: [5], 4: [5], 5: [2]},
            {1: [2], 2: [3, 6], 3: [41, 42], 41: [5], 42: [5], 5: [2]},
        ]
        for G in cases:
            inv = build_dominator_tree(G, min(G))
            self.assertIsNotNone(inv)

    def test_audit_breaking_example(self):
        G = {0: [2, 3], 1: [0, 6], 2: [1, 3, 5], 3: [4, 5], 4: [3, 6], 5: [0, 1, 6], 6: [4, 5]}
        inv = build_dominator_tree(G, 0)
        self.assertIn(4, inv.get(0, []))
        self.assertNotIn(4, inv.get(3, []))

    def test_randomized_oracle(self):
        rng = random.Random(1234)
        mismatches = 0
        for _ in range(2000):
            size = rng.randint(3, 7)
            G = {i: [] for i in range(size)}
            for i in range(size):
                for j in range(size):
                    if i != j and rng.random() < 0.4:
                        G[i].append(j)
            r = 0
            fix = fix_graph(G)
            if r not in fix:
                continue
            inv = build_dominator_tree(G, r)
            oracle = _inverted_idoms(_bruteforce_idoms(fix, r))
            inv_sets = {k: set(v) for k, v in inv.items()}
            oracle_sets = {k: set(v) for k, v in oracle.items()}
            if inv_sets != oracle_sets:
                mismatches += 1
        self.assertEqual(mismatches, 0)

    def test_deep_ancestor_chain_does_not_exhaust_the_recursion_limit(self):
        # the back edge is what makes this deep: every node from the tail up to node 1 is
        # already LINKed by the time node 1 is processed, so EVAL walks the whole chain
        size = 1500
        G = {i: [i + 1] for i in range(size)}
        G[size] = [1]

        inv = build_dominator_tree(G, 0)

        self.assertEqual(inv[0], [1])
        self.assertEqual(inv[size - 1], [size])
        self.assertNotIn(size, inv)


if __name__ == "__main__":
    unittest.main()
