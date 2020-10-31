# Implementation by Armin Rigo
# source: https://bitbucket.org/arigo/arigo/src/default/hack/pypy-hack/heapstats/dominator.py

# Implementation following:
#
#   Lengauer, Thomas; and Tarjan, Robert Endre (July 1979).
#   "A fast algorithm for finding dominators in a flowgraph".
#   ACM Transactions on Programming Languages and Systems (TOPLAS) 1 (1):
#   121-141.
#
#   http://portal.acm.org/ft_gateway.cfm?id=357071

import logging

LOGGER = logging.getLogger(__name__)

class DominatorTree(object):

    def __init__(self, G, r):
        assert r in G
        self.succ = G
        self.r = r

    def init_variables(self):
        self.parent = {}
        self.pred = {}
        self.semi = {}
        self.vertex = []
        self.bucket = {}
        self.dom = {}
        self.ancestor = {}
        self.label = {}
        for v in self.succ:
            self.pred[v] = set()
            self.bucket[v] = set()

    def depth_first_search(self, v):
        stack = [v]
        while stack:
            v = stack.pop()
            n = len(self.vertex)
            self.semi[v] = n
            self.vertex.append(v)
            for w in self.succ[v]:
                self.pred[w].add(v)
                if w not in self.semi:
                    self.parent[w] = v
                    self.semi[w] = None     # temporarily
                    stack.append(w)

    def LINK(self, v, w):
        self.ancestor[w] = v

    def EVAL(self, v):
        if v not in self.ancestor:
            return v
        else:
            self.COMPRESS(v)
            return self.label.get(v, v)

    def COMPRESS(self, v):
        if self.ancestor[v] in self.ancestor:
            self.COMPRESS(self.ancestor[v])
            w = self.ancestor[v]
            if self.semi[self.label.get(w,w)] < self.semi[self.label.get(v,v)]:
                self.label[v] = self.label.get(w,w)
            self.ancestor[v] = self.ancestor[w]

    def steps_2_3(self):
        for w in self.vertex[:0:-1]:
            # step 2
            for v in self.pred[w]:
                u = self.EVAL(v)
                if self.semi[u] < self.semi[w]:
                    self.semi[w] = self.semi[u]
            self.bucket[self.vertex[self.semi[w]]].add(w)
            self.LINK(self.parent[w], w)
            # step 3
            for v in list(self.bucket[self.parent[w]]):
                self.bucket[self.parent[w]].remove(v)
                u = self.EVAL(v)
                if self.semi[u] < self.semi[v]:
                    self.dom[v] = u
                else:
                    self.dom[v] = self.parent[w]

    def step_4(self):
        for w in self.vertex[1:]:
            if self.dom[w] != self.vertex[self.semi[w]]:
                self.dom[w] = self.dom[self.dom[w]]

    def compute(self):
        self.init_variables()
        self.depth_first_search(self.r)
        self.steps_2_3()
        self.step_4()


def fix_graph(graph):
    expanded_graph = {}
    for key, values in graph.items():
        expanded_graph[key] = values
        for value in values:
            if value not in expanded_graph:
                expanded_graph[value] = []
    return expanded_graph


# Calculation of Nesting Depth by walking down dominators and summarizing weights
# Implementation by Steffen Enders and Daniel Plohmann

def build_dominator_tree(G, r):
    expanded_graph = fix_graph(G)
    if not r in expanded_graph:
        # print("r not in G:", r, G)
        LOGGER.debug("r not in G: %s %s", r, G)
        return None
    domtree = DominatorTree(expanded_graph, r)
    domtree.compute()
    inverted = {}
    for key, value in domtree.dom.items():
        if value not in inverted:
            inverted[value] = []
        inverted[value].append(key)
    return inverted

def get_nesting_depth(graph, domtree, root):
    expanded_graph = fix_graph(graph)
    significant_nodes = set.union(*([set(v) for v in expanded_graph.values() if len(v) > 1] + [set()]))
    # print("significant_nodes", significant_nodes)
    def maximum_costs(cn):
        # print("  maximum_costs cn", cn)
        if cn not in domtree or not domtree[cn]:
            # print("    %d not in domtree or not domtree[%d]" % (cn, cn), 1 if cn in significant_nodes else 0)
            return (1 if cn in significant_nodes else 0)
        val = max(maximum_costs(n) for n in domtree[cn]) + (1 if cn in significant_nodes else 0)
        # print("   ", val, 1 if cn in significant_nodes else 0)
        return val
    try:
        return maximum_costs(root)
    except:
        return 0



if __name__ == "__main__":
    test_data = [
        {
            "smda": {10208: [10229], 10229: [10240, 10253], 10240: [10244, 10246], 10244: [10246], 10246: [10240, 10253], 10253: [10229, 10261]},
            "smda_function": 10208,
            "fixed": {10208: [10229], 10229: [10240, 10253], 10240: [10244, 10246], 10253: [10229, 10261], 10244: [10246], 10246: [10240, 10253], 10261: []},
            "dt": {10240: [10244, 10246], 10229: [10240, 10253], 10253: [10261], 10208: [10229]},
            "nd": 3
        }, {
            "smda": {1: [2], 2: [3, 4, 6], 3: [5], 4: [5], 5: [2]},
            "smda_function": 1,
            "fixed": {1: [2], 2: [3, 4, 6], 3: [5], 4: [5], 6: [], 5: [2]},
            "dt": {2: [3, 4, 5, 6], 1: [2]},
            "nd": 1
        }, {
            "smda": {1: [2], 2: [3, 6], 3: [41, 42], 41: [5], 42: [5], 5: [2]},
            "smda_function": 1,
            "fixed": {1: [2], 2: [3, 6], 3: [41, 42], 6: [], 41: [5], 42: [5], 5: [2]},
            "dt": {3: [41, 42, 5], 2: [3, 6], 1: [2]},
            "nd": 2
        },

    ]
    for data in test_data:
        print("*" * 80)
        print("Running Test Case: ", data["smda_function"])
        print("*" * 80)
        print("smda", data["smda"])
        fixed_smda = {}
        for key, values in data["smda"].items():
            fixed_smda[key] = values
            for value in values:
                if value not in fixed_smda:
                    fixed_smda[value] = []
        print("fixed_smda", fixed_smda)
        assert fixed_smda == data["fixed"]
        dt = build_dominator_tree(data["smda"], data["smda_function"])
        print("dominator tree", dt)
        assert dt == data["dt"]
        nd = get_nesting_depth(fixed_smda, dt, data["smda_function"])
        print("nd", nd)
        assert nd == data["nd"]
