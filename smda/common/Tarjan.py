"""
    Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
    for finding the strongly connected components of a graph.
    This can be used to find loops.
    Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
    - Refactored into a class to allow pooled computation by Daniel Plohmann
    - Implementation by Bas Westerbaan:
      https://github.com/bwesterb/py-tarjan
"""

class Tarjan(object):
    """ g is the graph represented as a dictionary { <vertex> : <successors of vertex> } """

    def __init__(self, graph):
        self._graph = graph
        self._stack = []
        self._stack_set = set([])
        self._index = {}
        self._lowlink = {}
        self._nonrecursive_stack = []
        self._result = []

    def _tarjan_head(self, v):
        self._index[v] = len(self._index)
        self._lowlink[v] = self._index[v]
        self._stack.append(v)
        self._stack_set.add(v)
        it = iter(self._graph.get(v, ()))
        self._nonrecursive_stack.append((it, False, v, None))

    def _tarjan_body(self, it, v):
        for w in it:
            if w not in self._index:
                self._nonrecursive_stack.append((it, True, v, w))
                self._tarjan_head(w)
                return
            if w in self._stack_set:
                self._lowlink[v] = min(self._lowlink[v], self._index[w])
        if self._lowlink[v] == self._index[v]:
            scc = []
            w = None
            while v != w:
                w = self._stack.pop()
                scc.append(w)
                self._stack_set.remove(w)
            self._result.append(scc)

    def calculateScc(self):
        main_iter = iter(self._graph)
        while True:
            try:
                v = next(main_iter)
            except StopIteration:
                return self._result
            if v not in self._index:
                self._tarjan_head(v)
            while self._nonrecursive_stack:
                it, inside, v, w = self._nonrecursive_stack.pop()
                if inside:
                    self._lowlink[v] = min(self._lowlink[w], self._lowlink[v])
                self._tarjan_body(it, v)

    def closure(self):
        """ Given a graph @g, returns the transitive closure of @g """
        ret = {}
        for scc in self.calculateScc():
            ws = set()
            ews = set()
            for v in scc:
                ws.update(self._graph[v])
            for w in ws:
                assert w in ret or w in scc
                ews.add(w)
                ews.update(ret.get(w, ()))
            if len(scc) > 1:
                ews.update(scc)
            ews = tuple(ews)
            for v in scc:
                ret[v] = ews
        return ret

    def getResult(self):
        return self._result
