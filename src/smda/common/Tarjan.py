"""
Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
for finding the strongly connected components of a graph.
This can be used to find loops.
Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
- Refactored into a class to allow pooled computation by Daniel Plohmann
- Implementation by Bas Westerbaan:
  https://github.com/bwesterb/py-tarjan
"""


class Tarjan:
    """g is the graph represented as a dictionary { <vertex> : <successors of vertex> }"""

    def __init__(self, graph):
        self._graph = graph
        self._stack = []
        self._stack_set = set()
        self._index = {}
        self._lowlink = {}
        self._result = []

    def calculateScc(self):
        graph = self._graph
        stack = self._stack
        stack_set = self._stack_set
        index = self._index
        lowlink = self._lowlink
        result = self._result
        idx = 0

        for root in graph:
            if root in index:
                continue
            call_stack = [(root, iter(graph.get(root, ())))]
            index[root] = lowlink[root] = idx
            idx += 1
            stack.append(root)
            stack_set.add(root)

            while call_stack:
                v, it = call_stack[-1]
                pushed = False
                for w in it:
                    if w not in index:
                        index[w] = lowlink[w] = idx
                        idx += 1
                        stack.append(w)
                        stack_set.add(w)
                        call_stack.append((w, iter(graph.get(w, ()))))
                        pushed = True
                        break
                    elif w in stack_set:
                        if index[w] < lowlink[v]:
                            lowlink[v] = index[w]
                if pushed:
                    continue

                call_stack.pop()
                if lowlink[v] == index[v]:
                    scc = []
                    while True:
                        w = stack.pop()
                        stack_set.remove(w)
                        scc.append(w)
                        if w == v:
                            break
                    result.append(scc)

                if call_stack:
                    p = call_stack[-1][0]
                    if lowlink[v] < lowlink[p]:
                        lowlink[p] = lowlink[v]

        return result

    def closure(self):
        """Given a graph @g, returns the transitive closure of @g"""
        ret = {}
        for scc in self.calculateScc():
            ws = set()
            ews = set()
            for v in scc:
                ws.update(self._graph.get(v, ()))
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
