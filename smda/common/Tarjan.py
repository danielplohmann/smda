

class Tarjan(object):
    """
    Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
    for finding the strongly connected components of a graph.
    This can be used to find loops.
    Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm

    - Refactored to allow pooled computation by Daniel Plohmann
    - Implementation by Dries Verdegem:
      http://www.logarithmic.net/pfh-files/blog/01208083168/tarjan.py
    - Taken from Dr. Paul Harrison Blog:
      http://www.logarithmic.net/pfh/blog/01208083168
    """

    def __init__(self, graph):
        self._graph = graph
        self._index_counter = [0]
        self._stack = []
        self._lowlinks = {}
        self._index = {}
        self._result = []

    def _calculateSccForNode(self, node):
        # set the depth index for this node to the smallest unused index
        self._index[node] = self._index_counter[0]
        self._lowlinks[node] = self._index_counter[0]
        self._index_counter[0] += 1
        self._stack.append(node)

        # Consider successors of `node`
        try:
            successors = self._graph[node]
        except:
            successors = []
        for successor in successors:
            if successor not in self._lowlinks:
                # Successor has not yet been visited; recurse on it
                self._calculateSccForNode(successor)
                self._lowlinks[node] = min(self._lowlinks[node], self._lowlinks[successor])
            elif successor in self._stack:
                # the successor is in the stack and hence in the current strongly connected component (SCC)
                self._lowlinks[node] = min(self._lowlinks[node], self._index[successor])

        # If `node` is a root node, pop the stack and generate an SCC
        if self._lowlinks[node] == self._index[node]:
            connected_component = []

            while True:
                successor = self._stack.pop()
                connected_component.append(successor)
                if successor == node:
                    break
            component = tuple(connected_component)
            # storing the result
            self._result.append(component)

    def calculateScc(self):
        """
        @param graph: a dictionary describing a directed graph, with keys as nodes and values as successors.
        @type graph: (dict)
        @return: (a list of tuples) describing the SCCs
        """
        for node in self._graph:
            if node not in self._lowlinks:
                self._calculateSccForNode(node)

    def getResult(self):
        return self._result
