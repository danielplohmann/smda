import heapq


class _HeapItem:
    __slots__ = ("neg_score", "addr", "element")

    def __init__(self, element):
        self.element = element
        self.addr = element.addr
        self.neg_score = -element.getScore()

    def __lt__(self, other):
        return (self.neg_score, self.addr) < (other.neg_score, other.addr)


class PriorityQueue:
    def __init__(self, content=None):
        content = list(content) if content else []
        self._in_heap = set(content)
        self.heap = [_HeapItem(element) for element in content]
        if self.heap:
            heapq.heapify(self.heap)

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        while self.heap:
            item = heapq.heappop(self.heap)
            element = item.element
            if element not in self._in_heap:
                continue
            if item.neg_score != -element.getScore():
                heapq.heappush(self.heap, _HeapItem(element))
                continue
            self._in_heap.discard(element)
            return element
        raise StopIteration

    def add(self, element):
        if element in self._in_heap:
            return
        heapq.heappush(self.heap, _HeapItem(element))
        self._in_heap.add(element)

    def update(self, target_candidate=None):
        if target_candidate is not None:
            if target_candidate in self._in_heap:
                heapq.heappush(self.heap, _HeapItem(target_candidate))
            return
        self.heap = [_HeapItem(element) for element in self._in_heap]
        heapq.heapify(self.heap)

    def __str__(self):
        return str([item.element for item in self.heap])
