import heapq


class _MaxHeapItem:
    def __init__(self, element):
        self.element = element

    def __lt__(self, other):
        return other.element < self.element


class PriorityQueue:
    def __init__(self, content=None):
        if content is None:
            content = []
        self.heap = [_MaxHeapItem(element) for element in content]
        if self.heap:
            self.update()

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if not self.heap:
            raise StopIteration
        return heapq.heappop(self.heap).element

    def add(self, element):
        heapq.heappush(self.heap, _MaxHeapItem(element))

    def update(self, target_candidate=None):
        heapq.heapify(self.heap)

    def __str__(self):
        return str([item.element for item in self.heap])
