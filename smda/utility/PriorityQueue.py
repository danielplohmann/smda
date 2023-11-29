import heapq

class PriorityQueue(object):
    def __init__(self, content=None):
        if content is None:
            content = []
        self.heap = content
        if self.heap:
            self.update()

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if not self.heap:
            raise StopIteration
        if len(self.heap) == 1:
            return self.heap.pop()
        last_item = self.heap.pop()
        result = self.heap[0]
        self.heap[0] = last_item
        heapq._siftup_max(self.heap, 0)
        return result

    def add(self, element):
        self.heap.append(element)
        heapq._siftdown_max(self.heap, 0, len(self.heap)-1)

    def update(self, target_candidate=None):
        if target_candidate is None:
            heapq._heapify_max(self.heap)

    def __str__(self):
        return str(self.heap)
