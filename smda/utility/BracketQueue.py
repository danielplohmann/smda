class BracketQueue(object):
    """
    This queue is tailored based on our research rsults regarding function entry point identification
    """
    def __init__(self, candidates=None, initial_brackets=None):
        self.update_count = 0
        self.update_shift_count = 0
        self.brackets = {
            0: {},
            1: {},
            2: {}
        }
        if candidates is not None:
            for candidate in candidates:
                self.add(candidate)
            self.ensure_order()
        elif initial_brackets is not None:
            self.brackets = initial_brackets
            self.ensure_order()
        
    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if all(len(self.brackets[i]) == 0 for i in range(3)):
            raise StopIteration
        for bracket_index in range(2, -1, -1):
            if self.brackets[bracket_index]:
                offset, candidate = self.brackets[bracket_index].popitem()
                return candidate

    def add(self, candidate):
        bracket_index = min(2, len(candidate.call_ref_sources))
        self.brackets[bracket_index][candidate.addr] = candidate

    def update(self, target_candidate=None):
        if target_candidate:
            updated_bracket_index = min(2, len(target_candidate.call_ref_sources))
            # check if the element is still in the same bracket, otherwise shift to next bracket
            self.update_count += 1
            for bracket_index in range(2, -1, -1):
                if target_candidate.addr in self.brackets[bracket_index] and bracket_index != updated_bracket_index:
                    self.update_shift_count += 1
                    self.brackets[bracket_index].pop(target_candidate.addr)
                    self.brackets[updated_bracket_index][target_candidate.addr] = target_candidate
                    break

    def ensure_order(self):
        for bracket_index in range(2, -1, -1):
            if self.brackets[bracket_index]:
                self.brackets[bracket_index] = {offset: candidate for offset, candidate in sorted(self.brackets[bracket_index].items(), key=lambda x: x[1].getScore())}

    def __str__(self):
        return f"BracketQueue | 2: {len(self.brackets[2])} candidates, 1: {len(self.brackets[1])} candidates, 0: {len(self.brackets[0])} candidates,"
