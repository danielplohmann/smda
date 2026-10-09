from smda.common.FunctionCandidate import FunctionCandidate as _CommonFunctionCandidate

from .definitions import is_a32_prologue, is_t32_prologue


class FunctionCandidate(_CommonFunctionCandidate):
    """A function-start candidate that knows which instruction set it is decoded in.

    ``is_thumb`` is filled in by the candidate manager once the candidate exists; the
    entry-shape test reads the first word in that instruction set.
    """

    BYTE_WINDOW_SIZE = 4

    def __init__(self, binary_info, addr):
        super().__init__(binary_info, addr)
        self.is_thumb = False

    def hasCommonFunctionStart(self):
        if len(self.bytes) < 4:
            return False
        if self.is_thumb:
            return is_t32_prologue(int.from_bytes(self.bytes[:2], "little"), int.from_bytes(self.bytes[2:4], "little"))
        return self.addr % 4 == 0 and is_a32_prologue(int.from_bytes(self.bytes[:4], "little"))

    def getFunctionStartScore(self):
        # One point: enough for a prologue-only candidate that sits off a word boundary (T32
        # entries are only halfword aligned, so the base class's alignment point is not
        # guaranteed) to be analysed at all, and too little to outrank a single inbound
        # call. A frame push also appears after a shrink-wrapped early exit, and the
        # enclosing function has to claim those bytes first.
        if self.function_start_score is None:
            self.function_start_score = 1 if self.hasCommonFunctionStart() else 0
        return self.function_start_score

    def toJson(self):
        result = super().toJson()
        result["thumb"] = self.is_thumb
        return result
