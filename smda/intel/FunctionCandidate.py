from binascii import hexlify

from .definitions import COMMON_PROLOGUES

class FunctionCandidate(object):

    def __init__(self, addr, function_bytes, bitness=32):
        self.bitness = bitness
        self.addr = addr
        self.lang_spec = None
        self.bytes = function_bytes
        self.call_ref_sources = []
        self.finished = False
        self.analysis_aborted = False
        self.abortion_reason = ""
        self._score = None

    def hasCommonFunctionStart(self):
        for length in sorted([int(l) for l in COMMON_PROLOGUES], reverse=True):
            byte_sequence = self.bytes[:length]
            if byte_sequence in COMMON_PROLOGUES["%d" % length][self.bitness]:
                return True
        return False

    def getFunctionStartScore(self):
        for length in sorted([int(l) for l in COMMON_PROLOGUES], reverse=True):
            byte_sequence = self.bytes[:length]
            if byte_sequence in COMMON_PROLOGUES["%d" % length][self.bitness]:
                return COMMON_PROLOGUES["%d" % length][self.bitness][byte_sequence]
        return 0

    def addCallRef(self, source_addr):
        if source_addr not in self.call_ref_sources:
            self.call_ref_sources.append(source_addr)
        self._score = None

    def removeCallRefs(self, source_addrs):
        for addr in source_addrs:
            if addr in self.call_ref_sources:
                self.call_ref_sources.remove(addr)
        self._score = None

    def setLanguageSpec(self, lang_spec):
        self.lang_spec = lang_spec
        self._score = None

    def setAnalysisAborted(self, reason):
        self.finished = True
        self.analysis_aborted = True
        self.abortion_reason = reason

    def setAnalysisCompleted(self):
        self.finished = True

    def isFinished(self):
        return self.finished
        
    def calculateScore(self):
        score = 0
        # TODO: Review this scoring mechanism and replace intuition with science :)
        score += 1 if self.lang_spec is not None else 0
        score += self.getFunctionStartScore()
        call_ref_score = 1 + int(len(self.call_ref_sources) / 10)
        score += call_ref_score if self.call_ref_sources else 0
        return score
        
    def getScore(self):
        if self._score is None:
            self._score = self.calculateScore()
        return self._score

    def __lt__(self, other):
        own_score = self.getScore()
        other_score = other.getScore()
        if own_score == other_score:
            return self.addr > other.addr
        else:
            return own_score < other_score

    def __str__(self):
        is_ref = "r" if self.call_ref_sources else "-"
        is_prologue = "p" if self.hasCommonFunctionStart() else "-"
        is_lang_spec = "l" if self.lang_spec is not None else "-"
        is_finished = "f" if self.finished else "-"
        is_aborted = "a" if self.analysis_aborted else "-"
        prologue_score = "%d" % self.getFunctionStartScore()
        characteristics = is_ref + is_prologue + is_lang_spec + is_finished + is_aborted
        ref_summary = "{}".format(len(self.call_ref_sources)) if len(self.call_ref_sources) != 1 else "{}: 0x{:x}".format(len(self.call_ref_sources), self.call_ref_sources[0])
        return "0x{:x}: {} -> {} (total score: {}), inref: {} | {}".format(self.addr, hexlify(self.bytes), prologue_score, self.getScore(), ref_summary, characteristics)

