from binascii import hexlify

from .definitions import COMMON_PROLOGUES

class FunctionCandidate(object):

    def __init__(self, binary_info, addr):
        self.bitness = binary_info.bitness
        self.addr = addr
        rel_start_addr = addr - binary_info.base_addr
        self.bytes = binary_info.binary[rel_start_addr:rel_start_addr + 5]
        self.lang_spec = None
        self.call_ref_sources = []
        self.finished = False
        self.is_symbol = False
        self.is_gap_candidate = False
        self.is_tailcall = False
        self.alignment = 0
        if addr % 4 == 0:
            self.alignment = 4
        elif addr % 16 == 0:
            self.alignment = 16
        self.analysis_aborted = False
        self.abortion_reason = ""
        self._score = None
        self._tfidf_score = None
        self._confidence = None
        self.function_start_score = None
        self.is_stub = False
        self.is_initial_candidate = False
        self.is_exception_handler = False

    def setTfIdf(self, tfidf_score):
        self._tfidf_score = tfidf_score

    def getTfIdf(self):
        return round(self._tfidf_score, 3)

    def getConfidence(self):
        if self._confidence is None:
            # based on evaluation over Andriesse, Bao, and Plohmann data sets
            weighted_confidence = 0.298 * (1 if self.hasCommonFunctionStart() else 0)
            if self._tfidf_score is not None:
                weighted_confidence += (
                    0.321 * (1 if self._tfidf_score < 0 else 0) +
                    0.124 * (1 if self._tfidf_score < -2 else 0) +
                    0.120 * (1 if self._tfidf_score < -4 else 0) +
                    0.101 * (1 if self._tfidf_score < -1 else 0) +
                    0.025 * (1 if self._tfidf_score < -8 else 0)
                    )
            # above experiments show that multiple inbound call references are basically always indeed functions
            if len(self.call_ref_sources) > 1:
                self._confidence = 1.0
            # initially recognized candidates are also almost always functions as they follow this heuristic
            elif self.is_initial_candidate:
                self._confidence = round(0.5 + 0.5 * (weighted_confidence), 3)
            else:
                self._confidence = round(weighted_confidence, 3)
        return self._confidence

    def hasCommonFunctionStart(self):
        for length in sorted([int(l) for l in COMMON_PROLOGUES], reverse=True):
            byte_sequence = self.bytes[:length]
            if byte_sequence in COMMON_PROLOGUES["%d" % length][self.bitness]:
                return True
        return False

    def getFunctionStartScore(self):
        if self.function_start_score is None:
            for length in sorted([int(l) for l in COMMON_PROLOGUES], reverse=True):
                byte_sequence = self.bytes[:length]
                if byte_sequence in COMMON_PROLOGUES["%d" % length][self.bitness]:
                    self.function_start_score = COMMON_PROLOGUES["%d" % length][self.bitness][byte_sequence]
                    break
            self.function_start_score = self.function_start_score if self.function_start_score else 0
        return self.function_start_score

    def addCallRef(self, source_addr):
        if source_addr not in self.call_ref_sources:
            self.call_ref_sources.append(source_addr)
        self._score = None

    def removeCallRefs(self, source_addrs):
        for addr in source_addrs:
            if addr in self.call_ref_sources:
                self.call_ref_sources.remove(addr)
        self._score = None

    def setIsTailcallCandidate(self, is_tailcall):
        self.is_tailcall = is_tailcall

    def setInitialCandidate(self, initial):
        self.is_initial_candidate = initial

    def setIsGapCandidate(self, gap):
        self.is_gap_candidate = gap

    def setLanguageSpec(self, lang_spec):
        self.lang_spec = lang_spec
        self._score = None

    def setIsSymbol(self, is_symbol):
        self.is_symbol = is_symbol
        self._score = None

    def setIsExceptionHandler(self, is_exception_handler):
        self.is_exception_handler = is_exception_handler
        self._score = None

    def setIsStub(self, is_stub):
        self.is_stub = is_stub
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
        score += 10000 if self.is_symbol else 0
        score += 5000 if self.is_exception_handler else 0
        score += 1000 if self.is_stub else 0
        score += 100 if self.lang_spec is not None else 0
        score += self.getFunctionStartScore()
        num_call_refs = len(self.call_ref_sources)
        if num_call_refs >= 10:
            call_ref_score = 10 + int(num_call_refs / 10)
        else:
            call_ref_score = num_call_refs
        score += 10 * call_ref_score
        score += 1 if self.alignment else 0
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
        return own_score < other_score

    def getCharacteristics(self):
        is_aligned = "a" if self.alignment else "-"
        is_finished = "f" if self.finished else "-"
        is_gap = "g" if self.is_gap_candidate else "-"
        is_initial = "i" if self.is_initial_candidate else "-"
        is_lang_spec = "l" if self.lang_spec is not None else "-"
        is_prologue = "p" if self.hasCommonFunctionStart() else "-"
        is_ref = "r" if self.call_ref_sources else "-"
        is_symbol = "s" if self.is_symbol else "-"
        is_tailcall = "t" if self.is_tailcall else "-"
        is_stub = "u" if self.is_stub else "-"
        is_aborted = "x" if self.analysis_aborted else "-"
        characteristics = is_initial + is_symbol + is_stub + is_aligned + is_lang_spec + is_prologue + is_ref + is_tailcall + is_gap + is_finished + is_aborted
        return characteristics

    def __str__(self):
        characteristics = self.getCharacteristics()
        prologue_score = "%d" % self.getFunctionStartScore()
        ref_summary = "{}".format(len(self.call_ref_sources)) if len(self.call_ref_sources) != 1 else "{}: 0x{:x}".format(len(self.call_ref_sources), self.call_ref_sources[0])
        return "0x{:x}: {} -> {} (total score: {}), inref: {} | {}".format(self.addr, hexlify(self.bytes), prologue_score, self.getScore(), ref_summary, characteristics)

    def toJson(self):
        return {
            "addr": self.addr,
            "bytes": self.bytes.hex(),
            "alignment": self.alignment,
            "reason": self.abortion_reason,
            "num_refs": len(self.call_ref_sources),
            "characteristics": self.getCharacteristics(),
            "prologue_score": self.getFunctionStartScore(),
            "score": self.calculateScore(),
            "confidence": self.getConfidence()
        }
