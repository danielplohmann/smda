from smda.common.FunctionCandidate import FunctionCandidate as _CommonFunctionCandidate

from .definitions import COMMON_PROLOGUES, ENDBR64_BYTES

# Hoisted: prologue lengths are checked longest-first on every candidate scoring call.
# Pre-sort once at import time instead of re-sorting per call (hot path during CFG recovery).
_COMMON_PROLOGUE_LENGTHS = sorted((int(k) for k in COMMON_PROLOGUES), reverse=True)
_ENDBR64_LEN = len(ENDBR64_BYTES)
# longest byte window a candidate ever needs to see: the widest prologue match, plus a
# potential leading endbr64 to strip before re-matching the remainder.
_PROLOGUE_WINDOW_SIZE = _COMMON_PROLOGUE_LENGTHS[0] + _ENDBR64_LEN


class FunctionCandidate(_CommonFunctionCandidate):
    BYTE_WINDOW_SIZE = _PROLOGUE_WINDOW_SIZE

    def _lookupPrologueScore(self, byte_window):
        # longest-first, so a specific multi-byte match always wins over a weak single-byte fallback.
        for length in _COMMON_PROLOGUE_LENGTHS:
            window_slice = byte_window[:length]
            if len(window_slice) < length:
                continue
            prologue_score = COMMON_PROLOGUES.get(f"{length}", {}).get(self.bitness, {}).get(window_slice)
            if prologue_score is not None:
                return prologue_score
        return None

    def isLandingPadEntry(self):
        return self.bitness == 64 and self.bytes[:_ENDBR64_LEN] == ENDBR64_BYTES

    def getFunctionStartScore(self):
        if self.function_start_score is None:
            # endbr64 is a CET landing pad prefixing the real prologue, not a prologue itself:
            # strip it before matching so the prologue behind it is scored, not the raw bytes.
            byte_window = self.bytes
            if self.bitness == 64 and self.bytes[:_ENDBR64_LEN] == ENDBR64_BYTES:
                byte_window = self.bytes[_ENDBR64_LEN:]
            self.function_start_score = self._lookupPrologueScore(byte_window) or 0
        return self.function_start_score
