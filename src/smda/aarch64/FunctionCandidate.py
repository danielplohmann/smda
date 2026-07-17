from smda.common.FunctionCandidate import FunctionCandidate as _CommonFunctionCandidate

from .definitions import INSTRUCTION_SIZE, is_bti_landing_pad, is_function_prologue


class FunctionCandidate(_CommonFunctionCandidate):
    # entry-shape checks only ever inspect the first instruction word
    BYTE_WINDOW_SIZE = INSTRUCTION_SIZE

    def hasCommonFunctionStart(self):
        if len(self.bytes) < 4:
            return False
        word = int.from_bytes(self.bytes[:4], "little")
        return is_function_prologue(word) or is_bti_landing_pad(word)

    def getFunctionStartScore(self):
        # Intentionally 0 for priority-queue scoring. AArch64 frame-record stores
        # (stp x29,x30,[sp,#-imm]!) also appear mid-function; feeding them into
        # calculateScore would outrank call-ref seeds and split enclosing bodies
        # (regressing aarch64_static golden counts). Confidence still uses
        # hasCommonFunctionStart() above, which is arch-correct.
        if self.function_start_score is None:
            self.function_start_score = 0
        return self.function_start_score
