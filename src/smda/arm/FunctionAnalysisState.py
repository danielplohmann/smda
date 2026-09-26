"""Per-function analysis state for the ARM backend.

Adds the per-block scratch the ARM classifier keeps while it walks a function: register
values that a literal load or ``movw`` put in flight towards an ``add rd, pc`` or
``movt``, and the register branches left unresolved for the indirect-call pass.
"""

from smda.common.FunctionAnalysisState import FunctionAnalysisState as _CommonFunctionAnalysisState

from .definitions import BLOCK_CALL_MNEMONICS, BLOCK_END_MNEMONICS


class FunctionAnalysisState(_CommonFunctionAnalysisState):
    CALL_MNEMONICS = BLOCK_CALL_MNEMONICS
    END_MNEMONICS = BLOCK_END_MNEMONICS

    def __init__(self, start_addr, disassembly):
        super().__init__(start_addr, disassembly)
        self.arm_pending = {}
        self.arm_movw = {}
        self.arm_indirect_jumps = []
