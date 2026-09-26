"""Per-function analysis state for the ARM backend.

Adds the per-block scratch the ARM classifier keeps while it walks a function: register
values that a literal load or ``movw`` put in flight towards an ``add rd, pc`` or
``movt``, and the register branches left unresolved for the indirect-call pass.
"""

from smda.common.FunctionAnalysisState import FunctionAnalysisState as _CommonFunctionAnalysisState

from .definitions import BLOCK_CALL_MNEMONICS, BLOCK_END_MNEMONICS, split_mnemonic


class FunctionAnalysisState(_CommonFunctionAnalysisState):
    CALL_MNEMONICS = BLOCK_CALL_MNEMONICS
    END_MNEMONICS = BLOCK_END_MNEMONICS

    def __init__(self, start_addr, disassembly):
        super().__init__(start_addr, disassembly)
        self.arm_pending = {}
        self.arm_movw = {}
        self.arm_indirect_jumps = []

    def _branchesOutsideImage(self):
        for _address, _size, mnemonic, op_str, _bytes in self.instructions:
            if not op_str.startswith("#") or split_mnemonic(mnemonic)[0] not in ("b", "bl", "blx"):
                continue
            try:
                target = int(op_str[1:], 0)
            except ValueError:
                continue
            if not self.disassembly.isAddrWithinMemoryImage(target):
                return True
        return False

    def finalizeAnalysis(self, as_gap=False):
        # a direct branch or call that leaves the image is data decoded as code; only a gap
        # candidate has nothing but its own bytes to vouch for it
        if as_gap and self._branchesOutsideImage():
            return False
        return super().finalizeAnalysis(as_gap)
