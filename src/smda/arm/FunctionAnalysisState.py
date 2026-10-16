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
        #: whether a symbol or unwind record states this start; set by the backend
        self.arm_declared = None

    @staticmethod
    def endsBlock(instruction, refs_from):
        # ``bx lr`` and ``pop {.., pc}`` share their mnemonics with instructions that fall
        # through; what ends the block is that nothing follows the instruction
        del instruction
        return refs_from is None

    def _branchesOutsideImage(self):
        for _address, _size, mnemonic, op_str, _bytes in self.instructions:
            if not op_str.startswith("#") or split_mnemonic(mnemonic)[0] not in ("b", "bl", "blx"):
                continue
            try:
                target = int(op_str[1:], 0)
            except ValueError:
                continue
            if target and not self.disassembly.isAddrWithinMemoryImage(target):
                # address 0 is where a static link resolves an undefined weak symbol: a
                # ``b 0`` behind a null check is a tailcall the linker left there
                return True
        return False

    def finalizeAnalysis(self, as_gap=False):
        # compilers and linkers emit no direct branch or call out of the image (but to 0): one
        # that leaves it is data decoded as code, unless the image itself states the function
        if (as_gap or not self.arm_declared) and self._branchesOutsideImage():
            return False
        return super().finalizeAnalysis(as_gap)
