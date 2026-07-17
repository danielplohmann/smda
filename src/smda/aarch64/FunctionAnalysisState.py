"""Per-function analysis state for the AArch64 backend.

The recursive traversal, block reconstruction and result book-keeping live in
the architecture-neutral base under :mod:`smda.common`; this subclass only
supplies the AArch64 basic-block boundary mnemonic sets.
"""

from smda.common.FunctionAnalysisState import FunctionAnalysisState as _CommonFunctionAnalysisState

from .definitions import BLOCK_CALL_MNEMONICS, BLOCK_END_MNEMONICS


class FunctionAnalysisState(_CommonFunctionAnalysisState):
    # getBlocks() consults these to decide block boundaries: bl/blr must not split
    # a block, ret/brk/hlt/udf must end one.
    CALL_MNEMONICS = BLOCK_CALL_MNEMONICS
    END_MNEMONICS = BLOCK_END_MNEMONICS
