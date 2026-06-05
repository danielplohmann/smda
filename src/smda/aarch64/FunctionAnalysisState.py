"""Per-function analysis state for the AArch64 backend.

The recursive traversal, block reconstruction and result book-keeping are
architecture-neutral, so this reuses the engine state extracted under
:mod:`smda.intel` and only swaps the basic-block boundary mnemonic sets for the
AArch64 ones. (Reused from ``intel`` for now; a future iterate-step may hoist the
shared base into ``smda.common``.)
"""

from smda.intel.FunctionAnalysisState import FunctionAnalysisState as _IntelFunctionAnalysisState

from .definitions import BLOCK_CALL_MNEMONICS, BLOCK_END_MNEMONICS


class FunctionAnalysisState(_IntelFunctionAnalysisState):
    # getBlocks() consults these to decide block boundaries: bl/blr must not split
    # a block, ret/brk/hlt/udf must end one.
    CALL_MNEMONICS = BLOCK_CALL_MNEMONICS
    END_MNEMONICS = BLOCK_END_MNEMONICS
