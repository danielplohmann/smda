"""Per-function analysis state for the x86/x64 backend.

The traversal, block reconstruction and result book-keeping live in the
architecture-neutral base under :mod:`smda.common`; this subclass only supplies
the x86 basic-block boundary mnemonic sets.
"""

from smda.common.FunctionAnalysisState import FunctionAnalysisState as _CommonFunctionAnalysisState

from .definitions import CALL_INS, END_INS


class FunctionAnalysisState(_CommonFunctionAnalysisState):
    # getBlocks() consults these to decide block boundaries: calls must not split
    # a block, ret/trap instructions must end one.
    CALL_MNEMONICS = CALL_INS
    END_MNEMONICS = END_INS
