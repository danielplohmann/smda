"""Minimal AArch64 collaborators for the recursive engine.

v1 ("prove-then-iterate") provides correctness-neutral stubs for the optional
analysis passes the engine invokes generically. They satisfy the collaborator
contract without doing x86-specific work; richer AArch64 implementations (a
mnemonic TF-IDF model, register-call backtracking, jump-table recovery) are
future iterate-steps.
"""


class AArch64TfIdf:
    """No-op TF-IDF scorer.

    No AArch64 mnemonic-frequency model exists yet, so every function scores 0.0.
    The candidate confidence weighting only rewards *negative* TF-IDF scores, so
    0.0 is treated as "no signal" — it neither inflates nor suppresses confidence.
    """

    def __init__(self, bitness=64):
        self.bitness = bitness

    def getTfIdfFromBlocks(self, blocks):
        del blocks
        return 0.0


class AArch64IndirectCallAnalyzer:
    """No-op indirect-call resolver (register-call backtracking not yet ported)."""

    def __init__(self, disassembler):
        self.disassembler = disassembler

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        del analysis_state, block_depth
        return


class AArch64JumpTableAnalyzer:
    """No-op jump-table resolver (br jump-table recovery not yet ported)."""

    def __init__(self, disassembler):
        self.disassembler = disassembler

    def getJumpTargets(self, jump_instruction, state):
        del jump_instruction, state
        return []
