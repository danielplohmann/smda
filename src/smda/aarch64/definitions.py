"""AArch64 control-flow definitions for the architecture-agnostic CFG engine.

Mnemonic classes and raw-encoding masks used by the AArch64 backend. The
control-flow semantics here were verified against capstone (CS_ARCH_ARM64);
see the classifier in :mod:`smda.aarch64.AArch64Backend` for how they are applied.

Counter-evidence baked into these choices (verified live against capstone 5.0.7,
do not "simplify" away):
- ``blr`` carries capstone's BRANCH_RELATIVE group despite being an indirect
  (register) call, so calls are classified by mnemonic, never by group id.
- ``brk``/``hlt``/``udf`` expose *empty* capstone groups, so trap terminators
  are matched by mnemonic.
- ``svc`` is sequential (a supervisor call returns), not a terminator.
- ``b.cs``/``b.cc`` disassemble as the ``b.hs``/``b.lo`` aliases, so conditional
  branches are matched with a ``b.`` prefix test rather than an explicit list.
- Pointer-auth (PAC) branches keep distinct mnemonics: ``braa``/``brab``/``braaz``/
  ``brabz`` are indirect *jumps* (capstone group JUMP) and ``blraa``/``blrab``/
  ``blraaz``/``blrabz`` are indirect *calls* (group CALL). They MUST be matched by
  mnemonic — a ``br``/``bl`` prefix test would also swallow ``brk``. Likewise the
  PAC returns ``retaa``/``retab`` carry the RET group like ``ret``.
- ``b.al``/``b.nv`` live in the conditional-branch encoding space (capstone still
  spells them ``b.<cond>``) but ALWAYS branch — they have no live fall-through, so
  they are classified as unconditional and checked before the generic ``b.`` test.
- ``eret``/``eretaa``/``eretab`` return from an exception level with *no* capstone
  groups at all, so they too must be matched by mnemonic (kernel/firmware code).
"""

# fixed AArch64 instruction width (bytes); also the recursion stride
INSTRUCTION_SIZE = 4
NOP = 0xD503201F

# --- control-flow mnemonic classes (capstone arm64) ----------------------
#: function-return terminators, incl. pointer-auth variants (retaa/retab)
RET_INS = {"ret", "retaa", "retab"}
#: exception-level returns, incl. pointer-auth variants (kernel/firmware code)
EXCEPTION_RETURN_INS = {"eret", "eretaa", "eretab"}
#: direct (bl) and indirect (blr + pointer-auth blra*) calls — none terminate a block
CALL_INS = {"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"}
#: trap / undefined-instruction terminators (verified: empty capstone groups)
END_INS = {"brk", "hlt", "udf"}
#: compare-and-branch / test-and-branch conditionals (fall-through + target)
COND_BRANCH_INS = {"cbz", "cbnz", "tbz", "tbnz"}
#: always-true conditional branches (b.al/b.nv): single successor, no fall-through
ALWAYS_BRANCH_INS = {"b.al", "b.nv"}
#: unconditional direct branch (single successor; may be a tailcall)
UNCOND_JUMP_INS = {"b"}
#: indirect branch through a register, incl. pointer-auth variants (bra*)
INDIRECT_JUMP_INS = {"br", "braa", "brab", "braaz", "brabz"}

# Block-boundary mnemonic sets consumed by the AArch64 FunctionAnalysisState
# subclass (FunctionAnalysisState.getBlocks): calls do NOT end a basic block;
# returns (incl. exception returns) and traps do. Conditional / unconditional
# branches are handled by the engine via the block-ending flag, so they need not
# appear here.
BLOCK_CALL_MNEMONICS = frozenset(CALL_INS)
BLOCK_END_MNEMONICS = frozenset(RET_INS | EXCEPTION_RETURN_INS | END_INS)

# --- raw little-endian 32-bit encoding masks -----------------------------
# BL imm26 :  100101 iiiiiiiiiiiiiiiiiiiiiiiiii  -> (word & MASK) == VALUE
BL_MASK = 0xFC000000
BL_VALUE = 0x94000000
BL_IMM_MASK = 0x03FFFFFF
BL_IMM_SIGN_BIT = 0x02000000  # bit 25 of the 26-bit immediate

# Prologue: ``stp x29, x30, [sp, #imm]!`` (pre-index store of the frame record).
# Strong, position-independent function-start marker on AArch64.
STP_FP_LR_PREINDEX_MASK = 0xFFC07FFF
STP_FP_LR_PREINDEX_VALUE = 0xA9807BFD
# Prologue: ``paciasp`` (pointer-auth sign LR) emitted at the top of PAC frames.
PACIASP = 0xD503233F
