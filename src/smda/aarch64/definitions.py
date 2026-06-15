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

# --- control-flow masks consumed by the gap scan --------------------------
# Used by FunctionCandidateManager.nextGapCandidate to skip padding/stray tails
# and detect run terminators. Verified live against capstone 5.0.7.
B_MASK = 0xFC000000
B_VALUE = 0x14000000  # b <label> (unconditional direct branch; BL shares the mask at 0x94000000)
RET_MASK = 0xFFFFFC1F
RET_VALUE = 0xD65F0000  # ret {Xn}
BR_MASK = 0xFFFFFC1F
BR_VALUE = 0xD61F0000  # br Xn (indirect branch)
CBZ_CBNZ_MASK = 0x7E000000
CBZ_CBNZ_VALUE = 0x34000000
TBZ_TBNZ_MASK = 0x7E000000
TBZ_TBNZ_VALUE = 0x36000000
BCOND_MASK = 0xFF000010
BCOND_VALUE = 0x54000000  # b.<cond> (also matches the always-branches b.al/b.nv)

# --- PC-relative address materialization (reference recovery) -------------
# adrp Xd, #page and adr Xd, #imm share the mask; bit 31 selects adrp vs adr.
ADRP_MASK = 0x9F000000
ADRP_VALUE = 0x90000000
ADR_VALUE = 0x10000000
# add Xd, Xn, #imm12 — the lo12 of an adrp+add pair (sh=0 is required by the mask).
ADD_IMM64_MASK = 0xFFC00000
ADD_IMM64_VALUE = 0x91000000


def adrp_page_value(word, pc):
    """Absolute 4 KiB page address materialized by ``adrp`` at ``pc``.

    page = (pc & ~0xFFF) + sign_extend21(immhi:immlo) << 12. Cross-checked against
    capstone 5.0.7's resolved page for every adrp in the reference fixture's .text.
    """
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def is_conditional_branch(word):
    """True for cbz/cbnz, tbz/tbnz and b.<cond> (compare/test/condition branches).

    A function never opens with one of these, so the gap scan treats a leading
    conditional branch as a stray block tail (not an entry) and skips it. b.al/b.nv
    also match the b.<cond> mask; they are never valid entries, so skipping is benign.
    """
    return (
        (word & CBZ_CBNZ_MASK) == CBZ_CBNZ_VALUE
        or (word & TBZ_TBNZ_MASK) == TBZ_TBNZ_VALUE
        or (word & BCOND_MASK) == BCOND_VALUE
    )


# --- function-entry prologues ---------------------------------------------
# AArch64 has no single dominant byte prologue (no `push ebp`). The recognized
# strong, position-independent function-start markers are, in rough frequency
# order, the frame-record store, a callee-saved GPR-pair save, the link-register
# save, and the pointer-auth sign. Masks/values verified live against capstone 5.0.7.

# stp x29, x30, [sp, #imm]!  — pre-index frame-record store (any immediate)
STP_FP_LR_PREINDEX_MASK = 0xFFC07FFF
STP_FP_LR_PREINDEX_VALUE = 0xA9807BFD
# stp <Xt>, <Xt2>, [sp, #imm]!  — pre-index, 64-bit GPR pair (opcode bits 31:22)
STP_PREINDEX_MASK = 0xFFC00000
STP_PREINDEX_VALUE = 0xA9800000
STP_IMM7_NEGATIVE = 0x00200000  # imm7 sign bit (instr bit 21): stack-allocating
# str <Xt>, [sp, #imm]!  — pre-index, 64-bit store (pre-index marker in bits 11:10)
STR_PREINDEX_MASK = 0xFFE00C00
STR_PREINDEX_VALUE = 0xF8000C00
STR_IMM9_NEGATIVE = 0x00100000  # imm9 sign bit (instr bit 20)
# pointer-auth sign LR, emitted at the top of PAC frames
PACIAZ = 0xD503231F
PACIASP = 0xD503233F
PACIBZ = 0xD503235F
PACIBSP = 0xD503237F
PAC_PROLOGUES = frozenset({PACIAZ, PACIASP, PACIBZ, PACIBSP})

# BTI landing pads, emitted at entries and indirect-branch targets.
BTI = 0xD503241F
BTI_C = 0xD503245F
BTI_J = 0xD503249F
BTI_JC = 0xD50324DF
BTI_PROLOGUES = frozenset({BTI, BTI_C, BTI_J, BTI_JC})

_SP = 31  # x31 in an Rn field denotes the stack pointer
_CALLEE_SAVED_GPR = frozenset(range(19, 29))  # x19..x28
_LINK_REGISTER = 30  # x30


def is_bti_landing_pad(word):
    """Whether a word is a BTI landing-pad instruction."""
    return word in BTI_PROLOGUES


def is_function_prologue(word):
    """Whether a 32-bit little-endian word is a recognized AArch64 entry prologue.

    Covers PAC sign instructions, BTI landing pads, the frame-record store
    ``stp x29,x30,[sp,#imm]!``, a
    callee-saved GPR-pair pre-index store ``stp x{19..28},x{19..28},[sp,#-imm]!``,
    and the link-register save ``str x30,[sp,#-imm]!``. The pair/LR-save forms
    require a *negative* (stack-allocating) immediate to an SP base — the
    unambiguous prologue signal. Mid-function nested frames that reuse the same
    encoding are absorbed by the engine's collision-abort when the enclosing
    function claims the bytes first, so no terminator-preceded guard is applied
    (such a guard would wrongly drop functions that follow a no-return call).
    """
    if word in PAC_PROLOGUES or word in BTI_PROLOGUES:
        return True
    # frame-record store: stp x29, x30, [sp, #imm]!
    if (word & STP_FP_LR_PREINDEX_MASK) == STP_FP_LR_PREINDEX_VALUE:
        return True
    rn = (word >> 5) & 0x1F
    # callee-saved pair: stp x{19..28}, x{19..28}, [sp, #-imm]!
    if (
        (word & STP_PREINDEX_MASK) == STP_PREINDEX_VALUE
        and rn == _SP
        and word & STP_IMM7_NEGATIVE
        and (word & 0x1F) in _CALLEE_SAVED_GPR
        and ((word >> 10) & 0x1F) in _CALLEE_SAVED_GPR
    ):
        return True
    # link-register save: str x30, [sp, #-imm]!
    return bool(
        (word & STR_PREINDEX_MASK) == STR_PREINDEX_VALUE
        and rn == _SP
        and word & STR_IMM9_NEGATIVE
        and (word & 0x1F) == _LINK_REGISTER
    )
