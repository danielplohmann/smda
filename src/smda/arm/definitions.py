"""ARM (AArch32: A32 / T32) control-flow definitions for the architecture-agnostic engine.

Encodings follow the ARM Architecture Reference Manual for ARMv7-A and ARMv7-R
(DDI 0406C.d); section numbers below refer to it. Capstone (CS_ARCH_ARM) behaviour
that the backend relies on was verified against capstone 5.0.7:

- Conditions are folded into the mnemonic (``bxeq``, ``popne``, ``ldrls``) and a
  ``.w``/``.n`` width qualifier may follow (``beq.w``, ``pop.w``), so the backend
  splits every mnemonic into ``(base, condition)`` before classifying it.
- Capstone tracks an IT block (A8.8.54) only within one ``disasm`` call. The engine
  decodes a small window at a time, so the modal wrapper in
  :mod:`smda.arm.ArmBackend` re-decodes from the ``it`` instruction whenever a window
  starts inside an open IT block; without that, ``it eq; bxeq lr`` reads as an
  unconditional ``bx lr`` and every conditional return cuts its function short.
- A32 ``adr`` is printed as ``add rd, pc, #imm`` / ``sub rd, pc, #imm``; T32 ``adr``
  prints the offset from ``Align(PC, 4)``, not the resolved address.
- Branch and call targets (``b``, ``bl``, ``blx #imm``, ``cbz``) are printed as
  resolved absolute addresses, including the ``Align(PC, 4)`` a T32 ``blx`` applies.
"""

import itertools

from capstone import arm_const as _arm_const

from smda.common.instruction_set_probe import countCodeReturnSites, hasDenseReturnRun

#: condition-code suffixes as capstone spells them (A8.3); ``cs``/``cc`` print as ``hs``/``lo``
CONDITION_CODES = frozenset(
    {"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"}
)

#: every base mnemonic capstone's ARM decoder can emit
BASE_MNEMONICS = frozenset(
    name[len("ARM_INS_") :].lower() for name in dir(_arm_const) if name.startswith("ARM_INS_")
) - {"invalid", "ending"}

_WIDTH_QUALIFIERS = (".w", ".n")
#: capstone lists these flag-setting forms as instructions of their own (``subs pc, lr``
#: is the exception return); they are the S variants of ``mov`` and ``sub``
_FLAG_SETTING_BASES = {"movs": "mov", "subs": "sub"}
_SPLIT_MEMO = {}


def split_mnemonic(mnemonic):
    """Split a capstone ARM mnemonic into ``(base, condition, sets_flags)``.

    ``condition`` is None when the mnemonic carries no condition suffix. The base
    vocabulary comes from capstone's own instruction list, which is what resolves the
    ambiguous spellings: ``teq`` is a base, ``bls`` is ``b`` + ``ls``, ``bleq`` is
    ``bl`` + ``eq``, ``bics`` is ``bic`` with the S bit and ``mulls`` is ``mul`` + ``ls``.
    Data-type suffixes of VFP/NEON mnemonics (``vadd.f32``) are kept on the base.
    """
    result = _SPLIT_MEMO.get(mnemonic)
    if result is not None:
        return result
    name = mnemonic.lower()
    for qualifier in _WIDTH_QUALIFIERS:
        if name.endswith(qualifier):
            name = name[: -len(qualifier)]
            break
    head, dot, datatype = name.partition(".")
    suffix = dot + datatype
    result = (name, None, False)
    if head in _FLAG_SETTING_BASES:
        result = (_FLAG_SETTING_BASES[head] + suffix, None, True)
    elif head in BASE_MNEMONICS:
        result = (head + suffix, None, False)
    else:
        rest, condition = head[:-2], head[-2:]
        if condition in CONDITION_CODES and rest in BASE_MNEMONICS:
            result = (rest + suffix, condition, False)
        elif condition in CONDITION_CODES and rest.endswith("s") and rest[:-1] in BASE_MNEMONICS:
            result = (rest[:-1] + suffix, condition, True)
        elif head.endswith("s") and head[:-1] in BASE_MNEMONICS:
            result = (head[:-1] + suffix, None, True)
    _SPLIT_MEMO[mnemonic] = result
    return result


def is_conditional(mnemonic):
    condition = split_mnemonic(mnemonic)[1]
    return condition is not None and condition != "al"


# --- control-flow mnemonic classes (bases, conditions stripped) --------------
#: direct and indirect calls; none of them ends a basic block
CALL_BASES = frozenset({"bl", "blx", "blxns"})
#: direct branches taking a label (conditional when a condition is attached)
BRANCH_BASES = frozenset({"b"})
#: compare-and-branch on (non-)zero (T32 only, never conditional on flags)
COMPARE_BRANCH_BASES = frozenset({"cbz", "cbnz"})
#: register branches (``bx lr`` is the canonical return)
REGISTER_BRANCH_BASES = frozenset({"bx", "bxj", "bxns"})
#: table branches (A8.8.237): a byte / halfword offset table follows the instruction
TABLE_BRANCH_BASES = frozenset({"tbb", "tbh"})
#: permanently undefined and debug/halting traps: no fall-through
TRAP_BASES = frozenset({"udf", "bkpt", "hlt", "trap"})
#: exception returns (B9.1): ``eret``, ``rfe*`` and ``srs`` never fall through
EXCEPTION_RETURN_BASES = frozenset({"eret", "rfeda", "rfedb", "rfeia", "rfeib"})
#: data-processing and load bases that transfer control when their destination is pc
PC_WRITING_BASES = frozenset(
    {
        "mov",
        "mvn",
        "add",
        "adc",
        "sub",
        "sbc",
        "rsb",
        "rsc",
        "and",
        "orr",
        "eor",
        "bic",
        "lsl",
        "lsr",
        "asr",
        "ror",
        "rrx",
        "ldr",
    }
)
#: block-transfer loads, where pc in the register list makes the load a branch
LOAD_MULTIPLE_BASES = frozenset({"pop", "ldm", "ldmda", "ldmdb", "ldmib"})

IT_MNEMONICS = frozenset(
    "it" + "".join(pattern) for length in range(4) for pattern in itertools.product("te", repeat=length)
)


def _conditioned(bases):
    return frozenset(base + condition for base in bases for condition in CONDITION_CODES | {""})


# FunctionAnalysisState.getBlocks() matches against the capstone mnemonic with any width
# qualifier still attached, so both spellings are listed.
_CALL_MNEMONICS = _conditioned(CALL_BASES)
BLOCK_CALL_MNEMONICS = frozenset(_CALL_MNEMONICS | {mnemonic + ".w" for mnemonic in _CALL_MNEMONICS})
BLOCK_END_MNEMONICS = frozenset(
    TRAP_BASES | EXCEPTION_RETURN_BASES | {mnemonic + ".w" for mnemonic in TRAP_BASES | EXCEPTION_RETURN_BASES}
)

# --- A32 encodings (A5.x) -----------------------------------------------------
A32_INSTRUCTION_SIZE = 4
#: B / BL <label> (A8.8.18, A8.8.25): cond 101 L imm24, cond != 1111
A32_BRANCH_MASK = 0x0E000000
A32_BRANCH_VALUE = 0x0A000000
A32_BL_BIT = 0x01000000
#: BLX <label> (A8.8.25, encoding A2): 1111 101 H imm24
A32_BLX_IMM_MASK = 0xFE000000
A32_BLX_IMM_VALUE = 0xFA000000
#: BX / BLX <Rm> (A8.8.27, A8.8.26)
A32_BX_MASK = 0x0FFFFFF0
A32_BX_VALUE = 0x012FFF10
A32_BLX_REG_VALUE = 0x012FFF30
A32_BX_LR = 0xE12FFF1E
A32_MOV_PC_LR = 0xE1A0F00E
#: PUSH {..., lr} as STMDB sp!, <list> (A8.8.133), any condition bits masked out
A32_PUSH_MASK = 0x0FFF0000
A32_PUSH_VALUE = 0x092D0000
A32_PUSH_LR_BIT = 0x4000
#: STR lr, [sp, #-4]! (A8.8.204)
A32_PUSH_LR_SINGLE = 0xE52DE004
#: POP {..., pc} as LDMIA sp!, <list> (A8.8.131) and LDR pc, [sp], #4
A32_POP_MASK = 0x0FFF0000
A32_POP_VALUE = 0x08BD0000
A32_POP_PC_BIT = 0x8000
A32_POP_PC_SINGLE = 0xE49DF004
#: MOV ip, sp - the APCS frame setup that opens a frame-pointer prologue
A32_MOV_IP_SP = 0xE1A0C00D
#: canonical A32 no-ops: NOP (A8.8.119) and the pre-v6K ``mov r0, r0``
A32_NOPS = frozenset({0xE320F000, 0xE1A00000})
#: the fill lld writes between sections and PLT entries of an ARM image
A32_LLD_FILL = 0xD4D4D4D4
#: ``ldr pc, [ip, #imm]`` with bit 21 (writeback) clear: the last instruction of an A32 PLT entry
A32_LDR_PC_IP = 0xE59CF000
#: the A32 condition field meaning "always"
A32_COND_AL = 0xE0000000
A32_COND_MASK = 0xF0000000

# --- T32 encodings (A6.x) -----------------------------------------------------
T16_INSTRUCTION_SIZE = 2
#: PUSH {..., lr} (A8.8.133 T1): 1011 010 M list
T16_PUSH_MASK = 0xFE00
T16_PUSH_VALUE = 0xB400
T16_PUSH_LR_BIT = 0x0100
#: POP {..., pc} (A8.8.131 T1): 1011 110 P list
T16_POP_MASK = 0xFE00
T16_POP_VALUE = 0xBC00
T16_POP_PC_BIT = 0x0100
#: BX / BLX <Rm> (A8.8.27 T1 / A8.8.26 T1)
T16_BX_MASK = 0xFF87
T16_BX_VALUE = 0x4700
T16_BLX_REG_VALUE = 0x4780
T16_BX_LR = 0x4770
#: B <label> (A8.8.18 T2) and B<c> <label> (T1); cond 1110 is UDF and 1111 is SVC
T16_B_MASK = 0xF800
T16_B_VALUE = 0xE000
T16_BCOND_MASK = 0xF000
T16_BCOND_VALUE = 0xD000
T16_NOPS = frozenset({0xBF00, 0x46C0})
T16_LLD_FILL = 0xD4D4
T16_UDF_MASK = 0xFF00
T16_UDF_VALUE = 0xDE00
T16_BKPT_MASK = 0xFF00
T16_BKPT_VALUE = 0xBE00
#: first halfwords whose top five bits make the instruction 32 bits wide (A6.1)
T32_PREFIX_MASK = 0xF800
T32_PREFIXES = frozenset({0xE800, 0xF000, 0xF800})
#: BL / BLX <label> (A8.8.25 T1 / T2): 11110 S imm10 : 11 J1 L J2 imm11
T32_BL_HW1_MASK = 0xF800
T32_BL_HW1_VALUE = 0xF000
T32_BL_HW2_MASK = 0xD000
T32_BL_HW2_VALUE = 0xD000
T32_BLX_HW2_MASK = 0xD001
T32_BLX_HW2_VALUE = 0xC000
#: PUSH.W / POP.W (A8.8.133 T2, A8.8.131 T2)
T32_PUSH_HW1 = 0xE92D
T32_POP_HW1 = 0xE8BD
T32_LIST_LR_BIT = 0x4000
T32_LIST_PC_BIT = 0x8000
#: STR.W lr, [sp, #-4]! and LDR.W pc, [sp], #4 (single-register PUSH / POP)
T32_PUSH_LR_SINGLE = (0xF84D, 0xED04)
T32_POP_PC_SINGLE = (0xF85D, 0xFB04)

#: evidence a raw buffer must carry before it is read as ARM rather than x86
MIN_RETURN_SITES = 16
#: A32 returns: ``bx lr`` and ``mov pc, lr``, little-endian
A32_RETURN_BYTES = (b"\x1e\xff\x2f\xe1", b"\x0e\xf0\xa0\xe1")
#: T32 return: ``bx lr``, little-endian
T16_RETURN_BYTES = b"\x70\x47"


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def a32_branch_target(word, address):
    """Target of an A32 B/BL/BLX <label>, and whether the destination is Thumb.

    Returns None for anything else. BLX <label> always switches to Thumb and carries
    the halfword bit H in bit 24 (A8.8.25): target = PC + SignExtend(imm24:H:'0').
    """
    if (word & A32_BLX_IMM_MASK) == A32_BLX_IMM_VALUE:
        offset = (sign_extend(word & 0x00FFFFFF, 24) << 2) | ((word >> 23) & 2)
        return (address + 8 + offset) & 0xFFFFFFFF, True
    if (word & A32_BRANCH_MASK) == A32_BRANCH_VALUE and (word & A32_COND_MASK) != 0xF0000000:
        return (address + 8 + (sign_extend(word & 0x00FFFFFF, 24) << 2)) & 0xFFFFFFFF, False
    return None


def t32_call_target(hw1, hw2, address):
    """Target of a T32 BL/BLX <label> at ``address``, and whether it stays in Thumb.

    Returns None when the halfword pair is not a BL/BLX. I1 = NOT(J1 EOR S) and
    I2 = NOT(J2 EOR S) (A8.8.25); BLX aligns PC down to a word and lands in ARM state.
    """
    if (hw1 & T32_BL_HW1_MASK) != T32_BL_HW1_VALUE:
        return None
    is_bl = (hw2 & T32_BL_HW2_MASK) == T32_BL_HW2_VALUE
    is_blx = (hw2 & T32_BLX_HW2_MASK) == T32_BLX_HW2_VALUE
    if not (is_bl or is_blx):
        return None
    s = (hw1 >> 10) & 1
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    i1 = 1 - (j1 ^ s)
    i2 = 1 - (j2 ^ s)
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
    offset = sign_extend(imm, 25)
    if is_bl:
        return (address + 4 + offset) & 0xFFFFFFFF, True
    return (((address + 4) & ~3) + (offset & ~3)) & 0xFFFFFFFF, False


def is_t32_prefix(halfword):
    return (halfword & T32_PREFIX_MASK) in T32_PREFIXES


def is_a32_prologue(word):
    """An A32 entry: ``push {..., lr}``, ``str lr, [sp, #-4]!`` or the APCS ``mov ip, sp``.

    Unconditional only: a conditionally executed frame push is not how any compiler opens a
    function, and admitting the other fourteen conditions multiplies the chance that a data
    word in a literal pool matches.
    """
    if (word & A32_COND_MASK) != A32_COND_AL:
        return False
    if (word & A32_PUSH_MASK) == A32_PUSH_VALUE and word & A32_PUSH_LR_BIT:
        return True
    return word in (A32_PUSH_LR_SINGLE, A32_MOV_IP_SP)


def is_t32_prologue(hw1, hw2=None):
    """A T32 entry: ``push {..., lr}``, ``push.w {..., lr}`` or ``str.w lr, [sp, #-4]!``."""
    if (hw1 & T16_PUSH_MASK) == T16_PUSH_VALUE and hw1 & T16_PUSH_LR_BIT:
        return True
    if hw2 is None:
        return False
    if hw1 == T32_PUSH_HW1 and hw2 & T32_LIST_LR_BIT and not hw2 & 0xA000:
        return True
    return (hw1, hw2) == T32_PUSH_LR_SINGLE


def is_return_instruction(mnemonic, op_str):
    """Whether an instruction returns through lr or pops the return address into pc."""
    base, _condition, _sets_flags = split_mnemonic(mnemonic)
    if base in ("bx", "bxns"):
        return op_str.strip() == "lr"
    if base in LOAD_MULTIPLE_BASES:
        return "pc" in op_str and (base == "pop" or op_str.startswith("sp"))
    if base == "mov":
        return op_str.replace(" ", "") == "pc,lr"
    return base == "ldr" and op_str.startswith("pc, [sp")


def is_a32_return(word):
    if word in (A32_BX_LR, A32_MOV_PC_LR, A32_POP_PC_SINGLE):
        return True
    return (word & A32_COND_MASK) == A32_COND_AL and (word & A32_POP_MASK) == A32_POP_VALUE and word & A32_POP_PC_BIT


def is_t32_return(hw1, hw2=None):
    if hw1 == T16_BX_LR or ((hw1 & T16_POP_MASK) == T16_POP_VALUE and hw1 & T16_POP_PC_BIT):
        return True
    if hw2 is None:
        return False
    return (hw1 == T32_POP_HW1 and hw2 & T32_LIST_PC_BIT and not hw2 & 0x2000) or (hw1, hw2) == T32_POP_PC_SINGLE


def looksLikeArm(buffer):
    """Whether a raw buffer's bytes are little-endian AArch32 (A32 or T32) machine code.

    The A32 returns are the two signatures the unsupported-instruction-set probe already
    carried for ARM, with the same density requirement. ``bx lr`` in T32 is a single
    halfword, so a hit is weaker evidence per occurrence; it is counted at halfword
    alignment against the same window density, and hits sitting in UTF-16 text are
    discarded exactly as for the other signatures.
    """
    for pattern in A32_RETURN_BYTES:
        if countCodeReturnSites(buffer, pattern, A32_INSTRUCTION_SIZE, MIN_RETURN_SITES) >= MIN_RETURN_SITES:
            return _denseReturnRun(buffer, pattern, A32_INSTRUCTION_SIZE)
    return _denseReturnRun(buffer, T16_RETURN_BYTES, T16_INSTRUCTION_SIZE)


def _denseReturnRun(buffer, pattern, alignment):
    return hasDenseReturnRun(buffer, pattern, alignment, MIN_RETURN_SITES)


#: A32 words that cannot be read out of T32 code: ``bx lr``, ``mov pc, lr``,
#: ``ldr pc, [sp], #4`` and ``str lr, [sp, #-4]!``. The block-transfer forms are left out
#: on purpose: a T32 ``pop.w``/``push.w`` straddling a word boundary spells an A32
#: ``ldm``/``stmdb`` of sp with the preceding halfword as its register list.
A32_MODE_MARKERS = tuple(
    word.to_bytes(4, "little") for word in (A32_BX_LR, A32_MOV_PC_LR, A32_POP_PC_SINGLE, A32_PUSH_LR_SINGLE)
)
#: T32 ``bx lr``: absent from every A32 image measured, dense in every T32 one
T32_MODE_MARKERS = (T16_RETURN_BYTES,)


def _countAligned(buffer, pattern, alignment, start, end):
    found = 0
    index = buffer.find(pattern, start, end)
    while index >= 0:
        if index % alignment == 0:
            found += 1
        index = buffer.find(pattern, index + 1, end)
    return found


def countModeMarkers(buffer, start=0, end=None):
    """(A32, T32) marker counts over ``buffer[start:end]``, each at its own alignment.

    Offsets are taken relative to the buffer, which the loaders map at a page-aligned
    base, so buffer alignment and address alignment agree.
    """
    end = len(buffer) if end is None else min(end, len(buffer))
    start = max(0, start)
    arm = sum(_countAligned(buffer, pattern, A32_INSTRUCTION_SIZE, start, end) for pattern in A32_MODE_MARKERS)
    thumb = sum(_countAligned(buffer, pattern, T16_INSTRUCTION_SIZE, start, end) for pattern in T32_MODE_MARKERS)
    return arm, thumb


def probeThumbPreference(buffer, start=0, end=None):
    """Whether the code in ``buffer[start:end]`` is predominantly T32 rather than A32.

    Measured over clang-built A32, T32 and mixed images of three libraries and a GCC-built
    A32 malware sample: no A32 image held a single T32 ``bx lr`` and no T32 image a single
    A32 marker word, so the larger count names the instruction set. None when neither
    appears; the caller then keeps whatever it already believed.
    """
    arm, thumb = countModeMarkers(buffer, start, end)
    if arm == thumb:
        return None
    return thumb > arm
