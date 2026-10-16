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

import bisect
import heapq
import itertools
from collections import deque

from capstone import arm_const as _arm_const

from smda.common.instruction_set_probe import (
    MAX_PROBES,
    NEIGHBOURHOOD_BYTES,
    TEXT_UNIT_SHARE,
    WINDOW_BYTES,
    hasDenseReturnRun,
)

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
        if condition in CONDITION_CODES and rest.endswith("s") and rest[:-1] in BASE_MNEMONICS:
            result = (rest[:-1] + suffix, condition, True)
        elif condition in CONDITION_CODES and rest in BASE_MNEMONICS:
            result = (rest + suffix, condition, False)
        elif head.endswith("s") and head[:-1] in BASE_MNEMONICS:
            result = (head[:-1] + suffix, None, True)
    _SPLIT_MEMO[mnemonic] = result
    return result


#: imported functions that never return to their caller. A call to one ends the block, and the
#: compiler places whatever comes next (a literal pool, the next function) straight behind it:
#: GCC's ``-fstack-protector`` epilogue is ``blx __stack_chk_fail`` followed by the pool.
NORETURN_APIS = frozenset(
    {
        "__stack_chk_fail",
        "__stack_chk_fail_local",
        "__fortify_fail",
        "__chk_fail",
        "__assert_fail",
        "__assert_perror_fail",
        "__assert2",
        "abort",
        "exit",
        "_exit",
        "_Exit",
        "quick_exit",
        "pthread_exit",
        "err",
        "errx",
        "verr",
        "verrx",
        "longjmp",
        "_longjmp",
        "siglongjmp",
        "__longjmp_chk",
        "__cxa_throw",
        "__cxa_rethrow",
        "__cxa_bad_cast",
        "__cxa_bad_typeid",
        "__cxa_pure_virtual",
        "__cxa_call_unexpected",
        "_Unwind_Resume",
        "_ZSt9terminatev",
        "ExitProcess",
        "ExitThread",
        "FreeLibraryAndExitThread",
        "RaiseFailFastException",
        "_CxxThrowException",
        "_invalid_parameter_noinfo_noreturn",
        "_amsg_exit",
    }
)


def is_noreturn_api(api):
    """Whether an import name resolved for a call target never returns (``@`` versions dropped)."""
    return bool(api) and api.split("@", 1)[0] in NORETURN_APIS


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
#: BX <Rm> (A8.8.27)
A32_BX_MASK = 0x0FFFFFF0
A32_BX_VALUE = 0x012FFF10
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
#: UDF and BKPT (A8.8.247, A8.8.24): the condition field of UDF is ignored, BKPT's is AL
A32_UDF_MASK = 0x0FF000F0
A32_UDF_VALUE = 0x07F000F0
A32_BKPT_MASK = 0xFFF000F0
A32_BKPT_VALUE = 0xE1200070
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
#: BX <Rm> (A8.8.27 T1)
T16_BX_MASK = 0xFF87
T16_BX_VALUE = 0x4700
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


def pc_value(address, thumb, aligned=False):
    """What an instruction at ``address`` reads as pc (A2.3): its address plus 8 in A32 and
    plus 4 in T32, the latter aligned down to a word for literals, ``adr`` and BLX."""
    if thumb:
        return ((address + 4) & ~3) if aligned else address + 4
    return address + 8


def a32_branch_target(word, address):
    """Target of an A32 B/BL/BLX <label>, and whether the destination is Thumb.

    Returns None for anything else. BLX <label> always switches to Thumb and carries
    the halfword bit H in bit 24 (A8.8.25): target = PC + SignExtend(imm24:H:'0').
    """
    if (word & A32_BLX_IMM_MASK) == A32_BLX_IMM_VALUE:
        offset = (sign_extend(word & 0x00FFFFFF, 24) << 2) | ((word >> 23) & 2)
        return (pc_value(address, False) + offset) & 0xFFFFFFFF, True
    if (word & A32_BRANCH_MASK) == A32_BRANCH_VALUE and (word & A32_COND_MASK) != 0xF0000000:
        return (pc_value(address, False) + (sign_extend(word & 0x00FFFFFF, 24) << 2)) & 0xFFFFFFFF, False
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
        return (pc_value(address, True) + offset) & 0xFFFFFFFF, True
    return (pc_value(address, True, aligned=True) + (offset & ~3)) & 0xFFFFFFFF, False


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


def is_load_multiple_return(base, op_str):
    """Whether a block-transfer load writes pc, which returns whatever its base register:
    ``pop {..., pc}``, ``ldm sp!, {..., pc}`` and the APCS frame's ``ldmdb fp, {..., sp, pc}``."""
    if base not in LOAD_MULTIPLE_BASES:
        return False
    start = op_str.find("{")
    end = op_str.find("}", start)
    if start < 0 or end < 0:
        return False
    return "pc" in (register.strip() for register in op_str[start + 1 : end].split(","))


def is_return_instruction(mnemonic, op_str):
    """Whether an instruction returns through lr or pops the return address into pc."""
    base, _condition, sets_flags = split_mnemonic(mnemonic)
    if base in ("bx", "bxns"):
        return op_str.strip() == "lr"
    if base in LOAD_MULTIPLE_BASES:
        return is_load_multiple_return(base, op_str)
    if base == "mov":
        return op_str.replace(" ", "") == "pc,lr"
    if sets_flags and op_str.startswith("pc,") and "lr" in (operand.strip() for operand in op_str.split(",")[1:]):
        return True
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

    Each signature is tried on its own, and a miss on one falls through to the next. An
    earlier version returned the A32 dense-run verdict as soon as a pattern had sixteen hits
    anywhere in the buffer, so a Thumb-2 image carrying sixteen scattered A32 ``bx lr`` words
    (a veneer here, a literal there) never reached the T32 test that would have accepted it.

    The T32 test is :func:`_looksLikeThumb`: a halfword return is weak enough that it needs
    company before it counts, see there.
    """
    for pattern in A32_RETURN_BYTES:
        if hasDenseReturnRun(buffer, pattern, A32_INSTRUCTION_SIZE, MIN_RETURN_SITES):
            return True
    # A32 at a halfword offset (a dump cut two bytes into a word) is deliberately not tried:
    # it doubles the A32 scan, and so the probe's worst case, for a layout no loader produces.
    return _looksLikeThumb(buffer)


#: T32 ``pop.w {..., pc}`` (A8.8.131 T2): E8BD then a register list with P (bit 15) set and
#: SP (bit 13) clear; M (bit 14, lr) must be clear too, since loading both lr and pc is
#: UNPREDICTABLE. Little-endian that is ``bd e8 <list lo> <80..9f>``. MSVC ends nearly every
#: Thumb-2 function with it (``pop.w {r4-r11, pc}``) and emits ``bx lr`` only from leaves:
#: 5856 against 21 in one Windows-on-ARM DLL, which ``bx lr`` alone never recognised.
T32_POP_HW1_BYTES = T32_POP_HW1.to_bytes(2, "little")
T32_POP_PC_LIST_HI = range(0x80, 0xA0)
#: T32 ``push.w {..., lr}`` (A8.8.133 T2): E92D with M (bit 14) set and P, SP clear
T32_PUSH_HW1_BYTES = T32_PUSH_HW1.to_bytes(2, "little")
T32_PUSH_LR_LIST_HI = range(0x40, 0x60)
#: ``str.w lr, [sp, #-4]!`` / ``ldr.w pc, [sp], #4``, the single-register frame forms
T32_SINGLE_FRAME_BYTES = tuple(
    b"".join(halfword.to_bytes(2, "little") for halfword in pair) for pair in (T32_PUSH_LR_SINGLE, T32_POP_PC_SINGLE)
)
#: frame instructions a run of T32 returns must have inside its window. Every Thumb-2 run
#: measured over Debian armhf, Windows-on-ARM and GCC A32 images held 42 or more; the ASCII
#: and i386 ``.eh_frame`` runs that used to pass held none: every form carries an E8, E9 or F8
#: byte, which printable text cannot and those CFA programs did not.
MIN_T32_FRAME_SITES = 8
#: per-byte 0/1 tables, so the text tests below run as C-level byte operations: one hit costs
#: about a microsecond instead of the several a per-unit Python loop takes, which is what lets
#: the T32 test scan two return patterns within the time the one-pattern probe used to take
_PRINTABLE_ASCII = bytes(1 if 0x20 <= value < 0x7F else 0 for value in range(256))
_ASCII_TEXT = bytes(1 if 0x20 <= value < 0x7F or value in (9, 10, 13) else 0 for value in range(256))
_ZERO = bytes(1 if value == 0 else 0 for value in range(256))


def _ones(flags):
    """Number of 1 bytes in a string of 0/1 bytes."""
    return flags.count(1)


def _both(left, right):
    """Positions where two equally long 0/1 byte strings are both 1."""
    return (int.from_bytes(left, "big") & int.from_bytes(right, "big")).bit_count()


def _looksLikeTextAt(buffer, offset):
    """Whether the bytes around a halfword-aligned ``offset`` are ASCII or UTF-16 text.

    ``bx lr`` is ``70 47``, the text "pG", and ``looksLikeText`` only recognises UTF-16.
    Base64 holds an aligned "pG" every ~7.4 KiB, so a 16-in-64-KiB run turned up by chance in
    half of all 1 MiB base64 blobs (a notebook with embedded images among them), and a single
    such blob in an x86 dump sent the whole dump to this backend. A neighbourhood that is
    TEXT_UNIT_SHARE printable ASCII (tab and line breaks included) is text as well.

    The UTF-16 half is ``looksLikeText`` itself, for a halfword-aligned offset, computed on
    whole byte strings rather than unit by unit.
    """
    start = max(0, offset - NEIGHBOURHOOD_BYTES)
    window = bytes(buffer[start : offset + NEIGHBOURHOOD_BYTES])
    if _ones(window.translate(_ASCII_TEXT)) >= len(window) * TEXT_UNIT_SHARE:
        return True
    units = len(window) // 2
    if units < 8:
        return False
    low = window[0 : units * 2 : 2]
    high = window[1 : units * 2 : 2]
    little = _both(low.translate(_PRINTABLE_ASCII), high.translate(_ZERO))
    big = _both(high.translate(_PRINTABLE_ASCII), low.translate(_ZERO))
    return max(little, big) >= units * TEXT_UNIT_SHARE


def _occurrences(buffer, needle, last_byte_range=None):
    """Every offset of ``needle`` (whose 4th byte, if constrained, lies in the range)."""
    index = buffer.find(needle)
    while index >= 0:
        if last_byte_range is None or (index + 3 < len(buffer) and buffer[index + 3] in last_byte_range):
            yield index
        index = buffer.find(needle, index + 1)


def _alignedSites(buffer, streams):
    """Halfword-aligned offsets from several occurrence streams, in order, sharing one budget.

    Bounded like ``_codeReturnSites``: MAX_PROBES occurrences, aligned or not, for all the
    streams together, so a second pattern does not raise the probe's worst case.
    """
    for probes, offset in enumerate(heapq.merge(*streams), 1):
        if probes > MAX_PROBES:
            return
        if offset % T16_INSTRUCTION_SIZE == 0:
            yield offset


def _t32ReturnSites(buffer):
    """T32 returns (``bx lr``, ``pop.w {..., pc}``) not sitting in ASCII or UTF-16 text."""
    streams = (
        _occurrences(buffer, T16_RETURN_BYTES),
        _occurrences(buffer, T32_POP_HW1_BYTES, T32_POP_PC_LIST_HI),
    )
    for offset in _alignedSites(buffer, streams):
        if not _looksLikeTextAt(buffer, offset):
            yield offset


def _t32FrameSites(buffer):
    """T32 frame pushes and pops. No text test: each only corroborates a run whose returns passed one."""
    streams = [
        _occurrences(buffer, T32_PUSH_HW1_BYTES, T32_PUSH_LR_LIST_HI),
        _occurrences(buffer, T32_POP_HW1_BYTES, T32_POP_PC_LIST_HI),
    ]
    streams.extend(_occurrences(buffer, needle) for needle in T32_SINGLE_FRAME_BYTES)
    return list(_alignedSites(buffer, streams))


def _looksLikeThumb(buffer):
    """Whether MIN_RETURN_SITES T32 returns fall in one window that also holds T32 frames.

    Density alone let two kinds of data through. Base64 is handled by discarding hits in
    ASCII text. The other is i386 ``.eh_frame``: ``DW_CFA_def_cfa_offset 0x70`` followed by
    ``DW_CFA_advance_loc 7`` is ``0e 70 47``, and the argument pushes of i386 code step the
    CFA offset through 0x70 often enough to put 27 aligned ``bx lr`` in one 64 KiB window of a
    real libxml2. What that data did not hold is a 4-byte ``push.w``/``pop.w`` frame, which
    every Thumb-2 compiler emits for any function saving more than r4-r7, so a run counts
    only with MIN_T32_FRAME_SITES of those in the same window.

    A32 code passes this test as well, and is meant to: ``ldm sp!, {..., pc}`` and
    ``stmdb sp!, {..., lr}`` are E8BD8xxx / E92D4xxx, whose upper halfword followed by the
    next word's lower one spells the T32 ``pop.w``/``push.w`` at a halfword offset. That is
    what recognises GCC A32 code returning through ``ldm`` rather than ``bx lr``, and A32 code
    cut two bytes into a word; the backend still picks the instruction set per function.
    """
    recent = deque(maxlen=MIN_RETURN_SITES)
    frames = None
    for offset in _t32ReturnSites(buffer):
        recent.append(offset)
        if len(recent) < MIN_RETURN_SITES or offset - recent[0] >= WINDOW_BYTES:
            continue
        if frames is None:
            # collected once, on the first dense run, and only ever for a dense run
            frames = _t32FrameSites(buffer)
        start = recent[0]
        if bisect.bisect_left(frames, start + WINDOW_BYTES) - bisect.bisect_left(frames, start) >= MIN_T32_FRAME_SITES:
            return True
    return False


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
