"""Straight-line constant tracking over AArch32 instructions.

A deliberately small evaluator: it follows the handful of idioms compilers use to put an
address in a register - a literal-pool load, ``movw``/``movt``, ``adr`` and the
``add rd, pc`` of position-independent code - through register copies and loads from
known addresses. Everything else that writes a register makes it unknown. It is what the
jump-table, indirect-call and import-stub resolvers share.

The value of pc as an operand is the instruction address plus 8 in A32 and plus 4 in
T32 (A2.3); literal loads and ``adr`` in T32 use ``Align(PC, 4)`` instead (A8.8.64,
A8.8.12), while a T32 ``add rd, pc`` uses the unaligned value (A8.8.6).
"""

from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_SFT_INVALID, ARM_SFT_LSL

from .definitions import CALL_BASES, LOAD_MULTIPLE_BASES, split_mnemonic

_MASK = 0xFFFFFFFF
_CALLER_SAVED = ("r0", "r1", "r2", "r3", "ip", "lr")
#: bases whose first register operand is read rather than written
_NON_WRITING_BASES = frozenset(
    {
        "cmp",
        "cmn",
        "tst",
        "teq",
        "b",
        "bx",
        "bxj",
        "cbz",
        "cbnz",
        "tbb",
        "tbh",
        "it",
        "nop",
        "push",
        "vpush",
        "pld",
        "pldw",
        "pli",
        "svc",
        "bkpt",
        "udf",
        "dmb",
        "dsb",
        "isb",
        "msr",
        "vmsr",
        "mcr",
        "mcrr",
        "setend",
        "cps",
    }
)
_REGISTER_ALIASES = {"r9": "sb", "r10": "sl", "r11": "fp", "r12": "ip", "r13": "sp", "r14": "lr", "r15": "pc"}


def norm_reg(name):
    return _REGISTER_ALIASES.get(name, name)


def pc_value(address, thumb, aligned=False):
    if thumb:
        return ((address + 4) & ~3) if aligned else address + 4
    return address + 8


def _is_store(base):
    return base.startswith(("str", "stm", "stl", "vst")) or base in ("srsda", "srsdb", "srsia", "srsib")


class RegisterTracker:
    """Constant values (and load slots) of registers after a run of instructions."""

    def __init__(self, disassembler, thumb):
        self.disassembler = disassembler
        self.thumb = thumb
        self.values = {}
        #: register -> address it was last loaded from, while that load still defines it
        self.slots = {}

    def get(self, reg_name):
        return self.values.get(norm_reg(reg_name))

    def slot(self, reg_name):
        return self.slots.get(norm_reg(reg_name))

    def _set(self, reg, value):
        self.values[reg] = value & _MASK
        self.slots.pop(reg, None)

    def _kill(self, reg):
        self.values.pop(reg, None)
        self.slots.pop(reg, None)

    def _operandValue(self, ins, operand, aligned_pc=False):
        if operand.type == ARM_OP_IMM:
            return operand.imm & _MASK
        if operand.type != ARM_OP_REG or operand.shift.type != ARM_SFT_INVALID:
            return None
        reg = norm_reg(ins.reg_name(operand.reg))
        if reg == "pc":
            return pc_value(ins.address, self.thumb, aligned=aligned_pc)
        return self.values.get(reg)

    def memoryAddress(self, ins, operand):
        """Effective address of a memory operand, or None when a component is unknown."""
        base_reg = norm_reg(ins.reg_name(operand.mem.base))
        base = pc_value(ins.address, self.thumb, aligned=True) if base_reg == "pc" else self.values.get(base_reg)
        if base is None:
            return None
        offset = operand.mem.disp
        if operand.mem.index:
            index_reg = norm_reg(ins.reg_name(operand.mem.index))
            index = pc_value(ins.address, self.thumb) if index_reg == "pc" else self.values.get(index_reg)
            if index is None:
                return None
            shift = operand.shift.value if operand.shift.type == ARM_SFT_LSL else 0
            index <<= shift
            offset += -index if operand.subtracted else index
        return (base + offset) & _MASK

    def readWord(self, address):
        disassembly = self.disassembler.disassembly
        if not disassembly.isAddrWithinMemoryImage(address):
            return None
        data = disassembly.getBytes(address, 4)
        if not data or len(data) != 4:
            return None
        return int.from_bytes(data, "little")

    def step(self, ins, mnemonic=None):
        """Apply one detailed instruction. ``mnemonic`` overrides the capstone spelling,
        which loses the condition of an instruction decoded on its own out of an IT block."""
        base, condition, _sets_flags = split_mnemonic(mnemonic or ins.mnemonic)
        operands = ins.operands
        conditional = condition is not None and condition != "al"
        if base in CALL_BASES:
            for reg in _CALLER_SAVED:
                self._kill(reg)
            return
        if base in LOAD_MULTIPLE_BASES or base in ("vpop",):
            for operand in operands:
                if operand.type == ARM_OP_REG:
                    self._kill(norm_reg(ins.reg_name(operand.reg)))
            return
        if not operands or operands[0].type != ARM_OP_REG:
            return
        if base in _NON_WRITING_BASES or _is_store(base):
            self._killWriteback(ins)
            return
        dest = norm_reg(ins.reg_name(operands[0].reg))
        value, slot = self._evaluate(ins, base, operands, dest)
        self._killWriteback(ins)
        if conditional or value is None:
            self._kill(dest)
            return
        self._set(dest, value)
        if slot is not None:
            self.slots[dest] = slot

    def _killWriteback(self, ins):
        if not ins.writeback:
            return
        for operand in ins.operands:
            if operand.type == ARM_OP_MEM:
                self._kill(norm_reg(ins.reg_name(operand.mem.base)))

    def _evaluate(self, ins, base, operands, dest):
        count = len(operands)
        if count >= 3 and operands[-1].type == ARM_OP_IMM and operands[-2].type == ARM_OP_IMM:
            # capstone keeps an A32 modified immediate written with an explicit rotation
            # (``add ip, pc, #0, #12``) as two operands; fold them into the value (A5.2.4)
            operands = [*operands[:-2], _RotatedImmediate(operands[-2].imm, operands[-1].imm)]
            count -= 1
        if base in ("mov", "movw") and count == 2:
            return self._operandValue(ins, operands[1]), None
        if base == "mvn" and count == 2 and operands[1].type == ARM_OP_IMM:
            return ~operands[1].imm, None
        if base == "movt" and count == 2 and operands[1].type == ARM_OP_IMM:
            low = self.values.get(dest)
            if low is None:
                return None, None
            return (low & 0xFFFF) | ((operands[1].imm & 0xFFFF) << 16), None
        if base == "adr" and count == 2 and operands[1].type == ARM_OP_IMM:
            return pc_value(ins.address, self.thumb, aligned=True) + operands[1].imm, None
        if base in ("add", "addw", "sub", "subw") and count in (2, 3):
            if count == 2:
                left = self.values.get(dest)
                right = self._operandValue(ins, operands[1])
            else:
                aligned = self.thumb and operands[2].type == ARM_OP_IMM
                left = self._operandValue(ins, operands[1], aligned_pc=aligned)
                right = self._operandValue(ins, operands[2])
            if left is None or right is None:
                return None, None
            return (left + right) if base.startswith("add") else (left - right), None
        if base == "ldr" and count == 2 and operands[1].type == ARM_OP_MEM:
            address = self.memoryAddress(ins, operands[1])
            if address is None:
                return None, None
            return self.readWord(address), address
        return None, None


class _RotatedImmediate:
    type = ARM_OP_IMM

    def __init__(self, imm, rotation):
        rotation &= 31
        imm &= _MASK
        self.imm = ((imm >> rotation) | (imm << (32 - rotation))) & _MASK if rotation else imm


def track(disassembler, decoded, thumb):
    """Run a tracker over ``(tuple, detailed)`` pairs as :func:`decode` returns them."""
    tracker = RegisterTracker(disassembler, thumb)
    for ins, detailed in decoded:
        tracker.step(detailed, mnemonic=ins[2])
    return tracker


def precedingInstructions(state, address, limit):
    """The booked instructions that flow straight into ``address``, oldest first.

    Walks backwards through instructions the current analysis has already decoded while
    each one ends where the next begins, and stops before one that cannot fall through
    (an unconditional branch or return): whatever precedes that is not on this path.
    """
    by_end = getattr(state, "_arm_by_end", None)
    if by_end is None or getattr(state, "_arm_by_end_count", -1) != len(state.instructions):
        by_end = {ins[0] + ins[1]: ins for ins in state.instructions}
        state._arm_by_end = by_end
        state._arm_by_end_count = len(state.instructions)
    result = []
    cursor = address
    while len(result) < limit:
        ins = by_end.get(cursor)
        if ins is None or not _fallsThrough(ins):
            break
        result.append(ins)
        cursor = ins[0]
    result.reverse()
    return result


def _fallsThrough(ins):
    mnemonic = ins[2]
    op_str = ins[3]
    base, condition, _sets_flags = split_mnemonic(mnemonic)
    if condition is not None and condition != "al":
        return True
    if base in ("b", "bx", "bxj", "tbb", "tbh", "udf", "eret", "cbz", "cbnz"):
        return base in ("cbz", "cbnz")
    if base in LOAD_MULTIPLE_BASES and "pc" in op_str:
        return False
    return not op_str.startswith("pc,")


def decode(disassembler, instructions):
    """``(tuple, detailed)`` pairs for booked instruction tuples, in the current mode.

    An instruction capstone cannot decode on its own discards everything before it, so a
    caller always sees a contiguous run ending where the input does.
    """
    decoded = []
    capstone = disassembler.capstone
    for ins in instructions:
        data = disassembler.disassembly.getBytes(ins[0], ins[1])
        detailed = next(capstone.disasm(bytes(data), ins[0]), None) if data else None
        if detailed is None:
            decoded = []
            continue
        decoded.append((ins, detailed))
    return decoded
