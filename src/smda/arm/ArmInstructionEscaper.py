"""Instruction escaping for AArch32 (A32 and T32), the basis of PicHash and OpcHash.

Mnemonics are reduced to their base operation (``addeq.w`` and ``adds`` are both ``add``)
and classified into the same groups the AArch64 escaper uses. Binary escaping wildcards
exactly the fields that change when code moves: branch and call offsets, the offsets of
PC-relative literal loads and ``adr``, and the ``movw``/``movt`` immediates that carry
absolute addresses in position-dependent code. The field positions are the encodings of
the ARM Architecture Reference Manual (DDI 0406C), A5 for A32 and A6 for T32.

The instruction set is read from the function's ``architecture_metadata["thumb"]``; a
two-byte instruction is T16 whatever the metadata says.
"""

import logging
import re

from smda.arm.definitions import BASE_MNEMONICS, IT_MNEMONICS, split_mnemonic

LOGGER = logging.getLogger(__name__)

_CONTROL_FLOW = frozenset(
    {"b", "bl", "blx", "blxns", "bx", "bxj", "bxns", "cbz", "cbnz", "tbb", "tbh", "eret", "it"}
    | {"rfe", "rfeda", "rfedb", "rfeia", "rfeib"}
)
_STACK = frozenset({"push", "pop", "vpush", "vpop", "srsda", "srsdb", "srsia", "srsib"})
_NOP = frozenset({"nop"})
_PRIVILEGED = frozenset(
    {
        "svc",
        "smc",
        "hvc",
        "bkpt",
        "udf",
        "hlt",
        "trap",
        "cps",
        "cpsid",
        "cpsie",
        "mrs",
        "msr",
        "mcr",
        "mcr2",
        "mcrr",
        "mcrr2",
        "mrc",
        "mrc2",
        "mrrc",
        "mrrc2",
        "cdp",
        "cdp2",
        "ldc",
        "ldc2",
        "ldcl",
        "ldc2l",
        "stc",
        "stc2",
        "stcl",
        "stc2l",
        "wfi",
        "wfe",
        "sev",
        "sevl",
        "yield",
        "dmb",
        "dsb",
        "isb",
        "sb",
        "ssbb",
        "pssbb",
        "csdb",
        "setend",
        "setpan",
        "clrex",
        "dbg",
        "esb",
        "tsb",
    }
)
_FLOAT_DATATYPE = re.compile(r"\.f(?:16|32|64)\b")
_VECTOR_REGISTER = re.compile(r"\bq(?:[0-9]|1[0-5])\b")
_REGISTER = re.compile(
    r"^(?:r(?:[0-9]|1[0-5])|sb|sl|fp|ip|sp|lr|pc|[sd](?:[0-9]|[12][0-9]|3[01])|q(?:[0-9]|1[0-5])"
    r"|[cp](?:[0-9]|1[0-5])|apsr|apsr_nzcv|fpscr|fpexc|fpsid|mvfr[0-2])(?:\[\d*\])?!?$"
)
_SHIFT = re.compile(r"^(?:lsl|lsr|asr|ror)(?:\s+#?\S+)?$|^rrx$")
_CONDITION = re.compile(r"^(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$")
_BARRIER = re.compile(r"^(?:sy|st|ld|ish|ishst|ishld|nsh|nshst|nshld|osh|oshst|oshld|#\d+)$")
_SYSREG = re.compile(r"^(?:[acs]psr|spsr_\w+|cpsr_\w+|apsr_\w+|[a-z]+_(?:usr|svc|irq|fiq|abt|und|mon|hyp)|elr_hyp)$")


def _render(value, size, keep_mask):
    """Hex of ``value`` in little-endian byte order with every nibble whose bit in
    ``keep_mask`` (bit n = bits 4n..4n+3 of ``value``) is clear replaced by ``?``."""
    result = []
    for byte_index in range(size):
        byte = (value >> (byte_index * 8)) & 0xFF
        for shift in (4, 0):
            nibble_index = byte_index * 2 + (1 if shift == 4 else 0)
            result.append(f"{(byte >> shift) & 0xF:x}" if (keep_mask >> nibble_index) & 1 else "?")
    return "".join(result)


def _a32KeepMask(word):
    if (word >> 25) & 0x7 == 0b101:
        # B, BL and BLX (immediate): imm24 below the condition and opcode (A5.5)
        return 0xC0
    if (word >> 28) == 0xF:
        return None
    if word & 0x0FB00000 == 0x03000000:
        # MOVW / MOVT: imm4 at 16..19, imm12 at 0..11 (A8.8.102, A8.8.106)
        return 0xE8
    if word & 0x0E5F0000 == 0x041F0000 or word & 0x0FFF0000 in (0x028F0000, 0x024F0000):
        # LDR (literal) and ADR: imm12 (A8.8.65, A8.8.12)
        return 0xF8
    if word & 0x0F3F0E00 == 0x0D1F0A00:
        # VLDR (literal): imm8 (A8.8.333)
        return 0xFC
    return None


def _t16KeepMask(halfword):
    if halfword & 0xF000 == 0xD000 and (halfword >> 8) & 0xF < 0xE:
        return 0x0C
    if halfword & 0xF800 == 0xE000:
        return 0x08
    if halfword & 0xF500 == 0xB100:
        return 0x08
    if halfword & 0xF800 in (0x4800, 0xA000):
        return 0x0C
    return None


def _t32KeepMask(hw1, hw2):
    if (
        hw1 & 0xF800 == 0xF000
        and hw2 & 0x8000
        and (hw2 & 0x5000 or (hw2 & 0xD000 == 0x8000 and (hw1 >> 6) & 0xE != 0xE))
    ):
        # B.W, BL, BLX and conditional B.W: S:imm10 and J1:J2:imm11 (A6.3.4)
        return 0x88
    if hw1 & 0xFB70 == 0xF240 or hw1 & 0xFBFF in (0xF20F, 0xF2AF):
        # MOVW / MOVT and ADR.W: i:imm4 and imm3:imm8 around Rd (A8.8.102, A8.8.12)
        return 0x4A
    if hw1 & 0xFE1F == 0xF81F:
        # LDR{B,H,SB,SH}.W (literal): imm12 below Rt (A8.8.65)
        return 0x8F
    if hw1 & 0xFF3F == 0xED1F:
        # VLDR (literal): imm8
        return 0xCF
    return None


class ArmInstructionEscaper:
    @staticmethod
    def _isThumb(ins):
        if ins.bytes and len(ins.bytes) == 4:
            return True
        function = ins.smda_function
        metadata = getattr(function, "architecture_metadata", None) or {}
        return bool(metadata.get("thumb"))

    @staticmethod
    def escapeMnemonic(mnemonic, operands=None):
        base, _condition, _sets_flags = split_mnemonic(mnemonic)
        if base in _CONTROL_FLOW or base in IT_MNEMONICS:
            return "C"
        if base in _STACK:
            return "S"
        if base in _NOP:
            return "N"
        if base in _PRIVILEGED or base.startswith("cps"):
            return "P"
        if base.startswith("v"):
            if base.startswith(("vldr", "vstr", "vld", "vst")):
                return "M"
            if base in ("vmrs", "vmsr"):
                return "F"
            if operands and _VECTOR_REGISTER.search(operands):
                return "V"
            return "F" if _FLOAT_DATATYPE.search(mnemonic) or base.startswith("vcvt") else "V"
        if base.startswith(("ldr", "str", "ldm", "stm", "lda", "stl", "pld", "pli", "swp")):
            return "M"
        if base in BASE_MNEMONICS:
            return "A"
        LOGGER.debug("ARM escaper could not classify mnemonic %s", mnemonic)
        return "U"

    @staticmethod
    def escapeMnemonicForInstruction(ins):
        return ArmInstructionEscaper.escapeMnemonic(ins.mnemonic, ins.operands or "")

    @staticmethod
    def _splitOperands(operands):
        fields = []
        field_start = 0
        depth = 0
        for index, char in enumerate(operands):
            if char in "[{":
                depth += 1
            elif char in "]}" and depth > 0:
                depth -= 1
            elif char == "," and depth == 0:
                fields.append(operands[field_start:index])
                field_start = index + 1
        fields.append(operands[field_start:])
        return fields

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        if op_field.endswith("^"):
            op_field = op_field[:-1].strip()
        if not op_field:
            return ""
        if escape_pointers and op_field.startswith("["):
            return "PTR"
        if escape_registers and (_REGISTER.match(op_field) or (op_field.startswith("{") and op_field.endswith("}"))):
            return "REG"
        if escape_constants:
            value = op_field[1:] if op_field.startswith("#") else op_field
            try:
                int(value, 0)
                return "CONST"
            except ValueError:
                try:
                    float(value)
                    return "CONST"
                except ValueError:
                    pass
        if _SHIFT.match(op_field):
            return "SHIFT"
        if _CONDITION.match(op_field):
            return "COND"
        if _BARRIER.match(op_field):
            return "BARRIER"
        if _SYSREG.match(op_field):
            return "SYSREG"
        return "MISC"

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        operands = ins.operands or ""
        if offsets_only:
            if ArmInstructionEscaper.escapeMnemonic(ins.mnemonic, operands) == "C":
                return "OFFSET"
            return ", ".join(field.strip() for field in ArmInstructionEscaper._splitOperands(operands) if field.strip())
        tokens = []
        for field in ArmInstructionEscaper._splitOperands(operands):
            token = ArmInstructionEscaper.escapeField(field)
            if not token or (token == "SHIFT" and tokens):
                continue
            tokens.append(token)
        return ", ".join(tokens)

    @staticmethod
    def _value(ins):
        raw = bytes.fromhex(ins.bytes)
        return int.from_bytes(raw, "little"), len(raw)

    @staticmethod
    def escapeToOpcodeOnly(ins):
        if not ins.bytes or len(ins.bytes) not in (4, 8):
            return ins.bytes
        value, size = ArmInstructionEscaper._value(ins)
        control_flow = ArmInstructionEscaper.escapeMnemonic(ins.mnemonic, ins.operands or "") == "C"
        if size == 2:
            return _render(value, 2, 0x08 if control_flow else 0x0C)
        if ArmInstructionEscaper._isThumb(ins):
            return _render(value, 4, 0x88 if control_flow else 0x0E)
        return _render(value, 4, 0xC0 if control_flow else 0xE0)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        # every PC-relative field is position dependent and is wildcarded whether it stays
        # inside the function or not, so neither the flag nor the bounds change anything
        del escape_intraprocedural_jumps, lower_addr, upper_addr
        if not ins.bytes or len(ins.bytes) not in (4, 8):
            return ins.bytes
        value, size = ArmInstructionEscaper._value(ins)
        if size == 2:
            keep_mask = _t16KeepMask(value)
        elif ArmInstructionEscaper._isThumb(ins):
            keep_mask = _t32KeepMask(value & 0xFFFF, value >> 16)
        else:
            keep_mask = _a32KeepMask(value)
        if keep_mask is None:
            return ins.bytes
        return _render(value, size, keep_mask)
