import logging
import re

LOGGER = logging.getLogger(__name__)


class AArch64InstructionEscaper:
    _aritlog_group = {
        "adc",
        "adcs",
        "add",
        "adds",
        "adr",
        "adrp",
        "and",
        "ands",
        "asr",
        "bic",
        "bics",
        "clz",
        "cmp",
        "cmn",
        "eor",
        "extr",
        "lsl",
        "lsr",
        "madd",
        "mneg",
        "mov",
        "movk",
        "movn",
        "movz",
        "mul",
        "mvn",
        "neg",
        "negs",
        "orr",
        "ror",
        "sbc",
        "sbcs",
        "sdiv",
        "sub",
        "subs",
        "udiv",
    }
    _cfg_group = {
        "b",
        "b.al",
        "b.cc",
        "b.cs",
        "b.eq",
        "b.ge",
        "b.gt",
        "b.hi",
        "b.hs",
        "b.le",
        "b.lo",
        "b.ls",
        "b.lt",
        "b.mi",
        "b.ne",
        "b.nv",
        "b.pl",
        "b.vc",
        "b.vs",
        "bl",
        "blr",
        "blraaz",
        "blrabz",
        "blraa",
        "blrab",
        "br",
        "braaz",
        "brabz",
        "braa",
        "brab",
        "cbnz",
        "cbz",
        "eret",
        "eretaa",
        "eretab",
        "ret",
        "retaa",
        "retab",
        "tbnz",
        "tbz",
    }
    _mem_group = {
        "ldp",
        "ldpsw",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsb",
        "ldrsh",
        "ldrsw",
        "ldur",
        "ldurb",
        "ldurh",
        "ldursb",
        "ldursh",
        "ldursw",
        "stp",
        "str",
        "strb",
        "strh",
        "stur",
        "sturb",
        "sturh",
    }
    _stack_group = {
        "autiasp",
        "autibsp",
        "paciasp",
        "pacibsp",
        "stp",
    }
    _privileged_group = {
        "bti",
        "dc",
        "dsb",
        "dmb",
        "eret",
        "eretaa",
        "eretab",
        "isb",
        "mrs",
        "msr",
        "svc",
        "sys",
    }
    _float_group = {
        "fabs",
        "fadd",
        "fcmp",
        "fcvt",
        "fdiv",
        "fmadd",
        "fmov",
        "fmsub",
        "fmul",
        "fneg",
        "fnmadd",
        "fnmsub",
        "fnmul",
        "fsqrt",
        "fsub",
        "scvtf",
        "ucvtf",
    }
    _vector_group = {
        "addv",
        "andv",
        "dup",
        "eorv",
        "faddp",
        "ld1",
        "ld2",
        "ld3",
        "ld4",
        "movi",
        "orrv",
        "st1",
        "st2",
        "st3",
        "st4",
        "tbl",
        "tbx",
    }
    _nop_group = {"hint", "nop"}
    _register = re.compile(r"^(?:[wx][0-9]+|[sdqv][0-9]+|sp|wsp|xzr|wzr|fp|lr)(?:\\.[0-9]+[bhsd])?$")
    _condition = re.compile(r"^(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)$")

    @staticmethod
    def escapeMnemonic(mnemonic):
        mnemonic = mnemonic.split(" ")[-1]
        if mnemonic in AArch64InstructionEscaper._aritlog_group:
            return "A"
        if mnemonic in AArch64InstructionEscaper._cfg_group:
            return "C"
        if mnemonic in AArch64InstructionEscaper._mem_group:
            return "M"
        if mnemonic in AArch64InstructionEscaper._stack_group:
            return "S"
        if mnemonic in AArch64InstructionEscaper._privileged_group:
            return "P"
        if mnemonic in AArch64InstructionEscaper._float_group:
            return "F"
        if mnemonic in AArch64InstructionEscaper._vector_group:
            return "V"
        if mnemonic in AArch64InstructionEscaper._nop_group:
            return "N"
        if mnemonic == "error":
            return "U"
        LOGGER.error("********************************************** Unhandled mnemonic: %s", mnemonic)
        return "U"

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        if not op_field:
            return ""
        if escape_pointers and "[" in op_field and "]" in op_field:
            return "PTR"
        if escape_registers and (
            AArch64InstructionEscaper._register.match(op_field)
            or (
                op_field.startswith("{")
                and op_field.endswith("}")
                and all(
                    AArch64InstructionEscaper._register.match(item.strip()) for item in op_field.strip("{}").split(",")
                )
            )
        ):
            return "REG"
        if escape_constants:
            value = op_field[1:] if op_field.startswith("#") else op_field
            try:
                int(value, 0)
                return "CONST"
            except ValueError:
                pass
        if AArch64InstructionEscaper._condition.match(op_field):
            return "COND"
        return op_field

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
    def escapeOperands(ins, offsets_only=False):
        if offsets_only and AArch64InstructionEscaper.escapeMnemonic(ins.mnemonic) == "C":
            return "OFFSET"
        esc_regs = not offsets_only
        esc_consts = not offsets_only
        return ", ".join(
            AArch64InstructionEscaper.escapeField(
                op_field,
                escape_registers=esc_regs,
                escape_constants=esc_consts,
            )
            for op_field in AArch64InstructionEscaper._splitOperands(ins.operands)
        )

    @staticmethod
    def _wordWithMaskToHex(word, mask):
        result = []
        for byte_index in range(4):
            byte = (word >> (byte_index * 8)) & 0xFF
            byte_mask = (mask >> (byte_index * 8)) & 0xFF
            for shift in (4, 0):
                nibble_mask = (byte_mask >> shift) & 0xF
                if nibble_mask == 0xF:
                    result.append(f"{(byte >> shift) & 0xF:x}")
                else:
                    result.append("?")
        return "".join(result)

    @staticmethod
    def _hasExplicitOperands(ins):
        try:
            return bool(ins.getDetailed().operands)
        except (AttributeError, NotImplementedError, ValueError):
            return bool(ins.operands)

    @staticmethod
    def escapeToOpcodeOnly(ins):
        if len(ins.bytes) != 8 or not AArch64InstructionEscaper._hasExplicitOperands(ins):
            return ins.bytes
        word = int.from_bytes(bytes.fromhex(ins.bytes), "little")
        if AArch64InstructionEscaper.escapeMnemonic(ins.mnemonic) == "C":
            return AArch64InstructionEscaper._wordWithMaskToHex(word, 0xFC000000)
        return AArch64InstructionEscaper._wordWithMaskToHex(word, 0xFFE00000)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        del escape_intraprocedural_jumps, lower_addr, upper_addr
        if AArch64InstructionEscaper.escapeMnemonic(
            ins.mnemonic
        ) == "C" or AArch64InstructionEscaper._hasExplicitOperands(ins):
            return AArch64InstructionEscaper.escapeToOpcodeOnly(ins)
        return ins.bytes
