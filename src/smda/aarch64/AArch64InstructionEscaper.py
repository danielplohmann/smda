import logging
import re

from smda.aarch64.AArch64CapstoneVerification import (
    classify_mnemonic_fallback,
    expected_escaped_operands,
    expected_mnemonic_group,
)

LOGGER = logging.getLogger(__name__)


class AArch64InstructionEscaper:
    _aritlog_group = {
        "adc",
        "adcs",
        "add",
        "addg",
        "addpl",
        "adds",
        "adr",
        "adrp",
        "and",
        "ands",
        "asr",
        "asrd",
        "asrr",
        "asrv",
        "axflag",
        "bfi",
        "bfxil",
        "bic",
        "bics",
        "ccmp",
        "ccmn",
        "cinc",
        "cneg",
        "csel",
        "cset",
        "csetm",
        "csinc",
        "csinv",
        "csneg",
        "clz",
        "cmp",
        "cmn",
        "crc32b",
        "crc32h",
        "crc32w",
        "crc32x",
        "crc32cb",
        "crc32ch",
        "crc32cw",
        "crc32cx",
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
        "msub",
        "mul",
        "mvn",
        "neg",
        "negs",
        "orn",
        "orr",
        "rbit",
        "rev",
        "rev16",
        "rev32",
        "rev64",
        "ror",
        "sbc",
        "sbcs",
        "sbfx",
        "sbfiz",
        "sdiv",
        "smaddl",
        "smulh",
        "smull",
        "sub",
        "subs",
        "sxtb",
        "sxth",
        "sxtw",
        "tst",
        "ubfx",
        "ubfiz",
        "udiv",
        "umaddl",
        "umulh",
        "umull",
        "uxtb",
        "uxth",
        "uxtw",
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
        "bc",
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
        "casa",
        "casal",
        "cas",
        "casl",
        "casp",
        "caspl",
        "ld1r",
        "ldadd",
        "ldaddab",
        "ldaddal",
        "ldaddl",
        "ldapr",
        "ldaprb",
        "ldapurb",
        "ldar",
        "ldarb",
        "ldaxr",
        "ldaxrb",
        "ldclr",
        "ldclral",
        "ldclralb",
        "ldp",
        "ldpsw",
        "ldsetal",
        "ldsetalb",
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
        "prfm",
        "stp",
        "str",
        "strb",
        "strh",
        "stlrb",
        "stlr",
        "stlxr",
        "stlxrb",
        "stlur",
        "stlurb",
        "stur",
        "sturb",
        "sturh",
        "swp",
        "swpab",
        "swpal",
        "swplb",
    }
    _stack_group = {
        "autiasp",
        "autibsp",
        "paciasp",
        "pacibsp",
        "stp",
    }
    _privileged_group = {
        "at",
        "brk",
        "bti",
        "clrex",
        "dc",
        "dsb",
        "dmb",
        "hlt",
        "ic",
        "isb",
        "mrs",
        "msr",
        "smc",
        "svc",
        "sys",
        "tlbi",
        "udf",
        "wfe",
        "wfi",
        "yield",
    }
    _float_group = {
        "fabs",
        "fadd",
        "fcmp",
        "fcvt",
        "fcvtzs",
        "fcvtzu",
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
        "addp",
        "addv",
        "aese",
        "aesd",
        "aesimc",
        "aesmc",
        "andv",
        "bif",
        "bit",
        "bsl",
        "cmge",
        "cmeq",
        "cmlt",
        "cnt",
        "dup",
        "eorv",
        "faddp",
        "ld1",
        "ld2",
        "ld3",
        "ld4",
        "movi",
        "orrv",
        "shl",
        "st1",
        "st2",
        "st3",
        "st4",
        "tbl",
        "tbx",
        "uaddlv",
        "umaxv",
        "umov",
        "ushl",
        "ushll",
        "ushr",
    }
    _nop_group = {"hint", "nop"}
    _register = re.compile(r"^(?:[wx][0-9]+|[sdqv][0-9]+|sp|wsp|xzr|wzr|fp|lr)(?:\.[0-9]+[bhsd])?$")
    _lane = re.compile(r"^[bhsd][0-9]+$")
    _condition = re.compile(r"^(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)$")
    _shift_extend = re.compile(
        r"^(?:lsl|lsr|asr|ror|sxtw|uxtw|sxtb|uxtb|sxth|uxth|sxtx|uxtx)(?:\s+#-?(?:0x[0-9a-fA-F]+|\d+))?$",
        re.IGNORECASE,
    )
    _barrier = re.compile(r"^(?:(?:sy|osh|nsh|ish)(?:ld|st)?|ld|st)$", re.IGNORECASE)
    _prefetch = re.compile(r"^p(?:ld|st)[a-z0-9]+$", re.IGNORECASE)
    _sysreg = re.compile(r"^[a-z][a-z0-9_]*(?:_el\d+)?$")
    _sysop = re.compile(r"^[a-z][a-z0-9]+$")
    _MNEMONIC_PREFIX_FALLBACKS = (
        (("ld", "st", "swp", "cas", "prf"), "M"),
        (("aes", "sha", "sm4", "sha512", "sha3"), "V"),
        (("cb", "tb"), "C"),
        (
            (
                "at",
                "ic",
                "tlbi",
                "clrex",
                "svc",
                "smc",
                "mrs",
                "msr",
                "sys",
                "dc",
                "dsb",
                "dmb",
                "isb",
                "bti",
                "brk",
                "udf",
                "hlt",
                "wfe",
                "wfi",
                "yield",
            ),
            "P",
        ),
        (("nop", "hint"), "N"),
        (("pac", "aut"), "S"),
    )
    _VALID_ESCAPED_OPERANDS = frozenset(
        {"", "REG", "PTR", "CONST", "COND", "SHIFT", "EXT", "SYSREG", "BARRIER", "HINT", "SYSOP", "MISC"}
    )

    @staticmethod
    def _classify_mnemonic(mnemonic, operands=""):
        group = classify_mnemonic_fallback(
            mnemonic,
            operands,
            cfg_supplement=AArch64InstructionEscaper._cfg_group,
            privileged_supplement=AArch64InstructionEscaper._privileged_group,
            float_mnemonics=AArch64InstructionEscaper._float_group,
            vector_mnemonics=AArch64InstructionEscaper._vector_group,
            mem_mnemonics=AArch64InstructionEscaper._mem_group,
            stack_mnemonics=AArch64InstructionEscaper._stack_group,
            aritlog_mnemonics=AArch64InstructionEscaper._aritlog_group,
            prefix_fallbacks=AArch64InstructionEscaper._MNEMONIC_PREFIX_FALLBACKS,
        )
        if group == "U":
            LOGGER.debug("AArch64 escaper could not classify mnemonic %s", mnemonic.split(" ")[-1])
        return group

    @staticmethod
    def escapeMnemonic(mnemonic, operands=None):
        return AArch64InstructionEscaper._classify_mnemonic(mnemonic, operands or "")

    @staticmethod
    def escapeMnemonicForInstruction(ins):
        try:
            capstone_instruction = ins.getDetailed()
            capstone_engine = ins.smda_function.smda_report.getCapstone()
            return expected_mnemonic_group(capstone_instruction, capstone_engine)
        except (AttributeError, NotImplementedError, TypeError, ValueError):
            return AArch64InstructionEscaper._classify_mnemonic(ins.mnemonic, ins.operands or "")

    @staticmethod
    def _is_numeric_constant(value):
        try:
            int(value, 0)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_float_constant(value):
        try:
            float(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        if not op_field:
            return ""
        if escape_pointers and "[" in op_field and "]" in op_field:
            return "PTR"
        if escape_registers and (
            AArch64InstructionEscaper._register.match(op_field)
            or AArch64InstructionEscaper._lane.match(op_field)
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
            if AArch64InstructionEscaper._is_numeric_constant(value) or AArch64InstructionEscaper._is_float_constant(
                value
            ):
                return "CONST"
        if AArch64InstructionEscaper._shift_extend.match(op_field):
            return "SHIFT"
        if AArch64InstructionEscaper._condition.match(op_field):
            return "COND"
        if AArch64InstructionEscaper._barrier.match(op_field):
            return "BARRIER"
        if AArch64InstructionEscaper._prefetch.match(op_field):
            return "HINT"
        if AArch64InstructionEscaper._sysreg.match(op_field):
            return "SYSREG"
        if AArch64InstructionEscaper._sysop.match(op_field):
            return "SYSOP"
        LOGGER.debug("AArch64 escaper classifying unknown operand field %r as MISC", op_field)
        return "MISC"

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
    def _escapeOperandsFromText(ins, offsets_only=False):
        if offsets_only and AArch64InstructionEscaper._classify_mnemonic(ins.mnemonic, ins.operands or "") == "C":
            return "OFFSET"
        if offsets_only:
            return ", ".join(
                op_field.strip()
                for op_field in AArch64InstructionEscaper._splitOperands(ins.operands)
                if op_field.strip()
            )
        if ins.mnemonic == "prfm":
            return "PTR"
        esc_regs = not offsets_only
        esc_consts = not offsets_only
        tokens = []
        for op_field in AArch64InstructionEscaper._splitOperands(ins.operands):
            op_field = op_field.strip()
            if not op_field:
                continue
            token = AArch64InstructionEscaper.escapeField(
                op_field,
                escape_registers=esc_regs,
                escape_constants=esc_consts,
            )
            if token == "SHIFT" and tokens:
                continue
            tokens.append(token)
        return ", ".join(tokens)

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        if offsets_only and AArch64InstructionEscaper.escapeMnemonicForInstruction(ins) == "C":
            return "OFFSET"
        if offsets_only:
            return AArch64InstructionEscaper._escapeOperandsFromText(ins, offsets_only=True)
        try:
            return expected_escaped_operands(ins.getDetailed())
        except (AttributeError, NotImplementedError, TypeError, ValueError):
            return AArch64InstructionEscaper._escapeOperandsFromText(ins, offsets_only=offsets_only)

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
        if len(ins.bytes) != 8:
            return ins.bytes
        word = int.from_bytes(bytes.fromhex(ins.bytes), "little")
        if AArch64InstructionEscaper.escapeMnemonicForInstruction(ins) == "C":
            return AArch64InstructionEscaper._wordWithMaskToHex(word, 0xFF000000)
        if not AArch64InstructionEscaper._hasExplicitOperands(ins):
            return ins.bytes
        return AArch64InstructionEscaper._wordWithMaskToHex(word, 0xFFF00000)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        del escape_intraprocedural_jumps, lower_addr, upper_addr
        if AArch64InstructionEscaper.escapeMnemonicForInstruction(
            ins
        ) == "C" or AArch64InstructionEscaper._hasExplicitOperands(ins):
            return AArch64InstructionEscaper.escapeToOpcodeOnly(ins)
        return ins.bytes
