import logging
import re

from smda.aarch64.AArch64CapstoneVerification import (
    classify_mnemonic_fallback,
    expected_escaped_operands,
    expected_mnemonic_group,
)

LOGGER = logging.getLogger(__name__)

_KEEP_MASK_MEMO = {}
# mirrors the _shift_extend class attribute below; additions must be made in both places
_SHIFT_EXTEND_KEYWORDS = ("lsl", "lsr", "asr", "ror", "sxt", "uxt")
_SHIFT_EXTEND_IMMEDIATE_RE = re.compile(
    r"\b(?:lsl|lsr|asr|ror|sxtw|uxtw|sxtb|uxtb|sxth|uxth|sxtx|uxtx)\s*#-?(?:0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)


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
        "cinv",
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
        "smnegl",
        "smull",
        "smsubl",
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
        "umnegl",
        "umull",
        "umsubl",
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
    def _wordWithNibbleKeepMaskToHex(word, keep_mask):
        """Render `word` (32-bit) as 8 hex chars in little-endian byte order
        (byte 0 first, low nibble of each byte first), replacing nibbles
        whose corresponding bit in `keep_mask` is 0 with "?". `keep_mask`
        is 8 bits, bit n (LSB-first nibble index) = 1 means "keep this
        nibble from the original word".

        The output order matches the format of `ins.bytes` in SMDA (which
        stores raw instruction bytes in LE order) and matches the
        convention used by the older `_wordWithMaskToHex` helper, so
        consumers can compare escape output against the original byte
        string nibble-by-nibble.

        Nibble-granular wildcards give finer PIC-hash signal than byte-level
        wildcards and match aarch64's 4-bit-aligned instruction fields.
        """
        result = []
        # Iterate byte 0 (low) -> byte 3 (high), and within each byte the
        # low nibble first. This matches `ins.bytes` (LE) and the OLD
        # `_wordWithMaskToHex` convention.
        for byte_index in range(4):
            byte = (word >> (byte_index * 8)) & 0xFF
            for shift in (4, 0):
                nibble_index = byte_index * 2 + (1 if shift == 4 else 0)
                keep = (keep_mask >> nibble_index) & 1
                if keep:
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
    def _hasImmediateOperand(ins):
        """Return True only if the instruction has an *immediate* operand
        that we want to wildcard. We treat shift/extend modifiers like
        `lsl #3` and `sxtw #0` as not being immediates, because they
        describe the addressing mode, not a data value that gets
        relocated.

        The check is purely text-based (we look at `ins.operands`) so it
        is independent of capstone's detailed disassembly.
        """
        operands = ins.operands
        # stripping cannot change whether a "#" is present, and no "#" means no immediate
        if not operands or "#" not in operands:
            return False
        # the substitution below only ever deletes text containing "#", so without a
        # shift/extend keyword the cleaned string still holds the "#" seen above
        lowered = operands.lower()
        if not any(keyword in lowered for keyword in _SHIFT_EXTEND_KEYWORDS):
            return True
        # Strip shift/extend modifiers (e.g. "lsl #3", "sxtw #0") so they
        # don't count as immediates.
        #
        # Capstone renders extend modifiers with a leading space: "lsl #3"
        # or "sxtw #0". We replace these with "" before searching for a
        # real "#".
        #
        # Note: the regex below mirrors `_shift_extend` (defined above)
        # so any future additions to that pattern should be mirrored here.
        return "#" in _SHIFT_EXTEND_IMMEDIATE_RE.sub("", operands)

    # Per-mnemonic immediate-field masks. Each entry maps a base mnemonic
    # (after stripping condition codes such as "b.eq" -> "b") to an 8-bit
    # keep_mask: bit n (LSB-first nibble index) = 1 means "keep the original
    # nibble at output position n", 0 means "wildcard it".
    #
    # The masks cover word-bit ranges per the ARMv8 encodings. We wildcard
    # every nibble that overlaps an immediate field, which means we may
    # also wildcard a few bits of an adjacent register/opcode field. This
    # is the right trade-off: it makes the escape position-invariant
    # under relocation (the whole point of the pic_hash), at the cost of
    # losing a couple of bits of entropy per instruction. Wildcarding
    # partial fields would require byte-level granularity (intel's
    # approach); the nibble-granular approach is strictly finer.
    #
    # Most entries use mask 0xC1 (nibbles 0, 6, 7):
    #   nibble 0 : low 4 bits of Rd/Rt (preserves most register info)
    #   nibble 1 : wildcarded -- overlaps imm[5..7] for adr/adrp/cbz/cbnz/ldr/str/add/sub
    #   nibble 6 : high nibble of op byte
    #   nibble 7 : top nibble of op byte
    # The exception is unconditional `b`/`bl` (imm26 spans bits 0..25),
    # which uses mask 0xC0 (nibbles 6, 7 only) to keep the branch fully
    # position-invariant; for `b.cond` (cond in bits 0..3) we use 0xC1
    # via `_AARCH64_CONDITIONAL_KEEP_MASKS` to preserve the condition code.
    #
    # Mnemonics not in this table have no fixed-position immediate field that we
    # can wildcard without losing entropy, so they are returned as raw bytes
    # (matching the OLD `escapeBinary` for register-only instructions).
    _AARCH64_IMMEDIATE_KEEP_MASKS = {
        "adrp": 0xC1,
        "adr": 0xC1,
        "b": 0xC0,  # imm26 covers nibble 0 -> wildcard it for position-invariance
        "bl": 0xC0,
        "cbz": 0xC1,
        "cbnz": 0xC1,
        "tbz": 0xC1,
        "tbnz": 0xC1,
        "ldr": 0xC1,
        "ldrsw": 0xC1,
        "str": 0xC1,
        "ldp": 0xC1,
        "stp": 0xC1,
        "ldur": 0xC1,
        "stur": 0xC1,
        "ldrb": 0xC1,
        "ldrh": 0xC1,
        "ldrsb": 0xC1,
        "ldrsh": 0xC1,
        "strb": 0xC1,
        "strh": 0xC1,
        "ldnp": 0xC1,
        "stnp": 0xC1,
        "ldpsw": 0xC1,
        "add": 0xC1,
        "sub": 0xC1,
        "adds": 0xC1,
        "subs": 0xC1,
        "movz": 0xC1,
        "movk": 0xC1,
        "movn": 0xC1,
        "mov": 0xC1,
    }

    # Mnemonic prefix -> keep-mask for conditional variants: b.cond and FEAT_HBC's
    # hinted bc.cond share the same imm19 branch-offset layout (differing only in
    # bit 4), so both get the same keep-mask. Other conditional mnemonics use their
    # base entry.
    _AARCH64_CONDITIONAL_KEEP_MASKS = {
        "b.": 0xC1,
        "bc.": 0xC1,
    }

    @staticmethod
    def _baseMnemonic(mnemonic):
        """Strip condition codes (e.g. 'b.eq' -> 'b') for table lookup."""
        return mnemonic.split(".")[0]

    @classmethod
    def _keepMaskFor(cls, mnemonic):
        """Look up the keep-mask for `mnemonic`. Tries the full mnemonic
        first (so that special entries like 'b.cond' are picked up), then
        conditional prefixes (e.g. 'b.' for 'b.eq' / 'b.ne' / ...), then
        the base mnemonic (so that 'b.eq' resolves via 'b' when no cond
        special case applies).
        """
        if mnemonic in _KEEP_MASK_MEMO:
            return _KEEP_MASK_MEMO[mnemonic]
        keep = cls._AARCH64_IMMEDIATE_KEEP_MASKS.get(mnemonic)
        if keep is None:
            for prefix, mask in cls._AARCH64_CONDITIONAL_KEEP_MASKS.items():
                if mnemonic.startswith(prefix):
                    keep = mask
                    break
            else:
                keep = cls._AARCH64_IMMEDIATE_KEEP_MASKS.get(cls._baseMnemonic(mnemonic))
        # pure function of a short mnemonic drawn from a bounded vocabulary
        _KEEP_MASK_MEMO[mnemonic] = keep
        return keep

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
        # aarch64 has only one branch encoding (4 bytes, imm26/imm19/imm14),
        # so the intel-style `escape_intraprocedural_jumps` distinction has no
        # additional effect here; we accept the parameter for API compatibility
        # with the intel escaper but do not use it.
        del escape_intraprocedural_jumps
        # Similarly, aarch64's escape is position-based (per-mnemonic bit
        # layout) rather than operand-text based, so the address bounds
        # `lower_addr` / `upper_addr` are unused.
        del lower_addr, upper_addr
        if len(ins.bytes) != 8:
            return ins.bytes
        # Only instructions with an *immediate* operand are eligible for
        # wildcarding. Register-form operations (e.g. `add x0, x0, x0`,
        # `mov x0, x1` as an alias of `orr`) must keep their raw bytes to
        # avoid losing hash signal.
        if not AArch64InstructionEscaper._hasImmediateOperand(ins):
            return ins.bytes
        keep_mask = AArch64InstructionEscaper._keepMaskFor(ins.mnemonic)
        if keep_mask is None:
            return ins.bytes
        word = int.from_bytes(bytes.fromhex(ins.bytes), "little")
        return AArch64InstructionEscaper._wordWithNibbleKeepMaskToHex(word, keep_mask)
