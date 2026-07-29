#!/usr/bin/env python3
import logging
import re

from smda.dalvik.DalvikOpcodeDecoder import OPCODES

LOGGER = logging.getLogger(__name__)

# Split invoke register lists without breaking "{v0, v1}, Lfoo;->m()V"
_OPERAND_SPLIT = re.compile(r",\s*(?![^{]*\})")


class DalvikInstructionEscaper:
    """
    Escape Dalvik instruction bytes for PIC/opc hashing.

    Pool indices (string/type/field/method/proto/call_site/method_handle) and
    immediates/branch offsets shift across recompile/repack; the opcode and
    register layout are the stable signature. Format masks follow AOSP
    instruction-formats / dalvik-bytecode layouts (little-endian code units).

    Note: switch/array *payloads* are data and never enter SmdaFunction.blocks,
    so PicHash only sees the masked 31t reference — two methods that differ
    only in case-table contents can collide by design.
    """

    _aritlog_group = {
        "neg-int",
        "not-int",
        "neg-long",
        "not-long",
        "neg-float",
        "neg-double",
        "int-to-long",
        "int-to-float",
        "int-to-double",
        "long-to-int",
        "long-to-float",
        "long-to-double",
        "float-to-int",
        "float-to-long",
        "float-to-double",
        "double-to-int",
        "double-to-long",
        "double-to-float",
        "int-to-byte",
        "int-to-char",
        "int-to-short",
        "add-int",
        "sub-int",
        "mul-int",
        "div-int",
        "rem-int",
        "and-int",
        "or-int",
        "xor-int",
        "shl-int",
        "shr-int",
        "ushr-int",
        "add-long",
        "sub-long",
        "mul-long",
        "div-long",
        "rem-long",
        "and-long",
        "or-long",
        "xor-long",
        "shl-long",
        "shr-long",
        "ushr-long",
        "add-float",
        "sub-float",
        "mul-float",
        "div-float",
        "rem-float",
        "add-double",
        "sub-double",
        "mul-double",
        "div-double",
        "rem-double",
        "add-int/2addr",
        "sub-int/2addr",
        "mul-int/2addr",
        "div-int/2addr",
        "rem-int/2addr",
        "and-int/2addr",
        "or-int/2addr",
        "xor-int/2addr",
        "shl-int/2addr",
        "shr-int/2addr",
        "ushr-int/2addr",
        "add-long/2addr",
        "sub-long/2addr",
        "mul-long/2addr",
        "div-long/2addr",
        "rem-long/2addr",
        "and-long/2addr",
        "or-long/2addr",
        "xor-long/2addr",
        "shl-long/2addr",
        "shr-long/2addr",
        "ushr-long/2addr",
        "add-float/2addr",
        "sub-float/2addr",
        "mul-float/2addr",
        "div-float/2addr",
        "rem-float/2addr",
        "add-double/2addr",
        "sub-double/2addr",
        "mul-double/2addr",
        "div-double/2addr",
        "rem-double/2addr",
        "add-int/lit16",
        "rsub-int",
        "mul-int/lit16",
        "div-int/lit16",
        "rem-int/lit16",
        "and-int/lit16",
        "or-int/lit16",
        "xor-int/lit16",
        "add-int/lit8",
        "rsub-int/lit8",
        "mul-int/lit8",
        "div-int/lit8",
        "rem-int/lit8",
        "and-int/lit8",
        "or-int/lit8",
        "xor-int/lit8",
        "shl-int/lit8",
        "shr-int/lit8",
        "ushr-int/lit8",
        "cmpl-float",
        "cmpg-float",
        "cmpl-double",
        "cmpg-double",
        "cmp-long",
    }

    _cfg_group = {
        "return-void",
        "return",
        "return-wide",
        "return-object",
        "throw",
        "goto",
        "goto/16",
        "goto/32",
        "packed-switch",
        "sparse-switch",
        "if-eq",
        "if-ne",
        "if-lt",
        "if-ge",
        "if-gt",
        "if-le",
        "if-eqz",
        "if-nez",
        "if-ltz",
        "if-gez",
        "if-gtz",
        "if-lez",
        "invoke-virtual",
        "invoke-super",
        "invoke-direct",
        "invoke-static",
        "invoke-interface",
        "invoke-virtual/range",
        "invoke-super/range",
        "invoke-direct/range",
        "invoke-static/range",
        "invoke-interface/range",
        "invoke-polymorphic",
        "invoke-polymorphic/range",
        "invoke-custom",
        "invoke-custom/range",
    }

    _mem_group = {
        "array-length",
        "new-instance",
        "new-array",
        "filled-new-array",
        "filled-new-array/range",
        "fill-array-data",
        "aget",
        "aget-wide",
        "aget-object",
        "aget-boolean",
        "aget-byte",
        "aget-char",
        "aget-short",
        "aput",
        "aput-wide",
        "aput-object",
        "aput-boolean",
        "aput-byte",
        "aput-char",
        "aput-short",
        "iget",
        "iget-wide",
        "iget-object",
        "iget-boolean",
        "iget-byte",
        "iget-char",
        "iget-short",
        "iput",
        "iput-wide",
        "iput-object",
        "iput-boolean",
        "iput-byte",
        "iput-char",
        "iput-short",
        "sget",
        "sget-wide",
        "sget-object",
        "sget-boolean",
        "sget-byte",
        "sget-char",
        "sget-short",
        "sput",
        "sput-wide",
        "sput-object",
        "sput-boolean",
        "sput-byte",
        "sput-char",
        "sput-short",
    }

    _stack_group = {
        "move",
        "move/from16",
        "move/16",
        "move-wide",
        "move-wide/from16",
        "move-wide/16",
        "move-object",
        "move-object/from16",
        "move-object/16",
        "move-result",
        "move-result-wide",
        "move-result-object",
        "move-exception",
        "const/4",
        "const/16",
        "const",
        "const/high16",
        "const-wide/16",
        "const-wide/32",
        "const-wide",
        "const-wide/high16",
        "const-string",
        "const-string/jumbo",
        "const-class",
        "const-method-handle",
        "const-method-type",
        "monitor-enter",
        "monitor-exit",
        "check-cast",
        "instance-of",
    }

    _nop_group = {"nop"}
    _privileged_group = set()
    _crypto_group = set()
    # Float/double arithmetic is folded into _aritlog_group (Dalvik has no
    # separate float opcode class for MCRIT identity beyond the mnemonic itself).
    _float_group = set()
    _xmm_group = set()
    _vm_group = set()

    # Byte offsets (0-based) within the instruction to wildcard for PIC hashing.
    # Opcode byte (index 0) is always kept; register layout kept where it does not
    # embed pool indices or immediates.
    _FORMAT_MASK_BYTES = {
        "10x": (),
        "10t": (1,),  # signed branch offset
        "11n": (1,),  # B|A packed: whole-byte mask (cannot keep A without B)
        "11x": (),
        "12x": (),
        "20t": (2, 3),
        "21c": (2, 3),  # pool index
        "21h": (2, 3),  # high16 literal
        "21s": (2, 3),  # lit16
        "21t": (2, 3),  # branch
        "22b": (3,),  # lit8 (byte 2 is reg_b, kept)
        "22c": (2, 3),  # pool index
        "22s": (2, 3),  # lit16
        "22t": (2, 3),  # branch
        "22x": (),
        "23x": (),
        "30t": (2, 3, 4, 5),
        "31c": (2, 3, 4, 5),  # string jumbo index
        "31i": (2, 3, 4, 5),  # lit32
        "31t": (2, 3, 4, 5),  # payload offset (payload data not in block stream)
        "32x": (),
        "35c": (2, 3),  # method/type/call_site index
        "3rc": (2, 3),  # method/type/call_site index
        "45cc": (2, 3, 6, 7),  # method + proto
        "4rcc": (2, 3, 6, 7),
        "51l": (2, 3, 4, 5, 6, 7, 8, 9),  # lit64
    }

    @staticmethod
    def escapeMnemonic(mnemonic):
        mnemonic = mnemonic.split(" ")[-1]
        if mnemonic in DalvikInstructionEscaper._aritlog_group:
            return "A"
        if mnemonic in DalvikInstructionEscaper._cfg_group:
            return "C"
        if mnemonic in DalvikInstructionEscaper._mem_group:
            return "M"
        if mnemonic in DalvikInstructionEscaper._stack_group:
            return "S"
        if mnemonic in DalvikInstructionEscaper._privileged_group:
            return "P"
        if mnemonic in DalvikInstructionEscaper._crypto_group:
            return "Y"
        if mnemonic in DalvikInstructionEscaper._float_group:
            return "F"
        if mnemonic in DalvikInstructionEscaper._xmm_group:
            return "X"
        if mnemonic in DalvikInstructionEscaper._vm_group:
            return "V"
        if mnemonic in DalvikInstructionEscaper._nop_group:
            return "N"
        if mnemonic == "error":
            return "U"
        # Surface coverage gaps at warning so CI/verbose runs notice new opcodes.
        LOGGER.warning("Unhandled Dalvik mnemonic for group escape: %s", mnemonic)
        return "U"

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        if not op_field:
            return ""
        # Strip braces from register-list tokens produced by split edge cases.
        bare = op_field.strip("{}").strip()
        if escape_registers and bare.startswith("v") and bare[1:].isdigit():
            return "REG"
        if escape_constants and (bare.startswith(("#", "0x", "+", "-")) or bare[:1].isdigit()):
            return "CONST"
        if (escape_pointers or escape_constants) and (
            "->" in bare
            or bare.startswith(
                (
                    '"',
                    "L",
                    "(",
                    "string@",
                    "type@",
                    "field@",
                    "method@",
                    "proto@",
                    "call_site@",
                    "method_handle@",
                    "payload@",
                )
            )
        ):
            return "PTR"
        return op_field

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        opstring = ins.operands or ""
        if offsets_only:
            if ins.mnemonic in DalvikInstructionEscaper._cfg_group:
                return "OFFSET"
            return opstring
        # Keep "{v0, v1}" as one field, then split the rest.
        fields = _OPERAND_SPLIT.split(opstring)
        escaped = []
        for field in fields:
            field = field.strip()
            if field.startswith("{") and field.endswith("}"):
                inner = field[1:-1].strip()
                if not inner:
                    escaped.append("{}")
                    continue
                regs = [DalvikInstructionEscaper.escapeField(p.strip()) for p in inner.split(",")]
                escaped.append("{" + ", ".join(regs) + "}")
            else:
                escaped.append(DalvikInstructionEscaper.escapeField(field))
        return ", ".join(escaped)

    @staticmethod
    def escapeToOpcodeOnly(ins):
        # First code unit low byte is always the opcode (AOSP encoding).
        hex_bytes = ins.bytes or ""
        if len(hex_bytes) < 2:
            return hex_bytes
        return hex_bytes[:2] + "?" * (len(hex_bytes) - 2)

    @staticmethod
    def _maskHexBytes(hex_bytes, mask_byte_indices):
        if not hex_bytes or not mask_byte_indices:
            return hex_bytes
        chars = list(hex_bytes)
        for byte_index in mask_byte_indices:
            start = byte_index * 2
            end = start + 2
            if end <= len(chars):
                chars[start:end] = ["?", "?"]
        return "".join(chars)

    @staticmethod
    def _formatForInstruction(ins):
        hex_bytes = ins.bytes or ""
        if len(hex_bytes) < 2:
            return None
        try:
            opcode = int(hex_bytes[:2], 16)
        except ValueError:
            return None
        spec = OPCODES.get(opcode)
        return spec.fmt if spec else None

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        del lower_addr, upper_addr  # Dalvik has no absolute image addresses in opcodes
        hex_bytes = ins.bytes or ""
        fmt = DalvikInstructionEscaper._formatForInstruction(ins)
        if fmt is None:
            return DalvikInstructionEscaper.escapeToOpcodeOnly(ins)

        if fmt not in DalvikInstructionEscaper._FORMAT_MASK_BYTES:
            # Unknown format for a known opcode — fail soft to opcode-only.
            LOGGER.warning("Dalvik escapeBinary: no mask for format %s", fmt)
            return DalvikInstructionEscaper.escapeToOpcodeOnly(ins)

        # The format mask always covers branch offsets, pool indices and immediates.
        # escape_intraprocedural_jumps used to CLEAR the mask for the branch-only formats
        # (10t/20t/21t/22t/30t), which inverted the flag's meaning relative to every other
        # backend: in Intel and CIL the flag *wildcards* an intra-procedural branch
        # displacement, so the PIC hash stays position-independent. Retaining the raw
        # signed offset meant two structurally identical methods whose branch deltas
        # differed only because an earlier instruction had a different width (const/4 vs
        # const/16) produced different pic_hash values, defeating PIC matching for every
        # branching Dalvik method.
        del escape_intraprocedural_jumps
        mask = list(DalvikInstructionEscaper._FORMAT_MASK_BYTES[fmt])

        return DalvikInstructionEscaper._maskHexBytes(hex_bytes, mask)

    @staticmethod
    def escapeBinaryJumpCall(ins, escape_intraprocedural_jumps=False):
        return DalvikInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=escape_intraprocedural_jumps)

    @staticmethod
    def escapeBinaryPtrRef(ins):
        return DalvikInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)

    @staticmethod
    def escapeBinaryValue(ins, escaped_sequence, value):
        del value
        return DalvikInstructionEscaper.escapeToOpcodeOnly(ins)

    @staticmethod
    def getByteWithoutPrefixes(ins_bytes):
        return ins_bytes
