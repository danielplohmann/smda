#!/usr/bin/env python3
import logging

from dncil.cil.opcode import OpCode, OpCodes, OperandType

LOGGER = logging.getLogger(__name__)

# Build operand-type lookup from dncil (the actual decoder) so token/branch
# escaping stays synchronized with the opcode table.
_OPERAND_TYPE_BY_MNEMONIC = {}
for attr in dir(OpCodes):
    if not attr.startswith("_"):
        opcode = getattr(OpCodes, attr)
        if isinstance(opcode, OpCode):
            _OPERAND_TYPE_BY_MNEMONIC[opcode.name] = opcode.operand_type

# Operand types whose byte-level operand is a 4-byte metadata token (table kind
# in the last byte, RID in the previous three) — wildcard RID, keep table-kind.
_TOKEN_OPERAND_TYPES = frozenset(
    {
        OperandType.InlineField,
        OperandType.InlineMethod,
        OperandType.InlineTok,
        OperandType.InlineType,
        OperandType.InlineString,
        OperandType.InlineSig,
    }
)

# Operand types whose byte-level operand is a code offset (branch target) —
# wildcard entirely when escape_intraprocedural_jumps is set.
_BRANCH_OPERAND_TYPES = frozenset(
    {
        OperandType.InlineBrTarget,
        OperandType.ShortInlineBrTarget,
        OperandType.InlineSwitch,
    }
)


class CilInstructionEscaper:
    _aritlog_group = [
        "add",
        "add.ovf",
        "add.ovf.un",
        "and",
        "div",
        "div.un",
        "mul",
        "mul.ovf",
        "mul.ovf.un",
        "neg",
        "not",
        "or",
        "rem",
        "rem.un",
        "shl",
        "shr",
        "shr.un",
        "sub",
        "sub.ovf",
        "sub.ovf.un",
        "xor",
    ]

    _cfg_group = [
        # branching
        "beq",
        "beq.s",
        "bge",
        "bge.s",
        "bge.un",
        "bge.un.s",
        "bgt",
        "bgt.s",
        "bgt.un",
        "bgt.un.s",
        "ble",
        "ble.s",
        "ble.un",
        "ble.un.s",
        "blt",
        "blt.s",
        "blt.un",
        "blt.un.s",
        "bne.un",
        "bne.un.s",
        "br",
        "br.s",
        "brfalse",
        "brfalse.s",
        "brinst",
        "brinst.s",
        "brnull",
        "brnull.s",
        "brtrue",
        "brtrue.s",
        "brzero",
        "brzero.s",
        "jmp",
        "ret",
        "switch",
        # Exception handling control flow
        "leave",
        "leave.s",
        "throw",
        "rethrow",
        "endfilter",
        "endfault",
        "endfinally",
        # Calls
        "call",
        "calli",
        "callvirt",
        "newobj",
        # Comparisons
        "ceq",
        "cgt",
        "cgt.un",
        "clt",
        "clt.un",
        "ckfinite",
    ]

    _mem_group = [
        "ldarga",
        "ldarga.s",
        "starg",
        "starg.s",
        "stelem",
        "stelem.i",
        "stelem.i1",
        "stelem.i2",
        "stelem.i4",
        "stelem.i8",
        "stelem.ref",
        "stind.i",
        "stind.i1",
        "stind.i2",
        "stind.i4",
        "stind.i8",
        "stind.ref",
        "stfld",
        "stobj",
        "stsfld",
        # copy
        "cpblk",
        "cpobj",
        "initblk",
        "initobj",
        "localloc",
        "ldtoken",
        # allocation
        "newarr",
        # special
        "arglist",
    ]

    _stack_group = [
        "dup",
        "pop",
        "ldarg",
        "ldarg.0",
        "ldarg.1",
        "ldarg.2",
        "ldarg.3",
        "ldarg.s",
        "ldelem",
        "ldelem.i",
        "ldelem.i1",
        "ldelem.i2",
        "ldelem.i4",
        "ldelem.i8",
        "ldelem.ref",
        "ldelem.u1",
        "ldelem.u2",
        "ldelem.u4",
        "ldelem.u8",
        "ldelema",
        "ldfld",
        "ldflda",
        "ldlen",
        "ldobj",
        "ldsfld",
        "ldsflda",
        "ldstr",
        # Stack operations moved from mem_group
        "ldc.i4",
        "ldc.i4.0",
        "ldc.i4.1",
        "ldc.i4.2",
        "ldc.i4.3",
        "ldc.i4.4",
        "ldc.i4.5",
        "ldc.i4.6",
        "ldc.i4.7",
        "ldc.i4.8",
        "ldc.i4.m1",
        "ldc.i4.M1",
        "ldc.i4.s",
        "ldc.i8",
        "ldind.i",
        "ldind.i1",
        "ldind.i2",
        "ldind.i4",
        "ldind.i8",
        "ldind.ref",
        "ldind.u1",
        "ldind.u2",
        "ldind.u4",
        "ldind.u8",
        "ldloc",
        "ldloc.0",
        "ldloc.1",
        "ldloc.2",
        "ldloc.3",
        "ldloc.s",
        "ldloca",
        "ldloca.s",
        "ldnull",
        "stloc",
        "stloc.0",
        "stloc.1",
        "stloc.2",
        "stloc.3",
        "stloc.s",
        # Box/Unbox operations
        "box",
        "unbox",
        "unbox.any",
        # Function pointer to stack
        "ldftn",
        "ldvirtftn",
        # Type test / cast
        "castclass",
        "isinst",
        # Typed reference operations
        "mkrefany",
        "refanytype",
        "refanyval",
        # Sizeof pushes constant
        "sizeof",
        # Conversion operations (all work with stack)
        "conv.i",
        "conv.i1",
        "conv.i2",
        "conv.i4",
        "conv.i8",
        "conv.ovf.i",
        "conv.ovf.i.un",
        "conv.ovf.i1",
        "conv.ovf.i1.un",
        "conv.ovf.i2",
        "conv.ovf.i2.un",
        "conv.ovf.i4",
        "conv.ovf.i4.un",
        "conv.ovf.i8",
        "conv.ovf.i8.un",
        "conv.ovf.u",
        "conv.ovf.u.un",
        "conv.ovf.u1",
        "conv.ovf.u1.un",
        "conv.ovf.u2",
        "conv.ovf.u2.un",
        "conv.ovf.u4",
        "conv.ovf.u4.un",
        "conv.ovf.u8",
        "conv.ovf.u8.un",
        "conv.r.un",
        "conv.u",
        "conv.u1",
        "conv.u2",
        "conv.u4",
        "conv.u8",
    ]

    _prefix_group = [
        "constrained.",
        "readonly.",
        "unaligned.",
        "volatile.",
        "no.",
        "tail.",
    ]

    _reserved_group = [
        "UNKNOWN1",
        "UNKNOWN2",
        "prefix1",
        "prefix2",
        "prefix3",
        "prefix4",
        "prefix5",
        "prefix6",
        "prefix7",
        "prefixref",
    ]

    _privileged_group = ["break"]

    _crypto_group = []

    _float_group = [
        # while also stack instructions, float identity is more important for characteristics
        "stelem.r4",
        "stelem.r8",
        "stind.r4",
        "stind.r8",
        "ldelem.r4",
        "ldelem.r8",
        "ldc.r4",
        "ldc.r8",
        "ldind.r4",
        "ldind.r8",
        "conv.r4",
        "conv.r8",
    ]

    _nop_group = ["nop"]

    _xmm_group = []
    _vm_group = []

    _registers = []
    _segment_registers = []
    _extended_registers = []
    _control_registers = []

    @staticmethod
    def escapeMnemonic(mnemonic):
        mnemonic = mnemonic.split(" ")[-1]
        if mnemonic in CilInstructionEscaper._aritlog_group:
            return "A"
        elif mnemonic in CilInstructionEscaper._cfg_group:
            return "C"
        elif mnemonic in CilInstructionEscaper._mem_group:
            return "M"
        elif mnemonic in CilInstructionEscaper._stack_group:
            return "S"
        elif mnemonic in CilInstructionEscaper._prefix_group:
            return "N"
        elif mnemonic in CilInstructionEscaper._privileged_group:
            return "P"
        elif mnemonic in CilInstructionEscaper._crypto_group:
            return "Y"
        elif mnemonic in CilInstructionEscaper._float_group:
            return "F"
        elif mnemonic in CilInstructionEscaper._xmm_group:
            return "X"
        elif mnemonic in CilInstructionEscaper._vm_group:
            return "V"
        elif mnemonic in CilInstructionEscaper._nop_group:
            return "N"
        elif mnemonic in CilInstructionEscaper._reserved_group or mnemonic == "error":
            return "U"
        else:
            LOGGER.error(
                "********************************************** Unhandled mnemonic: %s",
                mnemonic,
            )
            return "U"

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        escaped_field = ""
        if op_field == "":
            return ""
        if escape_registers:
            pass
        if escape_pointers and not (op_field.startswith(("-", "0"))):
            escaped_field = "PTR"
        if escape_constants:
            try:
                int(op_field)
                escaped_field = "CONST"
            except ValueError:
                pass
            try:
                int(op_field, 16)
                escaped_field = "CONST"
            except ValueError:
                pass
            if ":" in op_field:
                escaped_field = "CONST"
        if not escaped_field:
            escaped_field = op_field
        return escaped_field

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        if offsets_only:
            op_type = _OPERAND_TYPE_BY_MNEMONIC.get(ins.mnemonic)
            if op_type in (
                OperandType.InlineBrTarget,
                OperandType.ShortInlineBrTarget,
                OperandType.InlineSwitch,
                OperandType.InlineMethod,
                OperandType.InlineSig,
            ):
                return "OFFSET"
        opstring = ins.operands
        op_fields = opstring.split(",")
        esc_regs = True
        esc_consts = True
        escaped_fields = []
        for op_field in op_fields:
            escaped_fields.append(
                CilInstructionEscaper.escapeField(op_field, escape_registers=esc_regs, escape_constants=esc_consts)
            )
        return ", ".join(escaped_fields)

    @staticmethod
    def escapeToOpcodeOnly(ins):
        opcode_length = 2 if ins.bytes.startswith("fe") else 1
        return ins.bytes[: opcode_length * 2] + "?" * (len(ins.bytes) - opcode_length * 2)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        op_type = _OPERAND_TYPE_BY_MNEMONIC.get(ins.mnemonic, OperandType.InlineNone)
        if op_type in _TOKEN_OPERAND_TYPES:
            return CilInstructionEscaper._escapeTokenBinary(ins)
        if op_type in _BRANCH_OPERAND_TYPES:
            if escape_intraprocedural_jumps:
                return CilInstructionEscaper.escapeToOpcodeOnly(ins)
            return ins.bytes
        return ins.bytes

    @staticmethod
    def _escapeTokenBinary(ins):
        bytes_str = ins.bytes
        opcode_hex_len = 4 if bytes_str.startswith("fe") else 2
        min_hex_len = opcode_hex_len + 8
        if len(bytes_str) >= min_hex_len:
            wildcard_len = len(bytes_str) - opcode_hex_len - 2
            return bytes_str[:opcode_hex_len] + "?" * wildcard_len + bytes_str[-2:]
        return bytes_str

    @staticmethod
    def escapeBinaryJumpCall(ins, escape_intraprocedural_jumps=False):
        return CilInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=escape_intraprocedural_jumps)

    @staticmethod
    def escapeBinaryPtrRef(ins):
        return ins.bytes

    @staticmethod
    def escapeBinaryValue(ins, escaped_sequence, value):
        return CilInstructionEscaper.escapeToOpcodeOnly(ins)

    @staticmethod
    def getByteWithoutPrefixes(ins_bytes):
        return ins_bytes
