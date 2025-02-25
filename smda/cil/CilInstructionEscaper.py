#!/usr/bin/env python3
import logging
import re
import struct
import codecs

def occurrences(string, sub):
    # https://stackoverflow.com/a/2970542
    count = start = 0
    while True:
        start = string.find(sub, start) + 1
        if start > 0:
            count += 1
        else:
            return count

LOGGER = logging.getLogger(__name__)


class CilInstructionEscaper:
    """ 
    Escaper to abstract information from disassembled instructions. 
    Based on https://en.wikipedia.org/wiki/List_of_CIL_instructions
    """

    _aritlog_group = [
        "add", "add.ovf", "add.ovf.un", "and", "div", "div.un", "mul", "mul.ovf", 
        "mul.ovf.un", "neg", "not", "or", "rem", "rem.un", "shl", "shr", "shr.un", "xor"
    ]
    
    _cfg_group = [
        # branching
        "beq", "beq.s", "bge", "bge.s", "bge.un", "bge.un.s", "bgt", "bgt.s", "bgt.un", 
        "bgt.un.s", "ble", "ble.s", "ble.un", "ble.un.s", "blt", "blt.s", "blt.un", 
        "blt.un.s", "bne.un", "bne.un.s", "br", "br.s", "brfalse", "brfalse.s", 
        "brinst", "brinst.s", "brnull", "brnull.s", "brtrue", "brtrue.s", "brzero", 
        "brzero.s", "jmp", "ret", "switch",
        # Exception handling control flow
        "leave", "leave.s", "throw", "rethrow", "endfilter", "endfault", "endfinally",
        # Calls
        "call", "calli", "callvirt", 
        # Comparisons
        "ceq", "cgt", "cgt.un", "clt", "clt.un", "ckfinite"
    ]
    
    _mem_group = [
        "ldarga", 
        "ldarga.s", "starg", "starg.s", 
        "stelem", "stelem.i", "stelem.i1", "stelem.i2", "stelem.i4", "stelem.i8", 
        "stelem.ref", 
        "stind.i", "stind.i1", "stind.i2", "stind.i4", "stind.i8", 
        "stind.ref", 
        "stfld", "stobj", "stsfld",
        # copy
        "cpblk", "initblk", "initobj", "localloc", "ldtoken",
        # special 
        "arglist"
    ]
    
    _stack_group = [
        "dup", "pop",
        "ldarg", "ldarg.0", "ldarg.1", "ldarg.2", "ldarg.3", "ldarg.s", 
        "ldelem", "ldelem.i", "ldelem.i1", "ldelem.i2", "ldelem.i4", 
        "ldelem.i8", "ldelem.ref", "ldelem.u1", "ldelem.u2", 
        "ldelem.u4", "ldelem.u8", "ldelema", "ldfld", "ldflda", "ldlen", "ldobj", 
        "ldsfld", "ldsflda", "ldstr", 
        # Stack operations moved from mem_group
        "ldc.i4", "ldc.i4.0", "ldc.i4.1", "ldc.i4.2", "ldc.i4.3", "ldc.i4.4",
        "ldc.i4.5", "ldc.i4.6", "ldc.i4.7", "ldc.i4.8", "ldc.i4.m1", "ldc.i4.M1", 
        "ldc.i4.s", "ldc.i8", 
        "ldind.i", "ldind.i1", "ldind.i2", "ldind.i4", "ldind.i8", 
        "ldind.ref", "ldind.u1", "ldind.u2", "ldind.u4", "ldind.u8",
        "ldloc", "ldloc.0", "ldloc.1", "ldloc.2", "ldloc.3", "ldloc.s", "ldloca", 
        "ldloca.s", "ldnull",
        "stloc", "stloc.0", "stloc.1", "stloc.2", "stloc.3", "stloc.s",
        # Box/Unbox operations
        "box", "unbox", "unbox.any",
        # Function pointer to stack
        "ldftn", "ldvirtftn",
        # Conversion operations (all work with stack)
        "conv.i", "conv.i1", "conv.i2", "conv.i4", "conv.i8",
        "conv.ovf.i", "conv.ovf.i1", "conv.ovf.i2", "conv.ovf.i4", "conv.ovf.i8",
        "conv.ovf.u", "conv.ovf.u1", "conv.ovf.u2", "conv.ovf.u4", "conv.ovf.u8",
        "conv.r.un", 
        "conv.u", "conv.u1", "conv.u2", "conv.u4", "conv.u8"
    ]
    
    _prefix_group = [
        "constrained.", "readonly.", "unaligned.", "volatile.",
        "no.typecheck", "no.rangecheck", "no.nullcheck", "tail",
    ]

    _privileged_group = [
        "break"
    ]

    _crypto_group = [
        ]

    _float_group = [
        # while also stack instructions, float identity is more important for characteristics
        "stelem.r4", "stelem.r8", 
        "stind.r4", "stind.r8",
        "ldelem.r4", "ldelem.r8", 
        "ldc.r4", "ldc.r8",
        "ldind.r4", "ldind.r8",
        "conv.r4", "conv.r8",
    ]

    _nop_group = [
        "nop"
    ]

    _xmm_group = [
    ]
    _vm_group = [
    ]

    _registers = [
    ]
    _segment_registers = [
    ]
    _extended_registers = [
    ]
    _control_registers = [
    ]

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
        elif mnemonic == "error":
            return "U"
        else:
            LOGGER.error("********************************************** Unhandled mnemonic: %s", mnemonic)
            return "U"
        return mnemonic

    @staticmethod
    def escapeField(op_field, escape_registers=True, escape_pointers=True, escape_constants=True):
        op_field = op_field.strip()
        escaped_field = ""
        if op_field == "":
            return ""
        if escape_registers:
            # there are no registers in CIL, it is a stack-based machine
            pass
        if escape_pointers:
            # if we do not have an immediate, we assume it is a pointer
            if not (op_field.startswith("-")
                    or op_field.startswith("0")
                    ):
                escaped_field = "PTR"
        if escape_constants:
            try:
                op_as_int = int(op_field)
                escaped_field = "CONST"
            except:
                pass
            try:
                op_as_int = int(op_field, 16)
                escaped_field = "CONST"
            except:
                pass
            if ":" in op_field:
                escaped_field = "CONST"
        if not escaped_field:
            escaped_field = op_field
        return escaped_field

    @staticmethod
    def escapeOperands(ins, offsets_only=False):
        opstring = ins.operands
        op_fields = opstring.split(",")
        esc_regs = True
        esc_consts = True
        if offsets_only:
            if ins.mnemonic in CilInstructionEscaper._cfg_group and ins.mnemonic not in [
                    "ceq", "cgt", "cgt.un", "clt", "clt.un", "ckfinite"]:
                return "OFFSET"
            esc_regs = False
            esc_consts = False
        escaped_fields = []
        for op_field in op_fields:
            escaped_fields.append(CilInstructionEscaper.escapeField(op_field, escape_registers=esc_regs, escape_constants=esc_consts))
        return ", ".join(escaped_fields)

    @staticmethod
    def escapeToOpcodeOnly(ins):
        opcode_length = 2 if ins.bytes.startswith("fe") else 1
        return ins.bytes[:opcode_length*2] + "?" * (len(ins.bytes) - opcode_length*2)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        escaped_sequence = ins.bytes
        if ins.mnemonic in CilInstructionEscaper._cfg_group and ins.mnemonic not in ["ceq", "cgt", "cgt.un", "clt", "clt.un", "ckfinite"]:
            escaped_sequence = CilInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if ins.mnemonic in ["newobj", "ldobj", "stobj", "newarr", "stsfld", "stfld", "ldsfld", "ldfld", "ldflda", "box", "unbox", "unbox.any", "isinst", "castclass", "ldtoken"]:
            escaped_sequence = ins.bytes[:2] + "?" * (len(ins.bytes) - 4) + ins.bytes[-2:]
            return escaped_sequence
        if ins.mnemonic in ["initobj", "ldftn", "constrained."]:
            escaped_sequence = ins.bytes[:4] + "?" * (len(ins.bytes) - 6) + ins.bytes[-2:]
            return escaped_sequence
        if False:
            # 20250211 - we don't know yet how allocations look like in CIL, so we leave this out for now
            escaped_sequence = CilInstructionEscaper.escapeBinaryPtrRef(ins)
        if ins.operands.startswith("0x") or ins.operands.startswith("-"):
            # 20250211 - when comparing with Intel, we onl want to wildcard addresses within our range - should we not wildcard at all here?
            pass
            # escaped_sequence = CilInstructionEscaper.escapeBinaryValue(ins, escaped_sequence, None)
        return escaped_sequence

    @staticmethod
    def escapeBinaryJumpCall(ins, escape_intraprocedural_jumps=False):
        escaped_sequence = ins.bytes
        if ins.mnemonic in CilInstructionEscaper._cfg_group and ins.mnemonic not in ["ceq", "cgt", "cgt.un", "clt", "clt.un", "ckfinite"]:
            if escape_intraprocedural_jumps and ins.mnemonic in [
                    "beq", "beq.s", "bge", "bge.s", "bge.un", "bge.un.s", "bgt", "bgt.s", "bgt.un", 
                    "bgt.un.s", "ble", "ble.s", "ble.un", "ble.un.s", "blt", "blt.s", "blt.un", 
                    "blt.un.s", "bne.un", "bne.un.s", "br", "br.s", "brfalse", "brfalse.s", 
                    "brinst", "brinst.s", "brnull", "brnull.s", "brtrue", "brtrue.s", "brzero", "switch"]:
                escaped_sequence = CilInstructionEscaper.escapeToOpcodeOnly(ins)
            elif ins.mnemonic in ["jmp", "call", "calli", "callvirt"]:
                escaped_sequence = ins.bytes[:2] + "?" * (len(ins.bytes) - 4) + ins.bytes[-2:]
        return escaped_sequence

    @staticmethod
    def escapeBinaryPtrRef(ins):
        escaped_sequence = ins.bytes
        return escaped_sequence

    @staticmethod
    def escapeBinaryValue(ins, escaped_sequence, value):
        return CilInstructionEscaper.escapeToOpcodeOnly(ins)

    @staticmethod
    def getByteWithoutPrefixes(ins_bytes):
        # if I understand correctly, there are only prefix instructions and not prefix bytes within instructions
        return ins_bytes
