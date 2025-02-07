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
    """ Escaper to abstract information from disassembled instructions. Based on https://en.wikipedia.org/wiki/List_of_CIL_instructions
    """

    _aritlog_group = [
    ]
    _cfg_group = [
    ]
    _mem_group = [
    ]
    _stack_group = [
    ]
    # unused, for completeness
    _prefix_group = [
    ]
    _privileged_group = [
    ]
    _crypto_group = [
        ]

    _float_group = [
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
            if op_field in CilInstructionEscaper._registers:
                escaped_field = "REG"
            elif op_field in CilInstructionEscaper._segment_registers:
                escaped_field = "SREG"
            elif op_field in CilInstructionEscaper._extended_registers:
                escaped_field = "XREG"
            elif re.search("zmm[0-9]+", op_field):
                escaped_field = "XREG"
            elif op_field in CilInstructionEscaper._control_registers:
                escaped_field = "CREG"
            elif op_field.startswith("st"):
                escaped_field = "FREG"
            elif op_field.startswith("mm"):
                escaped_field = "MMREG"
        if escape_pointers:
            if (op_field.startswith("xmmword ptr")
                    or op_field.startswith("ymmword ptr")
                    or op_field.startswith("zmmword ptr")
                    or op_field.startswith("xword ptr")
                    or op_field.startswith("tbyte ptr")
                    or op_field.startswith("qword ptr")
                    or op_field.startswith("dword ptr")
                    or op_field.startswith("word ptr")
                    or op_field.startswith("byte ptr")
                    or op_field.startswith("ptr")
                    or op_field.startswith("[")):
                escaped_field = "PTR"
        if escape_constants:
            # potentially include specific constants as extension to CONST
            try:
                op_as_int = int(op_field)
                # if op_as_int in [0, 1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0xFF, 0xFFFFFFFF, -1]:
                #     escaped_field += "_%d" % op_as_int
                escaped_field = "CONST"
            except:
                pass
            try:
                op_as_int = int(op_field, 16)
                # if op_as_int in [0, 1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0xFF, 0xFFFFFFFF, -1]:
                #     escaped_field += "_%d" % op_as_int
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
            if ins.mnemonic in [
                    "call", "lcall", "jmp", "ljmp",
                    "je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
                    "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz",
                    "loop", "loopne", "loope"]:
                return "OFFSET"
            esc_regs = False
            esc_consts = False
        escaped_fields = []
        for op_field in op_fields:
            escaped_fields.append(CilInstructionEscaper.escapeField(op_field, escape_registers=esc_regs, escape_constants=esc_consts))
        return ", ".join(escaped_fields)

    @staticmethod
    def escapeToOpcodeOnly(ins_bytes):
        opcode_length = 2 if ins_bytes.startswith("fe") else 1
        return ins_bytes[:opcode_length*2] + "?" * (len(ins_bytes) - opcode_length*2)

    @staticmethod
    def escapeBinary(ins, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        escaped_sequence = ins.bytes
        # remove segment, operand, address, repeat override prefixes
        if ins.mnemonic in [
                "call", "lcall", "jmp", "ljmp",
                "loop", "loopne", "loope"]:
            escaped_sequence = CilInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if ins.mnemonic in [
                "je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
                "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz"]:
            escaped_sequence = CilInstructionEscaper.escapeBinaryJumpCall(ins, escape_intraprocedural_jumps)
            return escaped_sequence
        if "ptr [0x" in ins.operands or "[rip + 0x" in ins.operands or "[rip - 0x" in ins.operands:
            escaped_sequence = CilInstructionEscaper.escapeBinaryPtrRef(ins)
        if lower_addr is not None and upper_addr is not None and (ins.operands.startswith("0x") or ", 0x" in ins.operands or "+ 0x" in ins.operands or "- 0x" in ins.operands):
            immediates = []
            for immediate_match in re.finditer(r"0x[0-9a-fA-F]{1,8}", ins.operands):
                immediate = int(immediate_match.group()[2:], 16)
                if lower_addr > 0x00100000 and lower_addr <= immediate < upper_addr:
                    immediates.append(immediate)
                    escaped_sequence = CilInstructionEscaper.escapeBinaryValue(ins, escaped_sequence, immediate)
        return escaped_sequence

    @staticmethod
    def escapeBinaryJumpCall(ins, escape_intraprocedural_jumps=False):
        clean_bytes = CilInstructionEscaper.getByteWithoutPrefixes(ins)
        if escape_intraprocedural_jumps and (
                clean_bytes.startswith("7") or
                clean_bytes.startswith("e0") or
                clean_bytes.startswith("e1") or
                clean_bytes.startswith("e2") or
                clean_bytes.startswith("e3") or
                clean_bytes.startswith("eb")):
            return ins.bytes[:-2] + "??"
        if escape_intraprocedural_jumps and clean_bytes.startswith("0f8"):
            return ins.bytes[:-8] + "????????"
        # these should cover most cross-function references and absolute offsets
        if (clean_bytes.startswith("e8") or
                clean_bytes.startswith("e9")):
            return ins.bytes[:-8] + "????????"
        if clean_bytes.startswith("ff"):
            if len(clean_bytes) <= 8:
                # these seem to be all relative or register based instructions and need no escaping
                return ins.bytes
            if (clean_bytes.startswith("ff14") or
                    clean_bytes.startswith("ff15") or
                    clean_bytes.startswith("ff24") or
                    clean_bytes.startswith("ff25") or
                    clean_bytes.startswith("ffaa")):
                    # FF9*: call dword ptr [<reg> + <offset>] - seem all relative in our test data
                return ins.bytes[:-8] + "????????"
        if clean_bytes.startswith("48"):
            if clean_bytes.startswith("48ff61") and len(clean_bytes) == 8:
                # jmp qword/fword ptr [<register> + <offset>]
                # these are definitely found as interprocedurals but might also be intraprocedurals?
                return ins.bytes[:-2] + "??"
            if clean_bytes.startswith("48ff25"):
                # jmp qword ptr [rip + <offset>]
                return ins.bytes[:-8] + "????????"
        if (clean_bytes.startswith("ea") or
                clean_bytes.startswith("9a")):
                # 9A*: lcall dword ptr [<seg> + <offset>]
                # EA*: ljmp dword ptr [<seg> + <offset>]
            return ins.bytes[:-12] + "????????????"
        return ins.bytes

    @staticmethod
    def escapeBinaryPtrRef(ins):
        escaped_sequence = ins.bytes
        addr_match = re.search(r"\[(rip (\+|\-) )?(?P<dword_offset>0x[a-fA-F0-9]+)\]", ins.operands)
        if addr_match:
            offset = int(addr_match.group("dword_offset"), 16)
            if "rip -" in ins.operands:
                offset = 0x100000000 - offset
            #TODO we need to check if this is actually a 64bit absolute offset (e.g. used by movabs)
            try:
                packed_hex = str(codecs.encode(struct.pack("I", offset), 'hex').decode('ascii'))
            except:
                packed_hex = str(codecs.encode(struct.pack("Q", offset), 'hex').decode('ascii'))
            num_occurrences = occurrences(ins.bytes, packed_hex)
            if num_occurrences == 1:
                escaped_sequence = ins.bytes.replace(packed_hex, "????????")
            elif num_occurrences == 2:
                escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
                LOGGER.warning("CilInstructionEscaper.escapeBinaryPtrRef: 2 occurrences for %s in %s (%s %s), escaping only the second one", packed_hex, ins.bytes, ins.mnemonic, ins.operands)
            elif num_occurrences > 2:
                LOGGER.warning("CilInstructionEscaper.escapeBinaryPtrRef: more than 2 occurrences for %s", packed_hex)
        return escaped_sequence

    @staticmethod
    def escapeBinaryValue(ins, escaped_sequence, value):
        packed_hex = str(codecs.encode(struct.pack("I", value), 'hex').decode('ascii'))
        num_occurrences = occurrences(escaped_sequence, packed_hex)
        if num_occurrences == 1:
            escaped_sequence = escaped_sequence.replace(packed_hex, "????????")
        elif num_occurrences == 2:
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            escaped_sequence = "????????".join(escaped_sequence.rsplit(packed_hex, 1))
            LOGGER.warning("CilInstructionEscaper.escapeBinaryValue: 2 occurrences for %s in %s, trying to escape both, if they were non-overlapping", packed_hex, escaped_sequence)
        elif num_occurrences > 2:
            LOGGER.warning("CilInstructionEscaper.escapeBinaryValue: more than 2 occurrences for %s", packed_hex)
        return escaped_sequence

    @staticmethod
    def getByteWithoutPrefixes(ins_bytes):
        # if I understand correctly, there are only prefix instructions and not prefix bytes within instructions
        return ins_bytes
