import struct
from dataclasses import dataclass
from typing import Dict, List, Optional


def read_uleb128(data, offset):
    result = 0
    shift = 0
    current = offset
    while current < len(data):
        byte = data[current]
        result |= (byte & 0x7F) << shift
        current += 1
        if byte & 0x80 == 0:
            return result, current
        shift += 7
        if shift > 35:
            break
    raise ValueError("Invalid uleb128 encoding")


def read_sleb128(data, offset):
    result = 0
    shift = 0
    current = offset
    size = 32
    while current < len(data):
        byte = data[current]
        current += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            if shift < size and byte & 0x40:
                result |= -(1 << shift)
            return result, current
        if shift > 35:
            break
    raise ValueError("Invalid sleb128 encoding")


def parse_code_item_header(raw_data, header_offset):
    if header_offset < 0 or header_offset + 16 > len(raw_data):
        raise ValueError("Invalid code_item header offset")
    (
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
    ) = struct.unpack_from("<HHHHII", raw_data, header_offset)
    return {
        "registers_size": registers_size,
        "ins_size": ins_size,
        "outs_size": outs_size,
        "tries_size": tries_size,
        "debug_info_off": debug_info_off,
        "insns_size": insns_size,
    }


@dataclass(frozen=True)
class DalvikOpcode:
    mnemonic: str
    fmt: str
    size_units: int
    ref_kind: Optional[str] = None
    can_throw: bool = False
    is_invoke: bool = False
    is_terminator: bool = False
    is_conditional: bool = False
    payload_kind: Optional[str] = None


@dataclass
class DecodedDalvikInstruction:
    opcode: int
    mnemonic: str
    fmt: str
    size_units: int
    size_bytes: int
    bytes_: bytes
    operands: str
    registers: List[int]
    literal: Optional[int] = None
    ref_kind: Optional[str] = None
    ref_index: Optional[int] = None
    ref_index_aux: Optional[int] = None
    branch_target_idx: Optional[int] = None
    payload_idx: Optional[int] = None
    is_invoke: bool = False
    is_terminator: bool = False
    is_conditional: bool = False
    can_throw: bool = False
    payload_kind: Optional[str] = None


OPCODES: Dict[int, DalvikOpcode] = {}


def _register(opcode, mnemonic, fmt, size_units, **kwargs):
    OPCODES[opcode] = DalvikOpcode(mnemonic, fmt, size_units, **kwargs)


def _register_range(start, names, fmt, size_units, **kwargs):
    for index, mnemonic in enumerate(names):
        _register(start + index, mnemonic, fmt, size_units, **kwargs)


_register(0x00, "nop", "10x", 1)
_register(0x01, "move", "12x", 1)
_register(0x02, "move/from16", "22x", 2)
_register(0x03, "move/16", "32x", 3)
_register(0x04, "move-wide", "12x", 1)
_register(0x05, "move-wide/from16", "22x", 2)
_register(0x06, "move-wide/16", "32x", 3)
_register(0x07, "move-object", "12x", 1)
_register(0x08, "move-object/from16", "22x", 2)
_register(0x09, "move-object/16", "32x", 3)
_register_range(0x0A, ["move-result", "move-result-wide", "move-result-object", "move-exception"], "11x", 1)
_register(0x0E, "return-void", "10x", 1, is_terminator=True)
_register_range(
    0x0F,
    ["return", "return-wide", "return-object"],
    "11x",
    1,
    is_terminator=True,
)
_register(0x12, "const/4", "11n", 1)
_register(0x13, "const/16", "21s", 2)
_register(0x14, "const", "31i", 3)
_register(0x15, "const/high16", "21h", 2)
_register(0x16, "const-wide/16", "21s", 2)
_register(0x17, "const-wide/32", "31i", 3)
_register(0x18, "const-wide", "51l", 5)
_register(0x19, "const-wide/high16", "21h", 2)
_register(0x1A, "const-string", "21c", 2, ref_kind="string")
_register(0x1B, "const-string/jumbo", "31c", 3, ref_kind="string")
_register(0x1C, "const-class", "21c", 2, ref_kind="type", can_throw=True)
_register(0x1D, "monitor-enter", "11x", 1, can_throw=True)
_register(0x1E, "monitor-exit", "11x", 1, can_throw=True)
_register(0x1F, "check-cast", "21c", 2, ref_kind="type", can_throw=True)
_register(0x20, "instance-of", "22c", 2, ref_kind="type")
_register(0x21, "array-length", "12x", 1, can_throw=True)
_register(0x22, "new-instance", "21c", 2, ref_kind="type", can_throw=True)
_register(0x23, "new-array", "22c", 2, ref_kind="type", can_throw=True)
_register(0x24, "filled-new-array", "35c", 3, ref_kind="type", can_throw=True)
_register(0x25, "filled-new-array/range", "3rc", 3, ref_kind="type", can_throw=True)
_register(0x26, "fill-array-data", "31t", 3, payload_kind="fill-array-data")
_register(0x27, "throw", "11x", 1, can_throw=True, is_terminator=True)
_register(0x28, "goto", "10t", 1, is_terminator=True)
_register(0x29, "goto/16", "20t", 2, is_terminator=True)
_register(0x2A, "goto/32", "30t", 3, is_terminator=True)
_register(0x2B, "packed-switch", "31t", 3, payload_kind="packed-switch")
_register(0x2C, "sparse-switch", "31t", 3, payload_kind="sparse-switch")
_register_range(
    0x2D,
    ["cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"],
    "23x",
    2,
)
_register_range(
    0x32,
    ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"],
    "22t",
    2,
    is_conditional=True,
)
_register_range(
    0x38,
    ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"],
    "21t",
    2,
    is_conditional=True,
)
_register_range(
    0x44,
    [
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
    ],
    "23x",
    2,
    can_throw=True,
)
_register_range(
    0x52,
    [
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
    ],
    "22c",
    2,
    ref_kind="field",
    can_throw=True,
)
_register_range(
    0x60,
    [
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
    ],
    "21c",
    2,
    ref_kind="field",
)
_register_range(
    0x6E,
    ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"],
    "35c",
    3,
    ref_kind="method",
    can_throw=True,
    is_invoke=True,
)
_register_range(
    0x74,
    [
        "invoke-virtual/range",
        "invoke-super/range",
        "invoke-direct/range",
        "invoke-static/range",
        "invoke-interface/range",
    ],
    "3rc",
    3,
    ref_kind="method",
    can_throw=True,
    is_invoke=True,
)
_register_range(
    0x7B,
    [
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
    ],
    "12x",
    1,
)
_register_range(
    0x90,
    [
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
    ],
    "23x",
    2,
)
_register_range(
    0xB0,
    [
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
    ],
    "12x",
    1,
)
_register_range(
    0xD0,
    [
        "add-int/lit16",
        "rsub-int",
        "mul-int/lit16",
        "div-int/lit16",
        "rem-int/lit16",
        "and-int/lit16",
        "or-int/lit16",
        "xor-int/lit16",
    ],
    "22s",
    2,
)
_register_range(
    0xD8,
    [
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
    ],
    "22b",
    2,
)
_register(0xFA, "invoke-polymorphic", "45cc", 4, ref_kind="method", can_throw=True, is_invoke=True)
_register(0xFB, "invoke-polymorphic/range", "4rcc", 4, ref_kind="method", can_throw=True, is_invoke=True)
_register(0xFC, "invoke-custom", "35c", 3, ref_kind="call_site", can_throw=True, is_invoke=True)
_register(0xFD, "invoke-custom/range", "3rc", 3, ref_kind="call_site", can_throw=True, is_invoke=True)
_register(0xFE, "const-method-handle", "21c", 2, ref_kind="method_handle")
_register(0xFF, "const-method-type", "21c", 2, ref_kind="proto")


def _reg_name(register_index):
    return f"v{register_index}"


def _format_registers(registers):
    return ", ".join(_reg_name(register_index) for register_index in registers)


def _decode_register_list_35c(raw_bytes):
    count = (raw_bytes[1] >> 4) & 0x0F
    reg_g = raw_bytes[1] & 0x0F
    word = int.from_bytes(raw_bytes[4:6], byteorder="little")
    reg_c = word & 0x0F
    reg_d = (word >> 4) & 0x0F
    reg_e = (word >> 8) & 0x0F
    reg_f = (word >> 12) & 0x0F
    registers = [reg_c, reg_d, reg_e, reg_f, reg_g][:count]
    return count, registers


def _decode_register_range(count, start):
    return list(range(start, start + count))


def _signed(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def decode_instruction(bytecode, byte_idx, resolve_ref):
    opcode_value = bytecode[byte_idx]
    if opcode_value not in OPCODES:
        raise ValueError(f"Unknown Dalvik opcode 0x{opcode_value:02x}")

    opcode = OPCODES[opcode_value]
    size_bytes = opcode.size_units * 2
    if byte_idx + size_bytes > len(bytecode):
        raise ValueError("Truncated Dalvik instruction")

    raw_bytes = bytes(bytecode[byte_idx : byte_idx + size_bytes])
    registers = []
    operands = ""
    literal = None
    ref_index = None
    ref_index_aux = None
    branch_target_idx = None
    payload_idx = None

    if opcode.fmt == "10x":
        operands = ""
    elif opcode.fmt == "10t":
        branch_delta = int.from_bytes(raw_bytes[1:2], byteorder="little", signed=True) * 2
        branch_target_idx = byte_idx + branch_delta
        operands = f"{hex(branch_target_idx)}"
    elif opcode.fmt == "11n":
        reg_a = raw_bytes[1] & 0x0F
        literal = _signed((raw_bytes[1] >> 4) & 0x0F, 4)
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, #{literal:+d}"
    elif opcode.fmt == "11x":
        reg_a = raw_bytes[1]
        registers = [reg_a]
        operands = _reg_name(reg_a)
    elif opcode.fmt == "12x":
        reg_a = raw_bytes[1] & 0x0F
        reg_b = (raw_bytes[1] >> 4) & 0x0F
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}"
    elif opcode.fmt == "20t":
        branch_delta = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=True) * 2
        branch_target_idx = byte_idx + branch_delta
        operands = f"{hex(branch_target_idx)}"
    elif opcode.fmt == "21c":
        reg_a = raw_bytes[1]
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, {resolve_ref(opcode.ref_kind, ref_index)}"
    elif opcode.fmt == "21h":
        reg_a = raw_bytes[1]
        value = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=False)
        shift = 48 if opcode.mnemonic.endswith("wide/high16") else 16
        literal = value << shift
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, #{hex(literal)}"
    elif opcode.fmt == "21s":
        reg_a = raw_bytes[1]
        literal = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=True)
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, #{literal:+d}"
    elif opcode.fmt == "21t":
        reg_a = raw_bytes[1]
        branch_delta = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=True) * 2
        branch_target_idx = byte_idx + branch_delta
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, {hex(branch_target_idx)}"
    elif opcode.fmt == "22b":
        reg_a = raw_bytes[1]
        reg_b = raw_bytes[2]
        literal = int.from_bytes(raw_bytes[3:4], byteorder="little", signed=True)
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}, #{literal:+d}"
    elif opcode.fmt == "22c":
        reg_a = raw_bytes[1] & 0x0F
        reg_b = (raw_bytes[1] >> 4) & 0x0F
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}, {resolve_ref(opcode.ref_kind, ref_index)}"
    elif opcode.fmt == "22s":
        reg_a = raw_bytes[1] & 0x0F
        reg_b = (raw_bytes[1] >> 4) & 0x0F
        literal = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=True)
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}, #{literal:+d}"
    elif opcode.fmt == "22t":
        reg_a = raw_bytes[1] & 0x0F
        reg_b = (raw_bytes[1] >> 4) & 0x0F
        branch_delta = int.from_bytes(raw_bytes[2:4], byteorder="little", signed=True) * 2
        branch_target_idx = byte_idx + branch_delta
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}, {hex(branch_target_idx)}"
    elif opcode.fmt == "22x":
        reg_a = raw_bytes[1]
        reg_b = int.from_bytes(raw_bytes[2:4], byteorder="little")
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}"
    elif opcode.fmt == "23x":
        reg_a = raw_bytes[1]
        reg_b = raw_bytes[2]
        reg_c = raw_bytes[3]
        registers = [reg_a, reg_b, reg_c]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}, {_reg_name(reg_c)}"
    elif opcode.fmt == "30t":
        branch_delta = int.from_bytes(raw_bytes[2:6], byteorder="little", signed=True) * 2
        branch_target_idx = byte_idx + branch_delta
        operands = f"{hex(branch_target_idx)}"
    elif opcode.fmt == "31c":
        reg_a = raw_bytes[1]
        ref_index = int.from_bytes(raw_bytes[2:6], byteorder="little")
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, {resolve_ref(opcode.ref_kind, ref_index)}"
    elif opcode.fmt == "31i":
        reg_a = raw_bytes[1]
        literal = int.from_bytes(raw_bytes[2:6], byteorder="little", signed=True)
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, #{literal:+d}"
    elif opcode.fmt == "31t":
        reg_a = raw_bytes[1]
        branch_delta = int.from_bytes(raw_bytes[2:6], byteorder="little", signed=True) * 2
        payload_idx = byte_idx + branch_delta
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, payload@{hex(payload_idx)}"
    elif opcode.fmt == "32x":
        reg_a = int.from_bytes(raw_bytes[2:4], byteorder="little")
        reg_b = int.from_bytes(raw_bytes[4:6], byteorder="little")
        registers = [reg_a, reg_b]
        operands = f"{_reg_name(reg_a)}, {_reg_name(reg_b)}"
    elif opcode.fmt == "35c":
        _, registers = _decode_register_list_35c(raw_bytes)
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        operands = f"{{{_format_registers(registers)}}}, {resolve_ref(opcode.ref_kind, ref_index)}"
    elif opcode.fmt == "3rc":
        count = raw_bytes[1]
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        first_reg = int.from_bytes(raw_bytes[4:6], byteorder="little")
        registers = _decode_register_range(count, first_reg)
        operands = f"{{{_format_registers(registers)}}}, {resolve_ref(opcode.ref_kind, ref_index)}"
    elif opcode.fmt == "45cc":
        _, registers = _decode_register_list_35c(raw_bytes[:6])
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        ref_index_aux = int.from_bytes(raw_bytes[6:8], byteorder="little")
        operands = "{{{}}}, {}, {}".format(
            _format_registers(registers),
            resolve_ref(opcode.ref_kind, ref_index),
            resolve_ref("proto", ref_index_aux),
        )
    elif opcode.fmt == "4rcc":
        count = raw_bytes[1]
        ref_index = int.from_bytes(raw_bytes[2:4], byteorder="little")
        first_reg = int.from_bytes(raw_bytes[4:6], byteorder="little")
        ref_index_aux = int.from_bytes(raw_bytes[6:8], byteorder="little")
        registers = _decode_register_range(count, first_reg)
        operands = "{{{}}}, {}, {}".format(
            _format_registers(registers),
            resolve_ref(opcode.ref_kind, ref_index),
            resolve_ref("proto", ref_index_aux),
        )
    elif opcode.fmt == "51l":
        reg_a = raw_bytes[1]
        literal = int.from_bytes(raw_bytes[2:10], byteorder="little", signed=True)
        registers = [reg_a]
        operands = f"{_reg_name(reg_a)}, #{hex(literal)}"
    else:
        raise ValueError(f"Unsupported Dalvik format {opcode.fmt}")

    return DecodedDalvikInstruction(
        opcode=opcode_value,
        mnemonic=opcode.mnemonic,
        fmt=opcode.fmt,
        size_units=opcode.size_units,
        size_bytes=size_bytes,
        bytes_=raw_bytes,
        operands=operands,
        registers=registers,
        literal=literal,
        ref_kind=opcode.ref_kind,
        ref_index=ref_index,
        ref_index_aux=ref_index_aux,
        branch_target_idx=branch_target_idx,
        payload_idx=payload_idx,
        is_invoke=opcode.is_invoke,
        is_terminator=opcode.is_terminator,
        is_conditional=opcode.is_conditional,
        can_throw=opcode.can_throw,
        payload_kind=opcode.payload_kind,
    )
