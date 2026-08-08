"""Capstone-ground-truth helpers for AArch64 escaping verification.

Operand typing follows capstone's ARM64 operand classes (see capstone/arm64.h) and
Binary Ninja's AArch64 lifter operand handling in binaryninja-api/arch/arm64/il.cpp,
where register shifts/extensions are carried on the register operand rather than as a
separate textual field.
"""

from __future__ import annotations

import re

import capstone.arm64_const as arm64_const
from capstone.arm64 import (
    ARM64_OP_BARRIER,
    ARM64_OP_FP,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_PREFETCH,
    ARM64_OP_REG,
    ARM64_OP_REG_MRS,
    ARM64_OP_REG_MSR,
    ARM64_OP_SYS,
)

from smda.aarch64.definitions import (
    ALWAYS_BRANCH_INS,
    CALL_INS,
    COND_BRANCH_INS,
    COND_BRANCH_PREFIXES,
    END_INS,
    EXCEPTION_RETURN_INS,
    INDIRECT_JUMP_INS,
    RET_INS,
    UNCOND_JUMP_INS,
)

_CC_MNEMONICS = frozenset(
    {
        "csel",
        "csinc",
        "csinv",
        "csneg",
        "cset",
        "csetm",
        "cinc",
        "cinv",
        "cneg",
        "ccmp",
        "ccmn",
    }
)
_PRIVILEGED_MNEMONICS = frozenset(
    {
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
)
_FLOAT_PREFIXES = ("f", "scvtf", "ucvtf")
_VECTOR_PREFIXES = ("aes", "sha", "sm4", "sha512", "sha3")
_SCALAR_LONG_MULTIPLY_MNEMONICS = frozenset(
    {
        "smaddl",
        "smull",
        "smulh",
        "umaddl",
        "umull",
        "umulh",
    }
)
_ARM64_OP_PSTATE = getattr(arm64_const, "ARM64_OP_PSTATE", -1)
_ARM64_OP_SVCR = getattr(arm64_const, "ARM64_OP_SVCR", -1)
_ARM64_OP_CIMM = getattr(arm64_const, "ARM64_OP_CIMM", -1)
_ARM64_OP_SME_INDEX = getattr(arm64_const, "ARM64_OP_SME_INDEX", -1)
_ARM64_CC_INVALID = getattr(arm64_const, "ARM64_CC_INVALID", 0)
_TRAP_MNEMONICS = frozenset(END_INS)
_CONTROL_FLOW_MNEMONICS = frozenset(
    RET_INS
    | EXCEPTION_RETURN_INS
    | CALL_INS
    | COND_BRANCH_INS
    | ALWAYS_BRANCH_INS
    | UNCOND_JUMP_INS
    | INDIRECT_JUMP_INS
)
_VECTOR_OPERAND = re.compile(r"v[0-9]+\.[0-9]*[bhsd](?:\[[^\]]+\])?", re.IGNORECASE)
# advanced-SIMD scalar forms address the vector file through b/h/s/d/q registers and carry
# no ".<layout>" suffix for the layout regex above to find
_SCALAR_SIMD_OPERAND = re.compile(r"\b[bhsdq][0-9]+\b", re.IGNORECASE)


def normalize_capstone_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def smda_instruction_matches_capstone(smda_instruction, capstone_instruction) -> bool:
    if smda_instruction.mnemonic != capstone_instruction.mnemonic:
        return False
    if normalize_capstone_text(smda_instruction.operands) != normalize_capstone_text(capstone_instruction.op_str):
        return False
    return capstone_instruction.size * 2 == len(smda_instruction.bytes)


def escape_capstone_operand(operand) -> str:
    operand_type = operand.type
    if operand_type == ARM64_OP_REG:
        return "REG"
    if operand_type in (ARM64_OP_IMM, ARM64_OP_FP):
        return "CONST"
    if operand_type == ARM64_OP_MEM:
        return "PTR"
    if operand_type in (ARM64_OP_REG_MRS, ARM64_OP_REG_MSR, _ARM64_OP_PSTATE, _ARM64_OP_SVCR):
        return "SYSREG"
    if operand_type == ARM64_OP_SYS:
        return "SYSOP"
    if operand_type == ARM64_OP_PREFETCH:
        return "HINT"
    if operand_type == ARM64_OP_BARRIER:
        return "BARRIER"
    if operand_type == _ARM64_OP_CIMM:
        return "COND"
    if operand_type == _ARM64_OP_SME_INDEX:
        return "MISC"
    return "MISC"


def expected_operand_tokens(capstone_instruction) -> list[str]:
    tokens = [escape_capstone_operand(operand) for operand in capstone_instruction.operands]
    if capstone_instruction.mnemonic in _CC_MNEMONICS and capstone_instruction.cc not in (
        0,
        _ARM64_CC_INVALID,
    ):
        tokens.append("COND")
    return tokens


def expected_escaped_operands(capstone_instruction) -> str:
    return ", ".join(expected_operand_tokens(capstone_instruction))


def operands_use_vector_layout(operands: str) -> bool:
    return bool(_VECTOR_OPERAND.search(operands or ""))


def is_control_flow_mnemonic(mnemonic: str) -> bool:
    if mnemonic in _TRAP_MNEMONICS:
        return False
    if mnemonic.startswith(COND_BRANCH_PREFIXES):
        return True
    return mnemonic in _CONTROL_FLOW_MNEMONICS


def expected_mnemonic_group(capstone_instruction, capstone_engine) -> str:
    mnemonic = capstone_instruction.mnemonic
    if mnemonic == "error":
        return "U"
    if operands_use_vector_layout(capstone_instruction.op_str):
        return "V"
    if is_control_flow_mnemonic(mnemonic):
        return "C"
    if mnemonic in _TRAP_MNEMONICS:
        return "P"
    if mnemonic in {"nop", "hint"}:
        return "N"
    if mnemonic in _PRIVILEGED_MNEMONICS:
        return "P"

    if mnemonic in _SCALAR_LONG_MULTIPLY_MNEMONICS:
        return "A"

    group_names = {capstone_engine.group_name(group) for group in capstone_instruction.groups}
    if "fparmv8" in group_names or mnemonic.startswith(_FLOAT_PREFIXES):
        return "F"
    if "neon" in group_names or "asimd" in group_names or mnemonic.startswith(_VECTOR_PREFIXES):
        return "V"
    if mnemonic.startswith(("ld", "st", "swp", "cas", "prf")):
        return "M"
    if mnemonic.startswith(("pac", "aut")):
        return "S"
    return "A"


def classify_mnemonic_fallback(
    mnemonic: str,
    operands: str = "",
    *,
    cfg_supplement: frozenset[str] | set[str] = frozenset(),
    privileged_supplement: frozenset[str] | set[str] = frozenset(),
    float_mnemonics: frozenset[str] | set[str] = frozenset(),
    vector_mnemonics: frozenset[str] | set[str] = frozenset(),
    mem_mnemonics: frozenset[str] | set[str] = frozenset(),
    stack_mnemonics: frozenset[str] | set[str] = frozenset(),
    aritlog_mnemonics: frozenset[str] | set[str] = frozenset(),
    prefix_fallbacks: tuple[tuple[tuple[str, ...], str], ...] = (),
) -> str:
    mnemonic = mnemonic.split(" ")[-1]
    if mnemonic == "error":
        return "U"
    if operands_use_vector_layout(operands):
        return "V"
    if is_control_flow_mnemonic(mnemonic) or mnemonic in cfg_supplement:
        return "C"
    if mnemonic in _TRAP_MNEMONICS:
        return "P"
    if mnemonic in {"nop", "hint"}:
        return "N"
    if mnemonic in _PRIVILEGED_MNEMONICS or mnemonic in privileged_supplement:
        return "P"
    if mnemonic in float_mnemonics or mnemonic.startswith(_FLOAT_PREFIXES):
        return "F"
    if mnemonic in _SCALAR_LONG_MULTIPLY_MNEMONICS:
        return "A"
    if mnemonic in vector_mnemonics or mnemonic.startswith(_VECTOR_PREFIXES):
        return "V"
    if mnemonic in mem_mnemonics or mnemonic.startswith(("ld", "st", "swp", "cas", "prf")):
        return "M"
    if mnemonic in stack_mnemonics or mnemonic.startswith(("pac", "aut")):
        return "S"
    if _SCALAR_SIMD_OPERAND.search(operands):
        return "V"
    if mnemonic in aritlog_mnemonics:
        return "A"
    for prefixes, group in prefix_fallbacks:
        if any(mnemonic.startswith(prefix) for prefix in prefixes):
            return group
    return "U"


def should_opcode_mask_immediates(capstone_instruction) -> bool:
    if is_control_flow_mnemonic(capstone_instruction.mnemonic):
        return True
    return bool(capstone_instruction.operands)
