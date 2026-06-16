"""AArch64 collaborators for the recursive engine.

Provides TF-IDF mnemonic frequency analysis, register-based indirect call
resolution, and jump table analysis for AArch64.
"""

import logging
import struct

from .definitions import adrp_page_value

LOGGER = logging.getLogger(__name__)


def norm_reg(name):
    """Normalize register names to handle wD vs xD classes."""
    if not name:
        return ""
    name = name.lower()
    if name.startswith(("w", "x")):
        return "x" + name[1:]
    return name


class AArch64TfIdf:
    """No-op TF-IDF scorer.

    No AArch64 mnemonic-frequency model exists yet, so every function scores 0.0.
    The candidate confidence weighting only rewards *negative* TF-IDF scores, so
    0.0 is treated as "no signal" — it neither inflates nor suppresses confidence.
    """

    def __init__(self, bitness=64):
        self.bitness = bitness

    def getTfIdfFromBlocks(self, blocks):
        del blocks
        return 0.0


class AArch64IndirectCallAnalyzer:
    """Perform basic dataflow analysis to resolve AArch64 indirect call targets."""

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly

    def _resolveRegister(self, analysis_state, calling_addr, reg_name):
        d = self.disassembler
        block = getattr(analysis_state, "_block_index", {}).get(calling_addr, [])
        if not block:
            for blk in analysis_state.getBlocks():
                for ins in blk:
                    if ins[0] == calling_addr:
                        block = blk
                        break
                if block:
                    break
        if not block:
            return None

        insns_up_to_call = [ins for ins in block if ins[0] < calling_addr]
        constants = {}
        for ins in insns_up_to_call:
            bytes_ins = d.disassembly.getBytes(ins[0], ins[1])
            if not bytes_ins:
                continue
            cap_ins = next(d.capstone.disasm(bytes_ins, ins[0]), None)
            if not cap_ins or not cap_ins.operands:
                continue
            mnemonic = cap_ins.mnemonic.lower()
            dest_op = cap_ins.operands[0]
            if dest_op.type != 1:  # REG
                continue
            dest_reg = norm_reg(cap_ins.reg_name(dest_op.reg))

            if mnemonic == "adrp" and len(cap_ins.operands) >= 2:
                word = int.from_bytes(cap_ins.bytes, "little")
                constants[dest_reg] = adrp_page_value(word, cap_ins.address)
            elif mnemonic == "adr" and len(cap_ins.operands) >= 2:
                if cap_ins.operands[1].type == 2:  # IMM
                    constants[dest_reg] = cap_ins.operands[1].imm
            elif mnemonic == "add" and len(cap_ins.operands) >= 3:
                op1 = cap_ins.operands[1]
                op2 = cap_ins.operands[2]
                if op1.type == 1 and op2.type == 2:  # REG + IMM
                    src_reg = norm_reg(cap_ins.reg_name(op1.reg))
                    if src_reg in constants:
                        constants[dest_reg] = constants[src_reg] + op2.imm
                    else:
                        constants.pop(dest_reg, None)
                elif op1.type == 1 and op2.type == 1:  # REG + REG
                    reg1 = norm_reg(cap_ins.reg_name(op1.reg))
                    reg2 = norm_reg(cap_ins.reg_name(op2.reg))
                    if reg1 in constants and reg2 in constants:
                        constants[dest_reg] = constants[reg1] + constants[reg2]
                    else:
                        constants.pop(dest_reg, None)
            elif mnemonic in ("mov", "movz", "movk") and len(cap_ins.operands) >= 2:
                op1 = cap_ins.operands[1]
                if op1.type == 2:  # IMM
                    constants[dest_reg] = op1.imm
                elif op1.type == 1:  # REG
                    src_reg = norm_reg(cap_ins.reg_name(op1.reg))
                    if src_reg in constants:
                        constants[dest_reg] = constants[src_reg]
                    else:
                        constants.pop(dest_reg, None)
            elif mnemonic in ("ldr", "ldur") and len(cap_ins.operands) >= 2:
                op1 = cap_ins.operands[1]
                resolved = False
                if op1.type == 3:  # MEM
                    base_reg = norm_reg(cap_ins.reg_name(op1.mem.base))
                    if base_reg in constants and op1.mem.index == 0:
                        slot_addr = constants[base_reg] + op1.mem.disp
                        if d.disassembly.isAddrWithinMemoryImage(slot_addr):
                            raw_val = d.disassembly.getBytes(slot_addr, 8)
                            if raw_val and len(raw_val) == 8:
                                val = struct.unpack("<Q", raw_val)[0]
                                constants[dest_reg] = val
                                resolved = True
                if not resolved:
                    constants.pop(dest_reg, None)

        return constants.get(norm_reg(reg_name))

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        del block_depth
        if not analysis_state.call_register_ins:
            return

        d = self.disassembler
        for calling_addr in analysis_state.call_register_ins:
            bytes_ins = d.disassembly.getBytes(calling_addr, 4)
            if not bytes_ins:
                continue
            cap_ins = next(d.capstone.disasm(bytes_ins, calling_addr), None)
            if not cap_ins or not cap_ins.operands:
                continue
            target_op = cap_ins.operands[0]
            if target_op.type != 1:  # REG
                continue
            reg_name = cap_ins.reg_name(target_op.reg)

            candidate = self._resolveRegister(analysis_state, calling_addr, reg_name)
            if candidate:
                analysis_state.setLeaf(False)
                dll, api = d.resolveApi(candidate, candidate)
                if dll or api:
                    api_entry = {
                        "referencing_addr": [],
                        "dll_name": dll,
                        "api_name": api,
                    }
                    if candidate in d.disassembly.apis:
                        api_entry = d.disassembly.apis[candidate]
                    if calling_addr not in api_entry["referencing_addr"]:
                        api_entry["referencing_addr"].append(calling_addr)
                    d.disassembly.apis[candidate] = api_entry
                elif d.disassembly.isAddrWithinMemoryImage(candidate):
                    d.fc_manager.addCandidate(candidate, reference_source=calling_addr)


class AArch64JumpTableAnalyzer:
    """Perform jump table analysis by tracing register values back to their load sites."""

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly

    def getJumpTargets(self, jump_instruction, state):
        jump_instruction_address = jump_instruction[0]
        jump_instruction_size = jump_instruction[1]
        jump_instruction[2]
        jump_instruction[3]

        d = self.disassembler
        ins_bytes = d.disassembly.getBytes(jump_instruction_address, jump_instruction_size)
        if not ins_bytes:
            return []

        detailed_jump = next(d.capstone.disasm(ins_bytes, jump_instruction_address), None)
        if not detailed_jump or not detailed_jump.operands:
            return []

        target_op = detailed_jump.operands[0]
        if target_op.type != 1:  # REG
            return []

        target_reg = norm_reg(detailed_jump.reg_name(target_op.reg))
        if not target_reg:
            return []

        backtracked = state.backtrackInstructions(jump_instruction_address, 40)
        if not backtracked:
            return []

        detailed_insns = []
        for ins in backtracked:
            if ins[0] == jump_instruction_address:
                continue
            bytes_ins = d.disassembly.getBytes(ins[0], ins[1])
            if bytes_ins:
                cap_ins = next(d.capstone.disasm(bytes_ins, ins[0]), None)
                if cap_ins:
                    detailed_insns.append(cap_ins)

        constants = {}
        for ins in detailed_insns:
            mnemonic = ins.mnemonic.lower()
            if not ins.operands:
                continue
            dest_op = ins.operands[0]
            if dest_op.type != 1:  # REG
                continue
            dest_reg = norm_reg(ins.reg_name(dest_op.reg))

            if mnemonic == "adrp" and len(ins.operands) >= 2:
                word = int.from_bytes(ins.bytes, "little")
                constants[dest_reg] = adrp_page_value(word, ins.address)
            elif mnemonic == "adr" and len(ins.operands) >= 2:
                if ins.operands[1].type == 2:  # IMM
                    constants[dest_reg] = ins.operands[1].imm
            elif mnemonic == "add" and len(ins.operands) >= 3:
                op1 = ins.operands[1]
                op2 = ins.operands[2]
                if op1.type == 1 and op2.type == 2:  # REG + IMM
                    src_reg = norm_reg(ins.reg_name(op1.reg))
                    if src_reg in constants:
                        constants[dest_reg] = constants[src_reg] + op2.imm
                elif op1.type == 1 and op2.type == 1:  # REG + REG
                    reg1 = norm_reg(ins.reg_name(op1.reg))
                    reg2 = norm_reg(ins.reg_name(op2.reg))
                    if reg1 in constants and reg2 in constants:
                        constants[dest_reg] = constants[reg1] + constants[reg2]
            elif mnemonic in ("mov", "movz", "movk") and len(ins.operands) >= 2:
                op1 = ins.operands[1]
                if op1.type == 2:  # IMM
                    constants[dest_reg] = op1.imm
                elif op1.type == 1:  # REG
                    src_reg = norm_reg(ins.reg_name(op1.reg))
                    if src_reg in constants:
                        constants[dest_reg] = constants[src_reg]

        tracked_regs = {target_reg}
        table_base = None
        index_reg = None
        entry_size = 8
        is_signed = False
        is_relative = False

        for ins in reversed(detailed_insns):
            mnemonic = ins.mnemonic.lower()
            if not ins.operands:
                continue
            dest_op = ins.operands[0]
            if dest_op.type != 1:  # REG
                continue
            dest_reg = norm_reg(ins.reg_name(dest_op.reg))

            if dest_reg in tracked_regs:
                tracked_regs.remove(dest_reg)
                if mnemonic == "add" and len(ins.operands) >= 3:
                    op1 = ins.operands[1]
                    op2 = ins.operands[2]
                    if op1.type == 1 and op2.type == 1:  # REG + REG
                        reg1 = norm_reg(ins.reg_name(op1.reg))
                        reg2 = norm_reg(ins.reg_name(op2.reg))
                        tracked_regs.add(reg1)
                        tracked_regs.add(reg2)
                        # Detect relative base
                        if reg1 in constants:
                            table_base = constants[reg1]
                            is_relative = True
                        elif reg2 in constants:
                            table_base = constants[reg2]
                            is_relative = True
                    elif op1.type == 1 and op2.type == 2:  # REG + IMM
                        reg1 = norm_reg(ins.reg_name(op1.reg))
                        tracked_regs.add(reg1)
                elif mnemonic in ("ldr", "ldrsw", "ldrh", "ldrb", "ldrsh", "ldrsb") and len(ins.operands) >= 2:
                    op1 = ins.operands[1]
                    if op1.type == 3:  # MEM
                        base_reg = norm_reg(ins.reg_name(op1.mem.base))
                        if base_reg in constants:
                            table_base = constants[base_reg]
                        if op1.mem.index:
                            index_reg = norm_reg(ins.reg_name(op1.mem.index))

                        if mnemonic == "ldrsw":
                            entry_size = 4
                            is_signed = True
                            is_relative = True
                        elif mnemonic == "ldr":
                            entry_size = 4 if ins.reg_name(dest_op.reg).lower().startswith("w") else 8
                        elif mnemonic in ("ldrh", "ldrsh"):
                            entry_size = 2
                            is_signed = mnemonic == "ldrsh"
                            is_relative = True
                        elif mnemonic in ("ldrb", "ldrsb"):
                            entry_size = 1
                            is_signed = mnemonic == "ldrsb"
                            is_relative = True
                elif mnemonic in ("mov", "movz", "movk", "movn") and len(ins.operands) >= 2:
                    op1 = ins.operands[1]
                    if op1.type == 1:  # REG
                        tracked_regs.add(norm_reg(ins.reg_name(op1.reg)))

        # Try to find table size from cmp
        table_size = 0
        if index_reg:
            index_regs_to_match = {index_reg}
            if index_reg.startswith("x"):
                index_regs_to_match.add("w" + index_reg[1:])
            elif index_reg.startswith("w"):
                index_regs_to_match.add("x" + index_reg[1:])

            for ins in reversed(detailed_insns):
                if ins.mnemonic.lower() == "cmp" and len(ins.operands) >= 2:
                    op1 = ins.operands[0]
                    op2 = ins.operands[1]
                    if op1.type == 1 and op2.type == 2:  # REG, IMM
                        reg_name = ins.reg_name(op1.reg).lower()
                        if reg_name in index_regs_to_match:
                            table_size = op2.imm + 1
                            break

        if not table_base:
            return []

        if not table_size:
            table_size = 32

        targets = []
        for i in range(table_size):
            entry_addr = table_base + i * entry_size
            if not d.disassembly.isAddrWithinMemoryImage(entry_addr):
                break

            raw_bytes = d.disassembly.getBytes(entry_addr, entry_size)
            if not raw_bytes or len(raw_bytes) != entry_size:
                break

            if entry_size == 4:
                val = struct.unpack("<i" if is_signed else "<I", raw_bytes)[0]
            elif entry_size == 8:
                val = struct.unpack("<q" if is_signed else "<Q", raw_bytes)[0]
            elif entry_size == 2:
                val = struct.unpack("<h" if is_signed else "<H", raw_bytes)[0]
            elif entry_size == 1:
                val = struct.unpack("<b" if is_signed else "<B", raw_bytes)[0]
            else:
                break

            target = table_base + val & d.getBitMask() if is_relative else val & d.getBitMask()

            if not d.disassembly.isAddrWithinMemoryImage(target):
                break

            if d.disassembly.binary_info.isInCodeAreas(target):
                targets.append(target)
                state.addDataRef(jump_instruction_address, entry_addr, size=entry_size)
            else:
                break

        return targets
