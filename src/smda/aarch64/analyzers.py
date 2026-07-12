"""AArch64 collaborators for the recursive engine.

Provides TF-IDF mnemonic frequency analysis, register-based indirect call
resolution, and jump table analysis for AArch64.
"""

import contextlib
import logging
import struct

from .dataflow import gatherContextInstructions, norm_reg, propagateConstants, propagateConstantsHistory

LOGGER = logging.getLogger(__name__)

# Bounded predecessor-block hops fed into gatherContextInstructions when the seed
# block alone doesn't resolve a jump-table base/index (e.g. an adrp/add chain that
# lives in a prior block). Kept small and fixed: jump tables resolve eagerly,
# mid-function, so code_refs_to is only partially populated and deep chases would
# just burn time chasing edges that don't exist yet.
JUMPTABLE_PREDECESSOR_DEPTH = 2


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

    def searchBlock(self, analysis_state, address):
        # Lazy-cache an {instruction_addr: containing_block} index on the
        # analysis_state (mirrors intel.IndirectCallAnalyzer.searchBlock) so
        # repeated lookups during the same function analysis are O(1) instead of
        # O(blocks * instructions). Only safe to build once block reconstruction
        # has finished (resolveRegisterCalls runs after state.finalizeAnalysis(),
        # so getBlocks() here returns/caches the real, complete block layout).
        block_index = getattr(analysis_state, "_block_index", None)
        if not isinstance(block_index, dict):
            block_index = {}
            for block in analysis_state.getBlocks():
                for ins in block:
                    addr = ins[0]
                    if addr not in block_index:
                        block_index[addr] = block
            with contextlib.suppress(AttributeError):
                analysis_state._block_index = block_index
        return block_index.get(address, [])

    def _resolveRegister(self, analysis_state, calling_addr, reg_name, block_depth):
        self.searchBlock(analysis_state, calling_addr)  # ensures _block_index is built
        block_index = getattr(analysis_state, "_block_index", {})
        cap_insns = gatherContextInstructions(
            self.disassembler,
            analysis_state,
            calling_addr,
            block_depth,
            block_index=block_index,
        )
        constants = propagateConstants(cap_insns, self.disassembler)
        return constants.get(norm_reg(reg_name))

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        if not analysis_state.call_register_ins:
            return

        d = self.disassembler
        max_calls_per_block = getattr(getattr(d, "config", None), "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK", 50)
        calls_per_block = {}
        for calling_addr in analysis_state.call_register_ins:
            block = self.searchBlock(analysis_state, calling_addr)
            start_block = [ins for ins in block if ins[0] <= calling_addr]
            if not start_block:
                continue
            block_key = start_block[0][0]
            calls_per_block[block_key] = calls_per_block.get(block_key, 0) + 1
            # we only process at most MAX_INDIRECT_CALLS_PER_BASIC_BLOCK register-calls
            # per block to avoid extreme cases (e.g. a Go binary with huge switch-like
            # register-call fan-out in a single block).
            if calls_per_block[block_key] > max_calls_per_block:
                continue

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

            candidate = self._resolveRegister(analysis_state, calling_addr, reg_name, block_depth)
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

    def _nextKnownBoundary(self, after_addr):
        """Nearest known function candidate/border start after `after_addr`, if any.

        Used to stop a runaway table read before it overruns into the next
        function - relevant both for tables placed in .rodata ahead of an
        unrelated later function and for tables a compiler places inline in .text.
        """
        d = self.disassembler
        candidates = getattr(getattr(d, "fc_manager", None), "candidates", None) or {}
        borders = getattr(d.disassembly, "function_borders", None) or {}
        candidate_boundary = min((addr for addr in candidates if addr > after_addr), default=None)
        border_boundary = min((fn_min for fn_min, _fn_max in borders.values() if fn_min > after_addr), default=None)
        boundaries = [b for b in (candidate_boundary, border_boundary) if b is not None]
        return min(boundaries) if boundaries else None

    def getJumpTargets(self, jump_instruction, state):
        jump_instruction_address = jump_instruction[0]
        jump_instruction_size = jump_instruction[1]

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

        detailed_insns = gatherContextInstructions(d, state, jump_instruction_address, JUMPTABLE_PREDECESSOR_DEPTH)
        if not detailed_insns:
            return []

        # A per-instruction history (not one trailing dict) is required here: the reverse
        # scan below inspects an instruction's *source* operands, but that same
        # instruction may also write an unresolved value to the register it reads (e.g.
        # the table-base register reused as the destination of the very load it
        # addresses) - only the map as of just before that instruction still shows the
        # base it actually used.
        constants_before = propagateConstantsHistory(detailed_insns, d)

        tracked_regs = {target_reg}
        table_base = None
        index_reg = None
        entry_size = 8
        is_signed = False
        is_relative = False

        for idx in range(len(detailed_insns) - 1, -1, -1):
            ins = detailed_insns[idx]
            constants = constants_before[idx]
            mnemonic = ins.mnemonic.lower()
            if not ins.operands:
                continue
            dest_op = ins.operands[0]
            if dest_op.type != 1:  # REG
                continue
            dest_reg = norm_reg(ins.reg_name(dest_op.reg))
            if dest_reg not in tracked_regs:
                continue
            tracked_regs.remove(dest_reg)

            if mnemonic == "add" and len(ins.operands) >= 3:
                op1 = ins.operands[1]
                op2 = ins.operands[2]
                if op1.type == 1 and op2.type == 1:  # REG + REG (incl. extended/shifted reg)
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
            elif mnemonic in ("sxtb", "sxth", "sxtw", "uxtb", "uxth") and len(ins.operands) >= 2:
                # Standalone sign/zero-extend feeding the final add/br chain (e.g. a plain
                # `ldr` of a raw entry followed by an explicit `sxtw` rather than `ldrsw`
                # directly) - continue the chase into the source register and record the
                # entry's signedness (verified live against capstone 5.0.7: sxtw/uxtb/etc.
                # disassemble as ordinary 2-operand reg-to-reg instructions).
                op1 = ins.operands[1]
                if op1.type == 1:  # REG
                    tracked_regs.add(norm_reg(ins.reg_name(op1.reg)))
                    is_signed = mnemonic.startswith("sxt")

        # Try to find table size from a bounds check (cmp <idx>, #imm or subs <dst>, <idx>, #imm)
        table_size = 0
        if index_reg:
            index_regs_to_match = {index_reg}
            if index_reg.startswith("x"):
                index_regs_to_match.add("w" + index_reg[1:])
            elif index_reg.startswith("w"):
                index_regs_to_match.add("x" + index_reg[1:])

            for ins in reversed(detailed_insns):
                mnemonic = ins.mnemonic.lower()
                cmp_reg_op, cmp_imm_op = None, None
                if mnemonic == "cmp" and len(ins.operands) >= 2:
                    cmp_reg_op, cmp_imm_op = ins.operands[0], ins.operands[1]
                elif mnemonic == "subs" and len(ins.operands) >= 3:
                    cmp_reg_op, cmp_imm_op = ins.operands[1], ins.operands[2]
                if cmp_reg_op is None or cmp_reg_op.type != 1 or cmp_imm_op.type != 2:
                    continue
                reg_name = ins.reg_name(cmp_reg_op.reg).lower()
                if reg_name in index_regs_to_match:
                    table_size = cmp_imm_op.imm + 1
                    break

        if not table_base:
            return []

        if not table_size:
            table_size = 32

        next_boundary = self._nextKnownBoundary(table_base)

        targets = []
        for i in range(table_size):
            entry_addr = table_base + i * entry_size
            if next_boundary is not None and entry_addr >= next_boundary:
                break
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
