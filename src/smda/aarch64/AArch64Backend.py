#!/usr/bin/python

import logging
import re

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM

from smda.common.arch.ArchBackend import ArchBackend
from smda.utility.ElfFileLoader import ElfFileLoader

from .analyzers import AArch64IndirectCallAnalyzer, AArch64JumpTableAnalyzer, AArch64TfIdf
from .definitions import (
    ADD_IMM64_MASK,
    ADD_IMM64_VALUE,
    ADRP_MASK,
    ADRP_VALUE,
    ALWAYS_BRANCH_INS,
    BR_MASK,
    BR_VALUE,
    CALL_INS,
    COND_BRANCH_INS,
    END_INS,
    EXCEPTION_RETURN_INS,
    INDIRECT_JUMP_INS,
    INSTRUCTION_SIZE,
    NOP,
    RET_INS,
    UNCOND_JUMP_INS,
    adrp_page_value,
    is_bti_landing_pad,
    is_function_prologue,
)
from .FunctionAnalysisState import FunctionAnalysisState
from .FunctionCandidateManager import FunctionCandidateManager

LOGGER = logging.getLogger(__name__)

# capstone renders AArch64 immediates as "#0x....": match the hex operands.
_HEX_OPERAND = re.compile(r"0x[0-9a-fA-F]+")
_LDR_UNSIGNED_64_MASK = 0xFFC00000
_LDR_UNSIGNED_64_VALUE = 0xF9400000


class AArch64Backend(ArchBackend):
    """AArch64 backend: capstone (CS_ARCH_ARM64) setup, AArch64 collaborators and
    the AArch64 control-flow classifier driving the architecture-agnostic engine.

    The classifier is an ordered, first-match-wins mapping from a capstone arm64
    instruction to control flow (ret / call / end / cond-jump / uncond-jump /
    indirect-jump / sequential), verified against capstone semantics. Branch
    targets are the *last* immediate operand (the tbz/tbnz trap: their condition
    register precedes the destination)."""

    name = "aarch64"
    # AArch64 is fixed-width: a 4-byte look-ahead window decodes exactly one instruction.
    max_instruction_size = INSTRUCTION_SIZE

    # --- collaborator factories ------------------------------------------
    def createCapstone(self, bitness):
        del bitness  # AArch64 is always 64-bit; 32-bit ARM would be a separate backend
        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True
        return capstone

    def createTfIdf(self, bitness):
        return AArch64TfIdf(bitness=bitness)

    def createCandidateManager(self, config):
        return FunctionCandidateManager(config)

    def createAnalysisState(self, start_addr, disassembly):
        return FunctionAnalysisState(start_addr, disassembly)

    def createJumpTableAnalyzer(self, disassembler):
        return AArch64JumpTableAnalyzer(disassembler)

    def createIndirectCallAnalyzer(self, disassembler):
        return AArch64IndirectCallAnalyzer(disassembler)

    def probeBitness(self, disassembly):
        del disassembly
        return 64

    # --- helpers ----------------------------------------------------------
    @staticmethod
    def _branchTarget(op_str):
        """Return the branch destination: the LAST immediate operand, or None.

        The destination is always the trailing immediate — for tbz/tbnz the bit
        position (#<imm>) precedes it, so taking the first immediate would mis-resolve
        the target."""
        matches = _HEX_OPERAND.findall(op_str)
        if matches:
            return int(matches[-1], 16)
        return None

    @staticmethod
    def _endFunction(state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _cutFunctionBeforeInstruction(state, previous_address, current_address):
        state.removeCodeRef(previous_address, current_address)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)
        state.endBlock()
        state.setSanelyEnding(True)

    @staticmethod
    def _wordAt(d, addr):
        if not d.disassembly.isAddrWithinMemoryImage(addr):
            return None
        offset = addr - d.disassembly.binary_info.base_addr
        data = d.disassembly.binary_info.binary[offset : offset + INSTRUCTION_SIZE]
        if len(data) != INSTRUCTION_SIZE:
            return None
        return int.from_bytes(data, "little")

    @classmethod
    def _isFunctionPrologueAt(cls, d, addr):
        word = cls._wordAt(d, addr)
        if word is None:
            return False
        return is_function_prologue(word)

    @classmethod
    def _callFallthroughFunctionStart(cls, d, addr):
        if addr in d.fc_manager.getFunctionStartCandidates():
            return addr

        cursor = addr
        skipped_nop = False
        while cls._wordAt(d, cursor) == NOP:
            skipped_nop = True
            cursor += INSTRUCTION_SIZE
        if skipped_nop and cursor in d.fc_manager.getFunctionStartCandidates():
            return cursor
        if skipped_nop and cursor % 16 == 0:
            word = cls._wordAt(d, cursor)
            if word not in (None, 0, NOP):
                return cursor
        return None

    def _analyzeCondBranch(self, d, instruction, state):
        i_address, i_size, _i_mnemonic, i_op_str = instruction
        # conditional branch: fall-through successor is reachable and booked by the
        # engine; queue the taken target as the second successor.
        state.addBlockToQueue(i_address + i_size)
        target = self._branchTarget(i_op_str)
        d.tailcall_analyzer.addJump(i_address, target if target is not None else 0)
        if target is not None:
            if target in d.disassembly.functions:
                # taken edge into an already-recovered function: a conditional tailcall edge
                state.setSanelyEnding(True)
            else:
                # AArch64 conditional branches are ordinary intra-function CFG edges.
                # Prologue-like slow paths can sit behind guards; do not split them
                # merely because the prologue scanner also found the target.
                state.addBlockToQueue(target)
            state.addCodeRef(i_address, target, by_jump=True)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _isBackwardTailcallTarget(target, state):
        return target < state.start_addr

    def _isShortBranchStub(self, d, state, target):
        return (
            state.num_blocks_analyzed == 0
            and len(state.instructions) <= 4
            and abs(target - state.start_addr) >= 0x40
            and not self._isFunctionPrologueAt(d, state.start_addr)
        )

    def _analyzeUncondBranch(self, d, instruction, state):
        i_address, _i_size, _i_mnemonic, i_op_str = instruction
        target = self._branchTarget(i_op_str)
        if target is not None:
            d.tailcall_analyzer.addJump(i_address, target)
            if target in d.disassembly.functions:
                # case = "TAILCALL!"
                state.setSanelyEnding(True)
            elif self._isBackwardTailcallTarget(target, state) or self._isShortBranchStub(d, state, target):
                # A direct branch to code before the current entry, or from a short
                # no-frame stub, is a tailcall/shared thunk target, not a local block.
                d.fc_manager.addTailcallCandidate(target)
                state.setSanelyEnding(True)
            elif target in d.fc_manager.getFunctionStartCandidates():
                # case = "TAILCALL?" — leave for its own analysis
                pass
            elif state.isFirstInstruction():
                # case = "STUB-TAILCALL!" — a lone branch stub to another function
                pass
            else:
                state.addBlockToQueue(target)
            state.addCodeRef(i_address, target, by_jump=True)
        # an unconditional branch does not fall through
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _recordDataRefs(d, instruction, state):
        i_address, i_size, i_mnemonic, _i_op_str = instruction
        if i_mnemonic in CALL_INS or i_mnemonic in RET_INS or i_mnemonic in EXCEPTION_RETURN_INS:
            return
        if i_mnemonic in END_INS or i_mnemonic in ALWAYS_BRANCH_INS or i_mnemonic in UNCOND_JUMP_INS:
            return
        if i_mnemonic.startswith("b.") or i_mnemonic in COND_BRANCH_INS or i_mnemonic in INDIRECT_JUMP_INS:
            return

        ins_bytes = d.disassembly.getBytes(i_address, i_size)
        if not ins_bytes or len(ins_bytes) != i_size:
            return
        detailed = next(d.capstone.disasm(ins_bytes, i_address), None)
        if detailed is None:
            return
        binary_info = d.disassembly.binary_info
        emitted = set()
        for operand in detailed.operands:
            value = None
            if operand.type == ARM64_OP_IMM:
                value = operand.imm
            elif operand.type == ARM64_OP_MEM and operand.mem.base == 0:
                value = operand.mem.disp
            if value is None or value in emitted:
                continue
            if d.disassembly.isAddrWithinMemoryImage(value) and not binary_info.isInCodeAreas(value):
                emitted.add(value)
                state.addDataRef(i_address, value)

    @staticmethod
    def _getPltRanges(binary_info):
        if not hasattr(binary_info, "_plt_ranges"):
            binary_info._plt_ranges = ElfFileLoader.getPltRanges(
                binary_info.raw_data or binary_info.binary,
                parsed=binary_info.getLiefBinary(),
            )
        return binary_info._plt_ranges

    @classmethod
    def _resolvePltGotSlot(cls, d, target):
        binary_info = d.disassembly.binary_info
        if not any(start <= target < end for start, end in cls._getPltRanges(binary_info)):
            return None

        cursor = target
        for _ in range(2):
            prefix = cls._wordAt(d, cursor)
            if prefix is None:
                return None
            if prefix == NOP or is_bti_landing_pad(prefix):
                cursor += INSTRUCTION_SIZE
                continue
            break

        registers = {}
        for index in range(4):
            addr = cursor + index * INSTRUCTION_SIZE
            word = cls._wordAt(d, addr)
            if word is None:
                return None

            rd = word & 0x1F
            if (word & ADRP_MASK) == ADRP_VALUE:
                registers[rd] = adrp_page_value(word, addr)
            elif (word & ADD_IMM64_MASK) == ADD_IMM64_VALUE:
                rn = (word >> 5) & 0x1F
                if rn not in registers:
                    return None
                registers[rd] = registers[rn] + ((word >> 10) & 0xFFF)
            elif (word & _LDR_UNSIGNED_64_MASK) == _LDR_UNSIGNED_64_VALUE:
                rn = (word >> 5) & 0x1F
                if rn not in registers:
                    return None
                registers[rd] = registers[rn] + (((word >> 10) & 0xFFF) * 8)
            elif (word & BR_MASK) == BR_VALUE:
                rn = (word >> 5) & 0x1F
                return registers.get(rn)
            else:
                return None
        return None

    # --- engine entry point ----------------------------------------------
    def analyzeInstruction(self, disassembler, instruction, state, previous_instruction, start_addr):
        del start_addr
        d = disassembler
        i_address, _i_size, i_mnemonic, i_op_str = instruction
        # capstone arm64 mnemonics carry no prefixes, so the mnemonic is used as-is.

        self._recordDataRefs(d, instruction, state)

        if previous_instruction and previous_instruction[2] == "bl":
            boundary = self._callFallthroughFunctionStart(d, i_address)
            if boundary is not None:
                d.fc_manager.addTailcallCandidate(boundary)
                self._cutFunctionBeforeInstruction(state, previous_instruction[0], i_address)
                return True

        # Ordered, first-match-wins classifier (verified against capstone arm64).
        if i_mnemonic in RET_INS or i_mnemonic in EXCEPTION_RETURN_INS:
            # function return / exception-level return (incl. PAC retaa/retab, eret*)
            self._endFunction(state)
            LOGGER.debug("  analyzeFunction() found return @0x%08x", i_address)
        elif i_mnemonic in CALL_INS:
            state.setLeaf(False)
            if i_mnemonic == "bl":
                target = self._branchTarget(i_op_str)
                if target is not None:
                    got_slot = self._resolvePltGotSlot(d, target)
                    if got_slot is not None and d._handleApiTarget(i_address, got_slot, got_slot):
                        state.addCodeRef(i_address, target)
                    else:
                        d._handleCallTarget(state, i_address, target)
            else:
                # blr and the PAC indirect calls (blraa/blrab/blraaz/blrabz): the
                # target lives in a register, resolved by a future iterate-step.
                state.call_register_ins.append(i_address)
            # a call falls through: not block-ending, next instruction stays reachable
        elif i_mnemonic in END_INS:
            self._endFunction(state)
            LOGGER.debug("  analyzeFunction() found trap terminator @0x%08x", i_address)
        elif i_mnemonic in ALWAYS_BRANCH_INS:
            # b.al / b.nv are spelled b.<cond> but always branch (no fall-through),
            # so they are unconditional. Must precede the generic "b." test below.
            self._analyzeUncondBranch(d, instruction, state)
        elif i_mnemonic.startswith("b.") or i_mnemonic in COND_BRANCH_INS:
            self._analyzeCondBranch(d, instruction, state)
        elif i_mnemonic in UNCOND_JUMP_INS:
            self._analyzeUncondBranch(d, instruction, state)
        elif i_mnemonic in INDIRECT_JUMP_INS:
            # br and the PAC indirect jumps (braa/brab/braaz/brabz): indirect
            # branch; successor(s) unresolved in v1.
            state.setNextInstructionReachable(False)
            state.setBlockEndingInstruction(True)
        # else: SEQUENTIAL — engine books it and continues to the next instruction.
        return False
