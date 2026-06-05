#!/usr/bin/python

import logging
import re

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from smda.common.arch.ArchBackend import ArchBackend

from .analyzers import AArch64IndirectCallAnalyzer, AArch64JumpTableAnalyzer, AArch64TfIdf
from .definitions import (
    ALWAYS_BRANCH_INS,
    CALL_INS,
    COND_BRANCH_INS,
    END_INS,
    EXCEPTION_RETURN_INS,
    INDIRECT_JUMP_INS,
    INSTRUCTION_SIZE,
    NOP,
    PACIASP,
    RET_INS,
    STP_FP_LR_PREINDEX_MASK,
    STP_FP_LR_PREINDEX_VALUE,
    UNCOND_JUMP_INS,
)
from .FunctionAnalysisState import FunctionAnalysisState
from .FunctionCandidateManager import FunctionCandidateManager

LOGGER = logging.getLogger(__name__)

# capstone renders AArch64 immediates as "#0x....": match the hex operands.
_HEX_OPERAND = re.compile(r"0x[0-9a-fA-F]+")


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
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

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
        return word == PACIASP or (word & STP_FP_LR_PREINDEX_MASK) == STP_FP_LR_PREINDEX_VALUE

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

    # --- engine entry point ----------------------------------------------
    def analyzeInstruction(self, disassembler, instruction, state, previous_instruction, start_addr):
        del start_addr
        d = disassembler
        i_address, _i_size, i_mnemonic, i_op_str = instruction
        # capstone arm64 mnemonics carry no prefixes, so the mnemonic is used as-is.

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
