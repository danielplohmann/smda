#!/usr/bin/python

import logging

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.arch.ArchBackend import ArchBackend

from .BitnessAnalyzer import BitnessAnalyzer
from .definitions import (
    CALL_INS,
    CJMP_INS,
    JMP_INS,
    LOOP_INS,
    REGS_32BIT,
    REGS_64BIT,
    RET_INS,
)
from .FunctionAnalysisState import FunctionAnalysisState
from .FunctionCandidateManager import FunctionCandidateManager
from .IndirectCallAnalyzer import IndirectCallAnalyzer
from .JumpTableAnalyzer import JumpTableAnalyzer
from .MnemonicTfIdf import MnemonicTfIdf

LOGGER = logging.getLogger(__name__)


class X86Backend(ArchBackend):
    """x86/x64 backend: capstone setup, x86 collaborators and the x86 control-flow
    semantics (call/jmp/cond-jmp/loop/ret classification plus the push-ret,
    syscall-exit and alignment-after-call idioms) used by the recursive engine."""

    name = "intel"
    # maximum x86/x64 instruction size in bytes (used to size the look-ahead window)
    max_instruction_size = 15

    # --- collaborator factories ------------------------------------------
    def createCapstone(self, bitness):
        return Cs(CS_ARCH_X86, CS_MODE_64) if bitness == 64 else Cs(CS_ARCH_X86, CS_MODE_32)

    def createTfIdf(self, bitness):
        return MnemonicTfIdf(bitness=64) if bitness == 64 else MnemonicTfIdf(bitness=32)

    def createCandidateManager(self, config):
        return FunctionCandidateManager(config)

    def createAnalysisState(self, start_addr, disassembly):
        return FunctionAnalysisState(start_addr, disassembly)

    def createJumpTableAnalyzer(self, disassembler):
        return JumpTableAnalyzer(disassembler)

    def createIndirectCallAnalyzer(self, disassembler):
        return IndirectCallAnalyzer(disassembler)

    def probeBitness(self, disassembly):
        return BitnessAnalyzer().determineBitnessFromDisassembly(disassembly)

    # --- per-kind instruction analysis -----------------------------------
    def _analyzeCallInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        state.setLeaf(False)
        # case = "FALLTHROUGH"
        call_destination = d.getReferencedAddr(i_op_str)
        if ":" in i_op_str:
            # case = "LONG-CALL"
            pass
        if i_op_str.startswith("dword ptr ["):
            # reg+offset is currently ignored as it is a minority of calls
            # case = "DWORD-PTR-REG"
            if i_op_str.startswith("dword ptr [0x"):
                # case = "DWORD-PTR"
                dereferenced = d.disassembly.dereferenceDword(call_destination)
                if dereferenced is not None:
                    state.addCodeRef(i_address, dereferenced)
                    d._handleCallTarget(state, i_address, dereferenced)
                    d._handleApiTarget(i_address, call_destination, dereferenced)
        elif i_op_str.startswith("qword ptr [rip"):
            rip = i_address + i_size
            call_destination = rip + d.getReferencedAddr(i_op_str)
            dereferenced = d.disassembly.dereferenceQword(call_destination)
            state.addCodeRef(i_address, call_destination)
            if dereferenced is not None:
                d._handleApiTarget(i_address, call_destination, dereferenced)
        elif i_op_str.startswith("0x"):
            # case = "DIRECT"
            d._handleCallTarget(state, i_address, call_destination)
            d._handleApiTarget(i_address, call_destination, call_destination)
        elif i_op_str.lower() in REGS_32BIT or i_op_str.lower() in REGS_64BIT:
            # case = "REG"
            # this is resolved by backtracking at the end of function analysis.
            state.call_register_ins.append(i_address)

    def _analyzeCondJmpInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        state.addBlockToQueue(i_address + i_size)
        jump_destination = d.getReferencedAddr(i_op_str)
        # case = "FALLTHROUGH"
        d.tailcall_analyzer.addJump(i_address, jump_destination)
        if jump_destination:
            if jump_destination in d.disassembly.functions:
                # case = "TAILCALL!"
                state.setSanelyEnding(True)
            elif jump_destination in d.fc_manager.getFunctionStartCandidates():
                # it's tough to decide whether this should be disassembled here or not. topic of "code-sharing functions".
                # case = "TAILCALL?"
                pass
            else:
                # case = "OFFSET-QUEUE"
                state.addBlockToQueue(int(i_op_str, 16))
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        state.setBlockEndingInstruction(True)

    def _analyzeLoopInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        jump_destination = d.getReferencedAddr(i_op_str)
        if jump_destination:
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        # loops have two exits and should thus be handled as block ending instruction
        state.addBlockToQueue(i_address + i_size)
        state.setBlockEndingInstruction(True)

    def _analyzeJmpInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        # case = "FALLTHROUGH"
        if ":" in i_op_str:
            # case = "LONG-JMP"
            pass
        elif i_op_str.startswith("dword ptr [0x"):
            # case = "DWORD-PTR"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            jump_destination = d.getReferencedAddr(i_op_str)
            dereferenced = d.disassembly.dereferenceDword(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
            d.tailcall_analyzer.addJump(i_address, jump_destination)
            if dereferenced is not None:
                d._handleApiTarget(i_address, jump_destination, dereferenced)
        elif i_op_str.startswith("qword ptr [rip"):
            # case = "QWORD-PTR, RIP-relative"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            rip = i_address + i_size
            jump_destination = rip + d.getReferencedAddr(i_op_str)
            dereferenced = d.disassembly.dereferenceQword(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
            d.tailcall_analyzer.addJump(i_address, jump_destination)
            if dereferenced is not None:
                d._handleApiTarget(i_address, jump_destination, dereferenced)
        elif i_op_str.startswith("0x"):
            jump_destination = d.getReferencedAddr(i_op_str)
            d.tailcall_analyzer.addJump(i_address, jump_destination)
            if jump_destination in d.disassembly.functions:
                # case = "TAILCALL!"
                state.setSanelyEnding(True)
            elif jump_destination in d.fc_manager.getFunctionStartCandidates():
                # case = "TAILCALL?"
                pass
            else:
                if state.isFirstInstruction():
                    # case = "STUB-TAILCALL!"
                    pass
                else:
                    # case = "OFFSET-QUEUE"
                    state.addBlockToQueue(int(i_op_str, 16))
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        else:
            jumptable_targets = d.jumptable_analyzer.getJumpTargets(i, state)
            for target in jumptable_targets:
                if d.disassembly.isAddrWithinMemoryImage(target):
                    state.addBlockToQueue(target)
                    state.addCodeRef(i_address, target, by_jump=True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _analyzeEndInstruction(self, state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    # --- engine entry point ----------------------------------------------
    def analyzeInstruction(self, disassembler, instruction, state, previous_instruction, start_addr):
        d = disassembler
        i = instruction
        i_address, i_size, i_mnemonic, i_op_str = i
        if previous_instruction is not None:
            previous_address = previous_instruction[0]
            previous_mnemonic = previous_instruction[2].split(" ")[-1]
            previous_op_str = previous_instruction[3].strip()
        else:
            previous_address = None
            previous_mnemonic = None
            previous_op_str = None
        # remove potential "bnd" prefix
        i_mnemonic_noprefix = i_mnemonic.split(" ")[-1]
        if i_mnemonic_noprefix in CALL_INS:
            self._analyzeCallInstruction(d, i, state)
        elif i_mnemonic_noprefix in JMP_INS:
            self._analyzeJmpInstruction(d, i, state)
        elif i_mnemonic_noprefix in LOOP_INS:
            self._analyzeLoopInstruction(d, i, state)
        elif i_mnemonic_noprefix in CJMP_INS:
            self._analyzeCondJmpInstruction(d, i, state)
        elif i_mnemonic_noprefix.startswith("j"):
            LOGGER.error(
                "unsupported jump @0x%08x (0x%08x): %s %s",
                i_address,
                start_addr,
                i_mnemonic,
                i_op_str,
            )
            # we do not analyze any potential exception handler (tricks), so treat breakpoints as exit condition
        elif i_mnemonic_noprefix in RET_INS:
            self._analyzeEndInstruction(state)
            LOGGER.debug(
                "  analyzeFunction() found ending instruction @0x%08x",
                i_address,
            )
            if previous_address and previous_mnemonic == "push":
                push_ret_destination = d.getReferencedAddr(previous_op_str)
                if d.disassembly.isAddrWithinMemoryImage(push_ret_destination):
                    LOGGER.debug(
                        "  analyzeFunction() found push-return jump obfuscation: @0x%08x",
                        i_address,
                    )
                    state.addBlockToQueue(push_ret_destination)
                    state.addCodeRef(i_address, push_ret_destination, by_jump=True)
        elif i_mnemonic_noprefix in ["int3", "hlt"]:
            self._analyzeEndInstruction(state)
            LOGGER.debug(
                "  analyzeFunction() found ending instruction @0x%08x",
                i_address,
            )
        elif i_mnemonic_noprefix in ["syscall"]:
            if previous_address and previous_mnemonic == "mov":
                prev_operands = previous_op_str.split(",")
                if len(prev_operands) == 2:
                    reg = prev_operands[0].strip().lower()
                    if (d.disassembly.binary_info.bitness == 64 and reg == "rax") or (
                        d.disassembly.binary_info.bitness == 32 and reg == "eax"
                    ):
                        try:
                            syscall_number_str = int(prev_operands[1].strip(), 16)
                        except ValueError:
                            # TODO we should do backtracking on the basic block to resolve the value properly
                            LOGGER.debug(
                                "failed to extract syscall number from: %s at 0x%x",
                                prev_operands,
                                i_address,
                            )
                            syscall_number_str = None
                        if syscall_number_str == 60:
                            self._analyzeEndInstruction(state)
                            LOGGER.debug(
                                "  analyzeFunction() found program ending instruction @0x%08x",
                                i_address,
                            )
        elif previous_address and i_address != start_addr and previous_mnemonic == "call":
            instruction_sequence = list(d.capstone.disasm(d._getDisasmWindowBuffer(i_address), i_address))
            if (
                d.disassembly.language["_guess"] != "go" and d.fc_manager.isAlignmentSequence(instruction_sequence)
            ) or d.fc_manager.isFunctionCandidate(i_address):
                # LLVM and GCC sometimes tends to produce lots of tailcalls that basically mess with function end detection, we cut whenever we find effective nops after calls
                # however, Go tends to insert alignment NOPs after calls, too, but in this case, they are no tailcall indicator
                # apparently calls are frequently padded with NOPs, so one last chance to continue disassembly is when we already have instructions for our function beyond this call.
                if not any(disassembled_addr > i_address for disassembled_addr in state.instruction_start_bytes):
                    LOGGER.debug(
                        "    current function: 0x%x ---> ran into alignment sequence after call -> 0x%08x, cutting block here.",
                        start_addr,
                        i_address,
                    )
                    # remove next instruction from references
                    state.removeCodeRef(previous_address, i_address)
                    # end block
                    state.setBlockEndingInstruction(True)
                    state.endBlock()
                    state.setSanelyEnding(True)
                    if d.fc_manager.isAlignmentSequence(instruction_sequence):
                        next_aligned_address = previous_address + (16 - previous_address % 16)
                        LOGGER.debug(
                            "  Adding: 0x%x as candidate.",
                            next_aligned_address,
                        )
                        d.fc_manager.addCandidate(next_aligned_address, is_gap=True)
                    return True
                else:
                    LOGGER.debug(
                        "    current function: 0x%x ---> alignment sequence seems to just pad a call -> 0x%08x, NOT cutting block here.",
                        start_addr,
                        i_address,
                    )
        return False
