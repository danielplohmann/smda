#!/usr/bin/python

import logging

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.arch.ArchBackend import ArchBackend
from smda.utility.ElfFileLoader import ElfFileLoader

from .BitnessAnalyzer import BitnessAnalyzer
from .definitions import (
    CALL_INS,
    CJMP_INS,
    GAP_SEQUENCE_FIRST_BYTES,
    GAP_SEQUENCES,
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


SYSCALL_BACKTRACK_BOUNDARY = (
    set(CALL_INS)
    | set(JMP_INS)
    | set(CJMP_INS)
    | set(LOOP_INS)
    | set(RET_INS)
    | {"syscall", "sysenter", "int", "int3", "hlt"}
)

SYSCALL_IMPLICIT_RAX_WRITERS = {
    "cpuid",
    "rdtsc",
    "rdtscp",
    "rdmsr",
    "rdpmc",
    "xgetbv",
    "lodsb",
    "lodsw",
    "lodsd",
    "lodsq",
    "cbw",
    "cwde",
    "cdqe",
    "lahf",
    "xlat",
    "xlatb",
    "mul",
    "div",
    "idiv",
    "in",
    "ins",
    "insb",
    "insw",
    "insd",
    "cmpxchg",
    "cmpxchg8b",
    "cmpxchg16b",
    "aaa",
    "aas",
    "aad",
    "aam",
    "daa",
    "das",
}

SYSCALL_READ_ONLY_INS = {"cmp", "test", "push", "bt"}

# process-terminating syscall numbers (Linux x86_64 syscall convention: rax/eax)
SYSCALL_EXIT_NUMBERS = {60, 231}  # exit, exit_group
# process-terminating syscall numbers via the 32-bit ABI int 0x80 gate (always eax, even
# from a 64-bit process)
INT80_EXIT_NUMBERS = {1, 252}  # exit, exit_group

# hoisted membership tables for the per-instruction dispatch in analyzeInstruction()
_TRAP_TERMINATOR_INS = frozenset({"int3", "hlt"})
_SYSCALL_INS = frozenset({"syscall"})


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

    @staticmethod
    def _getElfGotBases(binary_info):
        if not hasattr(binary_info, "_elf_got_bases"):
            binary_info._elf_got_bases = ElfFileLoader.getGotBases(
                binary_info.raw_data or binary_info.binary,
                parsed=binary_info.getLiefBinary(),
            )
        return binary_info._elf_got_bases

    @classmethod
    def _resolveImportSlot(cls, d, target):
        binary_info = d.disassembly.binary_info
        if not any(start <= target < end for start, end in cls._getImportStubRanges(binary_info)):
            return None

        for address, size, mnemonic, op_str in d.capstone.disasm_lite(d._getDisasmWindowBuffer(target), target):
            mnemonic = mnemonic.split(" ")[-1]
            if mnemonic in ("endbr32", "endbr64", "nop"):
                continue
            if mnemonic != "jmp":
                return None
            if op_str.startswith("qword ptr [rip"):
                return address + size + d.getReferencedAddr(op_str)
            if op_str.startswith("dword ptr [0x"):
                return d.getReferencedAddr(op_str)
            if op_str.startswith("dword ptr [ebx"):
                displacement = d.getReferencedAddr(op_str)
                candidates = [base + displacement for base in cls._getElfGotBases(binary_info)]
                imported_functions = binary_info.getImportedFunctions() or {}
                return next((candidate for candidate in candidates if candidate in imported_functions), None)
            return None
        return None

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
            if dereferenced is not None and d.disassembly.isAddrWithinMemoryImage(dereferenced):
                # the slot holds an in-image target (thunk/local function): book the call
                # against the real destination, like the 32-bit dword-ptr path does
                state.addCodeRef(i_address, dereferenced)
                d._handleCallTarget(state, i_address, dereferenced)
                d._handleApiTarget(i_address, call_destination, dereferenced)
            else:
                # import-like case: keep the reference on the slot itself
                state.addCodeRef(i_address, call_destination)
                if dereferenced is not None:
                    d._handleApiTarget(i_address, call_destination, dereferenced)
        elif i_op_str.startswith("0x"):
            # case = "DIRECT"
            import_slot = self._resolveImportSlot(d, call_destination)
            if import_slot is not None and d._handleApiTarget(i_address, import_slot, import_slot):
                state.addCodeRef(i_address, call_destination)
            else:
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
            # loops are conditional branches: queue the taken edge as well
            state.addBlockToQueue(jump_destination)
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
                self._handleApiJumpTarget(d, state, i_address, jump_destination, dereferenced)
        elif i_op_str.startswith("qword ptr [rip"):
            # case = "QWORD-PTR, RIP-relative"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            rip = i_address + i_size
            jump_destination = rip + d.getReferencedAddr(i_op_str)
            dereferenced = d.disassembly.dereferenceQword(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
            d.tailcall_analyzer.addJump(i_address, jump_destination)
            if dereferenced is not None:
                self._handleApiJumpTarget(d, state, i_address, jump_destination, dereferenced)
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
                import_slot = self._resolveImportSlot(d, jump_destination)
                if import_slot is not None and self._handleApiJumpTarget(d, state, i_address, import_slot, import_slot):
                    # case = "STUB-TAILCALL-API!"
                    state.setSanelyEnding(True)
                elif state.isFirstInstruction():
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

    @staticmethod
    def _handleApiJumpTarget(d, state, instruction_addr, import_slot, dereferenced):
        resolved_api = d._handleApiTarget(instruction_addr, import_slot, dereferenced)
        if resolved_api and state.isFirstInstruction():
            # the entire function body is this one jmp-to-import: a thunk, not a real routine
            state.setThunkCall(True)
        return resolved_api

    def _analyzeEndInstruction(self, state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _resolveSyscallNumber(self, preceding_instructions, bitness):
        """Conservatively recover the syscall-number register (rax on 64-bit,
        eax on 32-bit) by backtracking over the preceding block-local
        instructions.
        """
        if bitness == 64:
            # a 32-bit write (e.g. ``mov eax, 0x3c``) zero-extends into rax,
            # so eax also carries the syscall number on 64-bit.
            target_regs = ("rax", "eax")
            clobber_regs = ("rax", "eax", "ax", "al", "ah")
        else:
            target_regs = ("eax",)
            clobber_regs = ("eax", "ax", "al", "ah")
        for instruction in reversed(preceding_instructions):
            mnemonic = instruction[2].split(" ")[-1]
            if mnemonic in SYSCALL_BACKTRACK_BOUNDARY or mnemonic.startswith("j"):
                return None
            # instructions that implicitly modify rax/eax (no explicit destination
            # operand) must stop resolution, or a write could be silently skipped
            if mnemonic in SYSCALL_IMPLICIT_RAX_WRITERS:
                return None
            operands = [operand.strip().lower() for operand in instruction[3].split(",") if operand.strip()]
            # single-operand imul writes rdx:rax implicitly (the multi-operand
            # forms write only their explicit destination, handled below)
            if mnemonic == "imul" and len(operands) == 1:
                return None
            # xchg/xadd write both operands, so the target register being written is
            # not necessarily the first operand
            if mnemonic in ("xchg", "xadd") and any(operand in clobber_regs for operand in operands):
                return None
            # read-only instructions whose first operand is a source do not clobber
            if mnemonic in SYSCALL_READ_ONLY_INS:
                continue
            if not operands:
                # operand-less and not a known implicit writer (nop, cld, leave, ...)
                continue
            destination = operands[0]
            if destination not in clobber_regs:
                # this instruction does not touch the syscall register; keep going
                continue
            if mnemonic in ("mov", "movabs") and len(operands) == 2 and destination in target_regs:
                try:
                    # base 0 handles capstone's 0x-prefixed hex as well as decimal
                    return int(operands[1], 0)
                except ValueError:
                    # source is a register, memory operand, or expression -> unresolved
                    return None
            # any other write to the register family cannot be tracked conservatively
            return None
        return None

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
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug(
                    "  analyzeFunction() found ending instruction @0x%08x",
                    i_address,
                )
            if previous_address is not None and previous_mnemonic == "push":
                push_ret_destination = d.getReferencedAddr(previous_op_str)
                if d.disassembly.isAddrWithinMemoryImage(push_ret_destination):
                    LOGGER.debug(
                        "  analyzeFunction() found push-return jump obfuscation: @0x%08x",
                        i_address,
                    )
                    state.addBlockToQueue(push_ret_destination)
                    state.addCodeRef(i_address, push_ret_destination, by_jump=True)
        elif i_mnemonic_noprefix in _TRAP_TERMINATOR_INS:
            self._analyzeEndInstruction(state)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug(
                    "  analyzeFunction() found ending instruction @0x%08x",
                    i_address,
                )
        elif i_mnemonic_noprefix in _SYSCALL_INS:
            syscall_number = self._resolveSyscallNumber(state.current_block, d.disassembly.binary_info.bitness)
            if syscall_number in SYSCALL_EXIT_NUMBERS:
                self._analyzeEndInstruction(state)
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug(
                        "  analyzeFunction() found program ending instruction @0x%08x",
                        i_address,
                    )
        elif i_mnemonic_noprefix == "int" and i_op_str == "0x80":
            # int 0x80 is always the 32-bit ABI syscall gate (eax), even from a 64-bit process.
            # Backtrack with bitness=64 regardless: its register set (rax/eax/ax/al/ah) is a
            # strict superset of the 32-bit one, so it also catches a full-width "mov rax, N"
            # write that a 64-bit binary may still use before dropping into int 0x80 -- forcing
            # 32 here would drop "rax" from the clobber set and silently walk past that write.
            syscall_number = self._resolveSyscallNumber(state.current_block, 64)
            # int 0x80 only reads the low 32 bits (eax); truncate in case a full-width
            # "mov rax, N" write resolved a value wider than that (e.g. mov rax, 0x100000001).
            if syscall_number is not None and (syscall_number & 0xFFFFFFFF) in INT80_EXIT_NUMBERS:
                self._analyzeEndInstruction(state)
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug(
                        "  analyzeFunction() found program ending instruction @0x%08x",
                        i_address,
                    )
        elif previous_address is not None and i_address != start_addr and previous_mnemonic == "call":
            instruction_bytes = d._getDisasmWindowBuffer(i_address)
            # isAlignmentSequence can only return True when the FIRST decoded instruction's bytes
            # are in GAP_SEQUENCES (otherwise it breaks with instructions_analyzed == 0, and the
            # trailing-mnemonic check can only force False), so this byte-level test is a
            # necessary condition and rejecting on its negation cannot change any outcome.
            # Measured on the bundled fixtures: rejects 99.0% of 3616 calls with zero false rejects.
            has_alignment_sequence = False
            if instruction_bytes[:1] in GAP_SEQUENCE_FIRST_BYTES:
                for size, sequences in GAP_SEQUENCES.items():
                    if instruction_bytes[:size] in sequences:
                        instruction_sequence = list(d.capstone.disasm_lite(instruction_bytes, i_address))
                        has_alignment_sequence = d.fc_manager.isAlignmentSequence(
                            instruction_sequence, instruction_bytes
                        )
                        break
            is_alignment_evidence = getattr(d.disassembly, "language_guess", None) != "go" and has_alignment_sequence
            is_candidate_evidence = d.fc_manager.isFunctionCandidate(i_address)
            if is_alignment_evidence and not is_candidate_evidence and d.disassembly.binary_info._getLiefType() == "PE":
                if d.fc_manager.isHotpatchPrologue(instruction_bytes[:5]):
                    seed_address = i_address
                else:
                    seed_address = previous_address + (16 - previous_address % 16)
                # MSVC also int3/nop-pads mid-function (after noreturn calls, loop-head
                # alignment) on PE images, so alignment-only evidence (no candidate hit at
                # i_address) needs its seed to actually decode as a function entry before
                # cutting -- real PE starts are seeded by exports/pdata/candidates anyway.
                # Other formats keep the plain alignment cut: clang/GCC/Go pad between
                # real functions with prologue-less entries.
                if not d.fc_manager.hasCommonPrologue(seed_address):
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug(
                            "    current function: 0x%x ---> alignment sequence after call seeds non-entry-shaped 0x%08x, NOT cutting block at -> 0x%08x.",
                            start_addr,
                            seed_address,
                            i_address,
                        )
                    return False
            if is_alignment_evidence or is_candidate_evidence:
                # LLVM and GCC sometimes tends to produce lots of tailcalls that basically mess with function end detection, we cut whenever we find effective nops after calls
                # however, Go tends to insert alignment NOPs after calls, too, but in this case, they are no tailcall indicator
                # apparently calls are frequently padded with NOPs, so one last chance to continue disassembly is when we already have instructions for our function beyond this call.
                max_instruction_start = getattr(state, "max_instruction_start", None)
                if max_instruction_start is None:
                    max_instruction_start = max(state.instruction_start_bytes, default=-1)
                if max_instruction_start <= i_address:
                    if LOGGER.isEnabledFor(logging.DEBUG):
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
                    if has_alignment_sequence:
                        # A hotpatch stub right after a call can look like alignment padding
                        # (its leading `mov edi, edi` is an effective NOP), but that byte pair
                        # is the next function's true entry. Seed it directly rather than the
                        # 16-byte-rounded address, which would land two bytes late.
                        if d.fc_manager.isHotpatchPrologue(instruction_bytes[:5]):
                            next_candidate_address = i_address
                        else:
                            next_candidate_address = previous_address + (16 - previous_address % 16)
                        if LOGGER.isEnabledFor(logging.DEBUG):
                            LOGGER.debug(
                                "  Adding: 0x%x as candidate.",
                                next_candidate_address,
                            )
                        d.fc_manager.addCandidate(next_candidate_address, is_gap=True)
                    return True
                elif LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug(
                        "    current function: 0x%x ---> alignment sequence seems to just pad a call -> 0x%08x, NOT cutting block here.",
                        start_addr,
                        i_address,
                    )
        return False
