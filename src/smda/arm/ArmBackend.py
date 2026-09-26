#!/usr/bin/python

import logging
import re

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs

from smda.common.arch.ArchBackend import ArchBackend

from .analyzers import ArmIndirectCallAnalyzer, ArmJumpTableAnalyzer, ArmTfIdf, resolveImportStub
from .definitions import (
    A32_INSTRUCTION_SIZE,
    A32_NOPS,
    BRANCH_BASES,
    CALL_BASES,
    COMPARE_BRANCH_BASES,
    EXCEPTION_RETURN_BASES,
    IT_MNEMONICS,
    LOAD_MULTIPLE_BASES,
    PC_WRITING_BASES,
    REGISTER_BRANCH_BASES,
    T16_INSTRUCTION_SIZE,
    T16_NOPS,
    TABLE_BRANCH_BASES,
    TRAP_BASES,
    is_a32_prologue,
    is_t32_prologue,
    split_mnemonic,
)
from .FunctionAnalysisState import FunctionAnalysisState
from .FunctionCandidateManager import FunctionCandidateManager

LOGGER = logging.getLogger(__name__)

_HEX_OPERAND = re.compile(r"#(0x[0-9a-fA-F]+|\d+)$")
#: a literal-pool access: ``[pc]`` or ``[pc, #imm]`` (A8.8.64 LDR (literal) and friends)
_PC_LITERAL = re.compile(r"\[pc(?:, #(-?(?:0x[0-9a-fA-F]+|\d+)))?\]")
_IMMEDIATE = re.compile(r"#(-?(?:0x[0-9a-fA-F]+|\d+))")
#: literal loads and the width of the datum each one reads
_LITERAL_LOAD_SIZES = {
    "ldr": 4,
    "ldrb": 1,
    "ldrsb": 1,
    "ldrh": 2,
    "ldrsh": 2,
    "ldrd": 8,
    "vldr": 8,
    "pld": 0,
    "pli": 0,
}
_WIDTH_QUALIFIERS = (".w", ".n")


class ArmCapstone:
    """One capstone handle per instruction set, switched per function by the disassembler.

    The engine holds a single ``capstone`` attribute and decodes a small window at a time;
    this wrapper gives it the A32 or T32 decoder the current function needs and keeps T32
    IT blocks intact across window boundaries. Capstone only applies an IT instruction's
    conditions to the instructions decoded in the same call, so a window that opens inside
    an IT block is decoded again from the ``it`` itself and the already-seen part dropped.
    """

    def __init__(self):
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.arm.detail = True
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.thumb.detail = True
        self.is_thumb = False
        self.binary_info = None
        self._it_anchor = None
        self._it_remaining = 0
        self._next_address = None

    @property
    def detail(self):
        return True

    def setThumb(self, is_thumb):
        self.is_thumb = bool(is_thumb)
        self._it_remaining = 0
        self._next_address = None

    def current(self):
        return self.thumb if self.is_thumb else self.arm

    def disasm(self, code, offset, count=0):
        return self.current().disasm(code, offset, count)

    def disasm_lite(self, code, offset, count=0):
        engine = self.current()
        binary_info = self.binary_info
        if (
            self.is_thumb
            and self._it_remaining
            and offset == self._next_address
            and binary_info is not None
            and self._it_anchor is not None
        ):
            start = self._it_anchor - binary_info.base_addr
            end = offset - binary_info.base_addr + len(code)
            if 0 <= start < end:
                return self._track(engine.disasm_lite(binary_info.binary[start:end], self._it_anchor), offset)
        self._it_remaining = 0
        return self._track(engine.disasm_lite(code, offset, count), offset)

    def _track(self, instructions, offset):
        for ins in instructions:
            if ins[0] < offset:
                continue
            if self.is_thumb:
                if ins[2] in IT_MNEMONICS:
                    self._it_anchor = ins[0]
                    self._it_remaining = len(ins[2]) - 1
                elif self._it_remaining:
                    self._it_remaining -= 1
            self._next_address = ins[0] + ins[1]
            yield ins


class ArmBackend(ArchBackend):
    """AArch32 backend: A32 and T32 (Thumb-2) decoding, interworking and CFG classification.

    Each function is decoded in one instruction set, chosen per entry by the candidate
    manager from the strongest evidence it holds (symbol and pointer bit 0, mapping
    symbols, the instruction that reached it, then the surrounding code). Control flow is
    classified from the capstone mnemonic split into base and condition (A8.3): any
    control transfer carrying a condition other than AL keeps its fall-through.

    A transfer is anything that writes pc (A2.3): the branch instructions, ``bx``/``blx``,
    a load or block load with pc as a destination and a data-processing instruction whose
    destination is pc. Returns are ``bx lr``, ``mov pc, lr`` and a load of pc from the stack
    (``pop {..., pc}``, ``ldm sp!, {..., pc}``, ``ldr pc, [sp], #4``); an ``ldm`` naming pc
    from any other base, as the APCS ``ldmdb fp, {..., pc}`` epilogue does, is also a return.
    """

    name = "arm"
    max_instruction_size = A32_INSTRUCTION_SIZE

    # --- collaborator factories ------------------------------------------
    def createCapstone(self, bitness):
        del bitness
        return ArmCapstone()

    def createTfIdf(self, bitness):
        return ArmTfIdf(bitness=bitness)

    def createCandidateManager(self, config):
        return FunctionCandidateManager(config)

    def createAnalysisState(self, start_addr, disassembly):
        return FunctionAnalysisState(start_addr, disassembly)

    def createJumpTableAnalyzer(self, disassembler):
        return ArmJumpTableAnalyzer(disassembler)

    def createIndirectCallAnalyzer(self, disassembler):
        return ArmIndirectCallAnalyzer(disassembler)

    def probeBitness(self, disassembly):
        del disassembly
        return 32

    # --- helpers ----------------------------------------------------------
    @staticmethod
    def _immediateTarget(op_str):
        match = _HEX_OPERAND.search(op_str)
        if match is None:
            return None
        return int(match.group(1), 0)

    @staticmethod
    def _endFunction(state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _endBlockKeepingFallthrough(state, i_address, i_size):
        # a conditional transfer without a label (a conditional return or register branch)
        # still has two successors; marking the fall-through as a jump target is what makes
        # getBlocks() start a new block there
        fallthrough = i_address + i_size
        state.addCodeRef(i_address, fallthrough, by_jump=True)
        state.addBlockToQueue(fallthrough)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _isKnownFunctionStart(d, addr):
        return addr in d.disassembly.functions or addr in d.fc_manager.getStrongFunctionStarts()

    def _callFallthroughFunctionStart(self, d, addr, thumb):
        """The function start a call's fall-through actually is, or None.

        A call to a function that does not return is the last instruction of its caller;
        without a return to stop at, decoding would run on into the next function and merge
        the two. The next function announces itself by independent evidence (a symbol, an
        exception record, an inbound call) or, after padding, by an entry prologue.
        """
        if self._isKnownFunctionStart(d, addr):
            return addr
        cursor = addr
        skipped = False
        for _ in range(8):
            if thumb:
                halfword = self._halfwordAt(d, cursor)
                if halfword not in T16_NOPS and halfword != 0:
                    break
                cursor += T16_INSTRUCTION_SIZE
            else:
                word = self._wordAt(d, cursor)
                if word not in A32_NOPS and word != 0:
                    break
                cursor += A32_INSTRUCTION_SIZE
            skipped = True
        if not skipped:
            return None
        if self._isKnownFunctionStart(d, cursor):
            return cursor
        if thumb and cursor % 4 == 0 and is_t32_prologue(self._halfwordAt(d, cursor), self._halfwordAt(d, cursor + 2)):
            return cursor
        if not thumb and cursor % 4 == 0 and is_a32_prologue(self._wordAt(d, cursor) or 0):
            return cursor
        return None

    @staticmethod
    def _bytesAt(d, addr, size):
        if not d.disassembly.isAddrWithinMemoryImage(addr):
            return None
        offset = addr - d.disassembly.binary_info.base_addr
        data = d.disassembly.binary_info.binary[offset : offset + size]
        return data if len(data) == size else None

    @classmethod
    def _wordAt(cls, d, addr):
        data = cls._bytesAt(d, addr, 4)
        return None if data is None else int.from_bytes(data, "little")

    @classmethod
    def _halfwordAt(cls, d, addr):
        data = cls._bytesAt(d, addr, 2)
        return None if data is None else int.from_bytes(data, "little")

    @staticmethod
    def _cutFunctionBeforeInstruction(state, previous_address, current_address):
        state.removeCodeRef(previous_address, current_address)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)
        state.endBlock()
        state.setSanelyEnding(True)

    # --- references ---------------------------------------------------------
    def _recordDataRefs(self, d, instruction, state, base, thumb):
        """Literal-pool loads, ``adr``, ``movw``/``movt`` pairs and the ``add rd, pc`` of PIC code.

        The pool word a literal load reads is data inside the code section; recording it
        keeps the gap scan from decoding it as an instruction. A word that holds an address
        of data is recorded as a reference as well, which is how string references are
        reached on ARM, and one that points into code is offered as a function candidate
        in the instruction set its bit 0 names.
        """
        i_address, _i_size, i_mnemonic, i_op_str = instruction
        pending = state.arm_pending
        if "pc" in i_op_str:
            literal = _PC_LITERAL.search(i_op_str)
            if literal is not None and base in _LITERAL_LOAD_SIZES and "!" not in i_op_str:
                size = _LITERAL_LOAD_SIZES[base]
                offset = int(literal.group(1), 0) if literal.group(1) else 0
                pool = ((i_address + 4) & ~3 if thumb else i_address + 8) + offset
                if size and d.disassembly.isAddrWithinMemoryImage(pool):
                    state.addDataRef(i_address, pool, size=size)
                    if size == 4:
                        value = self._wordAt(d, pool)
                        destination = i_op_str.split(",", 1)[0].strip()
                        if value is not None:
                            self._recordValue(d, state, i_address, value, allow_code=destination != "pc")
                            pending[destination] = value
                return
            if base in ("add", "sub", "adr") and not i_op_str.startswith("pc"):
                self._recordPcRelative(d, instruction, state, base, thumb, pending)
                return
        if base == "adr":
            immediate = _IMMEDIATE.search(i_op_str)
            if immediate is not None:
                value = ((i_address + 4) & ~3 if thumb else i_address + 8) + int(immediate.group(1), 0)
                self._recordValue(d, state, i_address, value)
            return
        if base in ("movw", "movt", "mov"):
            destination, _, source = i_op_str.partition(",")
            destination = destination.strip()
            immediate = _IMMEDIATE.fullmatch(source.strip())
            if immediate is None:
                pending.pop(destination, None)
                return
            value = int(immediate.group(1), 0) & 0xFFFF
            if base == "movt":
                low = state.arm_movw.pop(destination, None)
                if low is not None:
                    value = (value << 16) | low
                    pending[destination] = value
                    self._recordValue(d, state, i_address, value)
                return
            if base == "movw":
                state.arm_movw[destination] = value
            pending.pop(destination, None)
            return
        if pending:
            destination = i_op_str.split(",", 1)[0].strip()
            pending.pop(destination, None)

    def _recordPcRelative(self, d, instruction, state, base, thumb, pending):
        i_address, _i_size, _i_mnemonic, i_op_str = instruction
        operands = [operand.strip() for operand in i_op_str.split(",")]
        if len(operands) == 3 and operands[1] == "pc" and operands[2].startswith("#"):
            immediate = int(operands[2][1:], 0)
            value = (i_address + 4) & ~3 if thumb else i_address + 8
            value = value + immediate if base == "add" else value - immediate
            self._recordValue(d, state, i_address, value)
            pending.pop(operands[0], None)
            return
        if base != "add":
            return
        if len(operands) == 2 and operands[1] == "pc":
            register = operands[0]
        elif len(operands) == 3 and operands[1] == "pc" and operands[2] in pending:
            register = operands[2]
        elif len(operands) == 3 and operands[2] == "pc" and operands[1] in pending:
            register = operands[1]
        else:
            return
        literal = pending.pop(register, None)
        pending.pop(operands[0], None)
        if literal is None:
            return
        value = (literal + (i_address + 4 if thumb else i_address + 8)) & 0xFFFFFFFF
        self._recordValue(d, state, i_address, value)
        pending[operands[0]] = value

    @staticmethod
    def _recordValue(d, state, i_address, value, allow_code=True):
        value &= 0xFFFFFFFF
        disassembly = d.disassembly
        if not disassembly.isAddrWithinMemoryImage(value & ~1):
            return
        binary_info = disassembly.binary_info
        if not binary_info.isInCodeAreas(value & ~1):
            state.addDataRef(i_address, value)
        elif allow_code:
            d.fc_manager.addPointerCandidate(value, i_address)

    # --- control flow -------------------------------------------------------
    def _analyzeCall(self, d, instruction, state, base, thumb):
        i_address, _i_size, _i_mnemonic, i_op_str = instruction
        state.setLeaf(False)
        target = self._immediateTarget(i_op_str)
        if target is None:
            state.call_register_ins.append(i_address)
            return
        target_thumb = thumb if base == "bl" else not thumb
        slot = self._resolvePltSlot(d, target)
        if slot is not None and d._handleApiTarget(i_address, slot, slot, slot=slot):
            state.addCodeRef(i_address, target)
            return
        d.fc_manager.addCallCandidate(target, target_thumb, i_address)
        d._handleCallTarget(state, i_address, target)

    def _analyzeCondBranch(self, d, instruction, state, target):
        i_address, i_size, _i_mnemonic, _i_op_str = instruction
        state.addBlockToQueue(i_address + i_size)
        d.tailcall_analyzer.addJump(i_address, target)
        if target in d.disassembly.functions:
            state.setSanelyEnding(True)
        else:
            state.addBlockToQueue(target)
        state.addCodeRef(i_address, target, by_jump=True)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _restoresLinkRegister(previous_instruction):
        """Whether the instruction before a branch reloads lr from the stack: the frame is
        gone and the return address is the caller's again, so the branch is a tailcall."""
        if not previous_instruction:
            return False
        base, condition, _ = split_mnemonic(previous_instruction[2])
        if condition not in (None, "al"):
            return False
        op_str = previous_instruction[3]
        if base == "pop" or (base in LOAD_MULTIPLE_BASES and op_str.startswith("sp!")):
            return "lr" in ArmBackend._registerList(op_str)
        return base == "ldr" and op_str.startswith("lr, [sp], #")

    def _isPrologueCandidate(self, d, target):
        candidate = d.fc_manager.getFunctionCandidate(target)
        return candidate is not None and candidate.hasCommonFunctionStart()

    def _analyzeUncondBranch(self, d, instruction, state, target, thumb, previous_instruction=None):
        i_address, _i_size, _i_mnemonic, _i_op_str = instruction
        d.tailcall_analyzer.addJump(i_address, target)
        if target in d.disassembly.functions:
            state.setSanelyEnding(True)
        elif target in d.fc_manager.getStrongFunctionStarts():
            # an entry the image or a call instruction vouches for: a tailcall
            state.setSanelyEnding(True)
        else:
            slot = self._resolvePltSlot(d, target)
            if slot is not None and d._handleApiTarget(i_address, slot, slot, slot=slot):
                state.setSanelyEnding(True)
            elif (
                state.isFirstInstruction()
                or target < state.start_addr
                or self._restoresLinkRegister(previous_instruction)
                or self._isPrologueCandidate(d, target)
                or self._isVeneer(d, target, thumb)
            ):
                # a lone branch is a stub into another function; so is a branch that follows
                # the frame teardown, or lands on code before the entry, on an entry
                # prologue or in a linker veneer
                d.fc_manager.addTailcallCandidate(target, thumb)
                state.setSanelyEnding(True)
            else:
                state.addBlockToQueue(target)
        state.addCodeRef(i_address, target, by_jump=True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _analyzeIndirectJump(self, d, instruction, state, conditional):
        i_address, i_size, _i_mnemonic, _i_op_str = instruction
        stub = resolveImportStub(d, state.start_addr, d.capstone.is_thumb)
        if stub is not None and stub[0] == i_address + i_size:
            state.setThunkCall(True)
            if stub[1] is not None and d._handleApiTarget(i_address, stub[1], stub[2], slot=stub[1]):
                state.setSanelyEnding(True)
            elif stub[1] is None and self._isCodeAddress(d, stub[2] & ~1):
                d.fc_manager.addTailcallCandidate(stub[2] & ~1, bool(stub[2] & 1))
                state.addCodeRef(i_address, stub[2] & ~1, by_jump=True)
                state.setSanelyEnding(True)
        else:
            targets = d.jumptable_analyzer.getJumpTargets(instruction, state)
            for target in targets:
                if d.disassembly.isAddrWithinMemoryImage(target):
                    state.addBlockToQueue(target)
                    state.addCodeRef(i_address, target, by_jump=True)
            if not targets:
                state.arm_indirect_jumps.append(i_address)
                state.setSanelyEnding(True)
        if conditional:
            self._endBlockKeepingFallthrough(state, i_address, i_size)
        else:
            state.setNextInstructionReachable(False)
            state.setBlockEndingInstruction(True)

    @staticmethod
    def _registerList(op_str):
        start = op_str.find("{")
        end = op_str.find("}", start)
        if start < 0 or end < 0:
            return ()
        return tuple(reg.strip() for reg in op_str[start + 1 : end].split(","))

    def _analyzeReturn(self, state, instruction, conditional):
        i_address, i_size, _i_mnemonic, _i_op_str = instruction
        if conditional:
            state.setSanelyEnding(True)
            self._endBlockKeepingFallthrough(state, i_address, i_size)
        else:
            self._endFunction(state)

    @staticmethod
    def _isCodeAddress(d, addr):
        return d.disassembly.isAddrWithinMemoryImage(addr) and d.fc_manager._passesCodeFilter(addr)

    def _isVeneer(self, d, target, thumb):
        stub = resolveImportStub(d, target, thumb)
        return stub is not None and stub[1] is None and self._isCodeAddress(d, stub[2] & ~1)

    def _resolvePltSlot(self, d, target):
        binary_info = d.disassembly.binary_info
        if not any(start <= target < end for start, end in self._getImportStubRanges(binary_info)):
            return None
        stub = resolveImportStub(d, target, d.fc_manager.isThumb(target))
        return stub[1] if stub is not None else None

    # --- engine entry point ----------------------------------------------
    def analyzeInstruction(self, disassembler, instruction, state, previous_instruction, start_addr):
        del start_addr
        d = disassembler
        i_address, i_size, i_mnemonic, i_op_str = instruction
        thumb = d.capstone.is_thumb
        base, condition, _sets_flags = split_mnemonic(i_mnemonic)
        conditional = condition is not None and condition != "al"
        if previous_instruction is None:
            state.arm_pending.clear()
            state.arm_movw.clear()

        self._recordDataRefs(d, instruction, state, base, thumb)

        if previous_instruction is not None:
            previous_base, previous_condition, _ = split_mnemonic(previous_instruction[2])
            if (
                previous_base in ("bl", "blx")
                and previous_condition in (None, "al")
                and self._immediateTarget(previous_instruction[3]) is not None
            ):
                if i_address in state.data_bytes or i_address in d.disassembly.data_map:
                    # the call is followed by a literal this code loads: the callee does not
                    # return, and the compiler placed the pool straight after the call
                    self._cutFunctionBeforeInstruction(state, previous_instruction[0], i_address)
                    return True
                boundary = self._callFallthroughFunctionStart(d, i_address, thumb)
                if boundary is not None:
                    if d.config.RESOLVE_TAILCALLS:
                        d.fc_manager.addTailcallCandidate(boundary, thumb)
                    self._cutFunctionBeforeInstruction(state, previous_instruction[0], i_address)
                    return True

        if base in BRANCH_BASES:
            target = self._immediateTarget(i_op_str)
            if target is None:
                return False
            if conditional:
                self._analyzeCondBranch(d, instruction, state, target)
            else:
                self._analyzeUncondBranch(d, instruction, state, target, thumb, previous_instruction)
        elif base in COMPARE_BRANCH_BASES:
            target = self._immediateTarget(i_op_str)
            if target is not None:
                self._analyzeCondBranch(d, instruction, state, target)
        elif base in CALL_BASES:
            self._analyzeCall(d, instruction, state, base, thumb)
            if conditional:
                # a conditional call still falls through; nothing else to do
                pass
        elif base in REGISTER_BRANCH_BASES:
            if i_op_str == "lr":
                self._analyzeReturn(state, instruction, conditional)
            elif self._isLinkedBranch(previous_instruction):
                state.setLeaf(False)
                state.call_register_ins.append(i_address)
            else:
                self._analyzeIndirectJump(d, instruction, state, conditional)
        elif base in TABLE_BRANCH_BASES:
            self._analyzeIndirectJump(d, instruction, state, conditional)
        elif base in LOAD_MULTIPLE_BASES:
            registers = self._registerList(i_op_str)
            if "pc" in registers:
                if i_mnemonic.endswith("^") or i_op_str.endswith("^"):
                    self._endFunction(state)
                else:
                    self._analyzeReturn(state, instruction, conditional)
        elif base in PC_WRITING_BASES and i_op_str.startswith("pc,"):
            self._analyzePcWrite(d, instruction, state, base, conditional, previous_instruction)
        elif base in TRAP_BASES or base in EXCEPTION_RETURN_BASES:
            if conditional:
                self._endBlockKeepingFallthrough(state, i_address, i_size)
            else:
                self._endFunction(state)
        return False

    @staticmethod
    def _isLinkedBranch(previous_instruction):
        """Whether the previous instruction set lr for this transfer to return to.

        Before BLX <register> existed (ARMv5T), an indirect call was ``mov lr, pc``
        followed by a ``bx`` or pc-writing load; in A32 pc reads as the ``mov``'s address
        plus 8, which is exactly the instruction after the branch.
        """
        if previous_instruction is None:
            return False
        base, _condition, _ = split_mnemonic(previous_instruction[2])
        return base == "mov" and previous_instruction[3].replace(" ", "") == "lr,pc"

    def _analyzePcWrite(self, d, instruction, state, base, conditional, previous_instruction):
        i_address, i_size, _i_mnemonic, i_op_str = instruction
        operands = [operand.strip() for operand in i_op_str.split(",")]
        if self._isLinkedBranch(previous_instruction):
            state.setLeaf(False)
            state.call_register_ins.append(i_address)
            return
        if base == "mov" and operands[1:] == ["lr"]:
            self._analyzeReturn(state, instruction, conditional)
            return
        if base == "ldr" and len(operands) >= 2 and operands[1].startswith("[sp"):
            self._analyzeReturn(state, instruction, conditional)
            return
        if _sets_flags_to_pc(instruction) and "lr" in operands[1:]:
            # subs pc, lr, #imm / movs pc, lr: exception return (B9.3.20)
            self._endFunction(state)
            return
        if base == "ldr" and len(operands) == 2 and _PC_LITERAL.fullmatch(operands[1]):
            # ldr pc, [pc, #imm]: an absolute branch through the literal pool (veneers)
            thumb = d.capstone.is_thumb
            offset = _PC_LITERAL.fullmatch(operands[1]).group(1)
            pool = ((i_address + 4) & ~3 if thumb else i_address + 8) + (int(offset, 0) if offset else 0)
            value = self._wordAt(d, pool)
            if value is not None and d.disassembly.isAddrWithinMemoryImage(value & ~1):
                target = value & ~1
                d.fc_manager.addTailcallCandidate(target, bool(value & 1))
                state.addCodeRef(i_address, target, by_jump=True)
                if conditional:
                    self._endBlockKeepingFallthrough(state, i_address, i_size)
                else:
                    self._endFunction(state)
                return
        self._analyzeIndirectJump(d, instruction, state, conditional)


def _sets_flags_to_pc(instruction):
    mnemonic = instruction[2]
    base, _condition, sets_flags = split_mnemonic(mnemonic)
    return sets_flags and base in ("sub", "mov", "add", "rsb", "and", "orr", "eor", "bic", "mvn", "adc", "sbc", "rsc")
