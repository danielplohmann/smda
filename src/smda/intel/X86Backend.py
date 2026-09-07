#!/usr/bin/python

import logging
import re

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
    MAX_GAP_SEQUENCE_LENGTH,
    REGS_32BIT,
    REGS_64BIT,
    RET_INS,
    stripFlatSegmentOverride,
)
from .FunctionAnalysisState import FunctionAnalysisState
from .FunctionCandidateManager import FunctionCandidateManager
from .IndirectCallAnalyzer import IndirectCallAnalyzer
from .JumpTableAnalyzer import JumpTableAnalyzer
from .MnemonicTfIdf import MnemonicTfIdf

LOGGER = logging.getLogger(__name__)

# what a toolchain that emits CET landing pads aligns a function entry to
_ENTRY_ALIGNMENT = 16

# a call/jmp through a pointer slot the sample computes itself ("dword ptr [ebx + 0x2c]"),
# the shape a runtime-built import table is used through. An index register is excluded on
# purpose: the slot is then not a single address, and those operands belong to jump tables.
# capstone prints a displacement below 10 as a bare decimal digit, so "[esi + 8]" - the most
# common slot stride - has no 0x prefix to match on.
# an absolute memory operand: "dword ptr [0x401000]", "[0x401000]". A base or index
# register, or a rip-relative displacement, makes the effective address unknown here, so
# those forms deliberately do not match.
# A bracket whose first character is a hex prefix or a lone decimal digit: the only two forms
# the full operand pattern below can accept. Scanning for that once over the whole operand
# string is cheaper than splitting it and matching each part, and this runs per instruction.
ABSOLUTE_OPERAND_HINT = re.compile(r"\[(?:0x|[0-9]\])")

ABSOLUTE_MEM_OPERAND_RE = re.compile(
    r"^(?:(?P<width>byte|word|dword|qword|xword|tbyte|xmmword|ymmword|zmmword) ptr )?"
    r"\[(?P<address>0x[0-9a-fA-F]{1,16}|[0-9])\]$"
)

# What each size keyword capstone prints is worth in bytes, so a reference covers the whole
# datum rather than only its first byte. Both 80-bit keywords are here and they are not
# interchangeable: capstone prints `xword ptr` for the x87 extended-precision operand of
# fld/fstp, and `tbyte ptr` only for the packed-BCD operand of fbld/fbstp. An operand capstone
# prints with no size keyword names no width, and stays at one byte.
_OPERAND_WIDTHS = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "xword": 10,
    "tbyte": 10,
    "xmmword": 16,
    "ymmword": 32,
    "zmmword": 64,
}

MEM_REG_SLOT_RE = re.compile(
    r"^(?P<size>dword|qword) ptr \[(?P<reg>[a-z][a-z0-9]{1,3})"
    r"(?: (?P<sign>[+-]) (?P<disp>0x[0-9a-f]{1,16}|[0-9]))?\]$"
)

# a load of an import slot into a register: "mov rax, qword ptr [rip + 0x...]" (64-bit) or
# "mov eax, dword ptr [0x...]" (32-bit). The memory operand must be the source - a store to a
# slot is IAT patching, which is a different fact and is deliberately not recorded here.
IMPORT_SLOT_LOAD_RE = re.compile(
    r"^[a-z][a-z0-9]{1,4}, (?P<size>dword|qword) ptr \[(?P<rip>rip [+-] )?0x[0-9a-f]{1,16}\]$"
)

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
    # capstone spells the 32-bit pop-all forms popal/popad and popaw; both restore eax
    # from the stack with no explicit operand, so nothing else here can see the write.
    "popal",
    "popaw",
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

_KIND_CALL, _KIND_JMP, _KIND_LOOP, _KIND_CJMP, _KIND_RET, _KIND_TRAP, _KIND_SYSCALL = range(7)
_KIND_TABLES = (
    (CALL_INS, _KIND_CALL),
    (JMP_INS, _KIND_JMP),
    (LOOP_INS, _KIND_LOOP),
    (CJMP_INS, _KIND_CJMP),
    (RET_INS, _KIND_RET),
    (_TRAP_TERMINATOR_INS, _KIND_TRAP),
    (_SYSCALL_INS, _KIND_SYSCALL),
)
# one lookup replaces the membership chain that 77% of instructions fell all the way through;
# collapsing to a single dict is only valid while the tables stay disjoint
_INS_KIND = {mnemonic: kind for table, kind in _KIND_TABLES for mnemonic in table}
if len(_INS_KIND) != sum(len(table) for table, _ in _KIND_TABLES):
    raise AssertionError("intel control-flow mnemonic tables overlap")


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
            op_str = stripFlatSegmentOverride(op_str)
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
        # case = "LONG-CALL": a far call names a segment and an offset. capstone separates
        # the pair with a comma for lcall (a colon only for ljmp), so the operand string
        # still starts with "0x" and the direct-call arm below would book a code ref to the
        # segment selector. There is no in-image target to book, so drop it like _analyzeJmp.
        if i_mnemonic.split(" ")[-1] == "lcall":
            return
        i_op_str = stripFlatSegmentOverride(i_op_str)
        # case = "LONG-CALL-INDIRECT": FF /3 loads a seg:offset pair from memory. capstone
        # renders it with a bare "ptr " where a near indirect call (FF /2) always names its
        # width, and that is the only difference between them once a segment override is
        # normalized away. No arm below claims it today; saying so keeps it that way.
        if i_op_str.startswith("ptr "):
            return
        call_destination = d.getReferencedAddr(i_op_str)
        if i_op_str.startswith("dword ptr ["):
            if i_op_str.startswith("dword ptr [0x"):
                # case = "DWORD-PTR"
                dereferenced = d.disassembly.dereferenceDword(call_destination)
                if dereferenced and d.disassembly.isAddrWithinMemoryImage(dereferenced):
                    state.addCodeRef(i_address, dereferenced)
                    d._handleCallTarget(state, i_address, dereferenced)
                    d._handleApiTarget(i_address, call_destination, dereferenced, slot=call_destination)
                else:
                    # import-like case: keep the reference on the slot itself
                    state.addCodeRef(i_address, call_destination)
                    if dereferenced is not None:
                        d._handleApiTarget(i_address, call_destination, dereferenced, slot=call_destination)
            else:
                # case = "DWORD-PTR-REG"
                self._collectMemRegSlot(state, i_address, i_op_str)
        elif i_op_str.startswith("qword ptr [rip"):
            rip = i_address + i_size
            call_destination = rip + d.getReferencedAddr(i_op_str)
            dereferenced = d.disassembly.dereferenceQword(call_destination)
            if dereferenced and d.disassembly.isAddrWithinMemoryImage(dereferenced):
                # the slot holds an in-image target (thunk/local function): book the call
                # against the real destination, like the 32-bit dword-ptr path does
                state.addCodeRef(i_address, dereferenced)
                d._handleCallTarget(state, i_address, dereferenced)
                d._handleApiTarget(i_address, call_destination, dereferenced, slot=call_destination)
            else:
                # import-like case: keep the reference on the slot itself
                state.addCodeRef(i_address, call_destination)
                if dereferenced is not None:
                    d._handleApiTarget(i_address, call_destination, dereferenced, slot=call_destination)
        elif i_op_str.startswith("0x"):
            # case = "DIRECT"
            import_slot = self._resolveImportSlot(d, call_destination)
            if import_slot is not None and d._handleApiTarget(i_address, import_slot, import_slot, slot=import_slot):
                state.addCodeRef(i_address, call_destination)
            else:
                d._handleCallTarget(state, i_address, call_destination)
                d._handleApiTarget(i_address, call_destination, call_destination)
        elif i_op_str.lower() in REGS_32BIT or i_op_str.lower() in REGS_64BIT:
            # case = "REG"
            # this is resolved by backtracking at the end of function analysis.
            state.call_register_ins.append(i_address)
        elif i_op_str.startswith("qword ptr ["):
            # case = "QWORD-PTR-REG"
            self._collectMemRegSlot(state, i_address, i_op_str)

    @staticmethod
    def _paddingFillsToAlignment(d, addr):
        """Whether the bytes from `addr` to the next 16-byte boundary are all alignment filler.

        Padding that separates two functions runs from wherever the previous one ended up to
        the boundary the next one is aligned to, and stops there. Two things disqualify a run:
        anything that is not filler before the boundary -- a nop inside a function, a
        scheduling slot or a patch point, does not fill the rest of the line -- and filler that
        carries on past it, which means the boundary is in the middle of the run rather than
        the entry it aligns.

        Reading the whole run rather than its first encoding is what carries this: of the
        addresses it refuses that a bare "not on a boundary" test would have cut, 1,598 of
        1,778 are not functions, and on Go the split is 1,364 of 1,365.
        """
        distance = -addr % 16
        if not distance:
            return False
        window = d._getDisasmWindowBuffer(addr)
        if len(window) <= distance or window[:1] not in GAP_SEQUENCE_FIRST_BYTES:
            return False
        # more filler at the boundary means the run did not end there, so the boundary aligns
        # nothing and cutting on it would seed an entry in the middle of the padding
        if window[distance : distance + 1] in GAP_SEQUENCE_FIRST_BYTES:
            return False
        offset = 0
        while offset < distance:
            for size in range(min(MAX_GAP_SEQUENCE_LENGTH, distance - offset), 0, -1):
                if window[offset : offset + size] in GAP_SEQUENCES[size]:
                    offset += size
                    break
            else:
                return False
        return True

    @staticmethod
    def _recordAbsoluteDataRefs(d, i_address, i_op_str, state):
        """Book a data reference for every absolute memory operand naming an image address.

        Until now the intel backend recorded a data reference only from JumpTableAnalyzer, so
        an address a function loads outright - a dispatch table, a global, a stored method
        pointer - left no trace in the report at all, and nothing downstream could see it.
        The AArch64 backend has always recorded these from its own operands.

        A direct branch names its target as a bare immediate, so it cannot match the bracketed
        form read here. A bracketed branch operand names the pointer slot the branch reads
        through, which is data whatever the branch analyzers do with the value found in it.
        """
        # This runs for every instruction the engine decodes, so the two cheapest facts about
        # the form being looked for come first: an absolute memory operand is written in
        # brackets, and only an operand carrying a segment override needs one stripped. On a
        # static x86-64 ELF two thirds of operands have no bracket at all.
        if not i_op_str or ABSOLUTE_OPERAND_HINT.search(i_op_str) is None:
            return
        binary_info = d.disassembly.binary_info
        if binary_info is None:
            return
        declares_code_areas = bool(getattr(binary_info, "code_areas", None))
        emitted = set()
        normalized = stripFlatSegmentOverride(i_op_str) if ":" in i_op_str else i_op_str
        for operand in normalized.split(", "):
            match = ABSOLUTE_MEM_OPERAND_RE.match(operand.strip())
            if match is None:
                continue
            address = int(match.group("address"), 0)
            if address in emitted or not d.disassembly.isAddrWithinMemoryImage(address):
                continue
            if declares_code_areas and binary_info.isInCodeAreas(address):
                continue
            emitted.add(address)
            state.addDataRef(i_address, address, size=_OPERAND_WIDTHS.get(match.group("width"), 1))

    @staticmethod
    def _collectMemRegSlot(state, i_address, i_op_str):
        match = MEM_REG_SLOT_RE.match(i_op_str)
        if match is None:
            return
        displacement = int(match.group("disp"), 0) if match.group("disp") else 0
        if match.group("sign") == "-":
            displacement = -displacement
        state.call_memreg_ins.append(
            (i_address, match.group("reg"), displacement, 8 if match.group("size") == "qword" else 4)
        )

    def recordImportSlotLoads(self, disassembler, state):
        d = disassembler
        for i_address, i_size, i_mnemonic, i_op_str, _ in state.instructions:
            if i_mnemonic.split(" ")[-1] != "mov":
                continue
            i_op_str = stripFlatSegmentOverride(i_op_str)
            match = IMPORT_SLOT_LOAD_RE.match(i_op_str)
            if match is None:
                continue
            displacement = d.getReferencedAddr(i_op_str)
            slot = i_address + i_size + displacement if match.group("rip") else displacement
            if match.group("size") == "qword":
                dereferenced = d.disassembly.dereferenceQword(slot)
            else:
                dereferenced = d.disassembly.dereferenceDword(slot)
            # resolveApi() gates this: a slot that names no import resolves to (None, None)
            # and books nothing, so a non-import load costs one map lookup
            if dereferenced is not None:
                d._handleApiTarget(i_address, slot, dereferenced, slot=slot)

    def _analyzeCondJmpInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        state.addBlockToQueue(i_address + i_size)
        # capstone always prints a bare "0x..." rel8/rel32 target here, which the queue and the
        # code ref below already parsed with int(op_str, 16); one parse serves all three.
        # See _analyzeLoopInstruction for why this parse is deliberately unguarded and what
        # would have to change if capstone ever printed a Jcc operand in another form.
        jump_destination = int(i_op_str, 16)
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
                state.addBlockToQueue(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
        state.setBlockEndingInstruction(True)

    def _analyzeLoopInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        # loop/loope/loopne take a rel8 target, which capstone prints as a bare "0x...", so the
        # direct parse is safe. It is not tolerant, though: getReferencedAddr() used to return 0
        # for an operand carrying no hex at all and the guard below then skipped the
        # instruction, where int() raises. A ValueError here degrades the whole report to
        # status="error", and the fuzzing oracle will not flag it because ValueError is on its
        # allowlist - so widen this back to a guarded parse if capstone ever prints another form.
        jump_destination = int(i_op_str, 16)
        if jump_destination:
            # loops are conditional branches: queue the taken edge as well
            state.addBlockToQueue(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
        # loops have two exits and should thus be handled as block ending instruction
        state.addBlockToQueue(i_address + i_size)
        state.setBlockEndingInstruction(True)

    def _analyzeJmpInstruction(self, d, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        i_op_str = stripFlatSegmentOverride(i_op_str)
        i = (i_address, i_size, i_mnemonic, i_op_str)
        # case = "FALLTHROUGH"
        if i_op_str.startswith("ptr ") or ":" in i_op_str:
            # case = "LONG-JMP": a far branch names a segment and an offset, so it reaches no
            # address in this image. The direct form (ljmp) holds a colon; the indirect form
            # (FF /5) is told from a near indirect branch by the missing width - capstone
            # renders "ptr [0x402000]" where a near one renders "dword ptr [0x402000]".
            # Also the arm for an fs:/gs: operand whose base is not in the image.
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
            jump_destination = int(i_op_str, 16)
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
                    state.addBlockToQueue(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
        else:
            self._collectMemRegSlot(state, i_address, i_op_str)
            jumptable_targets = d.jumptable_analyzer.getJumpTargets(i, state)
            for target in jumptable_targets:
                if d.disassembly.isAddrWithinMemoryImage(target):
                    state.addBlockToQueue(target)
                    state.addCodeRef(i_address, target, by_jump=True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    @staticmethod
    def _handleApiJumpTarget(d, state, instruction_addr, import_slot, dereferenced):
        resolved_api = d._handleApiTarget(instruction_addr, import_slot, dereferenced, slot=import_slot)
        if resolved_api and state.isFirstInstruction():
            # the entire function body is this one jmp-to-import: a thunk, not a real routine
            state.setThunkCall(True)
        return resolved_api

    @staticmethod
    def _isPaddedLandingPad(d, state, i_address, previous_instruction, start_addr):
        """Whether this landing pad starts the function the decode is about to absorb.

        Only a pad reached by falling through padding qualifies. One that begins a block is
        the target of a branch already inside this function - which is how a switch case body
        is spelled in CET code - and cutting there would carve every one of them out.

        A function that has already booked an instruction past this address wraps around it,
        so cutting there would leave one function nested inside another. The alignment cut
        below declines for the same reason.

        Being a candidate is the weakest of these: every landing pad inside a code area is one,
        because the prologue scan seeds them all. It only rules out an address that candidate
        discovery already refused - one outside the code areas, or past the candidate cap.
        """
        if (
            previous_instruction is None
            or i_address == start_addr
            or i_address % _ENTRY_ALIGNMENT
            or previous_instruction[2].rpartition(" ")[2] != "nop"
            or not d.fc_manager.isFunctionCandidate(i_address)
        ):
            return False
        return state.max_instruction_start <= i_address

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
            previous_mnemonic = previous_instruction[2]
            if " " in previous_mnemonic:
                previous_mnemonic = previous_mnemonic.rpartition(" ")[2]
        else:
            previous_address = None
            previous_mnemonic = None
        # remove potential "bnd" prefix
        i_mnemonic_noprefix = i_mnemonic
        if " " in i_mnemonic_noprefix:
            i_mnemonic_noprefix = i_mnemonic_noprefix.rpartition(" ")[2]
        if i_mnemonic_noprefix == "endbr64" and self._isPaddedLandingPad(
            d, state, i_address, previous_instruction, start_addr
        ):
            # The alignment cut below fires only where the padding follows a call, so a
            # function that ends any other way and is padded up to the next entry runs
            # straight into it and reports the pair as one. A CET landing pad is emitted only
            # where an indirect branch can arrive, which is the entry-shape evidence that
            # alignment and padding alone do not carry.
            #
            # The fall-through reference is deliberately kept. Where the pad belongs to
            # another function this edge is what a tail call into it looks like, and where it
            # is a switch case body the dispatch already owns, removing it would delete a real
            # edge and leave the block before it with no successor at all.
            state.setBlockEndingInstruction(True)
            state.endBlock()
            state.setSanelyEnding(True)
            return True
        i_kind = _INS_KIND.get(i_mnemonic_noprefix)
        # the engine calls this for every decoded instruction, so the operand is screened for a
        # bracket here rather than paying a call to find out there is nothing to record
        if i_op_str and "[" in i_op_str:
            self._recordAbsoluteDataRefs(d, i_address, i_op_str, state)
        if i_kind == _KIND_CALL:
            self._analyzeCallInstruction(d, i, state)
        elif i_kind == _KIND_JMP:
            self._analyzeJmpInstruction(d, i, state)
        elif i_kind == _KIND_LOOP:
            self._analyzeLoopInstruction(d, i, state)
        elif i_kind == _KIND_CJMP:
            self._analyzeCondJmpInstruction(d, i, state)
        elif i_kind is None and i_mnemonic_noprefix.startswith("j"):
            LOGGER.error(
                "unsupported jump @0x%08x (0x%08x): %s %s",
                i_address,
                start_addr,
                i_mnemonic,
                i_op_str,
            )
            # we do not analyze any potential exception handler (tricks), so treat breakpoints as exit condition
        elif i_kind == _KIND_RET:
            self._analyzeEndInstruction(state)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug(
                    "  analyzeFunction() found ending instruction @0x%08x",
                    i_address,
                )
            if previous_address is not None and previous_mnemonic == "push":
                push_ret_destination = d.getReferencedAddr(previous_instruction[3].strip())
                if push_ret_destination and d.disassembly.isAddrWithinMemoryImage(push_ret_destination):
                    LOGGER.debug(
                        "  analyzeFunction() found push-return jump obfuscation: @0x%08x",
                        i_address,
                    )
                    state.addBlockToQueue(push_ret_destination)
                    state.addCodeRef(i_address, push_ret_destination, by_jump=True)
        elif i_kind == _KIND_TRAP:
            self._analyzeEndInstruction(state)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug(
                    "  analyzeFunction() found ending instruction @0x%08x",
                    i_address,
                )
        elif i_kind == _KIND_SYSCALL:
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
        elif (
            previous_address is not None
            and i_address != start_addr
            # a call used to be the only way in, on the theory that padding follows a function
            # that ended in a noreturn call; GCC pads between functions whatever the previous
            # one ended with, and those were swallowed into their predecessor
            and (previous_mnemonic == "call" or self._paddingFillsToAlignment(d, i_address))
        ):
            reached_by_call = previous_mnemonic == "call"
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
            # padding reached by falling through carries no prior that the function ended, so it
            # is gated on every format, not only on PE
            needs_entry_shape = d.disassembly.binary_info._getLiefType() == "PE" or not reached_by_call
            if is_alignment_evidence and not is_candidate_evidence and needs_entry_shape:
                if d.fc_manager.isHotpatchPrologue(instruction_bytes[:5]):
                    seed_address = i_address
                else:
                    seed_address = (i_address + 15) & ~15
                # MSVC also int3/nop-pads mid-function (after noreturn calls, loop-head
                # alignment) on PE images, so alignment-only evidence (no candidate hit at
                # i_address) needs its seed to actually decode as a function entry before
                # cutting -- real PE starts are seeded by exports/pdata/candidates anyway.
                # GCC aligns loop heads with the encodings it pads between functions with, so
                # a fall-through cut needs the same on any format; after a call the other
                # formats stay exempt, where clang/GCC/Go pad between real functions with
                # prologue-less entries the cut would lose.
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
                            next_candidate_address = (i_address + 15) & ~15
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
