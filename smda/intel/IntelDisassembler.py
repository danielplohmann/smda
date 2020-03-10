#!/usr/bin/python

import datetime
import logging
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from smda.DisassemblyResult import DisassemblyResult
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from .definitions import CJMP_INS, LOOP_INS, JMP_INS, CALL_INS, RET_INS, REGS_32BIT, DOUBLE_ZERO
from .FunctionCandidateManager import FunctionCandidateManager
from .FunctionAnalysisState import FunctionAnalysisState
from .IndirectCallAnalyzer import IndirectCallAnalyzer

LOGGER = logging.getLogger(__name__)


class IntelDisassembler(object):

    def __init__(self, config, bitness=None):
        self.config = config
        self.bitness = bitness
        self.capstone = None
        self._file_path = ""
        self.label_providers = []
        self._addLabelProviders()
        self.fc_manager = None
        self.tailcall_analyzer = None
        self.indcall_analyzer = None
        self.disassembly = DisassemblyResult()
        self._initCapstone()

    def _initCapstone(self):
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        if self.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)

    def setFilePath(self, file_path):
        self._file_path = file_path

    def _addLabelProviders(self):
        self.label_providers.append(WinApiResolver(self.config))
        self.label_providers.append(ElfSymbolProvider(self.config))
        self.label_providers.append(PdbSymbolProvider(self.config))

    def _updateLabelProviders(self, binary, base_addr):
        for provider in self.label_providers:
            provider.update(self._file_path, binary, base_addr)

    def addPdbFile(self, pdb_path, base_addr):
        LOGGER.info("adding PDB file: %s", pdb_path)
        if pdb_path and base_addr:
            for provider in self.label_providers:
                provider.update(pdb_path, b"", base_addr)

    def resolveApi(self, address):
        for provider in self.label_providers:
            if not provider.isApiProvider(): continue
            result = provider.getApi(address)
            if result: return result
        return ("", "")

    def resolveSymbol(self, address):
        for provider in self.label_providers:
            if not provider.isSymbolProvider(): continue
            result = provider.getSymbol(address)
            if result: return result
        return ""

    def getSymbolCandidates(self):
        symbol_offsets = set([])
        for provider in self.label_providers:
            if not provider.isSymbolProvider(): continue
            function_symbols = provider.getFunctionSymbols()
            symbol_offsets.update(list(function_symbols.keys()))
        return list(symbol_offsets)

    def dereferenceDword(self, addr):
        if self.disassembly.isAddrWithinMemoryImage(addr):
            extracted_dword = self.disassembly.binary[addr - self.disassembly.base_addr:addr - self.disassembly.base_addr + 4]
            return struct.unpack("I", extracted_dword)[0]
        return None

    def getReferencedAddr(self, op_str):
        referenced_addr = re.search(r"0x[a-fA-F0-9]+", op_str)
        if referenced_addr:
            return int(referenced_addr.group(), 16)
        return 0

    def _resolveSwitch(self, addr_switch_array):
        switch_addresses = []
        if self.disassembly.isAddrWithinMemoryImage(addr_switch_array):
            # we bruteforce and assume at most 512 array entries
            for i in range(0x80):
                rebased = addr_switch_array - self.disassembly.base_addr
                switch_entry = struct.unpack("I", self.disassembly.binary[rebased + i * 4:rebased + i * 4 + 4])[0]
                if not self.disassembly.isAddrWithinMemoryImage(switch_entry):
                    break
                switch_addresses.append(switch_entry)
        return switch_addresses

    def resolveIndirectSwitch(self, addr_switch_array, size):
        indirect_switch_bytes = []
        current_offset = addr_switch_array + size * 4
        if self.disassembly.isAddrWithinMemoryImage(current_offset):
            LOGGER.debug("0x%08x analyzing potentially indirect switch table (size: 0x%08x).", current_offset, size)
            current_byte = self.disassembly.binary[current_offset - self.disassembly.base_addr]
            if isinstance(current_byte, str):
                current_byte = ord(current_byte)
            while current_byte < size and not current_offset in self.fc_manager.getFunctionStartCandidates():
                indirect_switch_bytes.append(current_offset)
                current_offset += 1
                current_byte = self.disassembly.binary[current_offset - self.disassembly.base_addr]
                if isinstance(current_byte, str):
                    current_byte = ord(current_byte)
            LOGGER.debug("0x%08x found %d bytes.", current_offset, len(indirect_switch_bytes))
        return indirect_switch_bytes

    def _resolveUnlikelyJumpCase(self, i, state):
        """ 
            resolve GCC style jump tables (not implemented/tested for x64 yet).
            There are generally two typical patterns here:
            A) multiplicative
                cmp     eax, jumptable_size
                ja      loc_default
                mov     eax, ds:off_jumptable[eax*4]
                jmp     eax
            B) additive
                cmp     [ebp+arg_4], jumptable_size
                ja      loc_default
                mov     eax, [ebp+arg_4]
                shl     eax, 2
                add     eax, off_jumptable
                mov     eax, [eax]
                jmp     eax
        """
        register = i.op_str.strip().lower()
        jumptable_size = None  # int(state.instructions[-3][3].split(",")[-1].strip(), base=16) + 1
        backtracked = state.backtrackInstructions(i.address, 10)
        for instr in backtracked[::-1]:
            if instr[2] == "cmp" and re.match(r"[^,]+, (([0-9])|(0x[0-9a-f]+))", instr[3]):
                jumptable_size = int(instr[3].split(",")[-1].strip(), base=16) + 1
                break

        # ensure that we found a jumptable size
        if not jumptable_size:
            return

        data_ref_instruction_addr = None
        off_jumptable = None
        for instr in backtracked[::-1]:
            if instr[2] == "mov" and re.match(r"[^,]+, dword ptr \[[^ ]+ \+ 0x[0-9a-f]+\]", instr[3]):
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.getReferencedAddr(instr[3])
                break
            elif instr[2] == "add" and instr[3].startswith(register):
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.getReferencedAddr(instr[3])
                break

        # ensure that we found the respective mov-instruction
        if not off_jumptable:
            return
        state.addDataRef(data_ref_instruction_addr, off_jumptable, size=4)
        if self.disassembly.isAddrWithinMemoryImage(off_jumptable):
            for index in range(jumptable_size):
                rebased = off_jumptable - self.disassembly.base_addr
                try:
                    entry = struct.unpack("I", self.disassembly.binary[rebased + index * 4:rebased + index * 4 + 4])[0]
                except:
                    continue
                if self.disassembly.isAddrWithinMemoryImage(entry):
                    state.addBlockToQueue(entry)
                    state.addCodeRef(i.address, entry, by_jump=True)

    def _analyzeCallInstruction(self, i, state):
        state.setLeaf(False)
        # case = "FALLTHROUGH"
        call_destination = self.getReferencedAddr(i.op_str)
        if ":" in i.op_str.strip():
            # case = "LONG-CALL"
            pass
        if i.op_str.strip().startswith("dword ptr ["):
            # reg+offset is currently ignored as it is a minority of calls
            # case = "DWORD-PTR-REG"
            if i.op_str.strip().startswith("dword ptr [0x"):
                # case = "DWORD-PTR"
                dereferenced = self.dereferenceDword(call_destination)
                if dereferenced is not None:
                    state.addCodeRef(i.address, dereferenced)
                    self._handleCallTarget(state, i.address, dereferenced)
        elif i.op_str.strip().startswith("0x"):
            # case = "DIRECT"
            self._handleCallTarget(state, i.address, call_destination)
        elif i.op_str.lower() in REGS_32BIT:
            # case = "REG"
            # this is resolved by backtracking at the end of function analysis.
            state.call_register_ins.append(i.address)

    def _handleCallTarget(self, state, from_addr, to_addr):
        if to_addr and self.disassembly.isAddrWithinMemoryImage(to_addr):
            state.addCodeRef(from_addr, to_addr)
        if to_addr and not self.disassembly.isAddrWithinMemoryImage(to_addr):
            self._updateApiTarget(from_addr, to_addr)
        if state.start_addr == to_addr:
            state.setRecursion(True)

    def _updateApiTarget(self, from_addr, to_addr):
        # identify API calls on the fly
        dll, api = self.resolveApi(to_addr)
        if dll and api:
            self._updateApiInformation(from_addr, to_addr, dll, api)
        else:
            if not self.disassembly.isAddrWithinMemoryImage(to_addr):
                logging.debug("potentially uncovered DLL address: 0x%08x", to_addr)

    def _updateApiInformation(self, from_addr, to_addr, dll, api):
        api_entry = {"referencing_addr": [], "dll_name": dll, "api_name": api}
        if to_addr in self.disassembly.apis:
            api_entry = self.disassembly.apis[to_addr]
        if from_addr not in api_entry["referencing_addr"]:
            api_entry["referencing_addr"].append(from_addr)
        self.disassembly.apis[to_addr] = api_entry

    def _analyzeCondJmpInstruction(self, i, state):
        state.addBlockToQueue(i.address + i.size)
        jump_destination = self.getReferencedAddr(i.op_str)
        # case = "FALLTHROUGH"
        self.tailcall_analyzer.addJump(i.address, jump_destination)
        if jump_destination:
            if jump_destination in self.disassembly.functions:
                # case = "TAILCALL!"
                state.setSanelyEnding(True)
            elif jump_destination in self.fc_manager.getFunctionStartCandidates():
                # it's tough to decide whether this should be disassembled here or not. topic of "code-sharing functions".
                # case = "TAILCALL?"
                pass
            else:
                # case = "OFFSET-QUEUE"
                state.addBlockToQueue(int(i.op_str, 16))
            state.addCodeRef(i.address, int(i.op_str, 16), by_jump=True)
        state.setBlockEndingInstruction(True)

    def _analyzeLoopInstruction(self, i, state):
        jump_destination = self.getReferencedAddr(i.op_str)
        if jump_destination:
            state.addCodeRef(i.address, int(i.op_str, 16), by_jump=True)
        # loops have two exits and should thus be handled as block ending instruction
        state.addBlockToQueue(i.address + i.size)
        state.setBlockEndingInstruction(True)

    def _analyzeJmpInstruction(self, i, state):
        # case = "FALLTHROUGH"
        if ":" in i.op_str.strip():
            # case = "LONG-JMP"
            pass
        elif i.op_str.strip().startswith("dword ptr [0x"):
            # case = "DWORD-PTR"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            jump_destination = self.getReferencedAddr(i.op_str)
            dereferenced = self.dereferenceDword(jump_destination)
            state.addCodeRef(i.address, jump_destination, by_jump=True)
            self.tailcall_analyzer.addJump(i.address, jump_destination)
            if dereferenced and not self.disassembly.isAddrWithinMemoryImage(dereferenced):
                self._updateApiTarget(i.address, dereferenced)
        elif i.op_str.strip().startswith("dword ptr ["):
            # case = "SWITCH"
            # TODO 2018-11-26 instead of direct size bruteforcing, use backtracking to cmp instruction to derive jump table size first, fall back to bruteforcing
            addr_switch_array = self.getReferencedAddr(i.op_str)
            switch_addresses = self._resolveSwitch(addr_switch_array)
            for switch_index, switch_destination in enumerate(switch_addresses):
                state.addBlockToQueue(switch_destination)
                state.addCodeRef(i.address, switch_destination, by_jump=True)
                state.addDataRef(i.address, addr_switch_array + switch_index * 4, size=4)
            for index in self.resolveIndirectSwitch(addr_switch_array, len(switch_addresses)):
                # treat switch addresses as data to reduce FPs during gap analysis (instead of full data flow analysis, works sufficiently well)
                state.addDataRef(i.address, index, size=1)
        elif i.op_str.strip().startswith("0x"):
            jump_destination = self.getReferencedAddr(i.op_str)
            self.tailcall_analyzer.addJump(i.address, jump_destination)
            if jump_destination in self.disassembly.functions:
                # case = "TAILCALL!"
                state.setSanelyEnding(True)
            elif jump_destination in self.fc_manager.getFunctionStartCandidates():
                # case = "TAILCALL?"
                pass
            else:
                if state.isFirstInstruction():
                    # case = "STUB-TAILCALL!"
                    pass
                else:
                    # case = "OFFSET-QUEUE"
                    state.addBlockToQueue(int(i.op_str, 16))
            state.addCodeRef(i.address, int(i.op_str, 16), by_jump=True)
        else:
            self._resolveUnlikelyJumpCase(i, state)
            pass
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _analyzeEndInstruction(self, state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def analyzeFunction(self, start_addr, as_gap=False):
        self.tailcall_analyzer.initFunction()
        i = None
        state = FunctionAnalysisState(start_addr, self.disassembly)
        if state.isProcessedFunction():
            self.fc_manager.updateAnalysisAborted(start_addr, "collision with existing code of function 0x{:x}".format(self.disassembly.ins2fn[start_addr]))
            return []
        while state.hasUnprocessedBlocks():
            LOGGER.debug("current block queue: %s", ", ".join(["0x%x" % addr for addr in state.block_queue]))
            state.chooseNextBlock()
            r_block_start = state.block_start - self.disassembly.base_addr
            LOGGER.debug("analyzeFunction() now processing block @0x%08x", state.block_start)
            # in capstone, disassembly is more expensive than calling the function, so we use maximum x86/64 instruction size (14 bytes) as lookeahead.
            disasm_window = 15
            cache = [i for i in self.capstone.disasm(self.disassembly.binary[r_block_start:r_block_start + disasm_window], state.block_start)]
            cache_pos = 0
            previous_instruction = None
            while True:
                for i in cache:
                    LOGGER.debug("  analyzeFunction() now processing instruction @0x%08x: %s", i.address, i.mnemonic + " " + i.op_str)
                    cache_pos += i.size
                    state.setNextInstructionReachable(True)
                    # count appearences of "suspicious" byte patterns (like 00 00) that indicate non-function code
                    if i.bytes == DOUBLE_ZERO:
                        state.suspicious_ins_count += 1
                        LOGGER.debug("analyzeFunction() found suspicious function @0x%08x", i.address)
                        if state.suspicious_ins_count > 1:
                            self.fc_manager.updateAnalysisAborted(start_addr, "too many suspicious instructions.")
                            return []
                    if i.mnemonic in CALL_INS:
                        self._analyzeCallInstruction(i, state)
                    elif i.mnemonic in JMP_INS:
                        self._analyzeJmpInstruction(i, state)
                    elif i.mnemonic in LOOP_INS:
                        self._analyzeLoopInstruction(i, state)
                    elif i.mnemonic in CJMP_INS:
                        self._analyzeCondJmpInstruction(i, state)
                    elif i.mnemonic.startswith("j"):
                        LOGGER.error("unsupported jump @0x%08x (0x%08x): %s %s", i.address, start_addr, i.mnemonic, i.op_str)
                        # we do not analyze any potential exception handler (tricks), so treat breakpoints as exit condition
                    elif i.mnemonic in RET_INS:
                        self._analyzeEndInstruction(state)
                        LOGGER.debug("analyzeFunction() found ending instruction @0x%08x", i.address)
                        if previous_instruction and previous_instruction.mnemonic == "push":
                            push_ret_destination = self.getReferencedAddr(previous_instruction.op_str)
                            if self.disassembly.isAddrWithinMemoryImage(push_ret_destination):
                                LOGGER.debug("analyzeFunction() found push-return jump obfuscation: @0x%08x", i.address)
                                state.addBlockToQueue(push_ret_destination)
                                state.addCodeRef(i.address, push_ret_destination, by_jump=True)
                    elif i.mnemonic in ["int3"]:
                        self._analyzeEndInstruction(state)
                        LOGGER.debug("analyzeFunction() found ending instruction @0x%08x", i.address)
                    previous_instruction = i
                    if not i.address in self.disassembly.code_map and not state.isProcessed(i.address):
                        LOGGER.debug("  analyzeFunction() booked instruction @0x%08x: %s for processed state", i.address, i.mnemonic + " " + i.op_str)
                        state.addInstruction(i)
                    elif i.address in self.disassembly.code_map:
                        LOGGER.debug("  analyzeFunction() was already present?! instruction @0x%08x: %s (function: 0x%x)", i.address, i.mnemonic + " " + i.op_str, self.disassembly.ins2fn[i.address])
                        state.setBlockEndingInstruction(True)
                    else:
                        LOGGER.debug("  analyzeFunction() was already present in local function.")
                        state.setBlockEndingInstruction(True)
                    if state.isBlockEndingInstruction():
                        state.endBlock()
                        break
                else:
                    #if the inner loop did not break, we need to refill the cache in order to finish the block-analysis
                    r_block_cache = r_block_start + cache_pos
                    cache = [i for i in self.capstone.disasm(self.disassembly.binary[r_block_cache:r_block_cache + disasm_window], state.block_start + cache_pos)]
                    if not cache:
                        break
                    continue
                #if the inner loop did break, the cache didn't run empty and thus block-analysis is finished
                break
            if not state.isBlockEndingInstruction():
                if i is not None:
                    LOGGER.debug("No block submitted, last instruction: 0x%08x -> 0x%08x %s || %s",
                                 start_addr,
                                 i.address,
                                 i.mnemonic + " " + i.op_str,
                                 self.fc_manager.getFunctionCandidate(start_addr))
                else:
                    LOGGER.debug("No block submitted with no ins, last instruction: 0x%08x || %s",
                                 start_addr,
                                 self.fc_manager.getFunctionCandidate(start_addr))
        state.label = self.resolveSymbol(state.start_addr)
        analysis_result = state.finalizeAnalysis(as_gap)
        if analysis_result and self.config.RESOLVE_REGISTER_CALLS:
            self.indcall_analyzer.resolveRegisterCalls(state)
            self.tailcall_analyzer.finalizeFunction(state)
        self.fc_manager.updateAnalysisFinished(start_addr)
        self.fc_manager.updateCandidates(state)
        return state.getBlocks()

    def analyzeBuffer(self, binary, base_addr, bitness, cbAnalysisTimeout):
        LOGGER.debug("Analyzing buffer with %d bytes @0x%08x", len(binary), base_addr)
        self.bitness = bitness
        self._updateLabelProviders(binary, base_addr)
        self.disassembly = DisassemblyResult()
        self.disassembly.architecture = "intel"
        self.disassembly.analysis_start_ts = datetime.datetime.utcnow()
        self.disassembly.binary = binary
        self.disassembly.base_addr = base_addr
        self.tailcall_analyzer = TailcallAnalyzer()
        self.indcall_analyzer = IndirectCallAnalyzer(self)
        self.fc_manager = FunctionCandidateManager(self.config)
        self.fc_manager.init(self.disassembly, self.bitness)
        if self.config.USE_SYMBOLS_AS_CANDIDATES:
            self.fc_manager.addSymbolCandidates(self.getSymbolCandidates())

        if not self.bitness:
            self.bitness = self.fc_manager.bitness
            LOGGER.info("Automatically Recognized Bitness as: %d", self.bitness)
        else:
            LOGGER.debug("Using forced Bitness as: %d", self.bitness)
        self.disassembly.bitness = self.bitness
        self._initCapstone()
        # first pass, analyze locations identifiable by heuristics (e.g. call-reference, common prologue)
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout():
                break
            function_blocks = self.analyzeFunction(candidate.addr)
        LOGGER.debug("Finished heuristical analysis, functions: %d", len(self.disassembly.functions))
        # second pass, analyze remaining gaps for additional candidates in an iterative way
        gap_candidate = self.fc_manager.nextGapCandidate()
        while gap_candidate is not None:
            if cbAnalysisTimeout():
                break
            LOGGER.debug("based on gap, performing function analysis of 0x%08x", gap_candidate)
            function_blocks = self.analyzeFunction(gap_candidate, as_gap=True)
            if function_blocks:
                LOGGER.debug("+ got some blocks here -> 0x%08x", gap_candidate)
            if gap_candidate in self.disassembly.functions:
                fn_min = self.disassembly.function_borders[gap_candidate][0]
                fn_max = self.disassembly.function_borders[gap_candidate][1]
                LOGGER.debug("+++ YAY, is now a function! -> 0x%08x - 0x%08x", fn_min, fn_max)
            gap_candidate = self.fc_manager.nextGapCandidate()
        LOGGER.debug("Finished gap analysis, functions: %d", len(self.disassembly.functions))

        if self.config.RESOLVE_TAILCALLS or self.config.HIGH_ACCURACY:
            self.tailcall_analyzer.resolveTailcalls(self)
        self.disassembly.failed_analysis_addr = self.fc_manager.getAbortedCandidates()
        self.disassembly.analysis_end_ts = datetime.datetime.utcnow()
        if cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
