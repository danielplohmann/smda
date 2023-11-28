#!/usr/bin/python

import datetime
import logging
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from smda.DisassemblyResult import DisassemblyResult
from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from .definitions import CJMP_INS, LOOP_INS, JMP_INS, CALL_INS, RET_INS, REGS_32BIT, REGS_64BIT, DOUBLE_ZERO
from .FunctionCandidateManager import FunctionCandidateManager
from .FunctionAnalysisState import FunctionAnalysisState
from .IndirectCallAnalyzer import IndirectCallAnalyzer
from .JumpTableAnalyzer import JumpTableAnalyzer
from .MnemonicTfIdf import MnemonicTfIdf
from .BitnessAnalyzer import BitnessAnalyzer

LOGGER = logging.getLogger(__name__)


class SimpleIns(object):
    address = None
    size = None
    mnemonic = None
    op_str = None
    bytes = None

    def __init__(self, address, size, mnemonic, op_str, bytes):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = bytes


class IntelDisassembler(object):

    def __init__(self, config, forced_bitness=None):
        self.config = config
        self._forced_bitness = forced_bitness
        self.capstone = None
        self._tfidf = None
        self.binary_info = None
        self.label_providers = []
        self._addLabelProviders()
        self.fc_manager = None
        self.tailcall_analyzer = None
        self.indcall_analyzer = None
        self.jumptable_analyzer = None
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)

    def _initCapstone(self):
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_64) if self.disassembly.binary_info.bitness == 64 else Cs(CS_ARCH_X86, CS_MODE_32)

    def _initTfIdf(self):
        self._tfidf = MnemonicTfIdf(bitness=64) if self.disassembly.binary_info.bitness == 64 else MnemonicTfIdf(bitness=32)

    def getBitMask(self):
        if self.disassembly.binary_info.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def _addLabelProviders(self):
        self.label_providers.append(WinApiResolver(self.config))
        self.label_providers.append(ElfApiResolver(self.config))
        self.label_providers.append(ElfSymbolProvider(self.config))
        self.label_providers.append(PeSymbolProvider(self.config))
        self.label_providers.append(PdbSymbolProvider(self.config))
        self.label_providers.append(GoSymbolProvider(self.config))
        self.label_providers.append(DelphiKbSymbolProvider(self.config))

    def _updateLabelProviders(self, binary_info):
        for provider in self.label_providers:
            provider.update(binary_info)

    def addPdbFile(self, binary_info, pdb_path):
        LOGGER.debug("adding PDB file: %s", pdb_path)
        if pdb_path and binary_info.base_addr:
            pdb_info = BinaryInfo(b"")
            pdb_info.file_path = pdb_path
            pdb_info.base_addr = binary_info.base_addr
            for provider in self.label_providers:
                provider.update(pdb_info)

    def resolveApi(self, to_address, api_address):
        for provider in self.label_providers:
            if not provider.isApiProvider():
                continue
            dll, api = provider.getApi(to_address, api_address)
            if dll or api:
                return (dll, api)

        return ("", "")

    def resolveSymbol(self, address):
        for provider in self.label_providers:
            if not provider.isSymbolProvider():
                continue
            result = provider.getSymbol(address)
            if result:
                return result
        return ""

    def getSymbolCandidates(self):
        symbol_offsets = set([])
        for provider in self.label_providers:
            if not provider.isSymbolProvider():
                continue
            function_symbols = provider.getFunctionSymbols()
            symbol_offsets.update(list(function_symbols.keys()))
        return list(symbol_offsets)

    def getReferencedAddr(self, op_str):
        referenced_addr = re.search(r"0x[a-fA-F0-9]+", op_str)
        if referenced_addr:
            return int(referenced_addr.group(), 16)
        return 0

    def resolveIndirectSwitch(self, addr_switch_array, size):
        indirect_switch_bytes = []
        current_offset = addr_switch_array + size * 4
        if self.disassembly.isAddrWithinMemoryImage(current_offset):
            LOGGER.debug("0x%08x analyzing potentially indirect switch table (size: 0x%08x).", current_offset, size)
            current_byte = self.disassembly.getByte(current_offset)
            if isinstance(current_byte, str):
                current_byte = ord(current_byte)
            while current_byte < size and not current_offset in self.fc_manager.getFunctionStartCandidates():
                indirect_switch_bytes.append(current_offset)
                current_offset += 1
                current_byte = self.disassembly.getByte(current_offset)
                if isinstance(current_byte, str):
                    current_byte = ord(current_byte)
            LOGGER.debug("0x%08x found %d bytes.", current_offset, len(indirect_switch_bytes))
        return indirect_switch_bytes

    def _analyzeCallInstruction(self, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        state.setLeaf(False)
        # case = "FALLTHROUGH"
        call_destination = self.getReferencedAddr(i_op_str)
        if ":" in i_op_str:
            # case = "LONG-CALL"
            pass
        if i_op_str.startswith("dword ptr ["):
            # reg+offset is currently ignored as it is a minority of calls
            # case = "DWORD-PTR-REG"
            if i_op_str.startswith("dword ptr [0x"):
                # case = "DWORD-PTR"
                dereferenced = self.disassembly.dereferenceDword(call_destination)
                if dereferenced is not None:
                    state.addCodeRef(i_address, dereferenced)
                    self._handleCallTarget(state, i_address, dereferenced)
                    self._handleApiTarget(i_address, call_destination, dereferenced)
        elif i_op_str.startswith("qword ptr [rip"):
            rip = i_address + i_size
            call_destination = rip + self.getReferencedAddr(i_op_str)
            dereferenced = self.disassembly.dereferenceQword(call_destination)
            state.addCodeRef(i_address, call_destination)
            if dereferenced is not None:
                self._handleApiTarget(i_address, call_destination, dereferenced)
        elif i_op_str.startswith("0x"):
            # case = "DIRECT"
            self._handleCallTarget(state, i_address, call_destination)
            self._handleApiTarget(i_address, call_destination, call_destination)
        elif i_op_str.lower() in REGS_32BIT or i_op_str.lower() in REGS_64BIT:
            # case = "REG"
            # this is resolved by backtracking at the end of function analysis.
            state.call_register_ins.append(i_address)

    def _handleCallTarget(self, state, from_addr, to_addr):
        if to_addr and self.disassembly.isAddrWithinMemoryImage(to_addr):
            state.addCodeRef(from_addr, to_addr)
        if state.start_addr == to_addr:
            state.setRecursion(True)

    def _handleApiTarget(self, from_addr, to_addr, dereferenced):
        if to_addr:
            # identify API calls on the fly
            dll, api = self.resolveApi(to_addr, dereferenced)
            if dll or api:
                self._updateApiInformation(from_addr, dereferenced, dll, api)
                return (dll, api)
            elif not self.disassembly.isAddrWithinMemoryImage(to_addr):
                LOGGER.debug("potentially uncovered DLL address: 0x%08x", to_addr)

    def _updateApiInformation(self, from_addr, to_addr, dll, api):
        api_entry = {"referencing_addr": [], "dll_name": dll, "api_name": api}
        if to_addr in self.disassembly.apis:
            api_entry = self.disassembly.apis[to_addr]
        if from_addr not in api_entry["referencing_addr"]:
            api_entry["referencing_addr"].append(from_addr)
        self.disassembly.apis[to_addr] = api_entry

    def _analyzeCondJmpInstruction(self, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        state.addBlockToQueue(i_address + i_size)
        jump_destination = self.getReferencedAddr(i_op_str)
        # case = "FALLTHROUGH"
        self.tailcall_analyzer.addJump(i_address, jump_destination)
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
                state.addBlockToQueue(int(i_op_str, 16))
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        state.setBlockEndingInstruction(True)

    def _analyzeLoopInstruction(self, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        jump_destination = self.getReferencedAddr(i_op_str)
        if jump_destination:
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        # loops have two exits and should thus be handled as block ending instruction
        state.addBlockToQueue(i_address + i_size)
        state.setBlockEndingInstruction(True)

    def _analyzeJmpInstruction(self, i, state):
        i_address, i_size, i_mnemonic, i_op_str = i
        # case = "FALLTHROUGH"
        if ":" in i_op_str:
            # case = "LONG-JMP"
            pass
        elif i_op_str.startswith("dword ptr [0x"):
            # case = "DWORD-PTR"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            jump_destination = self.getReferencedAddr(i_op_str)
            dereferenced = self.disassembly.dereferenceDword(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
            self.tailcall_analyzer.addJump(i_address, jump_destination)
            if dereferenced is not None:
                self._handleApiTarget(i_address, jump_destination, dereferenced)
        elif i_op_str.startswith("qword ptr [rip"):
            # case = "QWORD-PTR, RIP-relative"
            # Handles mostly jmp-to-api, stubs or tailcalls, all should be handled sanely this way.
            rip = i_address + i_size
            jump_destination = rip + self.getReferencedAddr(i_op_str)
            dereferenced = self.disassembly.dereferenceQword(jump_destination)
            state.addCodeRef(i_address, jump_destination, by_jump=True)
            self.tailcall_analyzer.addJump(i_address, jump_destination)
            if dereferenced is not None:
                self._handleApiTarget(i_address, jump_destination, dereferenced)
        elif i_op_str.startswith("0x"):
            jump_destination = self.getReferencedAddr(i_op_str)
            self.tailcall_analyzer.addJump(i_address, jump_destination)
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
                    state.addBlockToQueue(int(i_op_str, 16))
            state.addCodeRef(i_address, int(i_op_str, 16), by_jump=True)
        else:
            jumptable_targets = self.jumptable_analyzer.getJumpTargets(i, state)
            for target in jumptable_targets:
                if self.disassembly.isAddrWithinMemoryImage(target):
                    state.addBlockToQueue(target)
                    state.addCodeRef(i_address, target, by_jump=True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _analyzeEndInstruction(self, state):
        state.setSanelyEnding(True)
        state.setNextInstructionReachable(False)
        state.setBlockEndingInstruction(True)

    def _getDisasmWindowBuffer(self, addr):
        relative_start = addr - self.disassembly.binary_info.base_addr
        relative_end = relative_start + 15
        return self.disassembly.binary_info.binary[relative_start:relative_end]

    def analyzeFunction(self, start_addr, as_gap=False):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        self.tailcall_analyzer.initFunction()
        i = None
        state = FunctionAnalysisState(start_addr, self.disassembly)
        if state.isProcessedFunction():
            self.fc_manager.updateAnalysisAborted(start_addr, "collision with existing code of function 0x{:08x}".format(self.disassembly.ins2fn[start_addr]))
            return []
        while state.hasUnprocessedBlocks():
            LOGGER.debug("  current block queue: %s", ", ".join(["0x%x" % addr for addr in state.block_queue]))
            state.chooseNextBlock()
            LOGGER.debug("  analyzeFunction() now processing block @0x%08x", state.block_start)
            # in capstone, disassembly is more expensive than calling the function, so we use maximum x86/64 instruction size (14 bytes) as lookeahead.
            # disasm_lite() also provides up to 30% faster disassembly than disasm(), so we work with tuples instead of objects
            cache = [i for i in self.capstone.disasm_lite(self._getDisasmWindowBuffer(state.block_start), state.block_start)]
            cache_pos = 0
            previous_address = None
            previous_mnemonic = None
            previous_op_str = None
            while True:
                for i in cache:
                    i_address, i_size, i_mnemonic, i_op_str = i
                    i_op_str = i_op_str.strip()
                    i_relative_address = i_address - self.disassembly.binary_info.base_addr
                    i_bytes = self.disassembly.binary_info.binary[i_relative_address:i_relative_address + i_size]
                    LOGGER.debug("  analyzeFunction() now processing instruction @0x%08x: %s", i_address, i_mnemonic + " " + i_op_str)
                    cache_pos += i_size
                    state.setNextInstructionReachable(True)
                    # count appearences of "suspicious" byte patterns (like 00 00) that indicate non-function code
                    if i_bytes == DOUBLE_ZERO:
                        state.suspicious_ins_count += 1
                        LOGGER.debug("    analyzeFunction() found suspicious function @0x%08x", i_address)
                        if state.suspicious_ins_count > 1:
                            self.fc_manager.updateAnalysisAborted(start_addr, "too many suspicious instructions @0x%08x" % i_address)
                            return state
                    if i_mnemonic in CALL_INS:
                        self._analyzeCallInstruction(i, state)
                    elif i_mnemonic in JMP_INS:
                        self._analyzeJmpInstruction(i, state)
                    elif i_mnemonic in LOOP_INS:
                        self._analyzeLoopInstruction(i, state)
                    elif i_mnemonic in CJMP_INS:
                        self._analyzeCondJmpInstruction(i, state)
                    elif i_mnemonic.startswith("j"):
                        LOGGER.error("unsupported jump @0x%08x (0x%08x): %s %s", i_address, start_addr, i_mnemonic, i_op_str)
                        # we do not analyze any potential exception handler (tricks), so treat breakpoints as exit condition
                    elif i_mnemonic in RET_INS:
                        self._analyzeEndInstruction(state)
                        LOGGER.debug("  analyzeFunction() found ending instruction @0x%08x", i_address)
                        if previous_address and previous_mnemonic == "push":
                            push_ret_destination = self.getReferencedAddr(previous_op_str)
                            if self.disassembly.isAddrWithinMemoryImage(push_ret_destination):
                                LOGGER.debug("  analyzeFunction() found push-return jump obfuscation: @0x%08x", i_address)
                                state.addBlockToQueue(push_ret_destination)
                                state.addCodeRef(i_address, push_ret_destination, by_jump=True)
                    elif i_mnemonic in ["int3", "hlt"]:
                        self._analyzeEndInstruction(state)
                        LOGGER.debug("  analyzeFunction() found ending instruction @0x%08x", i_address)
                    elif previous_address and i_address != start_addr and previous_mnemonic == "call":
                        instruction_sequence = [ins for ins in self.capstone.disasm(self._getDisasmWindowBuffer(i_address), i_address)]
                        if (not self.disassembly.language['_guess'] == "go" and self.fc_manager.isAlignmentSequence(instruction_sequence)) or self.fc_manager.isFunctionCandidate(i_address):
                            # LLVM and GCC sometimes tends to produce lots of tailcalls that basically mess with function end detection, we cut whenever we find effective nops after calls
                            # however, Go tends to insert alignment NOPs after calls, too, but in this case, they are no tailcall indicator
                            # apparently calls are frequently padded with NOPs, so one last chance to continue disassembly is when we already have instructions for our function beyond this call.
                            if not any([disassembled_addr > i_address for disassembled_addr in state.instruction_start_bytes]):
                                LOGGER.debug("    current function: 0x%x ---> ran into alignment sequence after call -> 0x%08x, cutting block here.", start_addr, i_address)
                                # remove next instruction from references
                                state.removeCodeRef(previous_address, i_address)
                                # end block
                                state.setBlockEndingInstruction(True)
                                state.endBlock()
                                state.setSanelyEnding(True)
                                if self.fc_manager.isAlignmentSequence(instruction_sequence):
                                    next_aligned_address = previous_address + (16 - previous_address % 16)
                                    LOGGER.debug("  Adding: 0x%x as candidate.", next_aligned_address)
                                    self.fc_manager.addCandidate(next_aligned_address, is_gap=True)
                                break
                            else:
                                LOGGER.debug("    current function: 0x%x ---> alignment sequence seems to just pad a call -> 0x%08x, NOT cutting block here.", start_addr, i_address)
                    previous_address = i_address
                    previous_mnemonic = i_mnemonic
                    previous_op_str = i_op_str
                    if not i_address in self.disassembly.code_map and not i_address in self.disassembly.data_map and not state.isProcessed(i_address):
                        LOGGER.debug("  analyzeFunction() booked instruction @0x%08x: %s for processed state", i_address, i_mnemonic + " " + i_op_str)
                        state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                    elif i_address in self.disassembly.code_map:
                        LOGGER.debug("  analyzeFunction() was already present?! instruction @0x%08x: %s (function: 0x%08x)", i_address, i_mnemonic + " " + i_op_str, self.disassembly.ins2fn[i_address])
                        state.setBlockEndingInstruction(True)
                        state.addCollision(i_address)
                    else:
                        LOGGER.debug("  analyzeFunction() was already present in local function.")
                        state.setBlockEndingInstruction(True)
                    if state.isBlockEndingInstruction():
                        state.endBlock()
                        break
                else:
                    #if the inner loop did not break, we need to refill the cache in order to finish the block-analysis
                    cache = [i for i in self.capstone.disasm_lite(self._getDisasmWindowBuffer(state.block_start + cache_pos), state.block_start + cache_pos)]
                    if not cache:
                        break
                    continue
                #if the inner loop did break, the cache didn't run empty and thus block-analysis is finished
                break
            if not state.isBlockEndingInstruction():
                if i is not None:
                    LOGGER.debug("No block submitted, last instruction: 0x%08x -> 0x%08x %s || %s",
                                 start_addr,
                                 i_address,
                                 i_mnemonic + " " + i_op_str,
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
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug("Analyzing buffer with %d bytes @0x%08x", binary_info.binary_size, binary_info.base_addr)
        self._updateLabelProviders(binary_info)
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "intel"
        self.disassembly.analysis_start_ts = datetime.datetime.utcnow()
        if self.disassembly.binary_info.bitness not in [32, 64]:
            bitness_analyzer = BitnessAnalyzer()
            self.disassembly.binary_info.bitness = bitness_analyzer.determineBitnessFromDisassembly(self.disassembly)
            LOGGER.debug("Automatically Recognized Bitness as: %d", self.disassembly.binary_info.bitness)
        else:
            LOGGER.debug("Using defined Bitness as: %d", self.disassembly.binary_info.bitness)
        if self._forced_bitness:
            self.disassembly.binary_info.bitness = self._forced_bitness
            LOGGER.debug("Forced Bitness override to: %d", self.disassembly.binary_info.bitness)

        self.tailcall_analyzer = TailcallAnalyzer()
        self.indcall_analyzer = IndirectCallAnalyzer(self)
        self.jumptable_analyzer = JumpTableAnalyzer(self)

        self.fc_manager = FunctionCandidateManager(self.config)
        if self.config.USE_SYMBOLS_AS_CANDIDATES:
            self.fc_manager.symbol_addresses = self.getSymbolCandidates()
        self.fc_manager.init(self.disassembly)
        self._initCapstone()
        self._initTfIdf()
        LOGGER.debug("Starting heuristical analysis.")
        # first pass, analyze locations identifiable by heuristics (e.g. call-reference, common prologue)
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            state = self.analyzeFunction(candidate.addr)
        LOGGER.debug("Finished heuristical analysis, functions: %d", len(self.disassembly.functions))
        # second pass, analyze remaining gaps for additional candidates in an iterative way
        gap_candidate = self.fc_manager.nextGapCandidate()
        while gap_candidate is not None:
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            LOGGER.debug("based on gap, performing function analysis of 0x%08x", gap_candidate)
            state = self.analyzeFunction(gap_candidate, as_gap=True)
            function_blocks = state.getBlocks()
            if function_blocks:
                LOGGER.debug("+ got some blocks here -> 0x%08x", gap_candidate)
            if gap_candidate in self.disassembly.functions:
                fn_min = self.disassembly.function_borders[gap_candidate][0]
                fn_max = self.disassembly.function_borders[gap_candidate][1]
                LOGGER.debug("+++ YAY, is now a function! -> 0x%08x - 0x%08x", fn_min, fn_max)
                # start looking directly after our new function
            else:
                self.fc_manager.updateAnalysisAborted(gap_candidate, "Gap candidate did not fulfil function criteria.")
            next_gap = self.fc_manager.getNextGap(dont_skip=True)
            gap_candidate = self.fc_manager.nextGapCandidate(next_gap)
        LOGGER.debug("Finished gap analysis, functions: %d", len(self.disassembly.functions))
        # third pass, fix potential tailcall functions that were identified during analysis
        if self.config.RESOLVE_TAILCALLS:
            tailcalled_functions = self.tailcall_analyzer.resolveTailcalls(self)
            for addr in tailcalled_functions:
                self.fc_manager.addTailcallCandidate(addr)
            LOGGER.debug("Finished tailcall analysis, functions.")
        self.disassembly.failed_analysis_addr = self.fc_manager.getAbortedCandidates()
        # package up and finish
        for addr, candidate in self.fc_manager.candidates.items():
            if addr in self.disassembly.functions:
                function_blocks = self.disassembly.getBlocksAsDict(addr)
                function_tfidf = self._tfidf.getTfIdfFromBlocks(function_blocks)
                candidate.setTfIdf(function_tfidf)
                candidate.getConfidence()
            self.disassembly.candidates[addr] = candidate
        self.disassembly.analysis_end_ts = datetime.datetime.utcnow()
        if cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
