#!/usr/bin/python

import datetime
import logging
import re

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)

# two consecutive null bytes are a strong, architecture-independent indicator of
# non-function code; used to abort analysis of obviously bogus candidates
DOUBLE_ZERO = b"\x00\x00"


class RecursiveDisassembler:
    """Architecture-agnostic recursive CFG-recovery engine.

    Owns the recursive traversal, function-candidate orchestration, gap/tailcall
    passes and label/symbol resolution. All architecture-specific behaviour
    (capstone setup, instruction classification, candidate manager, analysis
    state, jump-table / indirect-call analyzers, TF-IDF) is provided by an
    injected :class:`~smda.common.arch.ArchBackend.ArchBackend`.
    """

    def __init__(self, config, backend, forced_bitness=None):
        self.config = config
        self.backend = backend
        self._forced_bitness = forced_bitness
        self.capstone = None
        self._tfidf = None
        self.binary_info = None
        self.label_providers = []
        self.api_providers = []
        self.symbol_providers = []
        self.active_api_providers = []
        self.active_symbol_providers = []
        self._addLabelProviders()
        self.fc_manager = None
        self.tailcall_analyzer = None
        self.indcall_analyzer = None
        self.jumptable_analyzer = None
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)
        self._symbol_cache = {}
        self._api_cache = {}

    def _addLabelProviders(self):
        self._registerLabelProvider(WinApiResolver(self.config))
        self._registerLabelProvider(ElfApiResolver(self.config))
        # Language-specific symbol providers (checked first for proper demangling)
        self._registerLabelProvider(RustSymbolProvider(self.config))
        self._registerLabelProvider(GoSymbolProvider(self.config))
        self._registerLabelProvider(DelphiKbSymbolProvider(self.config))
        self._registerLabelProvider(DelphiReSymProvider(self.config))
        # Generic binary format providers (fallback)
        self._registerLabelProvider(ElfSymbolProvider(self.config))
        self._registerLabelProvider(PeSymbolProvider(self.config))
        self._registerLabelProvider(PdbSymbolProvider(self.config))

    def _registerLabelProvider(self, provider):
        self.label_providers.append(provider)
        if provider.isApiProvider():
            self.api_providers.append(provider)
        if provider.isSymbolProvider():
            self.symbol_providers.append(provider)

    def _updateLabelProviders(self, binary_info):
        for provider in self.label_providers:
            provider.update(binary_info)
        self.active_api_providers = [p for p in self.api_providers if p.is_active()]
        self.active_symbol_providers = [p for p in self.symbol_providers if p.is_active()]

    def addPdbFile(self, binary_info, pdb_path):
        LOGGER.debug("adding PDB file: %s", pdb_path)
        if pdb_path and binary_info.base_addr:
            pdb_info = BinaryInfo(b"")
            pdb_info.file_path = pdb_path
            pdb_info.base_addr = binary_info.base_addr
            for provider in self.label_providers:
                provider.update(pdb_info)
            self.active_api_providers = [p for p in self.api_providers if p.is_active()]
            self.active_symbol_providers = [p for p in self.symbol_providers if p.is_active()]

    def resolveApi(self, to_address, api_address):
        if not hasattr(self, "_api_cache"):
            self._api_cache = {}
        cache_key = (to_address, api_address)
        if cache_key in self._api_cache:
            return self._api_cache[cache_key]
        active_providers = getattr(self, "active_api_providers", self.api_providers)
        for provider in active_providers:
            dll, api = provider.getApi(to_address, api_address)
            if dll or api:
                self._api_cache[cache_key] = (dll, api)
                return (dll, api)

        self._api_cache[cache_key] = ("", "")
        return ("", "")

    def resolveSymbol(self, address):
        if not hasattr(self, "_symbol_cache"):
            self._symbol_cache = {}
        if address in self._symbol_cache:
            return self._symbol_cache[address]
        active_providers = getattr(self, "active_symbol_providers", self.symbol_providers)
        for provider in active_providers:
            result = provider.getSymbol(address)
            if result:
                self._symbol_cache[address] = result
                return result
        self._symbol_cache[address] = ""
        return ""

    def getSymbolCandidates(self):
        symbol_offsets = set()
        active_providers = getattr(self, "active_symbol_providers", self.symbol_providers)
        for provider in active_providers:
            function_symbols = provider.getFunctionSymbols()
            symbol_offsets.update(function_symbols)
        return list(symbol_offsets)

    def getBitMask(self):
        if self.disassembly.binary_info.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def getReferencedAddr(self, op_str):
        referenced_addr = re.search(r"0x[a-fA-F0-9]+", op_str)
        if referenced_addr:
            return int(referenced_addr.group(), 16)
        return 0

    def resolveIndirectSwitch(self, addr_switch_array, size):
        indirect_switch_bytes = []
        current_offset = addr_switch_array + size * 4
        if self.disassembly.isAddrWithinMemoryImage(current_offset):
            LOGGER.debug(
                "0x%08x analyzing potentially indirect switch table (size: 0x%08x).",
                current_offset,
                size,
            )
            current_byte = self.disassembly.getByte(current_offset)
            if isinstance(current_byte, str):
                current_byte = ord(current_byte)
            while current_byte < size and current_offset not in self.fc_manager.getFunctionStartCandidates():
                indirect_switch_bytes.append(current_offset)
                current_offset += 1
                current_byte = self.disassembly.getByte(current_offset)
                if isinstance(current_byte, str):
                    current_byte = ord(current_byte)
            LOGGER.debug("0x%08x found %d bytes.", current_offset, len(indirect_switch_bytes))
        return indirect_switch_bytes

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

    def _getDisasmWindowBuffer(self, addr):
        relative_start = addr - self.disassembly.binary_info.base_addr
        relative_end = relative_start + self.backend.max_instruction_size
        return self.disassembly.binary_info.binary[relative_start:relative_end]

    def analyzeFunction(self, start_addr, as_gap=False):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        self.tailcall_analyzer.initFunction()
        i = None
        state = self.backend.createAnalysisState(start_addr, self.disassembly)
        if state.isProcessedFunction():
            self.fc_manager.updateAnalysisAborted(
                start_addr,
                f"collision with existing code of function 0x{self.disassembly.ins2fn[start_addr]:08x}",
            )
            # return the (empty) state, not a bare list, so every caller path can safely call
            # state.getBlocks(); this collision path is unreachable from the gap pass today, so
            # the change is behavior-neutral (output stays byte-for-byte identical).
            return state
        while state.hasUnprocessedBlocks():
            LOGGER.debug(
                "  current block queue: %s",
                ", ".join([f"0x{addr:x}" for addr in state.block_queue]),
            )
            state.chooseNextBlock()
            LOGGER.debug("  analyzeFunction() now processing block @0x%08x", state.block_start)
            # in capstone, disassembly is more expensive than calling the function, so we use the maximum instruction
            # size as look-ahead. disasm_lite() also provides faster disassembly than disasm(), so we work with tuples.
            cache = list(self.capstone.disasm_lite(self._getDisasmWindowBuffer(state.block_start), state.block_start))
            cache_pos = 0
            previous_i = None
            while True:
                for i in cache:
                    i_address, i_size, i_mnemonic, i_op_str = i
                    i_op_str = i_op_str.strip()
                    i_relative_address = i_address - self.disassembly.binary_info.base_addr
                    i_bytes = self.disassembly.binary_info.binary[i_relative_address : i_relative_address + i_size]
                    LOGGER.debug(
                        "  analyzeFunction() now processing instruction @0x%08x: %s",
                        i_address,
                        i_mnemonic + " " + i_op_str,
                    )
                    cache_pos += i_size
                    state.setNextInstructionReachable(True)
                    # count appearences of "suspicious" byte patterns (like 00 00) that indicate non-function code
                    if i_bytes == DOUBLE_ZERO:
                        state.suspicious_ins_count += 1
                        LOGGER.debug(
                            "    analyzeFunction() found suspicious function @0x%08x",
                            i_address,
                        )
                        if state.suspicious_ins_count > 1:
                            self.fc_manager.updateAnalysisAborted(
                                start_addr,
                                f"too many suspicious instructions @0x{i_address:08x}",
                            )
                            return state
                    # delegate architecture-specific control-flow analysis to the backend;
                    # a True return means: cut the block here without booking this instruction
                    if self.backend.analyzeInstruction(self, i, state, previous_i, start_addr):
                        break
                    previous_i = i
                    if (
                        i_address not in self.disassembly.code_map
                        and i_address not in self.disassembly.data_map
                        and not state.isProcessed(i_address)
                    ):
                        LOGGER.debug(
                            "  analyzeFunction() booked instruction @0x%08x: %s for processed state",
                            i_address,
                            i_mnemonic + " " + i_op_str,
                        )
                        state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                    elif i_address in self.disassembly.code_map:
                        LOGGER.debug(
                            "  analyzeFunction() was already present?! instruction @0x%08x: %s (function: 0x%08x)",
                            i_address,
                            i_mnemonic + " " + i_op_str,
                            self.disassembly.ins2fn[i_address],
                        )
                        state.setBlockEndingInstruction(True)
                        state.addCollision(i_address)
                    else:
                        LOGGER.debug("  analyzeFunction() was already present in local function.")
                        state.setBlockEndingInstruction(True)
                    if state.isBlockEndingInstruction():
                        state.endBlock()
                        break
                else:
                    # if the inner loop did not break, we need to refill the cache in order to finish the block-analysis
                    cache = list(
                        self.capstone.disasm_lite(
                            self._getDisasmWindowBuffer(state.block_start + cache_pos),
                            state.block_start + cache_pos,
                        )
                    )
                    if not cache:
                        break
                    continue
                # if the inner loop did break, the cache didn't run empty and thus block-analysis is finished
                break
            if not state.isBlockEndingInstruction():
                if i is not None:
                    LOGGER.debug(
                        "No block submitted, last instruction: 0x%08x -> 0x%08x %s || %s",
                        start_addr,
                        i_address,
                        i_mnemonic + " " + i_op_str,
                        self.fc_manager.getFunctionCandidate(start_addr),
                    )
                else:
                    LOGGER.debug(
                        "No block submitted with no ins, last instruction: 0x%08x || %s",
                        start_addr,
                        self.fc_manager.getFunctionCandidate(start_addr),
                    )
        state.label = self.resolveSymbol(state.start_addr)
        analysis_result = state.finalizeAnalysis(as_gap)
        if analysis_result and self.config.RESOLVE_REGISTER_CALLS:
            self.indcall_analyzer.resolveRegisterCalls(state)
            self.tailcall_analyzer.finalizeFunction(state)
        self.fc_manager.updateAnalysisFinished(start_addr)
        self.fc_manager.updateCandidates(state)
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug(
            "Analyzing buffer with %d bytes @0x%08x",
            binary_info.binary_size,
            binary_info.base_addr,
        )
        self._updateLabelProviders(binary_info)
        self._symbol_cache = {}
        self._api_cache = {}
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = self.backend.name
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        if self.disassembly.binary_info.bitness not in [32, 64]:
            self.disassembly.binary_info.bitness = self.backend.probeBitness(self.disassembly)
            LOGGER.debug(
                "Automatically Recognized Bitness as: %d",
                self.disassembly.binary_info.bitness,
            )
        else:
            LOGGER.debug("Using defined Bitness as: %d", self.disassembly.binary_info.bitness)
        if self._forced_bitness:
            self.disassembly.binary_info.bitness = self._forced_bitness
            LOGGER.debug("Forced Bitness override to: %d", self.disassembly.binary_info.bitness)

        self.tailcall_analyzer = TailcallAnalyzer()
        self.indcall_analyzer = self.backend.createIndirectCallAnalyzer(self)
        self.jumptable_analyzer = self.backend.createJumpTableAnalyzer(self)

        self.fc_manager = self.backend.createCandidateManager(self.config)
        if self.config.USE_SYMBOLS_AS_CANDIDATES:
            self.fc_manager.symbol_addresses = self.getSymbolCandidates()
        # once we are initialized, add OEP
        if binary_info.oep is not None:
            self.fc_manager.symbol_addresses.append(binary_info.base_addr + binary_info.oep)
        self.fc_manager.init(self.disassembly)
        self.capstone = self.backend.createCapstone(self.disassembly.binary_info.bitness)
        self._tfidf = self.backend.createTfIdf(self.disassembly.binary_info.bitness)
        LOGGER.debug("Starting heuristical analysis.")
        # first pass, analyze locations identifiable by heuristics (e.g. call-reference, common prologue)
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            state = self.analyzeFunction(candidate.addr)
        LOGGER.debug(
            "Finished heuristical analysis, functions: %d",
            len(self.disassembly.functions),
        )
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
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
