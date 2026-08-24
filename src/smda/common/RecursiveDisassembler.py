#!/usr/bin/python

import datetime
import logging
import re
from bisect import bisect_right
from itertools import chain

from smda.common.BinaryInfo import BinaryInfo
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)

# a leading sign is preserved so that negative displacements ("[rip - 0x20]") resolve correctly
_REFERENCED_ADDR_RE = re.compile(r"(?P<sign>[+-])?\s*0x(?P<value>[a-fA-F0-9]+)")


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
        self._pdb_info = None
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
        self._registerLabelProvider(DelphiPythiaProvider(self.config))
        # Generic binary format providers (fallback)
        self._registerLabelProvider(ElfSymbolProvider(self.config))
        self._registerLabelProvider(PeSymbolProvider(self.config))
        self._registerLabelProvider(MachoSymbolProvider(self.config))
        self._registerLabelProvider(PdbSymbolProvider(self.config))

    def _registerLabelProvider(self, provider):
        self.label_providers.append(provider)
        if provider.isApiProvider():
            self.api_providers.append(provider)
        if provider.isSymbolProvider():
            self.symbol_providers.append(provider)

    def _runLabelProviderUpdate(self, binary_info):
        for provider in self.label_providers:
            try:
                provider.update(binary_info)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.error("Label provider %s failed to update: %r", provider.__class__.__name__, exc)

    def _updateLabelProviders(self, binary_info):
        self._runLabelProviderUpdate(binary_info)
        # a provider clears its symbol map at the top of update(), so a PDB supplied before
        # analysis would be wiped by this pass; re-apply it afterwards instead
        pdb_info = getattr(self, "_pdb_info", None)
        if pdb_info is not None:
            self._runLabelProviderUpdate(pdb_info)
        self.active_api_providers = [p for p in self.api_providers if p.is_active()]
        self.active_symbol_providers = [p for p in self.symbol_providers if p.is_active()]

    def addPdbFile(self, binary_info, pdb_path):
        LOGGER.debug("adding PDB file: %s", pdb_path)
        if pdb_path and binary_info.base_addr:
            pdb_info = BinaryInfo(b"")
            pdb_info.file_path = pdb_path
            pdb_info.base_addr = binary_info.base_addr
            self._pdb_info = pdb_info
            self._runLabelProviderUpdate(pdb_info)
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
        binary_info = self.disassembly.binary_info
        if binary_info is not None and binary_info.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def getReferencedAddr(self, op_str):
        # preserve a leading sign so that negative displacements (e.g. "qword ptr [rip - 0x20]")
        # resolve to the correct address instead of being treated as positive
        referenced_addr = _REFERENCED_ADDR_RE.search(op_str)
        if referenced_addr:
            value = int(referenced_addr.group("value"), 16)
            return -value if referenced_addr.group("sign") == "-" else value
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
            while (
                current_byte is not None
                and current_byte < size
                and current_offset not in self.fc_manager.getFunctionStartCandidates()
            ):
                indirect_switch_bytes.append(current_offset)
                current_offset += 1
                current_byte = self.disassembly.getByte(current_offset)
                if isinstance(current_byte, str):
                    current_byte = ord(current_byte)
            LOGGER.debug("0x%08x found %d bytes.", current_offset, len(indirect_switch_bytes))
        return indirect_switch_bytes

    def _handleCallTarget(self, state, from_addr, to_addr):
        # explicit None check: address 0 is valid in base-0 buffers
        if to_addr is not None and self.disassembly.isAddrWithinMemoryImage(to_addr):
            state.addCodeRef(from_addr, to_addr)
        if state.start_addr == to_addr:
            state.setRecursion(True)

    def _handleApiTarget(self, from_addr, to_addr, dereferenced, slot=None):
        if to_addr:
            # identify API calls on the fly
            dll, api = self.resolveApi(to_addr, dereferenced)
            if dll or api:
                self._updateApiInformation(from_addr, dereferenced, dll, api)
                if slot is not None:
                    self.disassembly.addImportSlot(slot, dll, api)
                return (dll, api)
            elif not self.disassembly.isAddrWithinMemoryImage(to_addr):
                LOGGER.debug("potentially uncovered DLL address: 0x%08x", to_addr)

    def _updateApiInformation(self, from_addr, to_addr, dll, api):
        self.disassembly.addApiReference(to_addr, from_addr, dll, api)

    def _getDisasmWindowBuffer(self, addr):
        binary_info = self.disassembly.binary_info
        if binary_info is None:
            return b""
        relative_start = addr - binary_info.base_addr
        if relative_start < 0 or relative_start >= len(binary_info.binary):
            return b""
        relative_end = relative_start + self.backend.max_instruction_size
        return binary_info.binary[relative_start:relative_end]

    def _revertGapFunction(self, colliding_addr, current_start_addr):
        """When a tailcall-discovered candidate's analysis reaches bytes already
        claimed by a gap function, the gap function is almost certainly part of
        the candidate's body (the gap scan over-eagerly claimed the fall-through
        before the tailcall candidate was known). Revert the gap function so the
        current analysis can absorb its bytes as ordinary blocks.

        Returns True if a gap function was reverted.
        """
        owner_fn = self.disassembly.ins2fn.get(colliding_addr)
        if owner_fn is None or owner_fn == current_start_addr:
            return False
        candidate = self.fc_manager.candidates.get(owner_fn)
        if candidate is None or not candidate.is_gap_candidate:
            return False
        if owner_fn not in self.disassembly.functions:
            return False
        owner_state = self.backend.createAnalysisState(owner_fn, self.disassembly)
        # Rebuild a minimal state from the disassembly's stored instructions
        # so revertAnalysis can undo code_map/ins2fn/function_borders entries.
        owner_state.instructions = [
            instruction for block in self.disassembly.functions[owner_fn] for instruction in block
        ]
        owner_state.code_refs = set()
        owner_state.data_refs = set()
        owner_state.revertAnalysis()
        self.fc_manager.updateAnalysisAborted(
            owner_fn, f"Reverted: absorbed by tailcall candidate 0x{current_start_addr:08x}"
        )
        LOGGER.debug(
            "Reverted gap function 0x%08x (absorbed by tailcall candidate 0x%08x)",
            owner_fn,
            current_start_addr,
        )
        return True

    def analyzeFunction(self, start_addr, as_gap=False):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        binary_info = self.disassembly.binary_info
        if binary_info is None:
            return None
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
            debug_logging = LOGGER.isEnabledFor(logging.DEBUG)
            if debug_logging:
                LOGGER.debug(
                    "  current block queue: %s",
                    ", ".join([f"0x{addr:x}" for addr in state.block_queue]),
                )
            state.chooseNextBlock()
            if debug_logging:
                LOGGER.debug("  analyzeFunction() now processing block @0x%08x", state.block_start)
            # in capstone, disassembly is more expensive than calling the function, so we use the maximum instruction
            # size as look-ahead. disasm_lite() also provides faster disassembly than disasm(), so we work with tuples.
            cache = self.capstone.disasm_lite(self._getDisasmWindowBuffer(state.block_start), state.block_start)
            cache_pos = 0
            previous_i = None
            while True:
                for i in cache:
                    i_address, i_size, i_mnemonic, i_op_str = i

                    i_op_str = i_op_str.strip()
                    i_relative_address = i_address - binary_info.base_addr
                    i_bytes = binary_info.binary[i_relative_address : i_relative_address + i_size]
                    if debug_logging:
                        LOGGER.debug(
                            "  analyzeFunction() now processing instruction @0x%08x: %s",
                            i_address,
                            i_mnemonic + " " + i_op_str,
                        )
                    cache_pos += i_size
                    state.is_next_instruction_reachable = True
                    # count "suspicious" all-zero instructions (e.g. x86 `00 00`,
                    # AArch64 `udf #0`) that indicate non-function code. Testing for an
                    # all-zero decoded instruction is architecture-independent; a
                    # fixed-width constant would never match wider fixed-width ISAs.
                    if i_bytes and not i_bytes[0] and not any(i_bytes):
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
                        and i_address not in state.processed_bytes
                    ):
                        if debug_logging:
                            LOGGER.debug(
                                "  analyzeFunction() booked instruction @0x%08x: %s for processed state",
                                i_address,
                                i_mnemonic + " " + i_op_str,
                            )
                        state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                    elif i_address in self.disassembly.code_map:
                        if debug_logging:
                            LOGGER.debug(
                                "  analyzeFunction() was already present?! instruction @0x%08x: %s (function: 0x%08x)",
                                i_address,
                                i_mnemonic + " " + i_op_str,
                                self.disassembly.ins2fn[i_address],
                            )
                        # If the collision is with a gap function, revert it and
                        # book this instruction so the current function absorbs it.
                        # Only apply during the tailcall re-drain (as_gap=False),
                        # not during the gap pass itself — gap candidates are
                        # expected to have independent analysis there.
                        if not as_gap and self._revertGapFunction(i_address, start_addr):
                            state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                        else:
                            state.setBlockEndingInstruction(True)
                            state.addCollision(i_address)
                    else:
                        LOGGER.debug("  analyzeFunction() was already present in local function.")
                        state.setBlockEndingInstruction(True)
                    if state.is_block_ending_instruction:
                        state.endBlock()
                        break
                else:
                    # if the inner loop did not break, we need to refill the cache in order to finish the block-analysis
                    cache = self.capstone.disasm_lite(
                        self._getDisasmWindowBuffer(state.block_start + cache_pos),
                        state.block_start + cache_pos,
                    )
                    # a generator is always truthy, so emptiness has to be probed by consuming
                    first_of_refill = next(cache, None)
                    if first_of_refill is None:
                        break
                    cache = chain((first_of_refill,), cache)
                    continue
                # if the inner loop did break, the cache didn't run empty and thus block-analysis is finished
                break
            if not state.is_block_ending_instruction:
                if i is not None:
                    i_address, i_size, i_mnemonic, i_op_str = i
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
        if analysis_result:
            if self.config.RESOLVE_REGISTER_CALLS:
                self.indcall_analyzer.resolveRegisterCalls(state)
            # only the intel backend fills call_memreg_ins, so the non-empty check also
            # keeps this off analyzers that have no such pass
            if self.config.RESOLVE_COMPUTED_IMPORT_SLOTS and state.call_memreg_ins:
                self.indcall_analyzer.resolveComputedImportSlots(state)
            if self.config.RECORD_IMPORT_SLOT_LOADS:
                self.backend.recordImportSlotLoads(self, state)
            # finalizeFunction is the only place that flushes TailcallAnalyzer's per-function
            # jumps into its cross-function state, and initFunction() clears them at the start
            # of every function - so gating it on RESOLVE_REGISTER_CALLS made RESOLVE_TAILCALLS
            # a silent no-op whenever register-call resolution was off (the third pass then
            # iterated empty structures and recovered nothing). The two flags are documented as
            # independent; the accumulated state has no consumer other than resolveTailcalls.
            if self.config.RESOLVE_TAILCALLS:
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
        self._symbol_cache = {}
        self._api_cache = {}
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        # analyzeBuffer replaces the DisassemblyResult allocated in __init__; re-apply
        # CONFIDENCE_THRESHOLD so report filtering actually sees the configured value.
        self.disassembly.setConfidenceThreshold(self.config.CONFIDENCE_THRESHOLD)
        self.disassembly.setBinaryInfo(binary_info)
        binary_info.architecture = self.backend.name
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        if binary_info.bitness not in [32, 64]:
            binary_info.bitness = self.backend.probeBitness(self.disassembly)
            LOGGER.warning(
                "No bitness was supplied; inferred %d-bit from the buffer's contents. "
                "Pass the bitness explicitly when it is known - decoding in the wrong mode "
                "yields a plausible-looking report whose blocks and edges are all wrong.",
                binary_info.bitness,
            )
        else:
            LOGGER.debug("Using defined Bitness as: %d", binary_info.bitness)
        if self._forced_bitness:
            binary_info.bitness = self._forced_bitness
            LOGGER.debug("Forced Bitness override to: %d", binary_info.bitness)

        # update providers after bitness is finalized: some (e.g. DelphiPythiaProvider) key parsing on it
        self._updateLabelProviders(binary_info)

        self.tailcall_analyzer = TailcallAnalyzer()
        self.indcall_analyzer = self.backend.createIndirectCallAnalyzer(self)
        self.jumptable_analyzer = self.backend.createJumpTableAnalyzer(self)

        self.fc_manager = self.backend.createCandidateManager(self.config)
        if self.config.USE_SYMBOLS_AS_CANDIDATES:
            self.fc_manager.symbol_addresses = self.getSymbolCandidates()
        # once we are initialized, add OEP
        if binary_info.oep is not None:
            self.fc_manager.symbol_addresses.append(binary_info.base_addr + binary_info.oep)
        self.fc_manager.init(self.disassembly, cbAnalysisTimeout)
        self.capstone = self.backend.createCapstone(binary_info.bitness)
        self._tfidf = self.backend.createTfIdf(binary_info.bitness)
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
        # deferred candidate sources need the primary pass's code_map claims to filter
        # against; they run before gap analysis so accepted starts anchor real functions
        for deferred_addr in self.fc_manager.locateDeferredCandidates():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            state = self.analyzeFunction(deferred_addr)
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
        # candidates may have been discovered during gap analysis (e.g. tailcall targets triggered
        # by _analyzeUncondBranch); drain them before moving to the tailcall pass.
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            state = self.analyzeFunction(candidate.addr)
        # third pass, fix potential tailcall functions that were identified during analysis
        if self.config.RESOLVE_TAILCALLS:
            tailcalled_functions = self.tailcall_analyzer.resolveTailcalls(self)
            for addr in tailcalled_functions:
                self.fc_manager.addTailcallCandidate(addr)
            LOGGER.debug("Finished tailcall analysis, functions.")
            # drain any candidates that were added during tailcall resolution
            for candidate in self.fc_manager.getNextFunctionStartCandidate():
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    break
                state = self.analyzeFunction(candidate.addr)
        if self.config.USE_PE_X64_PDATA_ENDS:
            self._splitMergedFunctionsAtPdataEnds(cbAnalysisTimeout)
        self.disassembly.failed_analysis_addr = self.fc_manager.getAbortedCandidates()
        # package up and finish
        for addr, candidate in self.fc_manager.candidates.items():
            if addr in self.disassembly.functions:
                # score from the raw instruction tuples directly: both backend TF-IDF
                # scorers only read ins[2] (mnemonic), so the hex-transformed
                # getBlocksAsDict() copy would be discarded work.
                function_blocks = {block[0][0]: block for block in self.disassembly.functions[addr]}
                function_tfidf = self._tfidf.getTfIdfFromBlocks(function_blocks)
                candidate.setTfIdf(function_tfidf)
                candidate.getConfidence()
            self.disassembly.candidates[addr] = candidate
        lang_analyzer = getattr(self.fc_manager, "lang_analyzer", None)
        if lang_analyzer is not None:
            # identify() ran before any function existed (candidate-discovery time), so its
            # c++ score always divided by 1; re-normalize now that the real function count
            # is known, so the exported SmdaReport.language reflects it correctly.
            self.disassembly.language = lang_analyzer.rescore(
                self.disassembly.language, len(self.disassembly.functions)
            )
            self.disassembly.language_guess = lang_analyzer.getGuess()
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly

    def _splitMergedFunctionsAtPdataEnds(self, cbAnalysisTimeout=None):
        if not self.config.USE_PE_X64_PDATA_ENDS:
            return 0
        if self.backend.name != "intel":
            return 0
        pdata_ends = self.fc_manager.pdata_end_addresses
        if not pdata_ends:
            return 0
        if self._pdataSplitTimeoutTripped(cbAnalysisTimeout):
            return 0
        split_points_by_owner = {}
        for index, end_addr in enumerate(sorted(pdata_ends)):
            if index and index % 4096 == 0 and self._pdataSplitTimeoutTripped(cbAnalysisTimeout):
                return 0
            fn_start = self.disassembly.ins2fn.get(end_addr)
            if (
                fn_start is None
                or end_addr == fn_start
                or end_addr not in self.disassembly.instructions
                or fn_start not in self.disassembly.functions
            ):
                continue
            fn_min, fn_max = self.disassembly.function_borders[fn_start]
            if not fn_min < end_addr < fn_max:
                continue
            if self._hasNonFallthroughCodeRef(end_addr, fn_start):
                split_points_by_owner.setdefault(fn_start, []).append(end_addr)
        splits_performed = 0
        for fn_start, genuine_splits in sorted(split_points_by_owner.items()):
            if self._pdataSplitTimeoutTripped(cbAnalysisTimeout):
                break
            splits_performed += self._partitionFunctionAtPdataEnds(fn_start, genuine_splits)
        return splits_performed

    def _pdataSplitTimeoutTripped(self, cbAnalysisTimeout):
        if self.disassembly.analysis_timeout:
            return True
        if cbAnalysisTimeout is not None and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
            return True
        return False

    def _hasNonFallthroughCodeRef(self, target_addr, owner_fn):
        for source_addr in self.disassembly.code_refs_to.get(target_addr, ()):
            instruction = self.disassembly.instructions.get(source_addr)
            source_owner = self.disassembly.ins2fn.get(source_addr)
            if instruction is not None and source_addr + instruction[1] != target_addr and source_owner is not None:
                return True
        return False

    def _partitionFunctionAtPdataEnds(self, fn_start, split_points):
        split_points = sorted(set(split_points))
        segment_starts = [fn_start, *split_points]
        partitioned_blocks = {start: [] for start in segment_starts}

        for block in self.disassembly.functions[fn_start]:
            current_segment = None
            block_fragment = []
            for instruction in block:
                segment = segment_starts[bisect_right(split_points, instruction[0])]
                if segment != current_segment and block_fragment:
                    partitioned_blocks[current_segment].append(block_fragment)
                    block_fragment = []
                current_segment = segment
                block_fragment.append(instruction)
            if block_fragment:
                partitioned_blocks[current_segment].append(block_fragment)

        if any(not blocks for blocks in partitioned_blocks.values()):
            return 0

        self.disassembly.recursive_functions.discard(fn_start)
        self.disassembly.leaf_functions.discard(fn_start)
        self.disassembly.thunk_functions.discard(fn_start)

        for segment_start, blocks in partitioned_blocks.items():
            instructions = [instruction for block in blocks for instruction in block]
            self.disassembly.functions[segment_start] = blocks
            self.disassembly.function_borders[segment_start] = (
                min(instruction[0] for instruction in instructions),
                max(instruction[0] + instruction[1] for instruction in instructions),
            )
            for instruction in instructions:
                for byte_addr in range(instruction[0], instruction[0] + instruction[1]):
                    self.disassembly.ins2fn[byte_addr] = segment_start

            self.disassembly.function_symbols[segment_start] = self.resolveSymbol(segment_start)
            if not any(instruction[2].split(" ")[-1] == "call" for instruction in instructions):
                self.disassembly.leaf_functions.add(segment_start)
            if any(
                instruction[2].split(" ")[-1] == "call"
                and segment_start in self.disassembly.code_refs_from.get(instruction[0], ())
                for instruction in instructions
            ):
                self.disassembly.recursive_functions.add(segment_start)
            if self._isApiJumpThunk(instructions):
                self.disassembly.thunk_functions.add(segment_start)

            candidate = self.fc_manager.candidates.get(segment_start)
            if candidate is not None:
                candidate.analysis_aborted = False
                candidate.abortion_reason = ""
                candidate.setAnalysisCompleted()

        for split_point in split_points:
            for source_addr in tuple(self.disassembly.code_refs_to.get(split_point, ())):
                instruction = self.disassembly.instructions.get(source_addr)
                if (
                    instruction is not None
                    and source_addr + instruction[1] == split_point
                    and self.disassembly.ins2fn.get(source_addr) != split_point
                ):
                    self.disassembly.removeCodeRefs(source_addr, split_point)

        return len(split_points)

    def _isApiJumpThunk(self, instructions):
        if len(instructions) != 1 or instructions[0][2].split(" ")[-1] != "jmp":
            return False
        instruction_addr = instructions[0][0]
        return any(instruction_addr in api.get("referencing_addr", ()) for api in self.disassembly.apis.values())
