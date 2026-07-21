"""Architecture-neutral function-candidate management.

Owns the machinery every native backend's candidate discovery shares: the
candidate registry and priority queue, evidence bookkeeping (call references,
symbols, exception records, language specifics, tailcalls), alignment
identification, gap bookkeeping between recovered functions, and the analysis
timeout guard. A backend subclass supplies its architecture through the
:attr:`CANDIDATE_CLASS` factory attribute and implements the byte-level scans
(:meth:`locateCandidates`, :meth:`nextGapCandidate`) against its own
instruction encodings.
"""

import logging
import struct

from smda.utility.BracketQueue import BracketQueue
from smda.utility.PriorityQueue import PriorityQueue

from .LanguageAnalyzer import LanguageAnalyzer

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager:
    #: architecture-specific FunctionCandidate subclass used by ensureCandidate()
    CANDIDATE_CLASS = None

    def __init__(self, config):
        self.config = config
        self.lang_analyzer = None
        self.disassembly = None
        self.bitness = None
        self._code_areas = []
        self.candidates = {}
        self.candidate_queue = []
        self.cached_candidates = None
        self._candidate_offsets = set()
        self.candidate_index = 0
        self._all_call_refs = {}
        self.symbol_addresses = []
        self.identified_alignment = 0
        self.go_objects = None
        self.delphi_kb_objects = None
        self.language_candidates_only = False
        # gap filling
        self.function_gaps = None
        self.max_function_addr = 0
        self.gap_pointer = None
        self.previously_analyzed_gap = 0
        self.capstone = None
        # backstop against memory usage explosion during candidate identification
        self._candidate_cap_logged = False
        self._cb_analysis_timeout = None

    def init(self, disassembly, cbAnalysisTimeout=None):
        if disassembly.binary_info.code_areas:
            self._code_areas = disassembly.binary_info.code_areas
        self.disassembly = disassembly
        self._cb_analysis_timeout = cbAnalysisTimeout
        self.lang_analyzer = LanguageAnalyzer(disassembly)
        self.disassembly.language = self.lang_analyzer.identify()
        self.bitness = disassembly.binary_info.bitness
        self.locateCandidates()
        self.disassembly.identified_alignment = self.identified_alignment
        self._buildQueue()

    def _passesCodeFilter(self, addr):
        if addr is None:
            return False
        if self._code_areas:
            return any(area[0] <= addr < area[1] for area in self._code_areas)
        return True

    def getBitMask(self):
        if self.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def setInitialCandidate(self, addr):
        if addr in self.candidates:
            self.candidates[addr].setInitialCandidate(True)

    def isFunctionCandidate(self, addr):
        return addr in self.candidates

    def getFunctionCandidate(self, addr):
        if addr in self.candidates:
            return self.candidates[addr]
        return None

    def getAbortedCandidates(self):
        aborted = []
        for addr, candidate in self.candidates.items():
            if candidate.analysis_aborted:
                aborted.append(addr)
        return aborted

    def updateAnalysisAborted(self, addr, reason):
        LOGGER.debug("function analysis of 0x%08x aborted: %s", addr, reason)
        if addr in self.candidates:
            self.candidates[addr].setAnalysisAborted(reason)

    def updateAnalysisFinished(self, addr):
        LOGGER.debug("function analysis of 0x%08x successfully completed.", addr)
        if addr in self.candidates:
            self.candidates[addr].setAnalysisCompleted()

    def updateCandidates(self, state):
        if self.config.HIGH_ACCURACY:
            conflicts = state.identifyCallConflicts(self._all_call_refs)
            if conflicts:
                for candidate_addr, conflict in conflicts.items():
                    self.candidates[candidate_addr].removeCallRefs(conflict)
                    # depending on implementation, update candidates individually
                    self.candidate_queue.update(self.candidates[candidate_addr])
                self.candidate_queue.update()

    def _addCappedCallRef(self, candidate, source_ref):
        """add an inbound call reference, honoring MAX_CALL_REFS_PER_CANDIDATE to bound set growth and rescoring."""
        cap = getattr(self.config, "MAX_CALL_REFS_PER_CANDIDATE", 0)
        if cap == 0 or len(candidate.call_ref_sources) < cap:
            candidate.addCallRef(source_ref)

    def addCandidate(self, addr, is_gap=False, reference_source=None):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr not in self.candidates:
            return False
        self.candidates[addr].setIsGapCandidate(is_gap)
        if reference_source:
            # register in _all_call_refs as well so late references still
            # participate in HIGH_ACCURACY call-conflict resolution
            self._all_call_refs[reference_source] = addr
            self._addCappedCallRef(self.candidates[addr], reference_source)
        self.candidate_queue.add(self.candidates[addr])
        self.candidate_queue.update()

    def getNextFunctionStartCandidate(self):
        for candidate in self.candidate_queue:
            if not (candidate.isFinished() or candidate.getScore() == 0):
                if self.language_candidates_only and candidate.lang_spec is None:
                    continue
                if self.identified_alignment and candidate.alignment < self.identified_alignment:
                    continue
                yield candidate

    def getFunctionStartCandidates(self):
        return self._candidate_offsets

    def updateFunctionGaps(self):
        gaps = []
        prev_ins = 0
        min_code = min(self.disassembly.code_map) if self.disassembly.code_map else self.getBitMask()
        max_code = max(self.disassembly.code_map) if self.disassembly.code_map else 0
        # Raw memory dumps are loaded without section info, so self._code_areas is empty; fall back to
        # the full mapped image so the head (before the first instruction) and tail (after the last
        # instruction) still get gap-scanned. Without this, functions that lie entirely before the
        # first or after the last already-discovered instruction (e.g. trailing jmp/thunk tables) are
        # never reached by the gap pass.
        using_synthetic_area = not self._code_areas
        code_areas = self._code_areas or [
            [
                self.disassembly.binary_info.base_addr,
                self.disassembly.binary_info.base_addr + self.disassembly.binary_info.binary_size,
            ]
        ]
        for code_area in code_areas:
            if code_area[0] < min_code < code_area[1] and min_code != code_area[0]:
                gaps.append([code_area[0], min_code, min_code - code_area[0]])
            if code_area[0] < max_code < code_area[1] and max_code != code_area[1]:
                # For the synthetic full-image fallback (raw memory dumps with no section info),
                # the tail gap must start AFTER the last instruction's address, mirroring the
                # interior-hole branch's prev_ins + 1 below. max_code is itself in code_map, so a
                # gap starting at max_code leaves the gap-pointer on a code_map address;
                # getNextGap()'s strict "gap[0] > gap_pointer" test then finds no further gap,
                # returns the bitmask sentinel, and the scan terminates -- abandoning the whole tail
                # region unscanned. Section-derived code areas keep the legacy start (behavior-neutral).
                tail_start = max_code + 1 if using_synthetic_area else max_code
                gaps.append([tail_start, code_area[1], code_area[1] - tail_start])
        for ins in sorted(self.disassembly.code_map.keys()):
            if prev_ins != 0 and ins - prev_ins > 1:
                gaps.append([prev_ins + 1, ins, ins - prev_ins])
            prev_ins = ins
        self.function_gaps = sorted(gaps)

    def initGapSearch(self):
        if self.gap_pointer is None:
            LOGGER.debug("initGapSearch()")
            self.gap_pointer = self.getBitMask()
            self.updateFunctionGaps()
            if self.function_gaps:
                self.gap_pointer = self.function_gaps[0][0]
        LOGGER.debug("initGapSearch() gaps are:")
        for gap in self.function_gaps:
            LOGGER.debug("initGapSearch() 0x%08x - 0x%08x == %d", gap[0], gap[1], gap[2])
        return

    def getNextGap(self, dont_skip=False):
        next_gap = self.getBitMask()
        for gap in self.function_gaps:
            if gap[0] > self.gap_pointer:
                next_gap = gap[0]
                break
        LOGGER.debug(
            "getNextGap(%s) for 0x%08x based on gap_map: 0x%08x",
            dont_skip,
            self.gap_pointer,
            next_gap,
        )
        # we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if dont_skip and self.gap_pointer in self.disassembly.code_map:
            function = self.disassembly.ins2fn[self.gap_pointer]
            next_gap = min(next_gap, self.disassembly.function_borders[function][1])
            LOGGER.debug(
                "getNextGap(%s) without skip => after checking versus code map: 0x%08x",
                dont_skip,
                next_gap,
            )
        LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", dont_skip, next_gap)
        return next_gap

    def nextGapCandidate(self, start_gap_pointer=None):
        """Architecture-specific gap scan; implemented per backend."""
        raise NotImplementedError

    def checkFunctionOverlap(self):
        function_boundaries = []
        for function in self.disassembly.functions:
            min_addr = self.getBitMask()
            max_addr = 0
            for block in self.disassembly.functions[function]:
                min_addr = min(min_addr, min([instruction[0] for instruction in block]))
                max_addr = max(
                    max_addr,
                    max([instruction[0] + instruction[1] for instruction in block]),
                )
            function_boundaries.append((min_addr, max_addr))
        current_entry = (0, 0)
        for entry in sorted(function_boundaries):
            if current_entry[1] > entry[0]:
                return True
            current_entry = entry
        return False

    def ensureCandidate(self, addr):
        """create candidate if it does not exist yet, returns True if newly created, else False"""
        if addr not in self.candidates:
            cap = getattr(self.config, "MAX_FUNCTION_CANDIDATES", 0)
            if cap and len(self.candidates) >= cap:
                if not self._candidate_cap_logged:
                    LOGGER.warning(
                        "MAX_FUNCTION_CANDIDATES cap (%d) reached during candidate identification; "
                        "refusing further candidates to bound memory usage.",
                        cap,
                    )
                    self._candidate_cap_logged = True
                return False
            self.candidates[addr] = self.CANDIDATE_CLASS(self.disassembly.binary_info, addr)
            return True
        return False

    def addGapCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsGapCandidate(True)

    def addTailcallCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsTailcallCandidate(True)

    def addReferenceCandidate(self, addr, source_ref):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self._all_call_refs[source_ref] = addr
        if addr in self.candidates:
            self._addCappedCallRef(self.candidates[addr], source_ref)

    def addLanguageSpecCandidate(self, addr, lang_spec):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setLanguageSpec(lang_spec)

    def addPrologueCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        return self.ensureCandidate(addr)

    def addSymbolCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsSymbol(True)
            self.candidates[addr].setInitialCandidate(True)

    def addExceptionCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsExceptionHandler(True)
            self.candidates[addr].setInitialCandidate(True)

    def _identifyAlignment(self):
        identified_alignment = 0
        if self.config.USE_ALIGNMENT:
            candidates_with_refs = [c for c in self.candidates.values() if len(c.call_ref_sources) > 1]
            num_candidates = len(candidates_with_refs)
            if num_candidates > 20:
                max_unaligned_16_budget = int(0.05 * num_candidates)
                max_unaligned_4_budget = int(0.05 * num_candidates)
                unaligned_16_count = 0
                unaligned_4_count = 0
                for candidate in candidates_with_refs:
                    if candidate.alignment != 16:
                        unaligned_16_count += 1
                    if candidate.alignment < 4:
                        unaligned_4_count += 1
                    if unaligned_16_count > max_unaligned_16_budget and unaligned_4_count > max_unaligned_4_budget:
                        break
                if unaligned_4_count <= max_unaligned_4_budget:
                    identified_alignment = 4
                if unaligned_16_count <= max_unaligned_16_budget:
                    identified_alignment = 16
        return identified_alignment

    def _candidateTimeoutTripped(self):
        """returns True once the wall-clock analysis timeout has been hit during candidate identification."""
        if self.disassembly is not None and self.disassembly.analysis_timeout:
            return True
        if self._cb_analysis_timeout is not None and self._cb_analysis_timeout():
            if self.disassembly is not None:
                self.disassembly.analysis_timeout = True
            return True
        return False

    def locateCandidates(self):
        """Architecture-specific candidate discovery; implemented per backend."""
        raise NotImplementedError

    def locateDeferredCandidates(self):
        """Deferred candidate sources that need the primary pass's results (e.g.
        code_map claims) before they can be filtered; yields addresses the engine
        analyzes between the primary pass and gap analysis. No sources here."""
        return ()

    def _buildQueue(self):
        LOGGER.debug("Located %d function candidates", len(self.candidates))
        # increase lookup speed with static set
        self._candidate_offsets = {c.addr for c in self.candidates.values()}
        self.cached_candidates = list(self.candidates.values())
        if self.config.CANDIDATE_QUEUE == "BracketQueue":
            self.candidate_queue = BracketQueue(candidates=self.cached_candidates)
            LOGGER.debug("Using BracketQueue")
        else:
            self.candidate_queue = PriorityQueue(content=self.cached_candidates)
            LOGGER.debug("Using PriorityQueue")

    def locateSymbolCandidates(self):
        for symbol_addr in self.symbol_addresses:
            self.addSymbolCandidate(symbol_addr)

    def locateLangSpecCandidates(self):
        if self.lang_analyzer.checkGo():
            self.go_objects = self.lang_analyzer.getGoObjects()
            LOGGER.debug(
                "Programming language recognized as Go, adding function start addresses from PCLNTAB: %d",
                len(self.go_objects),
            )
            for add in self.go_objects:
                self.addLanguageSpecCandidate(add, "go")
        if self.lang_analyzer.checkDelphiKb():
            LOGGER.debug("File recognized as Delphi knowledge base")
            self.language_candidates_only = True
            self.delphi_kb_objects = self.lang_analyzer.getDelphiKbObjects()
            LOGGER.debug("Knowledge Base Objects parsed.")
            # apply relocations with imaginary base_addr at 0x400000 (provided by file loader)
            relocations = self.lang_analyzer.delphi_kb_resolver.getRelocations()
            image_base_as_bytes = struct.pack("I", self.disassembly.binary_info.base_addr)
            LOGGER.debug("Iterating relocations.")
            binary_as_array = bytearray(self.disassembly.binary_info.binary)
            for relocation_offset in relocations:
                # don't relocate relative jumps/calls
                if self.disassembly.binary_info.binary[relocation_offset - 1] not in [
                    0xE8,
                    0xE9,
                ]:
                    binary_as_array[relocation_offset] = image_base_as_bytes[0]
                    binary_as_array[relocation_offset + 1] = image_base_as_bytes[1]
                    binary_as_array[relocation_offset + 2] = image_base_as_bytes[2]
                    binary_as_array[relocation_offset + 3] = image_base_as_bytes[3]
            self.disassembly.binary_info.binary = bytes(binary_as_array)
            LOGGER.debug("Adding function start addresses via parser: %d", len(self.delphi_kb_objects))
            for add in self.delphi_kb_objects:
                self.addLanguageSpecCandidate(add, "delphi_kb")
        elif self.lang_analyzer.checkDelphi():
            LOGGER.debug("Programming language recognized as Delphi, adding function start addresses from VMTs")
            delphi_objects = self.lang_analyzer.getDelphiObjects()
            LOGGER.debug("delphi candidates based on legacy VMT analysis: %d", len(delphi_objects))
            for obj in delphi_objects:
                self.addLanguageSpecCandidate(obj, "delphi")

            # Also extract symbols using DelphiReSym metadata parsing
            LOGGER.debug("Extracting Delphi symbols using DelphiReSym metadata parsing")
            delphi_resym_objects = self.lang_analyzer.getDelphiReSymObjects()
            LOGGER.debug("delphi candidates based on DelphiReSym analysis: %d", len(delphi_resym_objects))
            for obj in delphi_resym_objects:
                self.addLanguageSpecCandidate(obj, "delphi_resym")
