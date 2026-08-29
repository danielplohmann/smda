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

import bisect
import logging
import struct

import lief

from smda.utility.BracketQueue import BracketQueue
from smda.utility.MachoBinary import get_active_macho_binary, get_macho_address_adjustment
from smda.utility.PriorityQueue import PriorityQueue

from .EhFrameDecoder import decodeEhFrameFdeRanges, decodeEhFrameHdrStarts, decodeEhFrameLandingPads
from .LanguageAnalyzer import LanguageAnalyzer

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager:
    #: architecture-specific FunctionCandidate subclass used by ensureCandidate()
    CANDIDATE_CLASS = None
    #: instruction-start alignment a recovered candidate address has to satisfy
    CANDIDATE_ALIGNMENT = 1

    def __init__(self, config):
        self.config = config
        self.lang_analyzer = None
        self.disassembly = None
        self.bitness = None
        self._code_areas = []
        self.candidates = {}
        self.candidate_queue = PriorityQueue()
        self.cached_candidates = None
        self._candidate_offsets = set()
        self.candidate_index = 0
        self._all_call_refs = {}
        self._delphi_detected = False
        self.symbol_addresses = []
        self.identified_alignment = 0
        self.go_objects = None
        self.delphi_kb_objects = None
        self.language_candidates_only = False
        # gap filling
        self.function_gaps = []
        self.max_function_addr = 0
        self.gap_pointer = None
        self.previously_analyzed_gap = 0
        self.capstone = None
        # backstop against memory usage explosion during candidate identification
        self._candidate_cap_logged = False
        self._cb_analysis_timeout = None
        self._eh_frame_fde_ranges = None
        self._eh_frame_fde_starts = []
        self._declared_landing_pads = None
        self._plt_ranges = None

    def init(self, disassembly, cbAnalysisTimeout=None):
        self._code_area_index = None
        self._eh_frame_fde_ranges = None
        self._eh_frame_fde_starts = []
        self._declared_landing_pads = None
        self._plt_ranges = None
        if disassembly.binary_info.code_areas:
            self._code_areas = disassembly.binary_info.code_areas
        self.disassembly = disassembly
        self._cb_analysis_timeout = cbAnalysisTimeout
        self.lang_analyzer = LanguageAnalyzer(disassembly)
        self.disassembly.language = self.lang_analyzer.identify()
        self.disassembly.language_guess = self.lang_analyzer.getGuess()
        self.bitness = disassembly.binary_info.bitness
        self.locateCandidates()
        self.disassembly.identified_alignment = self.identified_alignment
        self._buildQueue()

    def _passesCodeFilter(self, addr):
        if addr is None:
            return False
        areas = self._code_areas
        if not areas:
            return True
        index = getattr(self, "_code_area_index", None)
        if index is None or index[0] is not areas:
            ordered = sorted((start, end) for start, end in areas)
            merged = [list(ordered[0])]
            for start, end in ordered[1:]:
                if start <= merged[-1][1]:
                    if end > merged[-1][1]:
                        merged[-1][1] = end
                else:
                    merged.append([start, end])
            starts = [start for start, _end in merged]
            self._code_area_index = (areas, starts, merged)
            index = self._code_area_index
        _areas, starts, merged = index
        pos = bisect.bisect_right(starts, addr) - 1
        return pos >= 0 and addr < merged[pos][1]

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
                dirty_candidates = []
                for candidate_addr, conflict in conflicts.items():
                    candidate = self.candidates[candidate_addr]
                    if candidate.removeCallRefs(conflict):
                        dirty_candidates.append(candidate)
                for candidate in dirty_candidates:
                    self.candidate_queue.update(candidate)

    def _addCappedCallRef(self, candidate, source_ref):
        """add an inbound call reference, honoring MAX_CALL_REFS_PER_CANDIDATE to bound set growth and rescoring."""
        cap = getattr(self.config, "MAX_CALL_REFS_PER_CANDIDATE", 0)
        if cap == 0 or len(candidate.call_ref_sources) < cap:
            return candidate.addCallRef(source_ref)
        return False

    def addCandidate(self, addr, is_gap=False, reference_source=None):
        if not self._passesCodeFilter(addr):
            return False
        is_new = self.ensureCandidate(addr)
        if addr not in self.candidates:
            return False
        candidate = self.candidates[addr]
        candidate.setIsGapCandidate(is_gap)
        score_changed = False
        if reference_source:
            # register in _all_call_refs as well so late references still
            # participate in HIGH_ACCURACY call-conflict resolution
            self._all_call_refs[reference_source] = addr
            score_changed = self._addCappedCallRef(candidate, reference_source)
        self.candidate_queue.add(candidate)
        if score_changed and not is_new:
            self.candidate_queue.update(candidate)

    def getNextFunctionStartCandidate(self):
        for candidate in self.candidate_queue:
            if not (candidate.isFinished() or candidate.getScore() == 0):
                if self.language_candidates_only and candidate.lang_spec is None:
                    continue
                if (
                    self.identified_alignment
                    and candidate.alignment < self.identified_alignment
                    and not candidate.is_exception_handler
                    and not candidate.call_ref_sources
                ):
                    # The floor is inferred from call-referenced candidates, so it only bounds
                    # a guess; an exception record is the image's own declaration, and so is a
                    # direct call to the address. The inference tolerates a twentieth of that
                    # population sitting off the alignment, so applying the floor to all of it
                    # discards exactly what the inference allowed for. Exempting symbols as
                    # well was measured to cost true positives -- do not widen this.
                    continue
                yield candidate

    def getFunctionStartCandidates(self):
        return self._candidate_offsets

    def updateFunctionGaps(self):
        if self.disassembly is None:
            return
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
        gap_index = bisect.bisect_right(
            self.function_gaps, self.gap_pointer if self.gap_pointer is not None else 0, key=lambda gap: gap[0]
        )
        if gap_index < len(self.function_gaps):
            next_gap = self.function_gaps[gap_index][0]
        LOGGER.debug(
            "getNextGap(%s) for 0x%08x based on gap_map: 0x%08x",
            dont_skip,
            self.gap_pointer,
            next_gap,
        )
        # we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if (
            dont_skip
            and self.gap_pointer is not None
            and self.disassembly is not None
            and self.gap_pointer in self.disassembly.code_map
        ):
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
        if self.disassembly is None:
            return False
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
            if self.CANDIDATE_CLASS is None:
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

    def _executableRanges(self):
        """Ranges an FDE start has to fall inside to be a function start."""
        return self._code_areas

    def locateEhFrameCandidates(self):
        """ELF .eh_frame FDE starts (opt-in).

        Every FDE names a code range that unwinding treats as one routine, so an FDE
        start the primary pass left unclaimed is strong evidence of a missed function
        (e.g. a wrapper only reached through data). Runs after the primary pass so
        code_map claims can veto entries: an already-claimed start would split existing
        functions, which this pass must never do. Accepted starts get ordinary candidate
        bookkeeping - deliberately NOT the PE exception-candidate priority, since
        .eh_frame commonly also covers non-function ranges.
        """
        if not self.config.USE_ELF_EH_FRAME_CANDIDATES:
            return
        fde_starts = self._ehFrameFunctionStarts()
        if not fde_starts:
            return
        exec_ranges = self._executableRanges()

        def in_exec(addr):
            return not exec_ranges or any(start <= addr < end for start, end in exec_ranges)

        accepted = []
        for fde_start in sorted(fde_starts):
            if self._candidateTimeoutTripped():
                return
            if fde_start % self.CANDIDATE_ALIGNMENT != 0 or not in_exec(fde_start):
                continue
            if not self._passesCodeFilter(fde_start):
                continue
            if self.disassembly.isCode(fde_start):
                continue
            self.ensureCandidate(fde_start)
            # MAX_FUNCTION_CANDIDATES can reject the registration; never analyze
            # a start that was not actually recorded
            if fde_start in self.candidates:
                accepted.append(fde_start)
        # register ALL accepted starts as known function starts before analyzing
        # any of them: the branch classifier consults getFunctionStartCandidates()
        # during analysis, so an earlier deferred function could otherwise absorb
        # a later FDE start it branches or tailcalls into
        self._candidate_offsets.update(accepted)
        for fde_start in accepted:
            if self._candidateTimeoutTripped():
                return
            # re-checked per yield: an earlier deferred candidate's analysis may
            # still have claimed this start in the meantime (e.g. as a callee)
            if self.disassembly.isCode(fde_start):
                continue
            yield fde_start

    def locateLateCandidates(self):
        """Candidate sources that need a near-complete function set, not just the primary
        pass: they run after gap analysis and its drain. No sources here."""
        return ()

    def _machoActiveBinaryAndAdjustment(self):
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary)):
            return None, 0
        macho = get_active_macho_binary(lief_binary, bitness=binary_info.bitness, architecture=binary_info.architecture)
        if macho is None or not isinstance(macho, lief.MachO.Binary):
            return None, 0
        adjustment = get_macho_address_adjustment(
            macho,
            base_addr=binary_info.base_addr,
            bitness=binary_info.bitness,
            architecture=binary_info.architecture,
        )
        return macho, adjustment

    def locateMachoFunctionStartCandidates(self):
        """Mach-O LC_FUNCTION_STARTS entries.

        The load command carries a delta-encoded list of every function start in the
        image, written by the linker and kept when the binary is stripped, so it is
        the Mach-O counterpart of the PE exception directory rather than of
        .eh_frame's unwind ranges. Runs deferred like the other metadata sources so a
        start the primary pass already claimed is left alone.

        lief accumulates the load command's deltas into offsets from the __TEXT
        segment's virtual address, not into virtual addresses, so each entry has to be
        rebased on that segment - which is also where a fat slice's own base comes from.
        """
        if not self.config.USE_MACHO_FUNCTION_STARTS:
            return
        macho, adjustment = self._machoActiveBinaryAndAdjustment()
        if macho is None:
            return
        function_starts = getattr(macho, "function_starts", None)
        if function_starts is None:
            return
        text_segment = next((segment for segment in macho.segments if segment.name == "__TEXT"), None)
        if text_segment is None:
            return
        image_base = text_segment.virtual_address + adjustment
        accepted = []
        for offset in sorted(set(function_starts.functions)):
            if self._candidateTimeoutTripped():
                return
            start = image_base + offset
            if start % self.CANDIDATE_ALIGNMENT != 0:
                continue
            if not self._passesCodeFilter(start) or not self.disassembly.isAddrWithinMemoryImage(start):
                continue
            if self.disassembly.isCode(start):
                continue
            self.ensureCandidate(start)
            if start in self.candidates:
                self.candidates[start].setIsSymbol(True)
                accepted.append(start)
        self._candidate_offsets.update(accepted)
        for start in accepted:
            if self._candidateTimeoutTripped():
                return
            if self.disassembly.isCode(start):
                continue
            yield start

    def ehFrameFdeRanges(self):
        """(start, end) for every FDE the image's own `.eh_frame` section declares.

        Only the section carries each record's length. `.eh_frame_hdr`'s search table names
        starts alone, so an image reduced to its segments has no ranges here and callers that
        need an extent are inert on it rather than wrong. Decoded once per binary because the
        section is walked record by record in Python.
        """
        if getattr(self, "_eh_frame_fde_ranges", None) is not None:
            return self._eh_frame_fde_ranges
        ranges = []
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary):
            eh_frame = next((section for section in lief_binary.sections if section.name == ".eh_frame"), None)
            if eh_frame is not None and eh_frame.virtual_address and eh_frame.size:
                section_bytes = self.disassembly.getBytes(eh_frame.virtual_address, eh_frame.size)
                if section_bytes:
                    pointer_size = 8 if binary_info.bitness == 64 else 4
                    ranges = sorted(
                        (start, start + length)
                        for start, length in decodeEhFrameFdeRanges(
                            bytes(section_bytes), eh_frame.virtual_address, pointer_size=pointer_size
                        )
                        if length
                    )
        self._eh_frame_fde_ranges = ranges
        self._eh_frame_fde_starts = [start for start, _ in ranges]
        return ranges

    def declaredLandingPads(self):
        """Every exception landing pad the image's own LSDAs declare.

        A landing pad is where the personality routine resumes, so it is interior to a function
        by construction and is never a function start. Under `-fcf-protection` each carries an
        `endbr64`, which is why a scan looking for entry shapes finds them at all. Decoded once
        per binary; an image with no `.eh_frame`, or none carrying an 'L' augmentation, declares
        none and every rule built on this is inert on it.
        """
        if getattr(self, "_declared_landing_pads", None) is not None:
            return self._declared_landing_pads
        pads = set()
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary):
            eh_frame = next((section for section in lief_binary.sections if section.name == ".eh_frame"), None)
            if eh_frame is not None and eh_frame.virtual_address and eh_frame.size:
                section_bytes = self.disassembly.getBytes(eh_frame.virtual_address, eh_frame.size)
                if section_bytes:
                    pointer_size = 8 if binary_info.bitness == 64 else 4
                    pads = decodeEhFrameLandingPads(
                        bytes(section_bytes),
                        eh_frame.virtual_address,
                        lambda addr, length: bytes(self.disassembly.getBytes(addr, length) or b""),
                        pointer_size=pointer_size,
                    )
        self._declared_landing_pads = pads
        return pads

    def isDeclaredLandingPad(self, addr):
        return addr in self.declaredLandingPads()

    #: sections an ELF names as a procedure linkage table, in the order a linker emits them
    PLT_SECTION_NAMES = (".plt", ".plt.sec", ".plt.got", ".iplt")

    def declaredPltRanges(self):
        """(start, end) for every section the image names as a procedure linkage table.

        The whole table sits under a single FDE, so any test that reads an unwind range as one
        function treats every stub after the first as interior to it. The section table is what
        says otherwise. An image reduced to its segments names no sections, so this is empty
        there and anything built on it is inert rather than wrong.
        """
        if getattr(self, "_plt_ranges", None) is not None:
            return self._plt_ranges
        ranges = []
        lief_binary = self.disassembly.binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary):
            for section in lief_binary.sections:
                if section.name in self.PLT_SECTION_NAMES and section.virtual_address and section.size:
                    ranges.append((section.virtual_address, section.virtual_address + section.size))
        self._plt_ranges = ranges
        return ranges

    def isInDeclaredPltSection(self, addr):
        return any(start <= addr < end for start, end in self.declaredPltRanges())

    def declaredLandingPadSkipTarget(self, addr):
        """Where a gap scan should resume after refusing the declared landing pad at `addr`.

        The end of the FDE that declares it, or None when the image declares no range around
        it. Everything between a landing pad and the end of its own function is that
        function's body, so resuming there skips interior addresses only. Resuming one
        instruction on instead lands inside the pad, and the scan books that in the pad's
        place -- a worse candidate than the one just refused, because it opens mid-body and
        its analysis runs on through whatever follows.
        """
        containing = self.declaredFdeRangeContaining(addr)
        return containing[1] if containing else None

    def declaredFdeRangeContaining(self, addr):
        """The declared FDE range `addr` falls inside, or None when it starts one or is outside.

        The unwinder's own record says an interior address belongs to the routine the range
        begins at, so it is not an entry. Ranges are deliberately not merged: consecutive
        functions are laid out end-to-start, and merging adjacent ones collapses the text
        section into a handful of spans where every address but the first looks interior.
        """
        ranges = self.ehFrameFdeRanges()
        starts = self._eh_frame_fde_starts
        index = bisect.bisect_right(starts, addr) - 1
        while index >= 0:
            start, end = ranges[index]
            if start < addr < end:
                return start, end
            # Ranges are sorted by start and a preceding one can still cover `addr` only while
            # its own end does; once one ends at or before it, no earlier one reaches further.
            if end <= addr and index and ranges[index - 1][1] <= addr:
                break
            index -= 1
        return None

    def opensInsideDeclaredFdeRange(self, addr):
        """Whether `addr` falls inside a declared FDE range without being that range's start."""
        return self.declaredFdeRangeContaining(addr) is not None

    def _ehFrameFunctionStarts(self):
        binary_info = self.disassembly.binary_info
        pointer_size = 8 if binary_info.bitness == 64 else 4
        section_starts = {fde_range[0] for fde_range in self.ehFrameFdeRanges()}
        # The two sources are unioned rather than tried in order. A memory image keeps its
        # program headers but not its section table, so .eh_frame_hdr is the only route
        # there; and the section decoder skips records whose CIE it cannot read, so a
        # partial section result would otherwise hide the starts the search table still names.
        return section_starts | decodeEhFrameHdrStarts(self.disassembly, pointer_size=pointer_size)

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
            image_base_as_bytes = struct.pack("<I", self.disassembly.binary_info.base_addr)
            LOGGER.debug("Iterating relocations.")
            binary_as_array = bytearray(self.disassembly.binary_info.binary)
            for relocation_offset in relocations:
                if not (relocation_offset > 0 and relocation_offset + 3 < len(binary_as_array)):
                    continue
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
            self._delphi_detected = True
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
