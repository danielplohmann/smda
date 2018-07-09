import re
import struct
import logging

from smda.utility.PriorityQueue import PriorityQueue
from .definitions import DEFAULT_PROLOGUES, GAP_SEQUENCES
from .LanguageAnalyzer import LanguageAnalyzer
from .FunctionCandidate import FunctionCandidate
from .BitnessAnalyzer import BitnessAnalyzer

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager(object):

    def __init__(self, config, disassembly, bitness=0):
        self.config = config
        self.lang_analyzer = LanguageAnalyzer()
        self.disassembly = disassembly
        self.candidates = {}
        self._all_call_refs = {}
        self.cached_candidates = None
        self._candidate_offsets = []
        self.candidate_index = 0
        self.bitness = bitness
        if bitness not in [32, 64]:
            bitness_analyzer = BitnessAnalyzer(common_function_starts_filepath=self.config.COMMON_FUNCTION_STARTS_FILE)
            self.bitness = bitness_analyzer.determineBitnessFromDisassembly(self.disassembly)
        self.disassembly.language = self.lang_analyzer.identify(self.disassembly)
        self.locateCandidates()
        # gap filling
        self.function_gaps = None
        self.max_function_addr = 0
        self.gap_pointer = None
        self.previously_analyzed_gap = 0

    def getBitMask(self):
        if self.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def getFunctionCandidate(self, addr):
        if addr in self.candidates:
            return self.candidates[addr]

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
                self.candidate_queue.update()

    def getNextFunctionStartCandidate(self):
        for candidate in self.candidate_queue:
            if not (candidate.isFinished() or candidate.getScore() == 0):
                yield candidate

    def _logCandidateStats(self):
        logging.debug("Candidate Statistics:")
        try:
            maxc = max([c.getScore() for c in self.candidates.values()])
            minc = min([c.getScore() for c in self.candidates.values()])
            candidates_2 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 2])
            candidates_1 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 1])
            candidates_0 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 0])
            logging.debug("  Max: %f, Min: %f", maxc, minc)
            logging.debug("  2: %d, 1: %d, 0: %d", candidates_2, candidates_1, candidates_0)
        except:
            logging.debug("  No candidates found.")

    def getFunctionStartCandidates(self):
        return self._candidate_offsets

    def initGapSearch(self):
        if self.gap_pointer is None:
            LOGGER.debug("initGapSearch()")
            self.gap_pointer = self.getBitMask()
            gaps = []
            prev_ins = 0
            for ins in sorted(self.disassembly.code_map):
                if prev_ins != 0:
                    if ins - prev_ins > 1:
                        gaps.append((prev_ins + 1, ins, ins - prev_ins))
                prev_ins = ins
            self.function_gaps = gaps
            if gaps:
                self.gap_pointer = self.function_gaps[0][0]
        LOGGER.debug("initGapSearch() gaps are:")
        for gap in self.function_gaps:
            LOGGER.debug("initGapSearch() 0x%08x - 0x%08x == %d", gap[0], gap[1], gap[2])
        return

    def getNextGap(self, skip=False):
        next_gap = self.getBitMask()
        for gap in self.function_gaps:
            if gap[0] > self.gap_pointer:
                next_gap = gap[0]
                break
        LOGGER.debug("getNextGap(%s) for 0x%08x based on gap_map: 0x%08x", skip, self.gap_pointer, next_gap)
        # we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if not skip:
            if self.gap_pointer in self.disassembly.code_map:
                function = self.disassembly.ins2fn[self.gap_pointer]
                next_gap = min(next_gap, self.disassembly.function_borders[function][1])
                LOGGER.debug("getNextGap(%s) without skip => after checking versus code map: 0x%08x", skip, next_gap)
        LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", skip, next_gap)
        return next_gap

    def nextGapCandidate(self):
        if self.gap_pointer is None:
            self.initGapSearch()
        LOGGER.debug("nextGapCandidate() finding new gap candidate, current gap_ptr: 0x%08x", self.gap_pointer)
        while True:
            if self.disassembly.base_addr + len(self.disassembly.binary) < self.gap_pointer:
                LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return None
            gap_offset = self.gap_pointer - self.disassembly.base_addr
            # some compilers aggressively emit these kinds of nops between functions
            if self.disassembly.binary[gap_offset:gap_offset + 3] in GAP_SEQUENCES["3"]:
                LOGGER.debug("nextGapCandidate() found 3 byte nop - gap_ptr += 3: 0x%08x", self.gap_pointer)
                self.gap_pointer += 3
                continue
            if self.disassembly.binary[gap_offset:gap_offset + 2] in GAP_SEQUENCES["2"]:
                LOGGER.debug("nextGapCandidate() found 2 byte nop - gap_ptr += 2: 0x%08x", self.gap_pointer)
                self.gap_pointer += 2
                continue
            byte = self.disassembly.binary[gap_offset]
            if isinstance(byte, int):
                byte = chr(byte)
            if byte in GAP_SEQUENCES["1"]:
                LOGGER.debug("nextGapCandidate() found 0xCC or 0x90 - gap_ptr += 1: 0x%08x", self.gap_pointer)
                self.gap_pointer += 1
                continue
            if self.gap_pointer in self.disassembly.data_map:
                LOGGER.debug("nextGapCandidate() gap_ptr is already inside data map: 0x%08x", self.gap_pointer)
                self.gap_pointer += 1
                continue
            if self.gap_pointer in self.disassembly.code_map:
                LOGGER.debug("nextGapCandidate() gap_ptr is already inside code map: 0x%08x", self.gap_pointer)
                self.gap_pointer = self.getNextGap()
                continue
            # we may have a candidate here
            LOGGER.debug("nextGapCandidate() using 0x%08x as candidate", self.gap_pointer)
            start_byte = self.disassembly.binary[gap_offset]
            has_common_prologue = True  # start_byte in FunctionCandidate(self.gap_pointer, start_byte, self.bitness).common_gap_starts[self.bitness]
            if self.previously_analyzed_gap == self.gap_pointer:
                LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed", self.gap_pointer)
                self.gap_pointer = self.getNextGap(skip=True)
            elif not has_common_prologue:
                LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%08x)", self.gap_pointer, ord(start_byte))
                self.gap_pointer = self.getNextGap(skip=True)
            else:
                self.previously_analyzed_gap = self.gap_pointer
                return self.gap_pointer
        return None

    def checkFunctionOverlap(self):
        function_boundaries = []
        for function in self.disassembly.functions:
            min_addr = self.getBitMask()
            max_addr = 0
            for block in self.disassembly.functions[function]:
                min_addr = min(min_addr, min([instruction[0] for instruction in block]))
                max_addr = max(max_addr, max([instruction[0] + instruction[1] for instruction in block]))
            function_boundaries.append((min_addr, max_addr))
        current_entry = (0, 0)
        for entry in sorted(function_boundaries):
            if current_entry[1] > entry[0]:
                return True
            current_entry = entry
        return False

    def checkCodePadding(self):
        pattern_count = 0
        pattern_functions = []
        for pattern in re.finditer(r"((\xCC){2,}|(\x90){2,})", self.disassembly.binary):
            pattern_count += 1
            pattern_functions.append(pattern.span()[1] + 1)

    def dereferenceDword(self, addr):
        if self.disassembly.isAddrWithinMemoryImage(addr):
            extracted_dword = self.disassembly.binary[addr - self.disassembly.base_addr:addr - self.disassembly.base_addr + 4]
            return struct.unpack("I", extracted_dword)[0]
        return self.getBitMask()

    def addReferenceCandidate(self, addr, source_ref):
        if addr not in self.candidates:
            start_bytes = self.disassembly.binary[addr - self.disassembly.base_addr:addr - self.disassembly.base_addr + 5]
            self.candidates[addr] = FunctionCandidate(addr, start_bytes, self.bitness)
            self._all_call_refs[source_ref] = addr
        self.candidates[addr].addCallRef(source_ref)

    def addLanguageSpecCandidate(self, addr, lang_spec):
        if addr not in self.candidates:
            start_bytes = self.disassembly.binary[addr - self.disassembly.base_addr:addr - self.disassembly.base_addr + 5]
            self.candidates[addr] = FunctionCandidate(addr, start_bytes, self.bitness)
        self.candidates[addr].setLanguageSpec(lang_spec)

    def addPrologueCandidate(self, addr):
        if addr not in self.candidates:
            start_bytes = self.disassembly.binary[addr - self.disassembly.base_addr:addr - self.disassembly.base_addr + 5]
            self.candidates[addr] = FunctionCandidate(addr, start_bytes, self.bitness)
            return True
        return False

    def resolvePointerReference(self, offset):
        if self.bitness == 32:
            addr_block = self.disassembly.binary[offset + 2:offset + 2 + 4]
            function_pointer = struct.unpack("I", addr_block)[0]
            return self.dereferenceDword(function_pointer)
        if self.bitness == 64:
            addr_block = self.disassembly.binary[offset + 2:offset + 2 + 4]
            function_pointer = struct.unpack("i", addr_block)[0]
            # we need to calculate RIP + offset + 7 (48 ff 25 ** ** ** **)
            if self.disassembly.binary[offset:offset + 2] == "\xFF\x25":
                function_pointer += offset + 7
            elif self.disassembly.binary[offset:offset + 2] == "\xFF\x15":
                function_pointer += offset + 6
            else:
                raise Exception("resolvePointerReference: should only be used on call/jmp * ptr")
            return self.disassembly.base_addr + function_pointer
        raise Exception("resolvePointerReference: undefined bitness")

    def locateCandidates(self):
        self.locateReferenceCandidates()
        self.locatePrologueCandidates()
        self.locateLangSpecCandidates()
        self.locateStubChainCandidates()
        LOGGER.debug("Located %d function candidates", len(self.candidates))
        # increase lookup speed with static list
        self._candidate_offsets = [c.addr for c in self.candidates.values()]
        self.cached_candidates = list(self.candidates.values())
        self.candidate_queue = PriorityQueue(content=self.cached_candidates)

    def locateReferenceCandidates(self):
        # check for potential call instructions and check if their destinations have a common function prologue
        for call_match in re.finditer(b"\xE8", self.disassembly.binary):
            if len(self.disassembly.binary) - call_match.start() > 5:
                packed_call = self.disassembly.binary[call_match.start() + 1:call_match.start() + 5]
                rel_call_offset = struct.unpack("i", packed_call)[0]
                call_destination = (self.disassembly.base_addr + rel_call_offset + call_match.start() + 5) & self.getBitMask()
                if self.disassembly.isAddrWithinMemoryImage(call_destination):
                    self.addReferenceCandidate(call_destination, self.disassembly.base_addr + call_match.start())
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        if self.bitness == 32:
            for match in re.finditer(b"\xFF\x25", self.disassembly.binary):
                function_addr = self.resolvePointerReference(match.start())
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(function_addr, self.disassembly.base_addr + match.start())
            # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
            for match in re.finditer(b"\xFF\x15", self.disassembly.binary):
                function_addr = self.resolvePointerReference(match.start())
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(function_addr, self.disassembly.base_addr + match.start())

    def locatePrologueCandidates(self):
        # next check for the default function prologue regardless of references
        for re_prologue in DEFAULT_PROLOGUES:
            for prologue_match in re.finditer(re_prologue, self.disassembly.binary):
                self.addPrologueCandidate((self.disassembly.base_addr + prologue_match.start()) & self.getBitMask())

    def locateLangSpecCandidates(self):
        # if the sample is highly likely delphi, extract t-string-objects and use their function-addresses as high-confidence function starts
        delphi_candidates = set([])
        if self.lang_analyzer.checkDelphi(self.disassembly.binary):
            LOGGER.debug("Programming language recognized as Delphi, adding function start addresses from TObjects")
            t_objects = self.lang_analyzer.getDelphiObjects(self.disassembly.binary, self.disassembly.base_addr)
            for t_string in t_objects:
                delphi_candidates.update(set(t_objects[t_string]))
            LOGGER.debug("delphi candidates based on TObject analysis: %d", len(delphi_candidates))
            for obj in delphi_candidates:
                self.addLanguageSpecCandidate(obj, "delphi")

    def locateStubChainCandidates(self):
        # binaries often contain long sequences of stubs, consisting only of jmp dword ptr <offset>, add such chains as candidates
        for block in re.finditer(b"(?P<block>(\xFF\x25[\S\s]{4}){2,})", self.disassembly.binary):
            for match in re.finditer(b"\xFF\x25(?P<function>[\S\s]{4})", block.group("block")):
                self.addPrologueCandidate((self.disassembly.base_addr + block.start() + match.start()) & self.getBitMask())
