import re
import struct
import logging

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from smda.utility.PriorityQueue import PriorityQueue
from smda.utility.BracketQueue import BracketQueue
from .definitions import DEFAULT_PROLOGUES, GAP_SEQUENCES
from .LanguageAnalyzer import LanguageAnalyzer
from .FunctionCandidate import FunctionCandidate

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager(object):

    def __init__(self, config):
        self.config = config
        self.lang_analyzer = None
        self.disassembly = None
        self.bitness = None
        self._code_areas = []
        self.candidates = {}
        self.candidate_queue = []
        self.cached_candidates = None
        self._candidate_offsets = []
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

    def init(self, disassembly):
        if disassembly.binary_info.code_areas:
            self._code_areas = disassembly.binary_info.code_areas
        self.disassembly = disassembly
        self.lang_analyzer = LanguageAnalyzer(disassembly)
        self.disassembly.language = self.lang_analyzer.identify()
        self.bitness = disassembly.binary_info.bitness
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        if self.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        self.locateCandidates()
        self.disassembly.identified_alignment = self.identified_alignment
        self._buildQueue()

    def _passesCodeFilter(self, addr):
        if addr is None:
            return False
        if self._code_areas:
            for area in self._code_areas:
                if area[0] <= addr < area[1]:
                    return True
            return False
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

    def addCandidate(self, addr, is_gap=False, reference_source=None):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsGapCandidate(is_gap)
        if reference_source:
            self.candidates[addr].addCallRef(reference_source)
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

    def _logCandidateStats(self):
        LOGGER.debug("Candidate Statistics:")
        try:
            maxc = max([c.getScore() for c in self.candidates.values()])
            minc = min([c.getScore() for c in self.candidates.values()])
            candidates_2 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 2])
            candidates_1 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 1])
            candidates_0 = len([c.getScore() for c in self.candidates.values() if c.getScore() == 0])
            LOGGER.debug("  Max: %f, Min: %f", maxc, minc)
            LOGGER.debug("  2: %d, 1: %d, 0: %d", candidates_2, candidates_1, candidates_0)
        except:
            LOGGER.debug("  No candidates found.")

    def getFunctionStartCandidates(self):
        return self._candidate_offsets

    def updateFunctionGaps(self):
        gaps = []
        prev_ins = 0
        min_code = min(self.disassembly.code_map) if self.disassembly.code_map else self.getBitMask()
        max_code = max(self.disassembly.code_map) if self.disassembly.code_map else 0
        for code_area in self._code_areas:
            if code_area[0] < min_code < code_area[1] and min_code != code_area[0]:
                gaps.append([code_area[0], min_code, min_code - code_area[0]])
            if code_area[0] < max_code < code_area[1] and max_code != code_area[1]:
                gaps.append([max_code, code_area[1], code_area[1] - max_code])
        for ins in sorted(self.disassembly.code_map.keys()):
            if prev_ins != 0:
                if ins - prev_ins > 1:
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
        LOGGER.debug("getNextGap(%s) for 0x%08x based on gap_map: 0x%08x", dont_skip, self.gap_pointer, next_gap)
        # we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if dont_skip:
            if self.gap_pointer in self.disassembly.code_map:
                function = self.disassembly.ins2fn[self.gap_pointer]
                next_gap = min(next_gap, self.disassembly.function_borders[function][1])
                LOGGER.debug("getNextGap(%s) without skip => after checking versus code map: 0x%08x", dont_skip, next_gap)
        LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", dont_skip, next_gap)
        return next_gap

    def isEffectiveNop(self, byte_sequence):
        if byte_sequence in GAP_SEQUENCES[len(byte_sequence)]:
            return True
        return False

    def isAlignmentSequence(self, instruction_sequence):
        is_alignment_sequence = False
        instructions_analyzed = 0
        if len(instruction_sequence) > 0:
            current_offset = instruction_sequence[0].address
            for instruction in instruction_sequence:
                if instruction.bytes in GAP_SEQUENCES[len(instruction.bytes)]:
                    instructions_analyzed += 1
                    current_offset += len(instruction.bytes)
                    if current_offset % 16 == 0:
                        is_alignment_sequence = True
                        break
                else:
                    break
        if len(instruction_sequence) > instructions_analyzed:
            if instruction_sequence[instructions_analyzed].mnemonic in ["leave", "ret", "retn"]:
                is_alignment_sequence = False
        return is_alignment_sequence

    def nextGapCandidate(self, start_gap_pointer=None):
        if self.language_candidates_only:
            return None
        if self.gap_pointer is None:
            self.initGapSearch()
        if start_gap_pointer:
            self.gap_pointer = start_gap_pointer
        LOGGER.debug("nextGapCandidate() finding new gap candidate, current gap_ptr: 0x%08x", self.gap_pointer)
        while True:
            if self.disassembly.binary_info.base_addr + self.disassembly.binary_info.binary_size < self.gap_pointer:
                LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return None
            gap_offset = self.gap_pointer - self.disassembly.binary_info.base_addr
            if gap_offset >= self.disassembly.binary_info.binary_size:
                return None
            # compatibility with python2/3...
            try:
                byte = self.disassembly.getRawByte(gap_offset)
            except:
                pass
                LOGGER.warn("could not fetch raw byte for gap pointer.")
                # print("0x%08x" % self.disassembly.binary_info.base_addr, "0x%08x" % self.disassembly.binary_info.binary_size, "0x%08x" % self.gap_pointer, "0x%08x" % gap_offset)
            # try to find padding symbols and skip them
            if isinstance(byte, int):
                byte = struct.pack("B", byte)
            if byte in GAP_SEQUENCES[1]:
                LOGGER.debug("nextGapCandidate() found 0xCC / 0x00 - gap_ptr += 1: 0x%08x", self.gap_pointer)
                self.gap_pointer += 1
                continue
            # try to find instructions that directly encode as NOP and skip them
            ins_buf = [i for i in self.capstone.disasm_lite(self.disassembly.getRawBytes(gap_offset, 15), gap_offset)]
            if ins_buf:
                i_address, i_size, i_mnemonic, i_op_str = ins_buf[0]
                if  i_mnemonic == "nop":
                    nop_instruction = i_mnemonic + " " + i_op_str
                    nop_length = i_size
                    LOGGER.debug("nextGapCandidate() found nop instruction (%s) - gap_ptr += %d: 0x%08x", nop_instruction, nop_length, self.gap_pointer)
                    self.gap_pointer += nop_length
                    continue
            # try to find effective NOPs and skip them.
            found_multi_byte_nop = False
            for gap_length in range(max(GAP_SEQUENCES.keys()), 1, -1):
                if self.disassembly.getRawBytes(gap_offset, gap_length) in GAP_SEQUENCES[gap_length]:
                    LOGGER.debug("nextGapCandidate() found %d byte effective nop - gap_ptr += %d: 0x%08x", gap_length, gap_length, self.gap_pointer)
                    self.gap_pointer += gap_length
                    found_multi_byte_nop = True
                    break
            if found_multi_byte_nop:
                continue
            # we know this place from data already
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
            start_byte = self.disassembly.getRawByte(gap_offset)
            has_common_prologue = True  # start_byte in FunctionCandidate(self.gap_pointer, start_byte, self.bitness).common_gap_starts[self.bitness]
            if self.previously_analyzed_gap == self.gap_pointer:
                LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed", self.gap_pointer)
                self.gap_pointer = self.getNextGap(dont_skip=True)
            elif not has_common_prologue:
                LOGGER.debug("--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%08x)", self.gap_pointer, ord(start_byte))
                self.gap_pointer = self.getNextGap(dont_skip=True)
            else:
                self.previously_analyzed_gap = self.gap_pointer
                self.addGapCandidate(self.gap_pointer)
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
        for pattern in re.finditer(r"((\xCC){2,}|(\x90){2,})", self.disassembly.binary_info.binary):
            pattern_count += 1
            pattern_functions.append(pattern.span()[1] + 1)

    def ensureCandidate(self, addr):
        """ create candidate if it does not exist yet, returns True if newly created, else False """
        if addr not in self.candidates:
            self.candidates[addr] = FunctionCandidate(self.disassembly.binary_info, addr)
            return True
        return False

    def addGapCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsGapCandidate(True)

    def addTailcallCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsTailcallCandidate(True)

    def addReferenceCandidate(self, addr, source_ref):
        if not self._passesCodeFilter(addr):
            return False
        if self.ensureCandidate(addr):
            self._all_call_refs[source_ref] = addr
        self.candidates[addr].addCallRef(source_ref)

    def addLanguageSpecCandidate(self, addr, lang_spec):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setLanguageSpec(lang_spec)

    def addPrologueCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        return self.ensureCandidate(addr)

    def addSymbolCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsSymbol(True)
        self.candidates[addr].setInitialCandidate(True)

    def addExceptionCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsExceptionHandler(True)
        self.candidates[addr].setInitialCandidate(True)

    def resolvePointerReference(self, offset):
        if self.bitness == 32:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            function_pointer = struct.unpack("I", addr_block)[0]
            return self.disassembly.dereferenceDword(function_pointer)
        if self.bitness == 64:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            function_pointer = struct.unpack("i", addr_block)[0]
            # we need to calculate RIP + offset + 7 (48 ff 25 ** ** ** **)
            if self.disassembly.getRawBytes(offset, 2) == "\xFF\x25":
                function_pointer += offset + 7
            elif self.disassembly.getRawBytes(offset, 2) == "\xFF\x15":
                function_pointer += offset + 6
            else:
                raise Exception("resolvePointerReference: should only be used on call/jmp * ptr")
            return self.disassembly.binary_info.base_addr + function_pointer
        raise Exception("resolvePointerReference: undefined bitness")

    def _identifyAlignment(self):
        identified_alignment = 0
        if self.config.USE_ALIGNMENT:
            num_candidates = sum([1 for addr, candidate in self.candidates.items() if len(candidate.call_ref_sources) > 1])
            num_aligned_16_candidates = sum([1 for addr, candidate in self.candidates.items() if len(candidate.call_ref_sources) > 1 and candidate.alignment == 16])
            num_aligned_4_candidates = sum([1 for addr, candidate in self.candidates.items() if len(candidate.call_ref_sources) > 1 and candidate.alignment >= 4])
            if num_candidates:
                alignment_16_ratio = 1.0 * num_aligned_16_candidates / num_candidates
                alignment_4_ratio = 1.0 * num_aligned_4_candidates / num_candidates
                if num_candidates > 20 and alignment_4_ratio > 0.95:
                    identified_alignment = 4
                if num_candidates > 20 and alignment_16_ratio > 0.95:
                    identified_alignment = 16
        return identified_alignment

    def locateCandidates(self):
        self.locateSymbolCandidates()
        self.locateReferenceCandidates()
        self.locatePrologueCandidates()
        self.locateLangSpecCandidates()
        self.locateStubChainCandidates()
        self.locateExceptionHandlerCandidates()
        self.identified_alignment = self._identifyAlignment()

    def _buildQueue(self):
        LOGGER.debug("Located %d function candidates", len(self.candidates))
        # increase lookup speed with static list
        self._candidate_offsets = [c.addr for c in self.candidates.values()]
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

    def locateReferenceCandidates(self):
        # check for potential call instructions and check if their destinations have a common function prologue
        for call_match in re.finditer(b"\xE8", self.disassembly.binary_info.binary):
            if not self._passesCodeFilter(self.disassembly.binary_info.base_addr + call_match.start()):
                continue
            if len(self.disassembly.binary_info.binary) - call_match.start() > 5:
                packed_call = self.disassembly.getRawBytes(call_match.start() + 1, 4)
                rel_call_offset = struct.unpack("i", packed_call)[0]
                # ignore zero offset calls, as they will likely not lead to functions but are rather used for positioning in shellcode etc
                if rel_call_offset == 0:
                    continue
                call_destination = (self.disassembly.binary_info.base_addr + rel_call_offset + call_match.start() + 5) & self.getBitMask()
                if self.disassembly.isAddrWithinMemoryImage(call_destination):
                    self.addReferenceCandidate(call_destination, self.disassembly.binary_info.base_addr + call_match.start())
                    self.setInitialCandidate(call_destination)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        if self.bitness == 32:
            for match in re.finditer(b"\xFF\x25", self.disassembly.binary_info.binary):
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(function_addr, self.disassembly.binary_info.base_addr + match.start())
                    self.setInitialCandidate(function_addr)
            # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
            for match in re.finditer(b"\xFF\x15", self.disassembly.binary_info.binary):
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(function_addr, self.disassembly.binary_info.base_addr + match.start())
                    self.setInitialCandidate(function_addr)

    def locatePrologueCandidates(self):
        # next check for the default function prologue regardless of references
        for re_prologue in DEFAULT_PROLOGUES:
            for prologue_match in re.finditer(re_prologue, self.disassembly.binary_info.binary):
                if not self._passesCodeFilter(self.disassembly.binary_info.base_addr + prologue_match.start()):
                    continue
                self.addPrologueCandidate((self.disassembly.binary_info.base_addr + prologue_match.start()) & self.getBitMask())
                self.setInitialCandidate((self.disassembly.binary_info.base_addr + prologue_match.start()) & self.getBitMask())

    def locateLangSpecCandidates(self):
        if self.lang_analyzer.checkGo():
            self.go_objects = self.lang_analyzer.getGoObjects()
            LOGGER.debug("Programming language recognized as Go, adding function start addresses from PCLNTAB: %d" % len(self.go_objects))
            for add in self.go_objects:
                self.addLanguageSpecCandidate(add, 'go')
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
                if self.disassembly.binary_info.binary[relocation_offset - 1] not in [0xE8, 0xE9]:
                    binary_as_array[relocation_offset] = image_base_as_bytes[0]
                    binary_as_array[relocation_offset + 1] = image_base_as_bytes[1]
                    binary_as_array[relocation_offset + 2] = image_base_as_bytes[2]
                    binary_as_array[relocation_offset + 3] = image_base_as_bytes[3]
            self.disassembly.binary_info.binary = bytes(binary_as_array)
            LOGGER.debug("Adding function start addresses via parser: %d" % len(self.delphi_kb_objects))
            for add in self.delphi_kb_objects:
                self.addLanguageSpecCandidate(add, 'delphi_kb')
        elif self.lang_analyzer.checkDelphi():
            LOGGER.debug("Programming language recognized as Delphi, adding function start addresses from VMTs")
            delphi_objects = self.lang_analyzer.getDelphiObjects()
            LOGGER.debug("delphi candidates based on VMT analysis: %d", len(delphi_objects))
            for obj in delphi_objects:
                self.addLanguageSpecCandidate(obj, "delphi")

    def locateStubChainCandidates(self):
        # binaries often contain long sequences of stubs, consisting only of jmp dword ptr <offset>, add such chains as candidates
        for block in re.finditer(b"(?P<block>(\xFF\x25[\S\s]{4}){2,})", self.disassembly.binary_info.binary):
            for match in re.finditer(b"\xFF\x25(?P<function>[\S\s]{4})", block.group("block")):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                self.addPrologueCandidate(stub_addr & self.getBitMask())
                self.setInitialCandidate(stub_addr & self.getBitMask())
                self.candidates[stub_addr].setIsStub(True)
        # structure for plt entries is similar but interleaved with additional code not considered functions
        for block in re.finditer(b"(?P<block>(\xFF\x25[\S\s]{4}\x68[\S\s]{4}\xE9[\S\s]{4}){2,})", self.disassembly.binary_info.binary):
            for match in re.finditer(b"\xFF\x25(?P<function>[\S\s]{4})", block.group("block")):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                self.addPrologueCandidate(stub_addr & self.getBitMask())
                self.setInitialCandidate(stub_addr & self.getBitMask())
                self.candidates[stub_addr].setIsStub(True)
                # define data bytes inbetween
                for offset in range(10):
                    self.disassembly.data_map.add(stub_addr + 6 + offset)
        # structure for plt.sec (Intel Control Flow Enforcement Technology) entries
        """
        those look e.g. like this (64bit):
        .plt.sec:000000000000CF70                                           ; =============== S U B R O U T I N E =======================================
        .plt.sec:000000000000CF70
        .plt.sec:000000000000CF70                                           ; Attributes: thunk
        .plt.sec:000000000000CF70
        .plt.sec:000000000000CF70                                           ; time_t time(time_t *timer)
        .plt.sec:000000000000CF70                                           _time           proc near               ; CODE XREF: main+BE↓p
        .plt.sec:000000000000CF70                                                                                   ; li_rand_init+37↓p ...
        .plt.sec:000000000000CF70 F3 0F 1E FA                                               endbr64
        .plt.sec:000000000000CF74 F2 FF 25 0D 2E 05 00                                      bnd jmp cs:time_ptr
        .plt.sec:000000000000CF74                                           _time           endp
        .plt.sec:000000000000CF74
        .plt.sec:000000000000CF74                                           ; ---------------------------------------------------------------------------
        .plt.sec:000000000000CF7B 0F 1F 44 00 00                                            align 20h
        """
        for block in re.finditer(b"(?P<block>(\xF3\x0F\x1E\xFA\xF2\xFF\x25[\S\s]{4}\x0F\x1F\x44\x00\x00){2,})", self.disassembly.binary_info.binary):
            for match in re.finditer(b"\xF3\x0F\x1E\xFA\xF2\xFF\x25(?P<function>[\S\s]{4})", block.group("block")):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                self.addPrologueCandidate(stub_addr & self.getBitMask())
                self.setInitialCandidate(stub_addr & self.getBitMask())
                self.candidates[stub_addr].setIsStub(True)
                # define data bytes inbetween
                for offset in range(5):
                    self.disassembly.data_map.add(stub_addr + 7 + offset)


    def locateExceptionHandlerCandidates(self):
        # 64bit only - if we have a .pdata section describing exception handlers, we extract entries of guaranteed function starts from it.
        # TODO 2020-10-29 continue here and extract function start candidates
        if self.disassembly.binary_info.bitness == 64:
            for section_info in self.disassembly.binary_info.getSections():
                section_name, section_va_start, section_va_end = section_info
                if section_name == ".pdata":
                    rva_start = section_va_start - self.disassembly.binary_info.base_addr
                    rva_end = section_va_end - self.disassembly.binary_info.base_addr
                    for offset in range(rva_start, rva_end + 1, 12):
                        packed_dword = self.disassembly.binary_info.binary[offset:offset + 4]
                        rva_function_candidate = None
                        if len(packed_dword) == 4:
                            rva_function_candidate = struct.unpack("I", packed_dword)[0]
                            self.addExceptionCandidate(self.disassembly.binary_info.base_addr + rva_function_candidate)
                        if not rva_function_candidate:
                            break
