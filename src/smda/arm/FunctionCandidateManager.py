"""AArch32 function-candidate discovery.

Reuses the candidate queue, scoring and gap book-keeping from the architecture-neutral
manager and supplies what AArch32 needs on top: every candidate is decoded in one of two
instruction sets, so the manager also owns the instruction-set map.

Instruction-set evidence, strongest first:

* bit 0 of an address the image states - an ELF function symbol or entry point, a PE
  ``.pdata`` record, a stored code pointer - is the Thumb bit (A2.3.2, interworking);
* ELF mapping symbols (``$a``/``$t``/``$d``, ARM ELF ABI 4.5.5) name the instruction set
  of every byte range, and mark literal pools as data;
* the instruction that reached an address: ``bl`` stays in the caller's instruction set,
  ``blx <label>`` switches it;
* the machine the container names (a PE ``ARMNT`` image is Thumb-2 only);
* the code around the address, read from which instruction set's returns it holds.

Candidate sources: symbols, the EHABI index table ``.ARM.exidx`` (ELF) or ``.pdata``
(PE), direct calls in both instruction sets, stored code pointers, entry prologues and
the linear gap scan.
"""

import bisect
import logging
import struct

import lief
from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs

from smda.common.FunctionCandidateManager import FunctionCandidateManager as _CommonFunctionCandidateManager

from .definitions import (
    A32_INSTRUCTION_SIZE,
    A32_LDR_PC_IP,
    A32_LLD_FILL,
    A32_NOPS,
    IT_MNEMONICS,
    T16_BKPT_MASK,
    T16_BKPT_VALUE,
    T16_INSTRUCTION_SIZE,
    T16_LLD_FILL,
    T16_NOPS,
    T16_UDF_MASK,
    T16_UDF_VALUE,
    a32_branch_target,
    countModeMarkers,
    is_a32_prologue,
    is_a32_return,
    is_t32_prefix,
    is_t32_prologue,
    is_t32_return,
    split_mnemonic,
    t32_call_target,
)
from .FunctionCandidate import FunctionCandidate

LOGGER = logging.getLogger(__name__)

_TIMEOUT_POLL_INTERVAL = 4096
#: bytes of surrounding code the instruction-set probe of an address without other evidence reads
_MODE_BLOCK_SIZE = 0x1000
_PE_MACHINE_ARM = 0x1C0
_PE_MACHINE_THUMB = 0x1C2
_PE_MACHINE_ARMNT = 0x1C4
_EXIDX_CANTUNWIND = 1
_PLT_SECTION_NAMES = frozenset({".plt", ".iplt"})
#: top bytes of every A32 BL (condition AL) and BLX <label> word
_A32_CALL_TOPBYTE_FILTER = bytes(1 if b in (0xEB, 0xFA, 0xFB) else 0 for b in range(256))
#: high bytes of the first halfword of every T32 BL / BLX <label>
_T32_CALL_HIGHBYTE_FILTER = bytes(1 if 0xF0 <= b <= 0xF7 else 0 for b in range(256))
#: top bytes of every recognised A32 prologue word
_A32_PROLOGUE_TOPBYTE_FILTER = bytes(1 if b in (0xE9, 0xE5, 0xE1) else 0 for b in range(256))
#: high bytes of every recognised T32 prologue's first halfword
_T32_PROLOGUE_HIGHBYTE_FILTER = bytes(1 if b in (0xB5, 0xE9, 0xF8) else 0 for b in range(256))
#: how far ahead of a frame push the code a compiler schedules before it may begin
HOISTED_ENTRY_WINDOW = 0x20
#: an early exit ahead of the push jumps forward into the body or to the epilogue, never further
_HOISTED_BRANCH_REACH = 0x4000
#: how many instructions behind the push may still act on the flags a compare ahead of it set
_FLAGS_READ_WINDOW = 6
_FLAG_SETTING_BASES = frozenset({"cmp", "cmn", "tst", "teq", "cbz", "cbnz"})
_INIT_FINI_TAGS = frozenset({lief.ELF.DynamicEntry.TAG.INIT, lief.ELF.DynamicEntry.TAG.FINI})
_HOIST_REFUSED_BASES = frozenset(
    {"bl", "blx", "blxns", "push", "pop", "stm", "stmdb", "stmfd", "ldm", "svc", "udf", "bkpt"}
)


class FunctionCandidateManager(_CommonFunctionCandidateManager):
    CANDIDATE_CLASS = FunctionCandidate
    CANDIDATE_ALIGNMENT = T16_INSTRUCTION_SIZE

    def __init__(self, config):
        super().__init__(config)
        self._resetModeState()

    _hoist_capstone = None
    _relocated_slots = None

    def _resetModeState(self):
        self._modes = {}
        self._mapping_starts = []
        self._mapping_kinds = []
        self._default_thumb = False
        self._block_modes = {}
        #: (start, end, thumb) of sections whose instruction set is known from their contents
        self._section_modes = []
        self._strong_starts = set()
        # the subset stated by the image itself: symbols and unwind records
        self._declared_starts = set()
        self._relocated_slots = None
        self._exec_ranges = None
        self._container_thumb = None

    def init(self, disassembly, cbAnalysisTimeout=None):
        self._resetModeState()
        self.disassembly = disassembly
        self._initModeEvidence()
        super().init(disassembly, cbAnalysisTimeout)

    # --- instruction-set map -------------------------------------------------
    def _initModeEvidence(self):
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary):
            self._readElfModeEvidence(lief_binary)
        elif isinstance(lief_binary, lief.PE.Binary):
            machine = int(lief_binary.header.machine)
            if machine == _PE_MACHINE_ARMNT:
                self._container_thumb = True
            elif machine == _PE_MACHINE_ARM:
                self._container_thumb = False
        if binary_info.oep is not None:
            self.noteMode(binary_info.base_addr + binary_info.oep)
        if self._container_thumb is not None:
            self._default_thumb = self._container_thumb
        else:
            arm, thumb = self._countMarkersInCode()
            self._default_thumb = thumb > arm

    def _countMarkersInCode(self):
        binary_info = self.disassembly.binary_info
        binary = binary_info.binary
        ranges = self._executableRanges() or [(binary_info.base_addr, binary_info.base_addr + len(binary))]
        arm = thumb = 0
        for start, end in ranges:
            counts = countModeMarkers(binary, start - binary_info.base_addr, end - binary_info.base_addr)
            arm += counts[0]
            thumb += counts[1]
        return arm, thumb

    def _readElfModeEvidence(self, lief_binary):
        mapping = []
        base_adjust = 0
        for symbol in self._elfSymbols(lief_binary):
            name = symbol.name
            value = symbol.value
            # lief hands a name that is not valid UTF-8 back as bytes
            if isinstance(name, str) and name.startswith(("$a", "$t", "$d")) and (len(name) == 2 or name[2] == "."):
                mapping.append((value + base_adjust, name[1]))
            elif symbol.type == lief.ELF.Symbol.TYPE.FUNC and value and symbol.shndx != 0:
                self.noteMode(value, authoritative=True)
                self._strong_starts.add(value & ~1)
                self._declared_starts.add(value & ~1)
        entry = lief_binary.header.entrypoint
        if entry:
            self.noteMode(entry, authoritative=True)
        # _init and _fini come from glibc's A32 crti in a Thumb build too; the dynamic
        # section states them like every other code address, with bit 0 for Thumb
        for dynamic_entry in lief_binary.dynamic_entries:
            if dynamic_entry.tag in _INIT_FINI_TAGS and dynamic_entry.value:
                self.noteMode(dynamic_entry.value, authoritative=True)
        for section in lief_binary.sections:
            if section.name in _PLT_SECTION_NAMES and section.size and self._holdsA32PltEntries(section):
                start = section.virtual_address
                self._section_modes.append((start, start + section.size, False))
        mapping.sort()
        self._mapping_starts = [addr for addr, _ in mapping]
        self._mapping_kinds = [kind for _, kind in mapping]

    @staticmethod
    def _holdsA32PltEntries(section):
        """Whether a PLT section is A32: GNU ld and lld both emit A32 PLT entries for every
        profile but M, ending each in ``ldr pc, [ip, #imm]`` (with or without writeback),
        whatever instruction set the code calling them uses."""
        content = bytes(section.content)
        for offset in range(0, len(content) - 3, 4):
            word = int.from_bytes(content[offset : offset + 4], "little")
            if (word & 0xFFDFF000) == A32_LDR_PC_IP:
                return True
        return False

    @staticmethod
    def _elfSymbols(lief_binary):
        seen = set()
        for symbols in (lief_binary.symtab_symbols, lief_binary.dynamic_symbols):
            for symbol in symbols:
                key = (symbol.name, symbol.value)
                if key in seen:
                    continue
                seen.add(key)
                yield symbol

    def noteMode(self, addr, thumb=None, authoritative=False):
        """Record the instruction set of the code at ``addr``; returns the even address.

        With ``thumb`` omitted, bit 0 of ``addr`` decides it, which is the interworking
        convention for every address the image stores or states. The first statement about an
        address stands unless a later one is authoritative (a symbol or the entry point).
        """
        if thumb is None:
            thumb = bool(addr & 1)
        addr &= ~1
        if authoritative or addr not in self._modes:
            self._modes[addr] = bool(thumb)
            candidate = self.candidates.get(addr)
            if candidate is not None and candidate.is_thumb != bool(thumb):
                if not candidate.isFinished():
                    candidate.is_thumb = bool(thumb)
                    candidate.function_start_score = None
                    candidate._score = None
                elif addr not in self.disassembly.functions and (
                    candidate.analysis_aborted or not self.disassembly.isCode(addr)
                ):
                    # decoded in the instruction set a guess named, and rejected there or left
                    # without a block: the statement now made about it earns it a second attempt
                    candidate.is_thumb = bool(thumb)
                    candidate.function_start_score = None
                    candidate._score = None
                    candidate.finished = False
                    candidate.analysis_aborted = False
                    candidate.abortion_reason = ""
                    self.candidate_queue.add(candidate)
        return addr

    def _mappingKind(self, addr):
        if not self._mapping_starts:
            return None
        index = bisect.bisect_right(self._mapping_starts, addr) - 1
        if index < 0:
            return None
        return self._mapping_kinds[index]

    def isMappedData(self, addr):
        return self._mappingKind(addr) == "d"

    def isThumb(self, addr):
        mode = self._declaredThumb(addr)
        return self._regionThumb(addr) if mode is None else mode

    def _declaredThumb(self, addr):
        mode = self._modes.get(addr)
        if mode is not None:
            return mode
        kind = self._mappingKind(addr)
        if kind in ("t", "a"):
            return kind == "t"
        for start, end, thumb in self._section_modes:
            if start <= addr < end:
                return thumb
        return None

    def _regionThumb(self, addr):
        if self._container_thumb is not None:
            return self._container_thumb
        binary_info = self.disassembly.binary_info
        block = (addr - binary_info.base_addr) // _MODE_BLOCK_SIZE
        mode = self._block_modes.get(block)
        if mode is None:
            start = block * _MODE_BLOCK_SIZE
            arm, thumb = countModeMarkers(binary_info.binary, start - _MODE_BLOCK_SIZE, start + 2 * _MODE_BLOCK_SIZE)
            mode = self._default_thumb if arm == thumb else thumb > arm
            self._block_modes[block] = mode
        return mode

    def getStrongFunctionStarts(self):
        """Starts vouched for by something other than their own bytes: symbols, unwind
        records and direct calls. A branch to one of these is a tailcall."""
        return self._strong_starts

    def getDeclaredFunctionStarts(self):
        """Starts the image states itself, in symbols and unwind records: code that runs or
        branches into one of these has reached another function."""
        return self._declared_starts

    # --- candidate registration ------------------------------------------------
    def ensureCandidate(self, addr):
        is_new = super().ensureCandidate(addr)
        if is_new:
            self.candidates[addr].is_thumb = self.isThumb(addr)
        return is_new

    def addSymbolCandidate(self, addr):
        return super().addSymbolCandidate(self.noteMode(addr) if addr & 1 else addr)

    def addExceptionCandidate(self, addr):
        return super().addExceptionCandidate(self.noteMode(addr) if addr & 1 else addr)

    def addCallCandidate(self, target, thumb, source):
        """A direct call's destination, found while analysing its caller."""
        if thumb and target & 1 or not thumb and target & 3:
            return False
        target = self.noteMode(target, thumb)
        if not self._passesCodeFilter(target) or not self.disassembly.isAddrWithinMemoryImage(target):
            return False
        self._strong_starts.add(target)
        if target in self.candidates:
            self._addCappedCallRef(self.candidates[target], source)
            self._all_call_refs[source] = target
            return True
        self.addCandidate(target, reference_source=source)
        self._candidate_offsets.add(target)
        return target in self.candidates

    def addPointerCandidate(self, value, source, pc_relative=False, from_thumb=False):
        """A code address held in data or materialised by code (literal, ``movw``/``movt``)."""
        target = value & ~1
        thumb = bool(value & 1)
        if not thumb and pc_relative and from_thumb and self._declaredThumb(target) is not False:
            # Thumb code's ``adr`` names its tables and literals, which sit at even addresses;
            # only an address something else states to be A32 is an A32 entry
            return False
        if not thumb and (target & 3 or (self._declaredThumb(target) if pc_relative else self.isThumb(target))):
            # an even address in Thumb code is not an entry: interworking needs bit 0 set
            return False
        if target in self.candidates or not self._passesCodeFilter(target):
            return False
        if self.disassembly.isCode(target) or not self.disassembly.isAddrWithinMemoryImage(target):
            return False
        if not thumb and self._followsThumbVeneerPrefix(target):
            # the A32 half of a Thumb veneer is entered by its ``bx pc``; a literal naming it
            # is far more often a constant that happens to match
            return False
        self.noteMode(target, thumb)
        self.addCandidate(target, reference_source=source)
        self._candidate_offsets.add(target)
        return True

    def _followsThumbVeneerPrefix(self, addr):
        # ``bx pc`` continues at the next word: right before it, or before its padding
        for prefix in (addr - 2, addr - 4):
            data = self.disassembly.getBytes(prefix, 2)
            if data and bytes(data) == b"\x78\x47" and (prefix + 4) & ~3 == addr:
                return True
        return False

    def addTailcallCandidate(self, addr, thumb=None):
        if thumb is not None:
            addr = self.noteMode(addr, thumb)
        elif addr & 1:
            addr = self.noteMode(addr)
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr not in self.candidates:
            return False
        self.candidates[addr].setIsTailcallCandidate(True)
        self._candidate_offsets.add(addr)
        self.candidate_queue.add(self.candidates[addr])
        return True

    # --- discovery ------------------------------------------------------------
    def locateCandidates(self):
        self.locateSymbolCandidates()
        for locate in (
            self.locateUnwindIndexCandidates,
            self.locateReferenceCandidates,
            self.locateDataPointerCandidates,
            self.locatePrologueCandidates,
        ):
            if self._candidateTimeoutTripped():
                return
            locate()
        if self._candidateTimeoutTripped():
            return
        self.locateLangSpecCandidates()
        self.identified_alignment = self._identifyAlignment()

    def _identifyAlignment(self):
        # An inferred alignment floor only discards candidates, and on AArch32 there is
        # nothing above the instruction alignment to infer: clang and GCC align entries to 4
        # in A32 and to 2 in T32 at -Os, and a floor of 4 learned from a T32 image's called
        # functions refused 38 of the 180 exported functions of lz4 built with -Os.
        return 0

    def _executableRanges(self):
        if self._exec_ranges is not None:
            return self._exec_ranges
        ranges = []
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary):
            flag = lief.ELF.Section.FLAGS.EXECINSTR.value
            for section in lief_binary.sections:
                try:
                    flags = section.flags
                except ValueError:
                    continue
                if section.virtual_address and section.size and flags & flag:
                    ranges.append((section.virtual_address, section.virtual_address + section.size))
        elif isinstance(lief_binary, lief.PE.Binary):
            execute = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
            for section in lief_binary.sections:
                if section.has_characteristic(execute) and section.virtual_size:
                    start = binary_info.base_addr + section.virtual_address
                    ranges.append((start, start + section.virtual_size))
        if not ranges and self._code_areas:
            ranges = [(start, end) for start, end in self._code_areas]
        self._exec_ranges = sorted(ranges)
        return self._exec_ranges

    def isExecutable(self, addr):
        """Whether ``addr`` lies in an executable section: ``.rodata`` often shares the
        executable segment, and a pointer to a string there is no code pointer."""
        ranges = self._executableRanges()
        if not ranges:
            return self.disassembly.binary_info.isInCodeAreas(addr)
        index = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
        return index >= 0 and addr < ranges[index][1]

    def _scanRanges(self):
        """``(start, end, thumb)`` spans of code to scan, split where the instruction set changes."""
        binary_info = self.disassembly.binary_info
        ranges = self._executableRanges() or [(binary_info.base_addr, binary_info.base_addr + len(binary_info.binary))]
        spans = []
        for start, end in ranges:
            if self._mapping_starts:
                cuts = [start]
                first = bisect.bisect_right(self._mapping_starts, start)
                last = bisect.bisect_left(self._mapping_starts, end)
                cuts.extend(self._mapping_starts[first:last])
                cuts.append(end)
                for span_start, span_end in zip(cuts, cuts[1:], strict=False):
                    kind = self._mappingKind(span_start)
                    if kind == "d" or span_start >= span_end:
                        continue
                    spans.append((span_start, span_end, kind == "t" if kind else self._regionThumb(span_start)))
            else:
                cursor = start
                while cursor < end:
                    block_end = min(
                        end, cursor - (cursor - binary_info.base_addr) % _MODE_BLOCK_SIZE + _MODE_BLOCK_SIZE
                    )
                    thumb = self._regionThumb(cursor)
                    if spans and spans[-1][2] == thumb and spans[-1][1] == cursor:
                        spans[-1] = (spans[-1][0], block_end, thumb)
                    else:
                        spans.append((cursor, block_end, thumb))
                    cursor = block_end
        return spans

    def locateUnwindIndexCandidates(self):
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, lief.ELF.Binary) and self.config.USE_ARM_EXIDX_CANDIDATES:
            self._locateExidxCandidates(lief_binary)
        elif isinstance(lief_binary, lief.PE.Binary) and self.config.USE_PE_ARM_PDATA_CANDIDATES:
            self._locatePdataCandidates(lief_binary)

    def _locateExidxCandidates(self, lief_binary):
        """Function starts from the EHABI exception index table (EHABI 5 / ARM IHI 0038).

        Every entry is a pair of words; the first is a prel31 offset from itself to the start
        of a function, and the table is sorted by that start. The table is located through
        its program header so a memory image that lost its section headers still has it.
        """
        exidx = None
        for segment in lief_binary.segments:
            if segment.type == lief.ELF.Segment.TYPE.ARM_EXIDX:
                exidx = (segment.virtual_address, segment.virtual_size)
                break
        if exidx is None:
            section = next((s for s in lief_binary.sections if s.name == ".ARM.exidx"), None)
            if section is None:
                return
            exidx = (section.virtual_address, section.size)
        table_start, table_size = exidx
        data = self.disassembly.getBytes(table_start, table_size)
        if not data:
            return
        data = bytes(data)
        starts = []
        for index in range(0, len(data) - 7, 8):
            if index % (_TIMEOUT_POLL_INTERVAL * 8) == 0 and self._candidateTimeoutTripped():
                return
            first, _second = struct.unpack_from("<II", data, index)
            if first & 0x80000000:
                continue
            offset = first & 0x7FFFFFFF
            if offset & 0x40000000:
                offset -= 0x80000000
            start = (table_start + index + offset) & 0xFFFFFFFF
            if start & 1:
                self.noteMode(start)
                start &= ~1
            starts.append(start)
        # An entry covers everything up to the next one, but that is not one function: lld
        # folds runs of adjacent functions with identical unwind data (all the
        # EXIDX_CANTUNWIND ones, typically) into a single entry, so brotli's 220 functions
        # carry three. The starts are entries; the extents are not function bounds.
        for start in starts:
            if not self.disassembly.isAddrWithinMemoryImage(start) or not self._passesCodeFilter(start):
                continue
            self._strong_starts.add(start)
            self._declared_starts.add(start)
            self.addExceptionCandidate(start)

    def _locatePdataCandidates(self, lief_binary):
        """Function starts from a PE ARMNT or Windows CE exception directory.

        Each ARMNT RUNTIME_FUNCTION is two words, the first the function's RVA with the Thumb bit
        set; the second holds either packed unwind data (flag bits 1:0 non-zero, function
        length in bits 12:2 in halfwords) or the RVA of its .xdata record.
        """
        directory = lief_binary.data_directory(lief.PE.DataDirectory.TYPES.EXCEPTION_TABLE)
        if directory is None or not directory.rva or not directory.size:
            return
        base = self.disassembly.binary_info.base_addr
        data = self.disassembly.getBytes(base + directory.rva, directory.size)
        if not data:
            return
        data = bytes(data)
        armnt = lief_binary.header.machine == lief.PE.Header.MACHINE_TYPES.ARMNT
        for index in range(0, len(data) - 7, 8):
            if index % (_TIMEOUT_POLL_INTERVAL * 8) == 0 and self._candidateTimeoutTripped():
                return
            begin, unwind = struct.unpack_from("<II", data, index)
            if not begin:
                continue
            if armnt:
                start = self.noteMode(base + begin, authoritative=True)
                length = self._pdataFunctionLength(unwind)
            else:
                # Windows CE: PrologLen:8 | FuncLen:22 | 32Bit:1 | ExceptionFlag:1, the length
                # counted in instructions of the set the 32Bit flag names
                a32 = bool(unwind >> 30 & 1)
                start = self.noteMode(begin if begin >= base else base + begin, not a32, authoritative=True)
                length = (unwind >> 8 & 0x3FFFFF) * (A32_INSTRUCTION_SIZE if a32 else T16_INSTRUCTION_SIZE)
            if length:
                self._pdata_ranges.append((start, start + length, False))
            self._strong_starts.add(start)
            self._declared_starts.add(start)
            self.addExceptionCandidate(start)

    def _pdataFunctionLength(self, unwind):
        if unwind & 3:
            return ((unwind >> 2) & 0x7FF) * 2
        xdata = self.disassembly.getBytes(self.disassembly.binary_info.base_addr + unwind, 4)
        if not xdata or len(xdata) != 4:
            return 0
        header = int.from_bytes(xdata, "little")
        return (header & 0x3FFFF) * 2

    def _pdataInteriorRefusalEnabled(self):
        return True

    def _halfwords(self, start, end):
        binary_info = self.disassembly.binary_info
        return binary_info.binary[start - binary_info.base_addr : end - binary_info.base_addr]

    def locateReferenceCandidates(self):
        """Direct calls: A32 ``bl``/``blx <label>`` words and T32 ``bl``/``blx`` pairs."""
        for start, end, thumb in self._scanRanges():
            if self._candidateTimeoutTripped():
                return
            if thumb:
                self._scanT32Calls(start, end)
            else:
                self._scanA32Calls(start, end)

    def _scanA32Calls(self, start, end):
        start = (start + 3) & ~3
        data = self._halfwords(start, end)
        usable = len(data) - len(data) % 4
        tops = data[3:usable:4].translate(_A32_CALL_TOPBYTE_FILTER)
        index = tops.find(1)
        while index >= 0:
            offset = index * 4
            source = start + offset
            word = int.from_bytes(data[offset : offset + 4], "little")
            resolved = a32_branch_target(word, source)
            if resolved is not None and (resolved[1] or word & 0x01000000):
                self._bookCall(resolved[0], resolved[1], source)
            index = tops.find(1, index + 1)

    def _scanT32Calls(self, start, end):
        start = (start + 1) & ~1
        data = self._halfwords(start, end)
        usable = len(data) - len(data) % 2
        highs = data[1:usable:2].translate(_T32_CALL_HIGHBYTE_FILTER)
        index = highs.find(1)
        while index >= 0:
            offset = index * 2
            if offset + 4 <= usable:
                hw1 = data[offset] | (data[offset + 1] << 8)
                hw2 = data[offset + 2] | (data[offset + 3] << 8)
                source = start + offset
                resolved = t32_call_target(hw1, hw2, source)
                if resolved is not None and not self._followsT32Prefix(data, offset):
                    self._bookCall(resolved[0], resolved[1], source)
                    # the second halfword of a call cannot start another one
                    index = highs.find(1, index + 2)
                    continue
            index = highs.find(1, index + 1)

    def _bookCall(self, target, thumb, source):
        if not self.disassembly.isAddrWithinMemoryImage(target) or not self._passesCodeFilter(target):
            return
        if not thumb and target & 3:
            return
        kind = self._mappingKind(target)
        if kind == "d":
            return
        if kind is None and target not in self._modes and thumb != self._regionThumb(target):
            # a scanned call that switches instruction set into code the region probe reads
            # as the caller's own set is far more often a halfword-misaligned read of two
            # unrelated instructions than an interworking call
            return
        self.noteMode(target, thumb)
        self._strong_starts.add(target)
        self.addReferenceCandidate(target, source)
        self.setInitialCandidate(target)

    def locateDataPointerCandidates(self):
        """Code addresses stored in data: constructors, vtables, callback tables.

        A T32 function's address is stored with bit 0 set, which makes such a pointer far
        stronger evidence than an arbitrary aligned word that happens to fall into code; an
        even pointer is only taken where the code around it is A32.
        """
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        exec_ranges = self._executableRanges()
        if not exec_ranges:
            return
        data_ranges = []
        if isinstance(lief_binary, lief.ELF.Binary):
            flag = lief.ELF.Section.FLAGS.EXECINSTR.value
            alloc = lief.ELF.Section.FLAGS.ALLOC.value
            for section in lief_binary.sections:
                try:
                    flags = section.flags
                except ValueError:
                    continue
                if section.virtual_address and flags & alloc and not flags & flag and section.name != ".ARM.exidx":
                    data_ranges.append((section.virtual_address, section.virtual_address + section.size))
        elif isinstance(lief_binary, lief.PE.Binary):
            execute = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
            for section in lief_binary.sections:
                if not section.has_characteristic(execute) and section.virtual_size and section.name != ".pdata":
                    section_start = binary_info.base_addr + section.virtual_address
                    data_ranges.append((section_start, section_start + section.virtual_size))
        else:
            return
        exec_starts = [start for start, _ in exec_ranges]

        def in_exec(addr):
            index = bisect.bisect_right(exec_starts, addr) - 1
            return index >= 0 and addr < exec_ranges[index][1]

        relocated = self._relocatedSlots(lief_binary)
        self._relocated_slots = relocated
        image_start = binary_info.base_addr
        image_end = image_start + binary_info.binary_size
        exec_low, exec_high = exec_ranges[0][0], max(end for _, end in exec_ranges)
        for section_start, section_end in data_ranges:
            scan_start = max((section_start + 3) & ~3, image_start)
            scan_end = min(section_end, image_end)
            data = self.disassembly.getBytes(scan_start, max(0, scan_end - scan_start))
            if not data:
                continue
            data = bytes(data)
            if relocated is not None:
                # only the relocated words can hold addresses: visit those, not every word
                offsets = sorted(
                    slot - scan_start
                    for slot in relocated
                    if scan_start <= slot <= scan_start + len(data) - 4 and not (slot - scan_start) & 3
                )
            else:
                offsets = range(0, len(data) - 3, 4)
            for count, offset in enumerate(offsets):
                if count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                    return
                value = int.from_bytes(data[offset : offset + 4], "little")
                target = value & ~1
                if not exec_low <= target < exec_high or not in_exec(target) or not self._passesCodeFilter(target):
                    continue
                thumb = bool(value & 1)
                if not thumb and (
                    target & 3 or (self._declaredThumb(target) if relocated is not None else self.isThumb(target))
                ):
                    continue
                if self._mappingKind(target) == "d":
                    continue
                self.noteMode(target, thumb)
                self.addReferenceCandidate(target, scan_start + offset)
                self.setInitialCandidate(target)

    def holdsAddress(self, slot):
        """Whether the word at `slot` can hold an address rather than an offset.

        In an image that is loaded anywhere every stored address carries a relocation, so a
        literal pool word without one is an offset: PIC code adds it to pc (``ldr r0, [pc,
        #n]`` then ``add r0, pc, r0``), and read as an address it lands on arbitrary code.
        """
        return self._relocated_slots is None or slot in self._relocated_slots

    def _relocatedSlots(self, lief_binary):
        """Addresses of the words the loader relocates, or None for an image with no relocations.

        An image that can be loaded anywhere (a shared object, a PIE, a relocatable PE) has
        every stored address fixed up at load, so a word without a relocation is not a
        pointer however much it looks like one; brotli's tables hold hundreds of constants
        such as 0x80000 that land on code. A fixed-address image has nothing to go by and
        is scanned in full.
        """
        base = self.disassembly.binary_info.base_addr
        slots = set()
        if isinstance(lief_binary, lief.ELF.Binary):
            if lief_binary.header.file_type != lief.ELF.Header.FILE_TYPE.DYN:
                return None
            slots.update(relocation.address for relocation in lief_binary.dynamic_relocations)
        elif isinstance(lief_binary, lief.PE.Binary):
            if not lief_binary.has_relocations:
                return None
            highlow = lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW
            for block in lief_binary.relocations:
                for entry in block.entries:
                    if entry.type == highlow:
                        slots.add(base + block.virtual_address + entry.position)
        return slots

    def locatePrologueCandidates(self):
        for start, end, thumb in self._scanRanges():
            if self._candidateTimeoutTripped():
                return
            if thumb:
                self._scanT32Prologues(start, end)
            else:
                self._scanA32Prologues(start, end)

    def _scanA32Prologues(self, start, end):
        start = (start + 3) & ~3
        data = self._halfwords(start, end)
        usable = len(data) - len(data) % 4
        tops = data[3:usable:4].translate(_A32_PROLOGUE_TOPBYTE_FILTER)
        index = tops.find(1)
        while index >= 0:
            offset = index * 4
            if is_a32_prologue(int.from_bytes(data[offset : offset + 4], "little")):
                self._bookPrologue(start + offset, False)
            index = tops.find(1, index + 1)

    def _scanT32Prologues(self, start, end):
        start = (start + 1) & ~1
        data = self._halfwords(start, end)
        usable = len(data) - len(data) % 2
        highs = data[1:usable:2].translate(_T32_PROLOGUE_HIGHBYTE_FILTER)
        index = highs.find(1)
        while index >= 0:
            offset = index * 2
            hw1 = data[offset] | (data[offset + 1] << 8)
            hw2 = data[offset + 2] | (data[offset + 3] << 8) if offset + 4 <= usable else None
            if is_t32_prologue(hw1, hw2) and not self._followsT32Prefix(data, offset):
                self._bookPrologue(start + offset, True)
            index = highs.find(1, index + 1)

    @staticmethod
    def _followsT32Prefix(data, offset):
        # a push-shaped halfword that is the second half of a 32-bit instruction is not one
        if offset < 2:
            return False
        return is_t32_prefix(data[offset - 2] | (data[offset - 1] << 8)) and not is_t32_prefix(
            data[offset - 4] | (data[offset - 3] << 8) if offset >= 4 else 0
        )

    def _bookPrologue(self, addr, thumb):
        if not self._passesCodeFilter(addr) or self._mappingKind(addr) == "d":
            return
        if addr in self._modes and self._modes[addr] != thumb:
            return
        if addr not in self._strong_starts and not self._splitsA32Prologue(addr, thumb):
            entry = self.hoistedEntryBefore(addr, thumb)
            if entry is not None:
                # the frame push of a function entered a few instructions earlier
                if entry not in self._strong_starts and entry not in self.candidates:
                    self.noteMode(entry, thumb)
                    if self.addPrologueCandidate(entry):
                        self.setInitialCandidate(entry)
                return
        self.noteMode(addr, thumb)
        if self.addPrologueCandidate(addr) or addr in self.candidates:
            self.setInitialCandidate(addr)

    def _splitsA32Prologue(self, addr, thumb):
        """Whether a T32 push at `addr` is the upper half of an A32 ``push {.., lr}`` word.

        The lower half of that word reads as a T32 literal load, which would pass for code
        scheduled ahead of the push and move the A32 function into the wrong instruction set.
        """
        if not thumb or addr & 3 != 2:
            return False
        data = self.disassembly.getBytes(addr - 2, 4)
        return bool(data) and len(data) == 4 and is_a32_prologue(int.from_bytes(data, "little"))

    def _endsFlowBefore(self, addr, thumb):
        """Whether the instruction ending at `addr` is padding or does not fall through."""
        if thumb:
            data = self.disassembly.getBytes(addr - 4, 4)
            if not data or len(data) != 4:
                return True
            hw0, hw1 = struct.unpack("<HH", data)
            if hw1 == 0 or hw1 == T16_LLD_FILL or hw1 in T16_NOPS or (hw1 & 0xF800) == 0xE000:
                return True
            if is_t32_prefix(hw0) and not is_t32_prefix(hw1):
                # a 32-bit instruction ends here: b.w, or a pop.w / ldr.w that loads pc
                return ((hw0 & 0xF800) == 0xF000 and (hw1 & 0xD000) == 0x9000) or is_t32_return(hw0, hw1)
            return is_t32_return(hw1)
        data = self.disassembly.getBytes(addr - 4, 4)
        if not data or len(data) != 4:
            return True
        word = struct.unpack("<I", data)[0]
        return (
            word in (0, A32_LLD_FILL)
            or word in A32_NOPS
            or is_a32_return(word)
            or (word & 0xFF000000) == 0xEA000000
            or (word & 0x0FFFFFF0) == 0x012FFF10
            and (word & 0xF0000000) == 0xE0000000
        )

    def hoistedEntryBefore(self, addr, thumb):
        """Where a function starts whose frame push at `addr` code ahead of it falls into, or None.

        Compilers schedule work ahead of the push: GCC loads the stack-protector guard or a
        global's GOT offset, or tests an argument and returns early, before saving registers.
        The push is then not the entry, and a function reached from nothing but its prologue
        would start too late. Walks back to the nearest instruction that does not fall
        through (a return, an unconditional branch, padding) at most `HOISTED_ENTRY_WINDOW`
        bytes away, and accepts the run from there to `addr` only when it decodes exactly up
        to `addr`, transfers control nowhere but forward, and carries something only code
        does: a literal load from a pool ahead of it, or a compare that a conditional branch
        or return acts on. Literal pools sit between functions too, so a run must not read as
        data: in A32 a conditional instruction with no compare before it, in T32 a halfword
        below 0x0800 (``lsls``, which is what an address in a pool decodes as).
        """
        step = T16_INSTRUCTION_SIZE if thumb else A32_INSTRUCTION_SIZE
        base = self.disassembly.binary_info.base_addr
        # the return may sit further back, behind the literal pool of the function before
        lowest = max(base, addr - 2 * HOISTED_ENTRY_WINDOW)
        start = addr - step
        while start >= lowest:
            if self._endsFlowBefore(start, thumb):
                break
            start -= step
        else:
            return None
        # the literal pool of the function before usually sits between its return and
        # this one's entry, so the run may begin anywhere behind that return
        start = max(start, addr - HOISTED_ENTRY_WINDOW)
        while start < addr:
            if start in self._strong_starts:
                return None
            if self._isHoistedEntry(start, addr, thumb):
                return start
            start += step
        return None

    def _hoistDecoder(self, thumb):
        if self._hoist_capstone is None:
            self._hoist_capstone = {
                False: Cs(CS_ARCH_ARM, CS_MODE_ARM),
                True: Cs(CS_ARCH_ARM, CS_MODE_THUMB),
            }
        return self._hoist_capstone[thumb]

    def _isHoistedEntry(self, start, addr, thumb):
        data = self.disassembly.getBytes(start, addr - start)
        if not data or len(data) != addr - start or self._mappingKind(start) == "d":
            return False
        run = list(self._hoistDecoder(thumb).disasm_lite(bytes(data), start))
        if not run or sum(instruction[1] for instruction in run) != addr - start:
            return False
        verdict = self._isHoistedRun(run, start, addr, thumb, data)
        if verdict is None:
            # a compare whose flags only the code behind the push reads: the push leaves them
            verdict = self._flagsReadAfter(addr, thumb)
        return verdict

    def _flagsReadAfter(self, addr, thumb):
        data = self.disassembly.getBytes(addr, 4 * _FLAGS_READ_WINDOW)
        if not data:
            return False
        for index, (_address, _size, mnemonic, _op_str) in enumerate(
            self._hoistDecoder(thumb).disasm_lite(bytes(data), addr, _FLAGS_READ_WINDOW)
        ):
            base, condition, sets_flags = split_mnemonic(mnemonic)
            if index and (mnemonic in IT_MNEMONICS or (condition is not None and condition != "al")):
                return True
            if index and (base in _FLAG_SETTING_BASES or sets_flags):
                return False
        return False

    @staticmethod
    def _isHoistedRun(run, start, addr, thumb, data):
        """True when the run is code ahead of a push, False when it is not, and None when
        it is otherwise acceptable but rests on a compare whose flags are read later."""
        flags_set = False
        evidence = False
        for i_address, i_size, i_mnemonic, i_op_str in run:
            base, condition, sets_flags = split_mnemonic(i_mnemonic)
            conditional = condition is not None and condition != "al"
            if thumb and i_size == 2:
                halfword = data[i_address - start] | (data[i_address - start + 1] << 8)
                if halfword < 0x0800:
                    return False
            if base in _HOIST_REFUSED_BASES or i_op_str.startswith("sp"):
                return False
            if i_mnemonic in IT_MNEMONICS:
                if not flags_set:
                    return False
                continue
            if conditional and not flags_set and base != "b":
                return False
            if base in ("b", "cbz", "cbnz"):
                target = i_op_str.rsplit("#", 1)[-1]
                try:
                    target = int(target, 0)
                except ValueError:
                    return False
                if not (conditional or base != "b") or not addr < target < addr + _HOISTED_BRANCH_REACH:
                    return False
                evidence = evidence or flags_set or base != "b"
            elif base in ("bx", "bxns") or i_op_str.startswith("pc"):
                if not conditional or i_op_str != "lr":
                    return False
                evidence = True
            elif "[pc" in i_op_str:
                literal = i_op_str.rsplit("#", 1)[-1].rstrip("]") if "#" in i_op_str else "0"
                try:
                    offset = int(literal, 0)
                except ValueError:
                    return False
                pool = ((i_address + 4) & ~3 if thumb else i_address + 8) + offset
                if pool < addr:
                    return False
                evidence = True
            if base in _FLAG_SETTING_BASES or sets_flags:
                flags_set = True
        if evidence:
            return True
        return None if flags_set else False

    # --- gap scan ---------------------------------------------------------------
    def _isPadding(self, addr, thumb):
        data = self.disassembly.getBytes(addr, 4 if not thumb else 2)
        if not data:
            return True
        value = int.from_bytes(data, "little")
        if thumb:
            return (
                value == 0
                or value == T16_LLD_FILL
                or value in T16_NOPS
                or (value & T16_UDF_MASK) == T16_UDF_VALUE
                or (value & T16_BKPT_MASK) == T16_BKPT_VALUE
            )
        return value in (0, A32_LLD_FILL) or value in A32_NOPS or (value & 0x0FF000F0) == 0x07F000F0

    def nextGapCandidate(self, start_gap_pointer=None):
        """Linear sweep of unclaimed executable bytes, halfword or word stepped by instruction set.

        Skips padding, bytes already claimed as code or data (literal pools reached by a
        load are data by the time the sweep runs), ranges a mapping symbol marks as data and
        addresses an unwind index entry declares interior to a recovered function.
        """
        if self.gap_pointer is None:
            self.initGapSearch()
        if start_gap_pointer is not None:
            self.gap_pointer = start_gap_pointer
        if self.gap_pointer is None:
            return None
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size or 0
        exec_ranges = self._executableRanges()
        exec_starts = [start for start, _ in exec_ranges]

        def in_exec(addr):
            index = bisect.bisect_right(exec_starts, addr) - 1
            return index >= 0 and addr < exec_ranges[index][1]

        scanned = 0
        while True:
            scanned += 1
            if scanned % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return None
            if base + size <= self.gap_pointer:
                return None
            thumb = self.isThumb(self.gap_pointer)
            step = T16_INSTRUCTION_SIZE if thumb else A32_INSTRUCTION_SIZE
            self.gap_pointer = (self.gap_pointer + step - 1) & ~(step - 1)
            addr = self.gap_pointer
            if addr - base + step > size:
                return None
            if addr in self.disassembly.code_map:
                self.gap_pointer = self.getNextGap()
                continue
            if exec_ranges and not in_exec(addr):
                # jump to the next executable range instead of stepping through data
                index = bisect.bisect_right(exec_starts, addr)
                if index >= len(exec_starts):
                    return None
                self.gap_pointer = exec_starts[index]
                continue
            if addr in self.disassembly.data_map or self.isMappedData(addr):
                self.gap_pointer += step
                continue
            if self._isPadding(addr, thumb):
                self.gap_pointer += step
                continue
            if self._pdata_ranges:
                containing = self.declaredExceptionRangeContaining(addr)
                if containing is not None and containing[0] in self.disassembly.functions:
                    self.gap_pointer = max(containing[1], addr + step)
                    continue
            if self.previously_analyzed_gap == addr:
                self.gap_pointer = self.getNextGap(dont_skip=True)
                continue
            if not self._passesCodeFilter(addr):
                self.gap_pointer += step
                continue
            self.previously_analyzed_gap = addr
            self.noteMode(addr, thumb)
            self.addGapCandidate(addr)
            return addr
