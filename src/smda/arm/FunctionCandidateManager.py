"""AArch32 function-candidate discovery.

Reuses the candidate queue, scoring and gap book-keeping from the architecture-neutral
manager and supplies what AArch32 needs on top: every candidate is decoded in one of two
instruction sets, so the manager also owns the instruction-set map.

Instruction-set evidence, strongest first:

* bit 0 of an address the image states - an ELF function symbol or entry point, a PE
  ``.pdata`` record, a stored code pointer - is the Thumb bit (A2.3.2, interworking), as
  is ``N_ARM_THUMB_DEF`` on a Mach-O symbol;
* ELF mapping symbols (``$a``/``$t``/``$d``, ARM ELF ABI 4.5.5) name the instruction set
  of every byte range, and mark literal pools as data; Mach-O ``LC_DATA_IN_CODE`` marks
  the tables;
* the instruction that reached an address: ``bl`` stays in the caller's instruction set,
  ``blx <label>`` switches it;
* the machine the container names: a PE ``ARMNT`` image is Thumb-2 only, and a Mach-O
  armv7 one has A32 code only where a symbol, a call or its stub sections say so;
* the code an unwind entry opens with (a frame push, a halfword-aligned start) or covers;
* the code around the address, read from which instruction set's returns it holds within
  its executable section, then from the function symbols there and in the whole image.

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
from smda.utility.MachoBinary import get_active_macho_binary, get_macho_address_adjustment

from .definitions import (
    A32_BKPT_MASK,
    A32_BKPT_VALUE,
    A32_BX_MASK,
    A32_BX_VALUE,
    A32_COND_AL,
    A32_COND_MASK,
    A32_INSTRUCTION_SIZE,
    A32_LDR_PC_IP,
    A32_LLD_FILL,
    A32_NOPS,
    A32_UDF_MASK,
    A32_UDF_VALUE,
    IT_MNEMONICS,
    T16_BKPT_MASK,
    T16_BKPT_VALUE,
    T16_BX_LR,
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
    pc_value,
    split_mnemonic,
    t32_call_target,
)
from .FunctionCandidate import FunctionCandidate

LOGGER = logging.getLogger(__name__)

_TIMEOUT_POLL_INTERVAL = 4096
_SCAN_CHUNK_BYTES = _TIMEOUT_POLL_INTERVAL * 4
_MODE_POLL_SPANS = 64
_MODE_POLL_BYTES = 0x40000
#: bytes of surrounding code the instruction-set probe of an address without other evidence reads
_MODE_BLOCK_SIZE = 0x1000
#: how much a statement about an address's instruction set weighs: a stronger one replaces a
#: weaker one, among equals the first stands (only the image's own statements replace each other)
MODE_GUESS = 0  # the region the gap scan stands in
MODE_SCAN = 1  # a linear scan read a call or a prologue there
MODE_DECODED = 2  # an instruction decoded on a path, or bit 0 of an address the image holds
MODE_STATED = 3  # a symbol, the entry point, an exception directory or pclntab
_PE_MACHINE_ARM = 0x1C0
_PE_MACHINE_THUMB = 0x1C2
_PE_MACHINE_ARMNT = 0x1C4
_EXIDX_CANTUNWIND = 1
#: Mach-O ARM subtypes that run Thumb-2 code unless a symbol states otherwise: v7, v7f, v7s, v7k, v6m, v7m, v7em
_MACHO_THUMB_SUBTYPES = frozenset({9, 10, 11, 12, 14, 15, 16})
_MACHO_N_STAB = 0xE0
_MACHO_N_TYPE = 0x0E
_MACHO_N_SECT = 0x0E
_MACHO_N_ARM_THUMB_DEF = 0x0008
#: code this many words long or more is classed by how many of them are unconditional A32
_CODE_MIN_WORDS = 4
_CODE_A32_SHARE = 0.75
#: a third of every A32 stub is the literal it loads
_STUB_A32_SHARE = 0.6
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


def _codeThumb(data, a32_share=_CODE_A32_SHARE):
    """The instruction set of a short, word-aligned run of code, or None when it does not say."""
    words = struct.unpack_from(f"<{len(data) // 4}I", data)
    # a bx of any condition in A32, a bx lr in T32
    arm = sum(1 for word in words if (word & A32_BX_MASK) == A32_BX_VALUE)
    thumb = struct.unpack_from(f"<{len(data) // 2}H", data).count(T16_BX_LR)
    if arm != thumb:
        return thumb > arm
    if len(words) < _CODE_MIN_WORDS:
        return None
    # nearly every A32 instruction is unconditional, while the upper halfwords of T32
    # code only rarely begin with 0xE (b, or the prefix of a 32-bit instruction)
    unconditional = sum(1 for word in words if word & A32_COND_MASK == A32_COND_AL) / len(words)
    if unconditional >= a32_share:
        return False
    if unconditional <= 1 - a32_share:
        return True
    return None


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
        self._mode_strengths = {}
        #: functions already decoded in an instruction set a stronger statement then contradicted
        self.mode_conflicts = []
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
        #: function starts a Go image's pclntab lists, and the span from its first to its last
        self._go_starts = frozenset()
        self._go_span = (0, 0)
        #: the image's A32 code is only what a symbol, a call or a mapping symbol names (ARMNT, Mach-O armv7)
        self._a32_needs_declaration = False
        #: sorted function symbol addresses and, per address, whether its symbol states Thumb
        self._symbol_starts = []
        self._symbol_thumb_counts = [0]
        #: starts and ends of the data the image declares inside code (Mach-O LC_DATA_IN_CODE)
        self._data_in_code_starts = []
        self._data_in_code_ends = []

    def init(self, disassembly, cbAnalysisTimeout=None):
        self._resetModeState()
        self.disassembly = disassembly
        self._cb_analysis_timeout = cbAnalysisTimeout
        self._initModeEvidence()
        super().init(disassembly, cbAnalysisTimeout)

    def _canStoreCandidateMetadata(self, addr, entries):
        if addr in entries:
            return True
        cap = getattr(self.config, "MAX_FUNCTION_CANDIDATES", 0)
        if cap and addr in self.candidates and len(self.candidates) <= cap:
            return True
        return not cap or len(entries) < cap

    def _addStrongStart(self, addr):
        if self._canStoreCandidateMetadata(addr, self._strong_starts):
            self._strong_starts.add(addr)

    def _addDeclaredStart(self, addr):
        self._declared_starts.add(addr)
        self._strong_starts.add(addr)

    # --- instruction-set map -------------------------------------------------
    def _initModeEvidence(self):
        if self._candidateTimeoutTripped():
            return
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        symbols = []
        if isinstance(lief_binary, lief.ELF.Binary):
            symbols = self._readElfModeEvidence(lief_binary)
        elif isinstance(lief_binary, lief.PE.Binary):
            machine = int(lief_binary.header.machine)
            if machine == _PE_MACHINE_ARMNT:
                self._container_thumb = True
                self._a32_needs_declaration = True
            elif machine == _PE_MACHINE_ARM:
                self._container_thumb = False
        elif lief_binary is not None:
            macho = get_active_macho_binary(lief_binary, bitness=32, architecture="arm")
            if isinstance(macho, lief.MachO.Binary):
                symbols = self._readMachoModeEvidence(macho)
        if self._candidateTimeoutTripped():
            return
        if binary_info.oep is not None:
            self.noteMode(binary_info.base_addr + binary_info.oep)
        symbols.sort()
        self._symbol_starts = [addr for addr, _ in symbols]
        for _, thumb in symbols:
            self._symbol_thumb_counts.append(self._symbol_thumb_counts[-1] + thumb)
        arm, thumb = self._symbolVotes(0, float("inf"))
        if self._container_thumb is not None:
            self._default_thumb = self._container_thumb
        elif arm != thumb:
            # the instruction set the image's own function symbols state outweighs any byte pattern
            self._default_thumb = thumb > arm
        else:
            arm, thumb = self._countMarkersInCode()
            self._default_thumb = thumb > arm

    def _symbolVotes(self, start, end):
        """(A32, T32) counts of the function symbols in [start, end)."""
        low = bisect.bisect_left(self._symbol_starts, start)
        high = bisect.bisect_left(self._symbol_starts, end)
        thumb = self._symbol_thumb_counts[high] - self._symbol_thumb_counts[low]
        return high - low - thumb, thumb

    def _countMarkersInCode(self):
        binary_info = self.disassembly.binary_info
        binary = binary_info.binary
        ranges = self._executableRanges() or [(binary_info.base_addr, binary_info.base_addr + len(binary))]
        arm = thumb = 0
        for start, end in ranges:
            cursor = start - binary_info.base_addr
            stop = end - binary_info.base_addr
            while cursor < stop:
                if self._candidateTimeoutTripped():
                    return arm, thumb
                chunk_end = min(stop, cursor + _MODE_POLL_BYTES)
                if chunk_end < stop:
                    chunk_end -= chunk_end % A32_INSTRUCTION_SIZE
                    if chunk_end <= cursor:
                        chunk_end = cursor + A32_INSTRUCTION_SIZE
                counts = countModeMarkers(binary, cursor, chunk_end)
                arm += counts[0]
                thumb += counts[1]
                cursor = chunk_end
        return arm, thumb

    def _readElfModeEvidence(self, lief_binary):
        """Mapping symbols, the instruction set of every function symbol, A32 PLT sections;
        returns ``(address, thumb)`` of the function symbols."""
        mapping = []
        symbols = {}
        for index, symbol in enumerate(self._elfSymbols(lief_binary)):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return list(symbols.items())
            name = symbol.name
            value = symbol.value
            # lief hands a name that is not valid UTF-8 back as bytes
            if isinstance(name, str) and name.startswith(("$a", "$t", "$d")) and (len(name) == 2 or name[2] == "."):
                mapping.append((value, name[1]))
            elif symbol.type == lief.ELF.Symbol.TYPE.FUNC and value and symbol.shndx != 0:
                symbols[self.noteMode(value, strength=MODE_STATED)] = bool(value & 1)
                self._addDeclaredStart(value & ~1)
        entry = lief_binary.header.entrypoint
        if entry:
            self.noteMode(entry, strength=MODE_STATED)
        # _init and _fini come from glibc's A32 crti in a Thumb build too; the dynamic
        # section states them like every other code address, with bit 0 for Thumb
        for index, dynamic_entry in enumerate(lief_binary.dynamic_entries):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return list(symbols.items())
            if dynamic_entry.tag in _INIT_FINI_TAGS and dynamic_entry.value:
                self.noteMode(dynamic_entry.value, strength=MODE_STATED)
        for index, section in enumerate(lief_binary.sections):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return list(symbols.items())
            if section.name in _PLT_SECTION_NAMES and section.size and self._holdsA32PltEntries(section):
                start = section.virtual_address
                self._section_modes.append((start, start + section.size, False))
        mapping.sort()
        self._mapping_starts = [addr for addr, _ in mapping]
        self._mapping_kinds = [kind for _, kind in mapping]
        return list(symbols.items())

    def _readMachoModeEvidence(self, macho):
        """A Mach-O armv7 image is Thumb-2 but for what its symbols state as A32 (no
        ``N_ARM_THUMB_DEF``) and the stubs reached by ``blx``; ``LC_DATA_IN_CODE`` names the
        jump tables and literals inside its code. Returns ``(address, thumb)`` of the symbols
        defined in code."""
        header = macho.header
        if header.cpu_type != lief.MachO.Header.CPU_TYPE.ARM or header.cpu_subtype not in _MACHO_THUMB_SUBTYPES:
            return []
        self._a32_needs_declaration = True
        binary_info = self.disassembly.binary_info
        adjustment = get_macho_address_adjustment(
            macho, base_addr=binary_info.base_addr, bitness=32, architecture="arm"
        )
        code_sections = []
        for index, section in enumerate(macho.sections):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return []
            if section.size and section.has(lief.MachO.Section.FLAGS.SOME_INSTRUCTIONS):
                start = section.virtual_address
                code_sections.append((start, start + section.size))
                if "stub" in section.name:
                    # the linker's stubs and lazy-binding helper are A32 in a Thumb image
                    thumb = _codeThumb(bytes(section.content), _STUB_A32_SHARE)
                    if thumb is not None:
                        self._section_modes.append((start + adjustment, start + adjustment + section.size, thumb))
        symbols = {}
        for index, symbol in enumerate(macho.symbols):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return list(symbols.items())
            raw_type = symbol.raw_type
            value = symbol.value
            if raw_type & _MACHO_N_STAB or raw_type & _MACHO_N_TYPE != _MACHO_N_SECT or not value:
                continue
            if any(start <= value < end for start, end in code_sections):
                thumb = bool(symbol.description & _MACHO_N_ARM_THUMB_DEF)
                symbols[self.noteMode(value + adjustment, thumb, strength=MODE_STATED)] = thumb
        if macho.has_data_in_code:
            segments = [
                (segment.file_offset, segment.file_offset + segment.file_size, segment.virtual_address)
                for segment in macho.segments
                if segment.file_size
            ]
            data_ranges = []
            for entry in macho.data_in_code.entries:
                for start, end, address in segments:
                    if start <= entry.offset < end:
                        data_start = address + entry.offset - start + adjustment
                        data_ranges.append((data_start, data_start + entry.length))
                        break
            data_ranges.sort()
            self._data_in_code_starts = [start for start, _ in data_ranges]
            self._data_in_code_ends = [end for _, end in data_ranges]
        return list(symbols.items())

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

    def noteMode(self, addr, thumb=None, strength=MODE_DECODED):
        """Record the instruction set of the code at ``addr``; returns the even address.

        With ``thumb`` omitted, bit 0 of ``addr`` decides it, which is the interworking
        convention for every address the image stores or states. A statement replaces an
        earlier one only if it is stronger, or both are the image's own (see ``MODE_*``).
        """
        if thumb is None:
            thumb = bool(addr & 1)
        thumb = bool(thumb)
        addr &= ~1
        if (
            strength < MODE_STATED
            and addr not in self._declared_starts
            and not self._canStoreCandidateMetadata(addr, self._modes)
        ):
            return addr
        previous = self._modes.get(addr)
        if previous is not None:
            previous_strength = self._mode_strengths.get(addr, MODE_DECODED)
            if strength < previous_strength or (strength == previous_strength < MODE_STATED):
                return addr
            self._mode_strengths[addr] = strength
            if previous == thumb:
                return addr
        elif strength != MODE_DECODED:
            self._mode_strengths[addr] = strength
        self._modes[addr] = thumb
        candidate = self.candidates.get(addr)
        if candidate is not None and candidate.is_thumb != thumb:
            if not candidate.isFinished():
                candidate.is_thumb = thumb
                candidate.function_start_score = None
                candidate._score = None
            elif addr in self.disassembly.functions:
                # decoded in the instruction set a weaker statement named: the disassembler
                # undoes it and decodes it again in this one
                self.mode_conflicts.append(addr)
            elif candidate.analysis_aborted or not self.disassembly.isCode(addr):
                # decoded in the instruction set a guess named, and rejected there or left
                # without a block: the statement now made about it earns it a second attempt
                self._requeueInMode(candidate, thumb)
        return addr

    def _requeueInMode(self, candidate, thumb):
        candidate.is_thumb = thumb
        candidate.function_start_score = None
        candidate._score = None
        candidate.finished = False
        candidate.analysis_aborted = False
        candidate.abortion_reason = ""
        self.candidate_queue.add(candidate)

    def takeModeConflicts(self):
        """Hand over the conflicting functions noted so far, with their current instruction set."""
        conflicts, self.mode_conflicts = self.mode_conflicts, []
        return [(addr, self._modes[addr]) for addr in dict.fromkeys(conflicts)]

    def requeueInMode(self, addr, thumb):
        candidate = self.candidates.get(addr)
        if candidate is not None:
            self._requeueInMode(candidate, thumb)

    def notedThumb(self, addr, strength=MODE_GUESS):
        """The instruction set noted for `addr` itself by a statement at least that strong, or None."""
        if strength > MODE_GUESS and self._mode_strengths.get(addr, MODE_DECODED) < strength:
            return None
        return self._modes.get(addr)

    def _mappingKind(self, addr):
        if self._data_in_code_starts:
            index = bisect.bisect_right(self._data_in_code_starts, addr) - 1
            if index >= 0 and addr < self._data_in_code_ends[index]:
                return "d"
        return self._mappingSymbolKind(addr)

    def _mappingSymbolKind(self, addr):
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
        kind = self._mappingSymbolKind(addr)
        if kind in ("t", "a"):
            return kind == "t"
        for start, end, thumb in self._section_modes:
            if start <= addr < end:
                return thumb
        return self._container_thumb

    def _regionThumb(self, addr):
        """The instruction set the code around `addr` reads as: the markers in the
        executable section around it, then the function symbols there, then the image's."""
        if self._container_thumb is not None:
            return self._container_thumb
        binary_info = self.disassembly.binary_info
        base = binary_info.base_addr
        block = (addr - base) // _MODE_BLOCK_SIZE
        mode = self._block_modes.get(block)
        if mode is not None:
            return mode
        block_start = base + block * _MODE_BLOCK_SIZE
        low = block_start - _MODE_BLOCK_SIZE
        high = block_start + 2 * _MODE_BLOCK_SIZE
        section = self._executableRangeAt(addr)
        if section is not None:
            # literal pools and tables in a neighbouring data section vote as noise
            low, high = max(low, section[0]), min(high, section[1])
        # a block wholly inside one section, or in an image without any, is one region;
        # any other is one per section
        if section is None:
            within = not self._executableRanges()
        else:
            within = section[0] <= block_start and block_start + _MODE_BLOCK_SIZE <= section[1]
        key = block if within else (block, section)
        mode = self._block_modes.get(key)
        if mode is None:
            arm, thumb = countModeMarkers(binary_info.binary, low - base, high - base)
            if arm == thumb:
                arm, thumb = self._symbolVotes(low, high)
            mode = self._default_thumb if arm == thumb else thumb > arm
            self._block_modes[key] = mode
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
        if addr & 2 and addr not in self._modes:
            # an A32 instruction is word aligned
            self.noteMode(addr, True)
        is_new = super().ensureCandidate(addr)
        if is_new:
            self.candidates[addr].is_thumb = self.isThumb(addr)
        return is_new

    def addSymbolCandidate(self, addr):
        target = addr & ~1 if addr & 1 else addr
        added = super().addSymbolCandidate(target)
        if addr & 1 and target in self.candidates:
            self.noteMode(addr)
        return added

    def addExceptionCandidate(self, addr):
        target = addr & ~1 if addr & 1 else addr
        added = super().addExceptionCandidate(target)
        if addr & 1 and target in self.candidates:
            self.noteMode(addr)
        return added

    def addCallCandidate(self, target, thumb, source):
        """A direct call's destination, found while analysing its caller."""
        if thumb and target & 1 or not thumb and target & 3:
            return False
        if not self._passesCodeFilter(target) or not self.disassembly.isAddrWithinMemoryImage(target):
            return False
        if target in self.candidates:
            self.noteMode(target, thumb)
            self._addStrongStart(target)
            self._addCappedCallRef(self.candidates[target], source)
            self._all_call_refs[source] = target
            return True
        self.addCandidate(target, reference_source=source)
        if target not in self.candidates:
            return False
        self.noteMode(target, thumb)
        self._addStrongStart(target)
        self._candidate_offsets.add(target)
        return True

    def addPointerCandidate(self, value, source, pc_relative=False, from_thumb=False):
        """A code address held in data or materialised by code (literal, ``movw``/``movt``)."""
        if self._go_starts and value not in self._go_starts:
            # pclntab names every start of a Go image; anything else is a constant
            return False
        target = value & ~1
        thumb = bool(value & 1)
        if self._mappingKind(target) == "d":
            # a mapping symbol or LC_DATA_IN_CODE marks it data: a table or literal, not code
            return False
        if not thumb and pc_relative and from_thumb and self._declaredThumb(target) is not False:
            # Thumb code's ``adr`` names its tables and literals, which sit at even addresses;
            # only an address something else states to be A32 is an A32 entry
            return False
        if not thumb and self._refusesA32Pointer(target, pc_relative):
            return False
        if target in self.candidates or not self._passesCodeFilter(target):
            return False
        if self.disassembly.isCode(target) or not self.disassembly.isAddrWithinMemoryImage(target):
            return False
        if not thumb and self._followsThumbVeneerPrefix(target):
            # the A32 half of a Thumb veneer is entered by its ``bx pc``; a literal naming it
            # is far more often a constant that happens to match
            return False
        self.addCandidate(target, reference_source=source)
        if target not in self.candidates:
            return False
        self.noteMode(target, thumb)
        self._candidate_offsets.add(target)
        return True

    def _refusesA32Pointer(self, target, declared_only):
        """Whether an even code address is no A32 entry: interworking needs bit 0 set for
        Thumb code, and an image without A32 code but for what it declares has none there.
        With `declared_only`, the region's instruction set is no evidence against it."""
        if target & 3:
            return True
        declared = self._declaredThumb(target)
        if declared is not None:
            return declared
        return self._a32_needs_declaration or (not declared_only and self._regionThumb(target))

    def _followsThumbVeneerPrefix(self, addr):
        # ``bx pc`` continues at the next word: right before it, or before its padding
        for prefix in (addr - 2, addr - 4):
            data = self.disassembly.getBytes(prefix, 2)
            if data and bytes(data) == b"\x78\x47" and pc_value(prefix, True, aligned=True) == addr:
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
        self._locateGoCandidates()
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

    def _locateGoCandidates(self):
        """Function starts from a Go image's pclntab.

        The Go toolchain only emits A32 for AArch32 (no GOARM level selects Thumb), so every
        listed start is an A32 entry and the block around it is A32 code, whatever the
        instruction-set probe would read from it. The table is complete for Go code, which
        makes these starts as strong as symbols.
        """
        if not self.lang_analyzer.checkGo():
            return
        starts = {addr & ~1 for addr in self.lang_analyzer.getGoObjects()}
        starts = frozenset(addr for addr in starts if self._passesCodeFilter(addr) and self.isExecutable(addr))
        base = self.disassembly.binary_info.base_addr
        for index, addr in enumerate(starts):
            if index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            self.noteMode(addr, False, strength=MODE_STATED)
            self._strong_starts.add(addr)
            self._block_modes[(addr - base) // _MODE_BLOCK_SIZE] = False
            self.addLanguageSpecCandidate(addr, "go")
        self._go_starts = starts
        if starts:
            self._go_span = (min(starts), max(starts))

    def isGoImage(self):
        """Whether the image is Go with a readable pclntab."""
        return bool(self._go_starts)

    def isGoFunctionStart(self, addr):
        return addr in self._go_starts

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
        # the code areas of the image itself: this runs before the base class takes them over
        code_areas = binary_info.code_areas
        if not ranges and code_areas:
            ranges = [(start, end) for start, end in code_areas]
        self._exec_ranges = sorted(ranges)
        return self._exec_ranges

    def isExecutable(self, addr):
        """Whether ``addr`` lies in an executable section: ``.rodata`` often shares the
        executable segment, and a pointer to a string there is no code pointer."""
        if not self._executableRanges():
            return self.disassembly.binary_info.isInCodeAreas(addr)
        return self._executableRangeAt(addr) is not None

    def _executableRangeAt(self, addr):
        ranges = self._executableRanges()
        index = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
        if index >= 0 and addr < ranges[index][1]:
            return ranges[index]
        return None

    def _scanRanges(self):
        """``(start, end, thumb)`` spans of code to scan, split where the instruction set changes."""
        binary_info = self.disassembly.binary_info
        ranges = self._executableRanges() or [(binary_info.base_addr, binary_info.base_addr + len(binary_info.binary))]
        spans = []
        span_count = 0
        bytes_since_poll = 0
        for range_index, (start, end) in enumerate(ranges):
            if range_index and range_index % _MODE_POLL_SPANS == 0 and self._candidateTimeoutTripped():
                return spans
            if self._mapping_starts:
                first = bisect.bisect_right(self._mapping_starts, start)
                last = bisect.bisect_left(self._mapping_starts, end)
                span_start = start
                for span_index in range(last - first + 1):
                    if span_index and span_index % _MODE_POLL_SPANS == 0 and self._candidateTimeoutTripped():
                        return spans
                    span_end = self._mapping_starts[first + span_index] if first + span_index < last else end
                    kind = self._mappingKind(span_start)
                    if kind == "d" or span_start >= span_end:
                        span_start = span_end
                        continue
                    spans.append((span_start, span_end, kind == "t" if kind else self._regionThumb(span_start)))
                    span_count += 1
                    bytes_since_poll += span_end - span_start
                    span_start = span_end
                    if span_count % _MODE_POLL_SPANS == 0 or bytes_since_poll >= _MODE_POLL_BYTES:
                        if self._candidateTimeoutTripped():
                            return spans
                        bytes_since_poll = 0
            else:
                cursor = start
                while cursor < end:
                    if (
                        span_count
                        and (span_count % _MODE_POLL_SPANS == 0 or bytes_since_poll >= _MODE_POLL_BYTES)
                        and self._candidateTimeoutTripped()
                    ):
                        return spans
                    block_end = min(
                        end, cursor - (cursor - binary_info.base_addr) % _MODE_BLOCK_SIZE + _MODE_BLOCK_SIZE
                    )
                    thumb = self._regionThumb(cursor)
                    span_bytes = block_end - cursor
                    if spans and spans[-1][2] == thumb and spans[-1][1] == cursor:
                        spans[-1] = (spans[-1][0], block_end, thumb)
                    else:
                        spans.append((cursor, block_end, thumb))
                    cursor = block_end
                    span_count += 1
                    bytes_since_poll += span_bytes
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
            address = start & ~1
            if self._holdsLinkerFill(address):
                # lld closes the table with an EXIDX_CANTUNWIND entry for the end of the last
                # code section, which is fill (or linker-made thunks after it), not a function
                continue
            if self.disassembly.isAddrWithinMemoryImage(address) and self._passesCodeFilter(address):
                self._addDeclaredStart(address)
            if start & 1:
                self.noteMode(start)
                start &= ~1
            starts.append(start)
        # An entry covers everything up to the next one, but that is not one function: lld
        # folds runs of adjacent functions with identical unwind data (all the
        # EXIDX_CANTUNWIND ones, typically) into a single entry, so brotli's 220 functions
        # carry three. The starts are entries; the extents are not function bounds.
        ordered = sorted(set(starts))
        for start, following in zip(ordered, ordered[1:] + [None], strict=True):
            if self._declaredThumb(start) is None:
                thumb = self._entryThumb(start, following)
                if thumb is not None:
                    self.noteMode(start, thumb, MODE_SCAN)
        for start in starts:
            if not self.disassembly.isAddrWithinMemoryImage(start) or not self._passesCodeFilter(start):
                continue
            self.addExceptionCandidate(start)

    def _entryThumb(self, start, following):
        """The instruction set of an unwind entry whose start carries no Thumb bit, or None.

        A halfword-aligned start is Thumb. Otherwise the frame push that opens most entries
        names it, and failing that the code up to the next entry: A32 runtime helpers sit
        amid Thumb code and back, so the region around it is the last resort.
        """
        if start & 2:
            return True
        data = self.disassembly.getBytes(start, 8)
        if not data or len(data) != 8:
            return None
        hw1, hw2, _hw3, hw4 = struct.unpack("<HHHH", data)
        # the push word of an A32 entry is followed by more unconditional A32
        if is_a32_prologue(hw1 | hw2 << 16) and hw4 >> 12 == 0xE:
            return False
        if is_t32_prologue(hw1, hw2):
            return True
        section = self._executableRangeAt(start)
        if section is None:
            return None
        end = min(section[1], start + _MODE_BLOCK_SIZE, following or section[1])
        return _codeThumb(bytes(self.disassembly.getBytes(start, max(0, end - start)) or b""))

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
                thumb = bool(begin & 1)
                start = self.noteMode(base + begin, thumb, strength=MODE_STATED)
                length = self._pdataFunctionLength(unwind)
            else:
                # Windows CE: PrologLen:8 | FuncLen:22 | 32Bit:1 | ExceptionFlag:1, the length
                # counted in instructions of the set the 32Bit flag names
                a32 = bool(unwind >> 30 & 1)
                thumb = not a32
                start = self.noteMode(begin if begin >= base else base + begin, thumb, strength=MODE_STATED)
                length = (unwind >> 8 & 0x3FFFFF) * (A32_INSTRUCTION_SIZE if a32 else T16_INSTRUCTION_SIZE)
            if length:
                self._pdata_ranges.append((start, start + length, False))
            self._addDeclaredStart(start)
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
        return memoryview(binary_info.binary)[start - binary_info.base_addr : end - binary_info.base_addr]

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
        for chunk_start in range(0, usable, _SCAN_CHUNK_BYTES):
            if self._candidateTimeoutTripped():
                return
            chunk_end = min(usable, chunk_start + _SCAN_CHUNK_BYTES)
            tops = bytes(data[chunk_start + 3 : chunk_end : 4]).translate(_A32_CALL_TOPBYTE_FILTER)
            index = tops.find(1)
            while index >= 0:
                offset = chunk_start + index * 4
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
        chunk_size = _SCAN_CHUNK_BYTES - _SCAN_CHUNK_BYTES % 2
        for chunk_start in range(0, usable, chunk_size):
            if self._candidateTimeoutTripped():
                return
            chunk_end = min(usable, chunk_start + chunk_size)
            highs = bytes(data[chunk_start + 1 : chunk_end : 2]).translate(_T32_CALL_HIGHBYTE_FILTER)
            index = highs.find(1)
            while index >= 0:
                offset = chunk_start + index * 2
                if offset + 4 <= usable:
                    hw1 = data[offset] | (data[offset + 1] << 8)
                    hw2 = data[offset + 2] | (data[offset + 3] << 8)
                    source = start + offset
                    resolved = t32_call_target(hw1, hw2, source)
                    if resolved is not None and not self._followsT32Prefix(data, offset):
                        self._bookCall(resolved[0], resolved[1], source)
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
        self.addReferenceCandidate(target, source)
        if target not in self.candidates:
            return
        self.noteMode(target, thumb, MODE_SCAN)
        self._addStrongStart(target)
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
        go_starts = self._go_starts
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
                if go_starts and value not in go_starts:
                    # Go data is full of words that land in code, and Go code is never
                    # Thumb: only a pointer naming a pclntab start is one
                    continue
                target = value & ~1
                if not exec_low <= target < exec_high or not in_exec(target) or not self._passesCodeFilter(target):
                    continue
                thumb = bool(value & 1)
                if not thumb and self._refusesA32Pointer(target, relocated is not None):
                    continue
                if self._mappingKind(target) == "d":
                    continue
                self.addReferenceCandidate(target, scan_start + offset)
                if target in self.candidates:
                    self.noteMode(target, thumb)
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
        for chunk_start in range(0, usable, _SCAN_CHUNK_BYTES):
            if self._candidateTimeoutTripped():
                return
            chunk_end = min(usable, chunk_start + _SCAN_CHUNK_BYTES)
            tops = bytes(data[chunk_start + 3 : chunk_end : 4]).translate(_A32_PROLOGUE_TOPBYTE_FILTER)
            index = tops.find(1)
            while index >= 0:
                offset = chunk_start + index * 4
                if is_a32_prologue(int.from_bytes(data[offset : offset + 4], "little")):
                    self._bookPrologue(start + offset, False)
                index = tops.find(1, index + 1)

    def _scanT32Prologues(self, start, end):
        start = (start + 1) & ~1
        data = self._halfwords(start, end)
        usable = len(data) - len(data) % 2
        chunk_size = _SCAN_CHUNK_BYTES - _SCAN_CHUNK_BYTES % 2
        for chunk_start in range(0, usable, chunk_size):
            if self._candidateTimeoutTripped():
                return
            chunk_end = min(usable, chunk_start + chunk_size)
            highs = bytes(data[chunk_start + 1 : chunk_end : 2]).translate(_T32_PROLOGUE_HIGHBYTE_FILTER)
            index = highs.find(1)
            while index >= 0:
                offset = chunk_start + index * 2
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
                    added = self.addPrologueCandidate(entry)
                    if added or entry in self.candidates:
                        self.noteMode(entry, thumb, MODE_SCAN)
                        self.setInitialCandidate(entry)
                return
        added = self.addPrologueCandidate(addr)
        if added or addr in self.candidates:
            self.noteMode(addr, thumb, MODE_SCAN)
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
                pool = pc_value(i_address, thumb, aligned=True) + offset
                if pool < addr:
                    return False
                evidence = True
            if base in _FLAG_SETTING_BASES or sets_flags:
                flags_set = True
        if evidence:
            return True
        return None if flags_set else False

    # --- gap scan ---------------------------------------------------------------
    def isPadding(self, addr, thumb):
        """Whether the instruction-sized unit at `addr` is fill between functions: zero, a nop
        or a trap (the linker's fill, ``udf``, ``bkpt``). Past the image counts as padding."""
        data = self.disassembly.getBytes(addr, 4 if not thumb else 2)
        if not data:
            return True
        value = int.from_bytes(data, "little")
        if value == 0:
            return True
        return value in (T16_NOPS if thumb else A32_NOPS) or self._isTrapValue(value, thumb)

    def _holdsLinkerFill(self, addr):
        data = self.disassembly.getBytes(addr, 2) if self.disassembly is not None else None
        return bool(data) and len(data) == 2 and int.from_bytes(data, "little") == T16_LLD_FILL

    def isTrap(self, addr, thumb):
        """Whether `addr` holds the linker's fill, ``udf`` or ``bkpt``: nothing a compiler
        places on a path that runs, so code that reaches it has already ended."""
        if self.disassembly is None:
            return False
        data = self.disassembly.getBytes(addr, 4 if not thumb else 2)
        if not data or len(data) != (2 if thumb else 4):
            return False
        return self._isTrapValue(int.from_bytes(data, "little"), thumb)

    @staticmethod
    def _isTrapValue(value, thumb):
        if thumb:
            return (
                value == T16_LLD_FILL
                or (value & T16_UDF_MASK) == T16_UDF_VALUE
                or (value & T16_BKPT_MASK) == T16_BKPT_VALUE
            )
        return (
            value == A32_LLD_FILL
            or (value & A32_UDF_MASK) == A32_UDF_VALUE
            or (value & A32_BKPT_MASK) == A32_BKPT_VALUE
        )

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
                following = bisect.bisect_right(exec_starts, addr)
                self.gap_pointer = exec_starts[following] if following < len(exec_starts) else base + size
                continue
            if addr in self.disassembly.data_map or self.isMappedData(addr):
                self.gap_pointer += step
                continue
            if self.isPadding(addr, thumb):
                self.gap_pointer += step
                continue
            if self._go_span[0] <= addr < self._go_span[1]:
                # pclntab lists every function of the Go text: what is left between them
                # is literal pools, each behind the ``b`` the assembler places ahead of it
                self.gap_pointer = self._go_span[1]
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
            self.noteMode(addr, thumb, MODE_GUESS)
            self.addGapCandidate(addr)
            return addr
