"""AArch64 function-candidate discovery.

Reuses the candidate queue, scoring and gap book-keeping from the
architecture-neutral candidate manager under :mod:`smda.common` and supplies
AArch64-aware byte-level scans:

* call-reference discovery scans for ``BL`` (direct call) and resolves its
  PC-relative target, in place of the x86 ``0xE8`` scan;
* prologue discovery scans for the recognized function-entry prologues (see
  :func:`smda.aarch64.definitions.is_function_prologue`), in place of the x86
  push/mov prologues;
* data-pointer discovery seeds candidates from ELF ``.init_array``/``.fini_array``
  entries and from data-section words that point into executable code, recovering
  functions reached only indirectly;
* the gap scan (:meth:`nextGapCandidate`) is an AArch64-aware linear sweep of
  unanalyzed executable bytes, recovering unreferenced / indirect-only functions
  that none of the above reaches.

* PE ARM64 exception-directory discovery (opt-in via
  ``USE_PE_ARM64_PDATA_CANDIDATES``) seeds guaranteed function starts from the
  image's ``.pdata`` RUNTIME_FUNCTION records, in place of the x86-shaped
  12-byte-record pass.

The x86-only PLT/stub-chain pass does not apply and remains a future
iterate-step; for a statically linked ELF there is no PLT to recover.
"""

import contextlib
import logging
import struct
import sys

import lief

from smda.common.FunctionCandidateManager import FunctionCandidateManager as _CommonFunctionCandidateManager
from smda.utility.MachoBinary import get_macho_stub_ranges

from .definitions import (
    ADD_IMM64_MASK,
    ADD_IMM64_VALUE,
    ADR_VALUE,
    ADRP_MASK,
    ADRP_VALUE,
    B_MASK,
    B_VALUE,
    BL_IMM_MASK,
    BL_IMM_SIGN_BIT,
    BL_MASK,
    BL_VALUE,
    BR_MASK,
    BR_VALUE,
    BTI_J,
    INSTRUCTION_SIZE,
    LDR_UNSIGNED_64_MASK,
    LDR_UNSIGNED_64_VALUE,
    NOP,
    RET_MASK,
    RET_VALUE,
    adrp_page_value,
    is_bti_landing_pad,
    is_conditional_branch,
    is_exception_record_entry,
    is_function_prologue,
    is_trap,
    rd_field,
    rn_field,
)
from .FunctionCandidate import FunctionCandidate

LOGGER = logging.getLogger(__name__)

#: How far either straight-line walk over a gap run will read before giving up. A run that
#: has not reached a terminator in this many bytes is not a block either walk can reason
#: about, so both stop rather than guess.
_GAP_RUN_LIMIT = 0x400

#: Share of an image's own call targets that metadata has to have named already before the
#: address-materialization scan is judged to have nothing left to reach. The measured
#: distribution is bimodal with a wide empty interval between the modes; this sits in its
#: upper half because the two errors are not symmetric -- running the scan when it is
#: useless costs precision, skipping it when it is not costs recall.
_METADATA_CALL_TARGET_COVERAGE = 0.95

_ARM64_PDATA_ENTRY_SIZE = 8
# items (words, matches or exception records) a scan steps over between budget polls, mirroring
# _TIMEOUT_POLL_BLOCKS in the engine. A whole exception table is walked inside one call, so
# the poll in the pass around it never comes round again while that walk is running
_TIMEOUT_POLL_INTERVAL = 4096
_ARM64_PDATA_MIN_ENTRIES = 16
_ARM64_PDATA_SEED_ENTRIES = 4
# a sample must land inside the shortest table worth carving, whatever the table's offset:
# _ARM64_PDATA_SAMPLE_STRIDE <= (MIN_ENTRIES - SEED_ENTRIES) * ENTRY_SIZE, pinned by a test
_ARM64_PDATA_SAMPLE_STRIDE = 64


class FunctionCandidateManager(_CommonFunctionCandidateManager):
    CANDIDATE_CLASS = FunctionCandidate
    CANDIDATE_ALIGNMENT = INSTRUCTION_SIZE

    def __init__(self, config):
        super().__init__(config)
        # init() resets these per binary, but a manager driven one pass at a time never
        # reaches init(), and the reference scan writes to them from its first call
        self._call_targets = set()
        self._metadata_candidates = set()

    def init(self, disassembly, cbAnalysisTimeout=None):
        # Reset the memoized executable-section ranges, the Mach-O fixup state and the
        # two sets the metadata-coverage test reads BEFORE base initialization:
        # super().init() runs candidate discovery, so a reused manager instance would
        # otherwise consume the previous binary's cached data during the scans.
        self._exec_ranges = None
        self._macho_fixup_state = None
        self._call_targets = set()
        self._metadata_candidates = set()
        super().init(disassembly, cbAnalysisTimeout)

    def hasCommonPrologue(self, addr):
        if self.disassembly.binary_info is None:
            return False
        return FunctionCandidate(self.disassembly.binary_info, addr).hasCommonFunctionStart()

    def locateCandidates(self):
        # AArch64 candidate discovery: symbols, PE ARM64 exception-directory entries
        # (opt-in), BL call references, stored function pointers (.init_array/
        # .fini_array + data tables), then entry prologues. The x86-only PLT/
        # stub-chain pass does not apply and is omitted; the NOP-based gap scan is
        # disabled (see nextGapCandidate).
        self.locateSymbolCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locatePeExceptionCandidates()
        if self._candidateTimeoutTripped():
            return
        # everything booked so far came from something the image says about itself, which is
        # what the coverage test below compares its call targets against
        self._metadata_candidates = set(self.candidates)
        self.locateReferenceCandidates()
        if self._candidateTimeoutTripped():
            return
        if not self._metadataNamedTheCallTargets():
            self.locateAddressRefCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateDataPointerCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locatePrologueCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateLangSpecCandidates()
        self.identified_alignment = self._identifyAlignment()

    @staticmethod
    def _executableSectionRanges(lief_binary):
        # Absolute [start, end) VAs of executable ELF sections (.text/.init/.fini/...).
        # Used to constrain pointer targets to genuine code: the loader's code_areas
        # can include read-only data sharing the same RX segment.
        ranges = []
        exec_flag = lief.ELF.Section.FLAGS.EXECINSTR.value
        for section in lief_binary.sections:
            flags = 0
            with contextlib.suppress(ValueError):
                flags = section.flags
            if section.virtual_address and (flags & exec_flag):
                ranges.append((section.virtual_address, section.virtual_address + section.size))
        return ranges

    @staticmethod
    def _peExecutableSectionRanges(lief_binary, base_addr):
        # Absolute [start, end) VAs of executable PE sections (IMAGE_SCN_MEM_EXECUTE).
        ranges = []
        for section in lief_binary.sections:
            if section.characteristics & 0x20000000:
                section_size = section.virtual_size or section.sizeof_raw_data
                if not section_size:
                    continue
                section_start = base_addr + section.virtual_address
                ranges.append((section_start, section_start + section_size))
        return ranges

    def _isValidArm64UnwindInfo(self, xdata_rva):
        # ARM64 .xdata header word: FunctionLength[17:0] (in words, must be nonzero),
        # Vers[19:18] (only version 0 is defined), X[20], E[21], EpilogCount[26:22],
        # CodeWords[31:27]. Records are 4-byte aligned and must lie inside the image.
        if xdata_rva == 0 or xdata_rva % 4 != 0:
            return False
        header = self.disassembly.getRawBytes(xdata_rva, 4)
        if header is None or len(header) < 4:
            return False
        return self._isValidArm64UnwindHeader(int.from_bytes(header, "little"))

    @staticmethod
    def _isValidArm64UnwindHeader(header_word):
        function_length = header_word & 0x3FFFF
        version = (header_word >> 18) & 0x3
        return version == 0 and function_length > 0

    def locatePeExceptionCandidates(self):
        # PE ARM64 exception directory: every RUNTIME_FUNCTION record names a
        # guaranteed function (or fragment) start, so accepted entries go through
        # the high-confidence exception-candidate path. Classic ARM64 (0xAA64)
        # images only; ARM64X/ARM64EC hybrids interleave x64 code and metadata
        # and are skipped. Bounds come from the Exception Directory data
        # directory's exact RVA/size, not page-rounded .pdata section bounds.
        if not self.config.USE_PE_ARM64_PDATA_CANDIDATES:
            return
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.PE.Binary):
            # A memory image keeps the mapped code but usually not a parseable header, so
            # the exception directory has to be found in the bytes instead of read from a
            # data directory. The table is self-describing enough to locate without one.
            if next(binary_info.getSections(), None) is None:
                self._carveArm64ExceptionRecords(binary_info.base_addr)
            return
        if lief_binary.header.machine != lief.PE.Header.MACHINE_TYPES.ARM64:
            return
        # is_arm64x/is_arm64ec and chpe_metadata need lief >= 0.17; on older lief an
        # ARM64X hybrid cannot be told apart, so absence of the accessors means skip.
        if getattr(lief_binary, "is_arm64x", True) or getattr(lief_binary, "is_arm64ec", True):
            return
        load_config = getattr(lief_binary, "load_configuration", None)
        if load_config is not None and getattr(load_config, "chpe_metadata", None) is not None:
            return
        exception_dir = lief_binary.data_directory(lief.PE.DataDirectory.TYPES.EXCEPTION_TABLE)
        if exception_dir is None or not exception_dir.rva or not exception_dir.size:
            return
        base_addr = binary_info.base_addr
        exec_ranges = self._peExecutableSectionRanges(lief_binary, base_addr)
        if not exec_ranges:
            return
        # 8-byte records: <BeginRVA, UnwindData>; UnwindData bits 0-1 select the format
        for record_index, record_rva in enumerate(
            range(exception_dir.rva, exception_dir.rva + exception_dir.size - 7, 8)
        ):
            if record_index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            packed_entry = self.disassembly.getRawBytes(record_rva, 8)
            if packed_entry is None or len(packed_entry) < 8:
                break
            begin_rva, unwind_data = struct.unpack("<II", packed_entry)
            if begin_rva == 0:
                break
            flag = unwind_data & 0x3
            if flag == 0:
                # UnwindData is the RVA of a full .xdata record; validate its header
                if not self._isValidArm64UnwindInfo(unwind_data):
                    continue
            elif flag != 1:
                # flag 2: packed fragment of another function's body; flag 3: reserved
                continue
            if begin_rva % INSTRUCTION_SIZE != 0:
                continue
            addr = base_addr + begin_rva
            if not any(start <= addr < end for start, end in exec_ranges):
                continue
            # Exception records also name funclets and function fragments, whose
            # begin address is a mid-body word continuing the enclosing function;
            # seeding those as authoritative starts splits real functions. Only a
            # record whose first word looks like a function entry (prologue, BTI
            # pad, or a thunk shape) names an independent function start.
            begin_word_bytes = self.disassembly.getRawBytes(begin_rva, 4)
            if begin_word_bytes is None or len(begin_word_bytes) < 4:
                continue
            begin_word = int.from_bytes(begin_word_bytes, "little")
            if not is_exception_record_entry(begin_word):
                continue
            self.addExceptionCandidate(addr)

    def _admitCarvedExceptionRecord(self, base_addr, begin_rva):
        begin_word_bytes = self.disassembly.getRawBytes(begin_rva, INSTRUCTION_SIZE)
        if begin_word_bytes is None or len(begin_word_bytes) < INSTRUCTION_SIZE:
            return
        if not is_exception_record_entry(int.from_bytes(begin_word_bytes, "little")):
            return
        self.addExceptionCandidate(base_addr + begin_rva)

    def _readArm64ExceptionRecord(self, binary, size, offset, previous_begin):
        """Return a validated ARM64 RUNTIME_FUNCTION pair at offset, or None.

        The exception directory is sorted and its BeginAddresses do not repeat, which is
        what separates a run of real records from data that merely holds plausible RVAs.
        """
        if offset + _ARM64_PDATA_ENTRY_SIZE > size:
            return None
        begin_rva, unwind_data = struct.unpack_from("<II", binary, offset)
        if begin_rva == 0 or begin_rva % INSTRUCTION_SIZE or begin_rva >= size:
            return None
        if begin_rva <= previous_begin:
            return None
        flag = unwind_data & 0x3
        if flag == 0:
            if not unwind_data or unwind_data + INSTRUCTION_SIZE > size:
                return None
            if not self._isValidArm64UnwindHeader(struct.unpack_from("<I", binary, unwind_data)[0]):
                return None
        elif flag == 3:
            return None
        else:
            function_words = (unwind_data >> 2) & 0x7FF
            if not function_words or begin_rva + function_words * INSTRUCTION_SIZE > size:
                return None
        return begin_rva, unwind_data

    def _countArm64ExceptionRecords(self, binary, size, offset, limit):
        count = 0
        previous_begin = 0
        while count < limit:
            if count and count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                break
            record = self._readArm64ExceptionRecord(binary, size, offset, previous_begin)
            if record is None:
                break
            previous_begin = record[0]
            offset += _ARM64_PDATA_ENTRY_SIZE
            count += 1
        return count

    def _locateArm64ExceptionRecordTable(self, binary):
        """Return (offset, count) of the longest RUNTIME_FUNCTION run, or (0, 0) if none qualifies."""
        size = len(binary)
        best_offset = best_count = 0
        offset = 0
        samples = 0
        while offset + _ARM64_PDATA_SEED_ENTRIES * _ARM64_PDATA_ENTRY_SIZE <= size:
            if samples % 4096 == 0 and self._candidateTimeoutTripped():
                break
            samples += 1
            for phase in (0, 4):
                seed = offset + phase
                if self._countArm64ExceptionRecords(binary, size, seed, _ARM64_PDATA_SEED_ENTRIES) < (
                    _ARM64_PDATA_SEED_ENTRIES
                ):
                    continue
                start = seed
                while start >= _ARM64_PDATA_ENTRY_SIZE:
                    previous = self._readArm64ExceptionRecord(binary, size, start - _ARM64_PDATA_ENTRY_SIZE, 0)
                    if previous is None or previous[0] >= struct.unpack_from("<I", binary, start)[0]:
                        break
                    start -= _ARM64_PDATA_ENTRY_SIZE
                count = self._countArm64ExceptionRecords(binary, size, start, size)
                if count > best_count:
                    best_offset, best_count = start, count
                offset = max(offset, start + count * _ARM64_PDATA_ENTRY_SIZE)
                break
            offset += _ARM64_PDATA_SAMPLE_STRIDE
        if best_count < _ARM64_PDATA_MIN_ENTRIES:
            return 0, 0
        return best_offset, best_count

    def _carveArm64ExceptionRecords(self, base_addr):
        binary = self.disassembly.binary_info.binary
        table_offset, table_count = self._locateArm64ExceptionRecordTable(binary)
        if not table_count:
            return
        LOGGER.debug("carved %d ARM64 RUNTIME_FUNCTION entries at 0x%08x", table_count, table_offset)
        for index in range(table_count):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            begin_rva, unwind_data = struct.unpack_from("<II", binary, table_offset + index * _ARM64_PDATA_ENTRY_SIZE)
            if unwind_data & 0x3 == 2:
                # a packed fragment continues another function's body, so its begin address is
                # not a function start - the parsed directory path skips these for the same
                # reason. The record still has to read as valid, or the run that found the
                # table would end at the first fragment in it.
                continue
            self._admitCarvedExceptionRecord(base_addr, begin_rva)

    def _executableRanges(self):
        return self._cachedExecutableSectionRanges()

    def locateDeferredCandidates(self):
        yield from self.locateEhFrameCandidates()
        yield from self.locateMachoFunctionStartCandidates()

    @staticmethod
    def _machoInstructionSectionRanges(macho, adjustment, pure_only=False):
        # SMDA-VA [start, end) ranges of Mach-O sections holding instructions.
        # pure_only restricts to S_ATTR_PURE_INSTRUCTIONS sections (no mixed
        # code/data), for scans that decode every word as an instruction.
        ins_flags = lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS.value
        if not pure_only:
            ins_flags += lief.MachO.Section.FLAGS.SOME_INSTRUCTIONS.value
        ranges = []
        for section in macho.sections:
            if section.virtual_address and section.flags.value & ins_flags:
                start = section.virtual_address + adjustment
                ranges.append((start, start + section.size))
        return ranges

    def _machoFixupState(self, macho):
        """(rebase map {LIEF slot VA -> LIEF target VA}, binding slot VAs, has_chained).

        With dyld chained fixups the mapped image holds packed fixup words, so a
        stored pointer is only meaningful through its RelocationFixup target; a
        binding slot holds an import and never a local function pointer.
        """
        # getattr: locateCandidates() runs inside the base init() before this
        # backend's init() epilogue can reset the cache attribute
        if getattr(self, "_macho_fixup_state", None) is None:
            rebases = {}
            for relocation in macho.relocations:
                target = getattr(relocation, "target", None)
                if target is not None:
                    rebases[relocation.address] = target
            bindings = set()
            for binding in getattr(macho, "bindings", []):
                address = getattr(binding, "address", 0)
                if address:
                    bindings.add(address)
            has_chained = getattr(macho, "dyld_chained_fixups", None) is not None
            self._macho_fixup_state = (rebases, bindings, has_chained)
        return self._macho_fixup_state

    def _resolveMachoStoredPointer(self, slot_lief_va, adjustment, fixup_state):
        """Resolve the pointer stored at a Mach-O slot to an SMDA VA, or None."""
        rebases, bindings, has_chained = fixup_state
        if slot_lief_va in bindings:
            return None  # import slot, never a local function
        if slot_lief_va in rebases:
            return rebases[slot_lief_va] + adjustment
        if has_chained:
            return None  # unresolved chained slot: the raw word is packed metadata
        raw = self.disassembly.getBytes(slot_lief_va + adjustment, 8)
        if raw is None or len(raw) != 8:
            return None
        value = int.from_bytes(raw, "little") & self.getBitMask()
        if not value:
            return None
        return value + adjustment

    def _locateMachoFunctionPointerMetadataCandidates(self):
        # Explicit Mach-O function-pointer metadata only - the platform-native
        # equivalent of ELF .init_array/.fini_array: mod-init/term and TLV-init
        # pointer sections, __init_offsets tables, and interposing pairs. Broad
        # regular-data sweeps are deliberately NOT performed; GOT/lazy pointers,
        # imports and stub islands are excluded.
        macho, adjustment = self._machoActiveBinaryAndAdjustment()
        if macho is None:
            return
        section_types = lief.MachO.Section.TYPE
        pointer_types = {
            section_types.MOD_INIT_FUNC_POINTERS,
            section_types.MOD_TERM_FUNC_POINTERS,
            section_types.THREAD_LOCAL_INIT_FUNCTION_POINTERS,
        }
        init_offsets_type = getattr(section_types, "INIT_FUNC_OFFSETS", None)
        interposing_type = section_types.INTERPOSING
        exec_ranges = self._machoInstructionSectionRanges(macho, adjustment)
        if not exec_ranges:
            return
        binary_info = self.disassembly.binary_info
        stub_ranges = get_macho_stub_ranges(
            macho,
            base_addr=binary_info.base_addr,
            bitness=binary_info.bitness,
            architecture=binary_info.architecture,
        )
        fixup_state = self._machoFixupState(macho)

        def seed(target, source_va):
            if target is None or target % INSTRUCTION_SIZE != 0:
                return
            if not any(start <= target < end for start, end in exec_ranges):
                return
            if any(start <= target < end for start, end in stub_ranges):
                return
            if not self._passesCodeFilter(target) or not self.disassembly.isAddrWithinMemoryImage(target):
                return
            self.addReferenceCandidate(target, source_va)
            self.setInitialCandidate(target)

        rebases = fixup_state[0]
        for section in macho.sections:
            if not section.virtual_address or not section.size:
                continue
            section_type = section.type
            if section_type in pointer_types:
                for slot_va in self._machoMetadataSlots(section, 8, adjustment, rebases):
                    if self._candidateTimeoutTripped():
                        return
                    seed(self._resolveMachoStoredPointer(slot_va, adjustment, fixup_state), slot_va + adjustment)
            elif init_offsets_type is not None and section_type == init_offsets_type:
                # __init_offsets: 32-bit offsets from the image base, no fixups involved
                for slot_va in self._machoMetadataSlots(section, 4, adjustment, ()):
                    if self._candidateTimeoutTripped():
                        return
                    raw = self.disassembly.getBytes(slot_va + adjustment, 4)
                    if raw is None or len(raw) != 4:
                        continue
                    seed(macho.imagebase + int.from_bytes(raw, "little") + adjustment, slot_va + adjustment)
            elif section_type == interposing_type:
                # interposing entries are <replacement, replacee> pointer pairs; only
                # the replacement of a complete pair is a local function
                for pair_va in self._machoMetadataSlots(section, 16, adjustment, rebases):
                    if self._candidateTimeoutTripped():
                        return
                    seed(self._resolveMachoStoredPointer(pair_va, adjustment, fixup_state), pair_va + adjustment)

    def _machoMetadataSlots(self, section, stride, adjustment, rebases):
        """Slot VAs in `section`, `stride` apart, that could resolve to anything at all.

        A section header declares an extent; the mapped image decides what can be read. A slot
        outside the image reads back None, so striding over a damaged `section.size` only spends
        the analysis budget - the same shape as the ELF scan next door. The one thing that can
        still resolve out there is a slot a rebase names, so those are yielded too rather than
        assumed away: the range is clamped for cost, the union keeps it output-equivalent.

        Addresses here are LIEF VAs, which `adjustment` maps to SMDA's, so the image bounds have
        to be brought back the other way before they can be compared.
        """
        binary_info = self.disassembly.binary_info
        image_start = binary_info.base_addr - adjustment
        image_end = image_start + binary_info.binary_size
        start = section.virtual_address
        end = start + section.size
        first = max(start, image_start)
        if first > start:
            # keep the stride phase the declared extent set, so the same slots are visited
            first = start + -(-(first - start) // stride) * stride
        last = min(end, image_end)
        if last > first:
            yield from range(first, last - (stride - 1), stride)
        for slot in sorted(rebases):
            if start <= slot < end and not (first <= slot < last) and (slot - start) % stride == 0:
                yield slot

    def locateDataPointerCandidates(self):
        # Seed candidates from stored function pointers. ELF .init_array/.fini_array
        # entries are authoritative constructor/destructor pointers; other data
        # sections are scanned for aligned words pointing into executable code.
        # Mach-O images use their explicit function-pointer metadata instead.
        # This recovers functions reached only indirectly (CRT init stubs, pointer
        # / dispatch tables) that no direct BL or recognized prologue would find,
        # and anchors true entries so the prologue scan no longer mislabels an
        # inner block as the function start.
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if isinstance(lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary)):
            self._locateMachoFunctionPointerMetadataCandidates()
            return
        if not isinstance(lief_binary, lief.ELF.Binary) or not lief_binary.sections:
            return
        exec_ranges = self._executableSectionRanges(lief_binary)
        if not exec_ranges:
            return

        def in_exec(addr):
            return any(start <= addr < end for start, end in exec_ranges)

        pointer_size = 8 if binary_info.bitness == 64 else 4
        bit_mask = self.getBitMask()
        image_start = binary_info.base_addr
        image_end = image_start + binary_info.binary_size
        exec_flag = lief.ELF.Section.FLAGS.EXECINSTR.value
        for section in lief_binary.sections:
            flags = 0
            with contextlib.suppress(ValueError):
                flags = section.flags
            # scan only non-executable, addressable sections for pointers into code
            if not section.virtual_address or (flags & exec_flag):
                continue
            section_start = section.virtual_address
            section_end = section_start + section.size
            # Align the scan to a pointer_size boundary: stored pointers are
            # naturally aligned, so an unaligned section start would otherwise
            # stride past every aligned pointer in the section.
            scan_start = (section_start + (pointer_size - 1)) & ~(pointer_size - 1)
            # A section header can describe an extent the mapped image does not hold, and a
            # damaged one routinely does. Every read outside the image comes back None, so
            # those addresses cannot yield a candidate and only spend the analysis budget;
            # the surviving range visits exactly the addresses that could have matched.
            if scan_start < image_start:
                scan_start += -(-(image_start - scan_start) // pointer_size) * pointer_size
            scan_end = min(section_end, image_end)
            for match_count, pointer_va in enumerate(range(scan_start, scan_end - (pointer_size - 1), pointer_size)):
                if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                    return
                raw = self.disassembly.getBytes(pointer_va, pointer_size)
                if raw is None or len(raw) != pointer_size:
                    continue
                target = int.from_bytes(raw, "little") & bit_mask
                # a function pointer is instruction-aligned and lands inside code
                if target % INSTRUCTION_SIZE != 0 or not in_exec(target):
                    continue
                if not self._passesCodeFilter(target):
                    continue
                self.addReferenceCandidate(target, pointer_va)
                self.setInitialCandidate(target)

    def _metadataNamedTheCallTargets(self):
        """Whether this image's metadata has already supplied the functions, leaving the
        address-materialization scan nothing to find.

        That scan exists to reach entries no call names -- a pointer handed to a callback,
        a table walked at run time. An image that ships a full function map has none of
        those left over: the symbol pass consumes the map, every entry is already a
        candidate, and what the scan then produces is the addresses that are materialized
        but are not entries. On a Go binary that is thousands of them for no recovered
        function at all.

        The question is asked of the image rather than of its container or its language,
        both of which have been the wrong variable before: of the addresses this image's
        own `bl` instructions call, how many did metadata name before this pass ran? A
        stripped C or C++ object answers near zero however it was linked; one carrying a
        complete map answers near one whoever compiled it.

        `bl` targets are the denominator because they are the one population both kinds of
        image have, in proportion to how many functions they contain, and because they are
        known at exactly this point -- the scan that resolves them has just finished.
        """
        if not self._call_targets:
            # nothing calls anything: no evidence either way, and the scan is the only pass
            # left that could reach an entry, so let it run
            return False
        named = sum(1 for target in self._call_targets if target in self._metadata_candidates)
        return named / len(self._call_targets) >= _METADATA_CALL_TARGET_COVERAGE

    def locateAddressRefCandidates(self):
        # Reference discovery for addresses materialized in code: adr Xd, #imm and the
        # adrp Xd, #page / add Xd, Xn, #lo12 pair. When the resulting address lands in
        # an executable section it is a function reference (e.g. a function pointer
        # passed to a callback), so seed it as a (weak) reference candidate. Tracks the
        # adrp page held per register along straight-line runs, invalidating on writes
        # and clearing at any control-flow edge. Targets reached only this way are
        # common in position-independent code.
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        adjustment = 0
        macho_fixup_state = None
        if isinstance(lief_binary, lief.ELF.Binary) and lief_binary.sections:
            exec_ranges = self._executableSectionRanges(lief_binary)
        elif self.config.USE_MACHO_ADDRESS_REF_CANDIDATES and isinstance(
            lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary)
        ):
            # opt-in Mach-O extension: scan only S_ATTR_PURE_INSTRUCTIONS sections
            # (every word is decoded as an instruction) and resolve loaded slots
            # through local fixups before trusting stored words
            macho, adjustment = self._machoActiveBinaryAndAdjustment()
            if macho is None:
                return
            exec_ranges = self._machoInstructionSectionRanges(macho, adjustment, pure_only=True)
            macho_fixup_state = self._machoFixupState(macho)
        else:
            return
        if not exec_ranges:
            return
        base = binary_info.base_addr
        binary = binary_info.binary
        bit_mask = self.getBitMask()
        words = self._wordsView()

        def in_exec(addr):
            return any(start <= addr < end for start, end in exec_ranges)

        def seed(target, source):
            if target is None:
                return
            target &= bit_mask
            if target % INSTRUCTION_SIZE != 0 or not in_exec(target):
                return
            if not (self._passesCodeFilter(target) and self.disassembly.isAddrWithinMemoryImage(target)):
                return
            if macho_fixup_state is not None:
                # Mach-O targets are weak address evidence, not inbound call refs:
                # register the bare candidate without a reference source so it gains
                # no call-reference score (addCandidate would touch the queue, which
                # does not exist yet during candidate identification)
                self.ensureCandidate(target)
            else:
                self.addReferenceCandidate(target, source)

        for low, high in exec_ranges:
            pages: dict[int, int] = {}  # Xd -> adrp page base currently held in that register
            addr = low
            match_count = 0
            while addr + INSTRUCTION_SIZE <= high:
                if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                    return
                match_count += 1
                offset = addr - base
                if offset < 0 or offset + INSTRUCTION_SIZE > len(binary):
                    addr += INSTRUCTION_SIZE
                    continue
                if offset % INSTRUCTION_SIZE == 0:
                    word = words[offset // INSTRUCTION_SIZE]
                else:
                    word = int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")
                if (word & ADRP_MASK) == ADRP_VALUE:
                    pages[rd_field(word)] = adrp_page_value(word, addr)
                elif (word & ADRP_MASK) == ADR_VALUE:
                    immlo = (word >> 29) & 0x3
                    immhi = (word >> 5) & 0x7FFFF
                    imm = (immhi << 2) | immlo
                    if imm & (1 << 20):
                        imm -= 1 << 21
                    seed(addr + imm, addr)
                    pages.pop(rd_field(word), None)
                elif (word & ADD_IMM64_MASK) == ADD_IMM64_VALUE:
                    rn = rn_field(word)
                    if rn in pages:
                        seed(pages[rn] + ((word >> 10) & 0xFFF), addr)
                    pages.pop(rd_field(word), None)
                elif (word & LDR_UNSIGNED_64_MASK) == LDR_UNSIGNED_64_VALUE:  # ldr Xt, [Xn, #imm]
                    rn = rn_field(word)
                    rd = rd_field(word)
                    if rn in pages:
                        imm = ((word >> 10) & 0xFFF) * 8
                        slot_addr = pages[rn] + imm
                        if macho_fixup_state is not None:
                            val = self._resolveMachoStoredPointer(slot_addr - adjustment, adjustment, macho_fixup_state)
                            if val is not None:
                                seed(val, addr)
                        elif self.disassembly.isAddrWithinMemoryImage(slot_addr):
                            raw_val = self.disassembly.getBytes(slot_addr, 8)
                            if raw_val and len(raw_val) == 8:
                                val = struct.unpack("<Q", raw_val)[0]
                                seed(val, addr)
                    pages.pop(rd, None)
                elif (
                    (word & B_MASK) == B_VALUE
                    or (word & BL_MASK) == BL_VALUE
                    or (word & RET_MASK) == RET_VALUE
                    or (word & BR_MASK) == BR_VALUE
                    or is_conditional_branch(word)
                ):
                    pages.clear()  # control-flow edge: register provenance no longer holds
                else:
                    pages.pop(rd_field(word), None)  # any other write invalidates the dest register
                addr += INSTRUCTION_SIZE

    def locateReferenceCandidates(self):
        # AArch64 direct calls are BL (100101 + imm26). Scan the mapped image
        # word-by-word, resolve each BL's PC-relative target and register it as a
        # call-reference candidate — the AArch64 analogue of the base 0xE8 scan.
        base = self.disassembly.binary_info.base_addr
        for match_count, word in enumerate(self._wordsView()):
            if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            if (word & BL_MASK) != BL_VALUE:
                continue
            source = base + match_count * INSTRUCTION_SIZE
            if not self._passesCodeFilter(source):
                continue
            imm = word & BL_IMM_MASK
            if imm & BL_IMM_SIGN_BIT:
                imm -= BL_IMM_SIGN_BIT << 1  # sign-extend the 26-bit immediate
            target = (source + imm * INSTRUCTION_SIZE) & self.getBitMask()
            if self.disassembly.isAddrWithinMemoryImage(target):
                self._call_targets.add(target)
                self.addReferenceCandidate(target, source)
                self.setInitialCandidate(target)

    def locatePrologueCandidates(self):
        # AArch64 lacks a single dominant byte prologue (no push ebp). Scan the
        # image word-by-word for the recognized function-entry prologues
        # (frame-record store, callee-saved pair save, link-register save, PAC/BTI);
        # see definitions.is_function_prologue for the exact encodings.
        base = self.disassembly.binary_info.base_addr
        for match_count, word in enumerate(self._wordsView()):
            if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            if not is_function_prologue(word):
                continue
            addr = (base + match_count * INSTRUCTION_SIZE) & self.getBitMask()
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(addr, word):
                continue
            if not self._passesCodeFilter(addr):
                continue
            self.addPrologueCandidate(addr)
            self.setInitialCandidate(addr)

    def addTailcallCandidate(self, addr, reference_source=None):
        if not self._passesCodeFilter(addr):
            return False
        is_new = self.ensureCandidate(addr)
        if addr not in self.candidates:
            return False
        candidate = self.candidates[addr]
        candidate.setIsTailcallCandidate(True)
        score_changed = self._addCappedCallRef(candidate, reference_source) if reference_source is not None else False
        self._candidate_offsets.add(addr)
        self.candidate_queue.add(candidate)
        if score_changed and not is_new:
            self.candidate_queue.update(candidate)
        return True

    def _cachedExecutableSectionRanges(self):
        ranges = getattr(self, "_exec_ranges", None)
        if ranges is None:
            lief_binary = self.disassembly.binary_info.getLiefBinary()
            ranges = self._executableSectionRanges(lief_binary) if isinstance(lief_binary, lief.ELF.Binary) else []
            self._exec_ranges = ranges
        return ranges

    def _wordsView(self):
        """Zero-copy little-endian 4-byte word view of the mapped image, shared by
        the word-at-a-time scan passes (reference/prologue discovery, gap sweep).

        memoryview.cast uses native byte order, so on big-endian hosts fall back to
        materialized little-endian words; the view is rebuilt if the binary buffer
        is replaced (e.g. by a relocation-applying language pass)."""
        binary = self.disassembly.binary_info.binary
        words = getattr(self, "_word_view", None)
        if words is None or getattr(self, "_word_view_source", None) is not binary:
            if sys.byteorder == "little":
                usable = len(binary) - (len(binary) % INSTRUCTION_SIZE)
                words = memoryview(binary[:usable]).cast("I")
            else:
                words = [
                    int.from_bytes(binary[o : o + INSTRUCTION_SIZE], "little")
                    for o in range(0, len(binary) - (len(binary) % INSTRUCTION_SIZE), INSTRUCTION_SIZE)
                ]
            self._word_view = words
            self._word_view_source = binary
        return words

    def _wordAtOffset(self, offset):
        """Word at byte offset, matching int.from_bytes(binary[o:o+4], "little")."""
        if offset >= 0 and offset % INSTRUCTION_SIZE == 0:
            words = self._wordsView()
            if offset // INSTRUCTION_SIZE < len(words):
                return words[offset // INSTRUCTION_SIZE]
            return None
        binary = self.disassembly.binary_info.binary
        if offset < 0 or offset + INSTRUCTION_SIZE > len(binary):
            return None
        return int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")

    def _gapRunFlowsIntoInterior(self, start):
        # G3: decode the straight-line run from `start` to its first terminator. If it
        # ends in an unconditional `b` into the interior of already-mapped code (a
        # known instruction that is not itself a function-start candidate), the run is
        # a mid-function tail rather than a new function — so suppress it.
        # The terminator set omits the trap words _endOfRefusedLandingPadRun stops at, and
        # that is deliberate: skipping and suppressing cannot stop in the same places. A
        # skip that reads one instruction too far steps over a real entry and loses it; a
        # suppression that reads further only learns more about the same candidate. Nor is
        # a trap a boundary the image declares - mid-body it is a bounds check, and it ends
        # a function only by the backend's own END_INS convention - so the words behind it
        # still belong to the enclosing routine. Pinned by
        # tests/testAArch64GapRunTerminators.py.
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size
        words = self._wordsView()
        addr = start
        limit = start + _GAP_RUN_LIMIT
        while addr + INSTRUCTION_SIZE <= base + size and addr < limit:
            word = words[(addr - base) // INSTRUCTION_SIZE]
            if (word & B_MASK) == B_VALUE:
                imm = word & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                target = addr + imm * INSTRUCTION_SIZE
                # getFunctionStartCandidates() is a snapshot taken before analysis begins, and
                # gap analysis never adds to it, so a function it discovered is code_map'd but
                # absent from the set -- indistinguishable here from somebody's interior. Ask
                # the live function set too, or a branch to a real entry reads as a tail.
                if target in self.disassembly.functions:
                    return False
                return target in self.disassembly.code_map and target not in self.getFunctionStartCandidates()
            if (word & RET_MASK) == RET_VALUE or (word & BR_MASK) == BR_VALUE:
                return False
            addr += INSTRUCTION_SIZE
        return False

    def _endOfRefusedLandingPadRun(self, start):
        """Where the scan may resume after refusing a landing pad, without meeting its body.

        Advancing one instruction from a refused pad lands on the pad's own first body
        instruction. That word is ordinary code, so it passes every remaining guard and is
        promoted in the pad's place four bytes along - the false positive moves rather than
        going. The block a pad labels ends at its first terminator, and past that is the
        first address the scan has not already decided against.

        Falls back to the single-instruction step when no terminator is in reach, so a run
        of undecodable bytes cannot make this skip an arbitrary distance.

        A trap ends the block here, unlike in _gapRunFlowsIntoInterior next door, which
        shares this walk's bound but not that terminator.
        """
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size
        words = self._wordsView()
        addr = start + INSTRUCTION_SIZE
        limit = start + _GAP_RUN_LIMIT
        while addr + INSTRUCTION_SIZE <= base + size and addr < limit:
            word = words[(addr - base) // INSTRUCTION_SIZE]
            if (
                (word & RET_MASK) == RET_VALUE
                or (word & BR_MASK) == BR_VALUE
                or (word & B_MASK) == B_VALUE
                or is_trap(word)
            ):
                return addr + INSTRUCTION_SIZE
            addr += INSTRUCTION_SIZE
        return start + INSTRUCTION_SIZE

    def _isLikelyInteriorBtiCandidate(self, addr, word):
        # BTI marks both real entries and indirect-branch landing pads. If the word
        # sits inside already claimed code, or immediately follows ordinary code
        # rather than padding / a terminator-like boundary, suppress it as an entry
        # candidate so switch targets and guarded blocks do not fragment functions.
        if self.config.USE_AARCH64_BTI_TARGET_TYPE and word == BTI_J:
            # `bti j` permits a target reached by `br` - an indirect jump - and never one
            # reached by `blr`: a call landing on a J-only pad faults. The compiler that wrote
            # J was naming an interior label, a switch case or a computed-goto target, and the
            # pad says so about itself before anything around it is read. The checks below
            # cannot say it: a case block is preceded by the previous case's terminating
            # branch, which is exactly the boundary shape they read as an entry.
            return True
        if (
            addr in self.disassembly.code_map
            and addr not in self.getFunctionStartCandidates()
            and addr not in self.disassembly.functions
        ):
            return True

        base = self.disassembly.binary_info.base_addr
        binary = self.disassembly.binary_info.binary
        offset = addr - base
        if offset < INSTRUCTION_SIZE or offset > len(binary):
            return False

        prev_word = self._wordAtOffset(offset - INSTRUCTION_SIZE)
        if prev_word in (0, NOP):
            return False
        auth_or_exception_return = prev_word in {
            0xD65F0BFF,  # retaa
            0xD65F0FFF,  # retab
            0xD69F03E0,  # eret
            0xD69F0BFF,  # eretaa
            0xD69F0FFF,  # eretab
            0xD6BF03E0,  # drps (Debug Restore PState: transfers control to ELR_ELx, same class)
        }
        return not (
            (prev_word & RET_MASK) == RET_VALUE
            or (prev_word & BR_MASK) == BR_VALUE
            or (prev_word & B_MASK) == B_VALUE
            or (prev_word & BL_MASK) == BL_VALUE
            or is_trap(prev_word)
            or auth_or_exception_return
        )

    def nextGapCandidate(self, start_gap_pointer=None):
        # AArch64 gap scan: a fixed-stride linear sweep of unanalyzed executable bytes
        # for functions that no prologue, call reference or stored pointer reached
        # (typically unreferenced / indirect-only routines). Guards keep each gap
        # candidate at a plausible function entry: skip padding (nop / zero) and traps,
        # constrain to genuine executable sections (the loader's code_areas can be a
        # coarse segment covering data), and drop runs that flow into the interior of an
        # already-mapped function.
        if self.gap_pointer is None:
            self.initGapSearch()
        # Explicit None test: a gap start at VA 0x0 (valid for a base-0 buffer) is a
        # real argument, not "unset", so a truthiness check would wrongly drop it.
        if start_gap_pointer is not None:
            self.gap_pointer = start_gap_pointer
        if self.gap_pointer is None:
            return None
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size or 0
        exec_ranges = self._cachedExecutableSectionRanges()
        words = self._wordsView()

        def in_exec(addr):
            return any(start <= addr < end for start, end in exec_ranges)

        scanned = 0
        while True:
            scanned += 1
            if scanned % 4096 == 0 and self._candidateTimeoutTripped():
                return None
            if base + size < self.gap_pointer:
                return None
            # align to the instruction stride
            self.gap_pointer = (self.gap_pointer + (INSTRUCTION_SIZE - 1)) & ~(INSTRUCTION_SIZE - 1)
            offset = self.gap_pointer - base
            if offset < 0 or offset + INSTRUCTION_SIZE > size:
                return None
            if self.gap_pointer in self.disassembly.code_map:
                self.gap_pointer = self.getNextGap()
                continue
            if self.gap_pointer in self.disassembly.data_map:
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if exec_ranges and not in_exec(self.gap_pointer):
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            word = words[offset // INSTRUCTION_SIZE]
            if word in (0, NOP):  # inter-function padding
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(self.gap_pointer, word):
                self.gap_pointer = self._endOfRefusedLandingPadRun(self.gap_pointer)
                continue
            if is_trap(word):  # udf-space data words / trap filler, never an entry
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if self.previously_analyzed_gap == self.gap_pointer:
                self.gap_pointer = self.getNextGap(dont_skip=True)
                continue
            if not self._passesCodeFilter(self.gap_pointer):
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if self._gapRunFlowsIntoInterior(self.gap_pointer):
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            self.previously_analyzed_gap = self.gap_pointer
            self.addGapCandidate(self.gap_pointer)
            return self.gap_pointer
