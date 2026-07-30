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

from smda.common.EhFrameDecoder import decodeEhFrameFdeRanges
from smda.common.FunctionCandidateManager import FunctionCandidateManager as _CommonFunctionCandidateManager
from smda.utility.MachoBinary import get_active_macho_binary, get_macho_address_adjustment, get_macho_stub_ranges

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


class FunctionCandidateManager(_CommonFunctionCandidateManager):
    CANDIDATE_CLASS = FunctionCandidate

    def init(self, disassembly, cbAnalysisTimeout=None):
        # Reset the memoized executable-section ranges and Mach-O fixup state
        # BEFORE base initialization: super().init() runs candidate discovery,
        # so a reused manager instance would otherwise consume the previous
        # binary's cached data during the scans.
        self._exec_ranges = None
        self._macho_fixup_state = None
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
        self.locateReferenceCandidates()
        if self._candidateTimeoutTripped():
            return
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
            if section.characteristics & 0x20000000 and section.virtual_size:
                section_start = base_addr + section.virtual_address
                ranges.append((section_start, section_start + section.virtual_size))
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
        header_word = int.from_bytes(header, "little")
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
            if record_index % 4096 == 0 and self._candidateTimeoutTripped():
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

    def locateDeferredCandidates(self):
        # ELF .eh_frame FDE starts (opt-in): every FDE names a code range that
        # unwinding treats as one routine, so an FDE start the primary pass left
        # unclaimed is strong evidence of a missed function (e.g. a wrapper only
        # reached through data). Runs after the primary pass so code_map claims
        # can veto entries: an already-claimed start would split existing
        # functions, which this pass must never do. Accepted starts get ordinary
        # candidate bookkeeping - deliberately NOT the PE exception-candidate
        # priority, since .eh_frame commonly also covers non-function ranges.
        if not self.config.USE_ELF_EH_FRAME_CANDIDATES:
            return
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
        if not isinstance(lief_binary, lief.ELF.Binary):
            return
        eh_frame = next((section for section in lief_binary.sections if section.name == ".eh_frame"), None)
        if eh_frame is None or not eh_frame.virtual_address or not eh_frame.size:
            return
        section_bytes = self.disassembly.getBytes(eh_frame.virtual_address, eh_frame.size)
        if not section_bytes:
            return
        pointer_size = 8 if binary_info.bitness == 64 else 4
        fde_ranges = decodeEhFrameFdeRanges(bytes(section_bytes), eh_frame.virtual_address, pointer_size=pointer_size)
        exec_ranges = self._cachedExecutableSectionRanges()

        def in_exec(addr):
            return any(start <= addr < end for start, end in exec_ranges)

        accepted = []
        for fde_start in sorted({fde_range[0] for fde_range in fde_ranges}):
            if self._candidateTimeoutTripped():
                return
            if fde_start % INSTRUCTION_SIZE != 0 or not in_exec(fde_start):
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

        for section in macho.sections:
            if not section.virtual_address or not section.size:
                continue
            section_type = section.type
            if section_type in pointer_types:
                for slot_va in range(section.virtual_address, section.virtual_address + section.size - 7, 8):
                    if self._candidateTimeoutTripped():
                        return
                    seed(self._resolveMachoStoredPointer(slot_va, adjustment, fixup_state), slot_va + adjustment)
            elif init_offsets_type is not None and section_type == init_offsets_type:
                # __init_offsets: 32-bit offsets from the image base, no fixups involved
                for slot_va in range(section.virtual_address, section.virtual_address + section.size - 3, 4):
                    if self._candidateTimeoutTripped():
                        return
                    raw = self.disassembly.getBytes(slot_va + adjustment, 4)
                    if raw is None or len(raw) != 4:
                        continue
                    seed(macho.imagebase + int.from_bytes(raw, "little") + adjustment, slot_va + adjustment)
            elif section_type == interposing_type:
                # interposing entries are <replacement, replacee> pointer pairs; only
                # the replacement of a complete pair is a local function
                for pair_va in range(section.virtual_address, section.virtual_address + section.size - 15, 16):
                    if self._candidateTimeoutTripped():
                        return
                    seed(self._resolveMachoStoredPointer(pair_va, adjustment, fixup_state), pair_va + adjustment)

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
            for match_count, pointer_va in enumerate(range(scan_start, section_end - (pointer_size - 1), pointer_size)):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
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
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
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
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
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
                self.addReferenceCandidate(target, source)
                self.setInitialCandidate(target)

    def locatePrologueCandidates(self):
        # AArch64 lacks a single dominant byte prologue (no push ebp). Scan the
        # image word-by-word for the recognized function-entry prologues
        # (frame-record store, callee-saved pair save, link-register save, PAC/BTI);
        # see definitions.is_function_prologue for the exact encodings.
        base = self.disassembly.binary_info.base_addr
        for match_count, word in enumerate(self._wordsView()):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return
            if not is_function_prologue(word):
                continue
            addr = (base + match_count * INSTRUCTION_SIZE) & self.getBitMask()
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(addr):
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
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size
        words = self._wordsView()
        addr = start
        limit = start + 0x400
        while addr + INSTRUCTION_SIZE <= base + size and addr < limit:
            word = words[(addr - base) // INSTRUCTION_SIZE]
            if (word & B_MASK) == B_VALUE:
                imm = word & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                target = addr + imm * INSTRUCTION_SIZE
                return target in self.disassembly.code_map and target not in self.getFunctionStartCandidates()
            if (word & RET_MASK) == RET_VALUE or (word & BR_MASK) == BR_VALUE:
                return False
            addr += INSTRUCTION_SIZE
        return False

    def _isLikelyInteriorBtiCandidate(self, addr):
        # BTI marks both real entries and indirect-branch landing pads. If the word
        # sits inside already claimed code, or immediately follows ordinary code
        # rather than padding / a terminator-like boundary, suppress it as an entry
        # candidate so switch targets and guarded blocks do not fragment functions.
        if addr in self.disassembly.code_map and addr not in self.getFunctionStartCandidates():
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
        # candidate at a plausible function entry: skip padding (nop / zero), a
        # leading conditional branch or trap, constrain to genuine executable sections (the
        # loader's code_areas can be a coarse segment covering data), and drop runs
        # that flow into the interior of an already-mapped function.
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

        while True:
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
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(self.gap_pointer):
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if is_conditional_branch(word):  # a function never opens with a cond branch
                self.gap_pointer += INSTRUCTION_SIZE
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
