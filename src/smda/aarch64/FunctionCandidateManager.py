"""AArch64 function-candidate discovery.

Reuses the candidate queue, scoring and gap book-keeping from the engine's
candidate manager (currently housed under :mod:`smda.intel`) and replaces the
x86 byte-level scans with AArch64-aware ones:

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

x86-only passes (PLT/stub chains, PE ``.pdata`` exception tables) do not apply and
remain future iterate-steps; for a statically linked ELF there is no PLT to recover.
"""

import contextlib
import logging
import struct

import lief

from smda.intel.FunctionCandidateManager import FunctionCandidateManager as _IntelFunctionCandidateManager

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
    is_function_prologue,
    rd_field,
    rn_field,
)

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager(_IntelFunctionCandidateManager):
    def init(self, disassembly, cbAnalysisTimeout=None):
        super().init(disassembly, cbAnalysisTimeout)
        # The base init() builds an x86 capstone purely for its NOP-based gap scan,
        # which this backend disables (see nextGapCandidate); drop the stale handle.
        self.capstone = None
        # Drop the memoized executable-section ranges so a reused manager instance
        # recomputes them for the new binary instead of leaking stale ranges.
        self._exec_ranges = None

    def locateCandidates(self):
        # AArch64 candidate discovery: symbols, BL call references, stored function
        # pointers (.init_array/.fini_array + data tables), then entry prologues.
        # The x86-only PLT/stub-chain and PE .pdata passes do not apply and are
        # omitted; the NOP-based gap scan is disabled (see nextGapCandidate).
        self.locateSymbolCandidates()
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

    def locateDataPointerCandidates(self):
        # Seed candidates from stored function pointers. ELF .init_array/.fini_array
        # entries are authoritative constructor/destructor pointers; other data
        # sections are scanned for aligned words pointing into executable code.
        # This recovers functions reached only indirectly (CRT init stubs, pointer
        # / dispatch tables) that no direct BL or recognized prologue would find,
        # and anchors true entries so the prologue scan no longer mislabels an
        # inner block as the function start.
        binary_info = self.disassembly.binary_info
        lief_binary = binary_info.getLiefBinary()
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
        if not isinstance(lief_binary, lief.ELF.Binary) or not lief_binary.sections:
            return
        exec_ranges = self._executableSectionRanges(lief_binary)
        if not exec_ranges:
            return
        base = binary_info.base_addr
        binary = binary_info.binary
        bit_mask = self.getBitMask()

        def in_exec(addr):
            return any(start <= addr < end for start, end in exec_ranges)

        def seed(target, source):
            target &= bit_mask
            if target % INSTRUCTION_SIZE != 0 or not in_exec(target):
                return
            if self._passesCodeFilter(target) and self.disassembly.isAddrWithinMemoryImage(target):
                self.addReferenceCandidate(target, source)

        for low, high in exec_ranges:
            pages = {}  # Xd -> adrp page base currently held in that register
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
                        if self.disassembly.isAddrWithinMemoryImage(slot_addr):
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
        binary = self.disassembly.binary_info.binary
        base = self.disassembly.binary_info.base_addr
        for match_count, offset in enumerate(range(0, len(binary) - (INSTRUCTION_SIZE - 1), INSTRUCTION_SIZE)):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return
            word = int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")
            if (word & BL_MASK) != BL_VALUE:
                continue
            source = base + offset
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
        binary = self.disassembly.binary_info.binary
        base = self.disassembly.binary_info.base_addr
        for match_count, offset in enumerate(range(0, len(binary) - (INSTRUCTION_SIZE - 1), INSTRUCTION_SIZE)):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return
            word = int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")
            if not is_function_prologue(word):
                continue
            addr = (base + offset) & self.getBitMask()
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(addr):
                continue
            if not self._passesCodeFilter(addr):
                continue
            self.addPrologueCandidate(addr)
            self.setInitialCandidate(addr)

    def addTailcallCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        self.candidates[addr].setIsTailcallCandidate(True)
        self._candidate_offsets.add(addr)
        self.candidate_queue.add(self.candidates[addr])
        self.candidate_queue.update()
        return True

    def _cachedExecutableSectionRanges(self):
        ranges = getattr(self, "_exec_ranges", None)
        if ranges is None:
            lief_binary = self.disassembly.binary_info.getLiefBinary()
            ranges = self._executableSectionRanges(lief_binary) if isinstance(lief_binary, lief.ELF.Binary) else []
            self._exec_ranges = ranges
        return ranges

    def _gapRunFlowsIntoInterior(self, start):
        # G3: decode the straight-line run from `start` to its first terminator. If it
        # ends in an unconditional `b` into the interior of already-mapped code (a
        # known instruction that is not itself a function-start candidate), the run is
        # a mid-function tail rather than a new function — so suppress it.
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size
        binary = self.disassembly.binary_info.binary
        addr = start
        limit = start + 0x400
        while addr + INSTRUCTION_SIZE <= base + size and addr < limit:
            word = int.from_bytes(binary[addr - base : addr - base + INSTRUCTION_SIZE], "little")
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

        prev_word = int.from_bytes(binary[offset - INSTRUCTION_SIZE : offset], "little")
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
            or auth_or_exception_return
        )

    def nextGapCandidate(self, start_gap_pointer=None):
        # AArch64 gap scan: a fixed-stride linear sweep of unanalyzed executable bytes
        # for functions that no prologue, call reference or stored pointer reached
        # (typically unreferenced / indirect-only routines). Guards keep each gap
        # candidate at a plausible function entry: skip padding (nop / zero) and a
        # leading conditional branch, constrain to genuine executable sections (the
        # loader's code_areas can be a coarse segment covering data), and drop runs
        # that flow into the interior of an already-mapped function.
        if self.gap_pointer is None:
            self.initGapSearch()
        # Explicit None test: a gap start at VA 0x0 (valid for a base-0 buffer) is a
        # real argument, not "unset", so a truthiness check would wrongly drop it.
        if start_gap_pointer is not None:
            self.gap_pointer = start_gap_pointer
        base = self.disassembly.binary_info.base_addr
        size = self.disassembly.binary_info.binary_size
        binary = self.disassembly.binary_info.binary
        exec_ranges = self._cachedExecutableSectionRanges()

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
            word = int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")
            if word in (0, NOP):  # inter-function padding
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if is_bti_landing_pad(word) and self._isLikelyInteriorBtiCandidate(self.gap_pointer):
                self.gap_pointer += INSTRUCTION_SIZE
                continue
            if is_conditional_branch(word):  # a function never opens with a cond branch
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
