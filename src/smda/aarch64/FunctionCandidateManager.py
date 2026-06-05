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
  functions reached only indirectly.

x86-only passes (PLT/stub chains, PE ``.pdata`` exception tables) do not apply,
and the NOP-based gap scan is disabled for v1; both remain future iterate-steps.
"""

import contextlib
import logging

import lief

from smda.intel.FunctionCandidateManager import FunctionCandidateManager as _IntelFunctionCandidateManager

from .definitions import (
    BL_IMM_MASK,
    BL_IMM_SIGN_BIT,
    BL_MASK,
    BL_VALUE,
    INSTRUCTION_SIZE,
    is_function_prologue,
)

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager(_IntelFunctionCandidateManager):
    def init(self, disassembly):
        super().init(disassembly)
        # The base init() builds an x86 capstone purely for its NOP-based gap scan,
        # which this backend disables (see nextGapCandidate); drop the stale handle.
        self.capstone = None

    def locateCandidates(self):
        # AArch64 candidate discovery: symbols, BL call references, stored function
        # pointers (.init_array/.fini_array + data tables), then entry prologues.
        # The x86-only PLT/stub-chain and PE .pdata passes do not apply and are
        # omitted; the NOP-based gap scan is disabled (see nextGapCandidate).
        self.locateSymbolCandidates()
        self.locateReferenceCandidates()
        self.locateDataPointerCandidates()
        self.locatePrologueCandidates()
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
            for pointer_va in range(section_start, section_end - (pointer_size - 1), pointer_size):
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

    def locateReferenceCandidates(self):
        # AArch64 direct calls are BL (100101 + imm26). Scan the mapped image
        # word-by-word, resolve each BL's PC-relative target and register it as a
        # call-reference candidate — the AArch64 analogue of the base 0xE8 scan.
        binary = self.disassembly.binary_info.binary
        base = self.disassembly.binary_info.base_addr
        for offset in range(0, len(binary) - (INSTRUCTION_SIZE - 1), INSTRUCTION_SIZE):
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
        # (frame-record store, callee-saved pair save, link-register save, paciasp);
        # see definitions.is_function_prologue for the exact encodings.
        binary = self.disassembly.binary_info.binary
        base = self.disassembly.binary_info.base_addr
        for offset in range(0, len(binary) - (INSTRUCTION_SIZE - 1), INSTRUCTION_SIZE):
            word = int.from_bytes(binary[offset : offset + INSTRUCTION_SIZE], "little")
            if not is_function_prologue(word):
                continue
            addr = (base + offset) & self.getBitMask()
            if not self._passesCodeFilter(addr):
                continue
            self.addPrologueCandidate(addr)
            self.setInitialCandidate(addr)

    def addTailcallCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        is_new = self.ensureCandidate(addr)
        self.candidates[addr].setIsTailcallCandidate(True)
        self._candidate_offsets.add(addr)
        if is_new and self.candidate_queue:
            self.candidate_queue.add(self.candidates[addr])
            self.candidate_queue.update()
        return True

    def nextGapCandidate(self, start_gap_pointer=None):
        # v1 relies on prologue + call-reference discovery only. The base-class gap
        # scan assumes x86 NOP/padding encodings (and an x86 capstone), so it is
        # disabled here pending an AArch64-aware gap heuristic.
        del start_gap_pointer
        return None
