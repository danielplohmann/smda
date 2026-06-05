"""AArch64 function-candidate discovery.

Reuses the candidate queue, scoring and gap book-keeping from the engine's
candidate manager (currently housed under :mod:`smda.intel`) and replaces the
x86 byte-level scans with AArch64-aware ones:

* call-reference discovery scans for ``BL`` (direct call) and resolves its
  PC-relative target, in place of the x86 ``0xE8`` scan;
* prologue discovery scans for the frame-record store and ``paciasp``, in place
  of the x86 push/mov prologues.

x86-only passes (PLT/stub chains, PE ``.pdata`` exception tables, the NOP-based
gap scan) are disabled for v1 and are tracked as future iterate-steps.
"""

import logging

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

    def locateStubChainCandidates(self):
        # x86 jmp-dword-ptr stub chains do not apply to AArch64; PLT recovery is a
        # future iterate-step.
        return

    def locateExceptionHandlerCandidates(self):
        # PE .pdata exception tables do not apply to ELF/AArch64; .eh_frame-based
        # function-start recovery is a future iterate-step.
        return

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
