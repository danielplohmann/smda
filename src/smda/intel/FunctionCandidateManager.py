"""x86/x64 function-candidate discovery.

The candidate registry, priority queue, evidence bookkeeping and gap
bookkeeping live in the architecture-neutral base under :mod:`smda.common`;
this subclass supplies the x86 byte-level scans: 0xE8 call-reference discovery,
prologue byte-pattern seeding, jmp/call-pointer and PLT stub-chain discovery,
PE x64 ``.pdata`` exception-record seeding, and the NOP/padding-aware gap scan.
"""

import logging
import re
import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.FunctionCandidateManager import FunctionCandidateManager as _CommonFunctionCandidateManager

from .definitions import (
    COMMON_PROLOGUES,
    DEFAULT_PROLOGUES,
    DEFAULT_PROLOGUES_64,
    ENDBR64_BYTES,
    GAP_SEQUENCES,
)
from .FunctionCandidate import FunctionCandidate

LOGGER = logging.getLogger(__name__)

# bytes.lstrip() can skip long runs of one-byte padding in C instead of
# crawling them byte-by-byte in the gap scanner.
_PADDING_STRIP_BYTES = bytes(sorted(seq[0] for seq in GAP_SEQUENCES[1]))

# The lowest score any multi-byte (length 3/4/5) COMMON_PROLOGUES entry carries, across
# both bitnesses. Used as the "looks like a real function entry" floor for hasCommonPrologue:
# excludes the single-opcode-byte fallback table's weak entries (score as low as 1) while
# still admitting its one strong signal (0x55 "push ebp/rbp", scored 51/33).
_ENTRY_SHAPE_MIN_SCORE = 30

# Written as `A(BA)+B` rather than the equivalent `(AB){2,}` so the pattern starts with a literal:
# only then does the regex engine emit a prefix fast-search instead of entering the matcher at
# every offset of the mapped image.
_RE_STUB_BLOCK = re.compile(b"\xff\x25(?:.{4}\xff\x25)+.{4}", re.DOTALL)
_RE_STUB_ENTRY = re.compile(b"\xff\x25(?P<function>.{4})", re.DOTALL)
_RE_PLT_BLOCK = re.compile(b"\xff\x25(?:.{4}\x68.{4}\xe9.{4}\xff\x25)+.{4}\x68.{4}\xe9.{4}", re.DOTALL)
_RE_PLTSEC_BLOCK = re.compile(
    b"\xf3\x0f\x1e\xfa\xf2\xff\x25(?:.{4}\x0f\x1f\x44\x00\x00\xf3\x0f\x1e\xfa\xf2\xff\x25)+.{4}\x0f\x1f\x44\x00\x00",
    re.DOTALL,
)
_RE_PLTSEC_ENTRY = re.compile(b"\xf3\x0f\x1e\xfa\xf2\xff\x25(?P<function>.{4})", re.DOTALL)


class FunctionCandidateManager(_CommonFunctionCandidateManager):
    CANDIDATE_CLASS = FunctionCandidate

    def __init__(self, config):
        super().__init__(config)
        self.pdata_start_addresses = set()
        self.pdata_end_addresses = set()

    def init(self, disassembly, cbAnalysisTimeout=None):
        # the gap scan decodes potential NOP instructions, so it needs an x86 capstone
        # matching the binary's bitness; build it before the base init runs discovery
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        if disassembly.binary_info.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        super().init(disassembly, cbAnalysisTimeout)

    def isEffectiveNop(self, byte_sequence):
        return byte_sequence in GAP_SEQUENCES[len(byte_sequence)]

    def isHotpatchPrologue(self, byte_window):
        # An MSVC hotpatch stub (`mov edi, edi; push ebp; mov ebp, esp`) opens with a
        # `mov edi, edi` that is byte-identical to a 2-byte effective NOP, yet it IS the
        # function's true entry. Recognizing the 5-byte prologue lets callers avoid
        # skipping/rounding past that leading NOP and mislocating the start two bytes late.
        return byte_window in COMMON_PROLOGUES["5"].get(self.bitness, {})

    def hasCommonPrologue(self, addr):
        # reuses FunctionCandidate's longest-first COMMON_PROLOGUES lookup (and endbr64
        # strip) to check whether an address, not necessarily a tracked candidate, is
        # entry-shaped -- e.g. a seed address about to be cut to from alignment padding.
        # A bare score > 0 (hasCommonFunctionStart) also passes on the single-opcode-byte
        # fallback table's weak entries (score as low as 1 -- a lone REX prefix or a
        # "mov"/"lea"/"test" opcode byte says nothing about being a function entry, it's
        # just a common byte anywhere in code). Require the multi-byte tables' natural
        # score floor so this gate isn't satisfied by ordinary mid-function bytes; the
        # single strong single-byte case (0x55 "push ebp/rbp") clears it too.
        if self.disassembly.binary_info is None:
            return False
        return FunctionCandidate(self.disassembly.binary_info, addr).getFunctionStartScore() >= _ENTRY_SHAPE_MIN_SCORE

    def isAlignmentSequence(self, instruction_sequence, raw_bytes=None):
        is_alignment_sequence = False
        instructions_analyzed = 0
        if len(instruction_sequence) > 0:
            start_addr = instruction_sequence[0].address if raw_bytes is None else instruction_sequence[0][0]
            current_offset = start_addr
            for instruction in instruction_sequence:
                if raw_bytes is None:
                    size = len(instruction.bytes)
                    instruction_bytes = instruction.bytes
                else:
                    address, size, _mnemonic, _operands = instruction
                    instruction_bytes = raw_bytes[address - start_addr : address - start_addr + size]
                if instruction_bytes in GAP_SEQUENCES[size]:
                    instructions_analyzed += 1
                    current_offset += size
                    if current_offset % 16 == 0:
                        is_alignment_sequence = True
                        break
                else:
                    break
        if len(instruction_sequence) > instructions_analyzed:
            trailing_instruction = instruction_sequence[instructions_analyzed]
            trailing_mnemonic = trailing_instruction.mnemonic if raw_bytes is None else trailing_instruction[2]
        else:
            trailing_mnemonic = ""
        if trailing_mnemonic.split(" ")[-1] in [
            "leave",
            "ret",
            "retn",
        ]:
            is_alignment_sequence = False
        return is_alignment_sequence

    def nextGapCandidate(self, start_gap_pointer=None):
        if self.language_candidates_only:
            return None
        if self.gap_pointer is None:
            self.initGapSearch()
        # Explicit None test: a gap start at VA 0x0 (valid for a base-0 buffer) is a
        # real argument, not "unset", so a truthiness check would wrongly drop it.
        if start_gap_pointer is not None:
            self.gap_pointer = start_gap_pointer
        if self.gap_pointer is None:
            return None
        LOGGER.debug(
            "nextGapCandidate() finding new gap candidate, current gap_ptr: 0x%08x",
            self.gap_pointer,
        )
        window_offset = -1
        window_bytes = b""

        def get_window_slice(offset, length):
            nonlocal window_offset, window_bytes
            if window_offset <= offset and offset + length <= window_offset + len(window_bytes):
                start = offset - window_offset
                return window_bytes[start : start + length]
            window_offset = offset
            window_bytes = self.disassembly.getRawBytes(offset, max(256, length))
            return window_bytes[:length]

        while True:
            if self.disassembly.binary_info.base_addr + self.disassembly.binary_info.binary_size < self.gap_pointer:
                LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return None
            gap_offset = self.gap_pointer - self.disassembly.binary_info.base_addr
            if gap_offset >= self.disassembly.binary_info.binary_size:
                return None
            # compatibility with python2/3...
            byte = b""
            try:
                byte = get_window_slice(gap_offset, 1)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.warning("could not fetch raw byte for gap pointer.")
            # try to find padding symbols and skip them
            if byte in GAP_SEQUENCES[1]:
                window = get_window_slice(gap_offset, 256)
                run = len(window) - len(window.lstrip(_PADDING_STRIP_BYTES))
                LOGGER.debug(
                    "nextGapCandidate() found %d-byte padding run - gap_ptr += %d: 0x%08x",
                    run,
                    run,
                    self.gap_pointer,
                )
                self.gap_pointer += run if run else 1
                continue
            # try to find instructions that directly encode as NOP and skip them
            ins_buf = list(self.capstone.disasm_lite(get_window_slice(gap_offset, 15), gap_offset))
            if ins_buf:
                i_address, i_size, i_mnemonic, i_op_str = ins_buf[0]
                if i_mnemonic == "nop":
                    nop_instruction = i_mnemonic + " " + i_op_str
                    nop_length = i_size
                    LOGGER.debug(
                        "nextGapCandidate() found nop instruction (%s) - gap_ptr += %d: 0x%08x",
                        nop_instruction,
                        nop_length,
                        self.gap_pointer,
                    )
                    self.gap_pointer += nop_length
                    continue
            # try to find effective NOPs and skip them.
            found_multi_byte_nop = False
            for gap_length in range(max(GAP_SEQUENCES.keys()), 1, -1):
                if get_window_slice(gap_offset, gap_length) in GAP_SEQUENCES[gap_length]:
                    # Do not skip a `mov edi, edi` effective NOP when it is the landing pad of
                    # a hotpatch stub: that byte pair is the function's true start, and skipping
                    # it would mislocate the function two bytes late (at the `push ebp`).
                    if self.isHotpatchPrologue(get_window_slice(gap_offset, 5)):
                        break
                    LOGGER.debug(
                        "nextGapCandidate() found %d byte effective nop - gap_ptr += %d: 0x%08x",
                        gap_length,
                        gap_length,
                        self.gap_pointer,
                    )
                    self.gap_pointer += gap_length
                    found_multi_byte_nop = True
                    break
            if found_multi_byte_nop:
                continue
            # we know this place from data already
            if self.gap_pointer in self.disassembly.data_map:
                LOGGER.debug(
                    "nextGapCandidate() gap_ptr is already inside data map: 0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer += 1
                continue
            if self.gap_pointer in self.disassembly.code_map:
                LOGGER.debug(
                    "nextGapCandidate() gap_ptr is already inside code map: 0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer = self.getNextGap()
                continue
            # we may have a candidate here
            LOGGER.debug("nextGapCandidate() using 0x%08x as candidate", self.gap_pointer)
            start_byte = byte[0] if byte else 0
            has_common_prologue = True  # start_byte in FunctionCandidate(self.gap_pointer, start_byte, self.bitness).common_gap_starts[self.bitness]
            if self.previously_analyzed_gap == self.gap_pointer:
                LOGGER.debug(
                    "--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed",
                    self.gap_pointer,
                )
                self.gap_pointer = self.getNextGap(dont_skip=True)
            elif not has_common_prologue:
                LOGGER.debug(
                    "--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%08x)",
                    self.gap_pointer,
                    ord(start_byte),
                )
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
            self.candidates[addr] = FunctionCandidate(self.disassembly.binary_info, addr)
            return True
        return False

    def resolvePointerReference(self, offset):
        if self.bitness == 32:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            if addr_block is None or len(addr_block) < 4:
                return None
            function_pointer = struct.unpack("<I", addr_block)[0]
            return self.disassembly.dereferenceDword(function_pointer)
        if self.bitness == 64:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            if addr_block is None or len(addr_block) < 4:
                return None
            function_pointer = struct.unpack("<i", addr_block)[0]
            # we need to calculate RIP + offset + 7 (48 ff 25 ** ** ** **)
            if self.disassembly.getRawBytes(offset, 2) == b"\xff\x25":
                function_pointer += offset + 7
            elif self.disassembly.getRawBytes(offset, 2) == b"\xff\x15":
                function_pointer += offset + 6
            else:
                raise Exception("resolvePointerReference: should only be used on call/jmp * ptr")
            return self.disassembly.binary_info.base_addr + function_pointer
        raise Exception("resolvePointerReference: undefined bitness")

    def locateCandidates(self):
        # add guaranteed / high-value starts first so that, if the candidate cap is hit, the most reliable
        # candidates are retained before the high-volume prologue and stub-chain scans can consume the budget.
        self.locateSymbolCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateReferenceCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateExceptionHandlerCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateLangSpecCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locatePrologueCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateStubChainCandidates()
        self.identified_alignment = self._identifyAlignment()

    def locateReferenceCandidates(self):
        # check for potential call instructions and check if their destinations have a common function prologue
        for match_count, call_match in enumerate(re.finditer(b"\xe8", self.disassembly.binary_info.binary)):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return
            if not self._passesCodeFilter(self.disassembly.binary_info.base_addr + call_match.start()):
                continue
            if len(self.disassembly.binary_info.binary) - call_match.start() >= 5:
                packed_call = self.disassembly.getRawBytes(call_match.start() + 1, 4)
                rel_call_offset = struct.unpack("<i", packed_call)[0]
                # ignore zero offset calls, as they will likely not lead to functions but are rather used for positioning in shellcode etc
                if rel_call_offset == 0:
                    continue
                call_destination = (
                    self.disassembly.binary_info.base_addr + rel_call_offset + call_match.start() + 5
                ) & self.getBitMask()
                if self.disassembly.isAddrWithinMemoryImage(call_destination):
                    self.addReferenceCandidate(
                        call_destination,
                        self.disassembly.binary_info.base_addr + call_match.start(),
                    )
                    self.setInitialCandidate(call_destination)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        if self.bitness == 32:
            for match_count, match in enumerate(re.finditer(b"\xff\x25", self.disassembly.binary_info.binary)):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                    return
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(
                        function_addr,
                        self.disassembly.binary_info.base_addr + match.start(),
                    )
                    self.setInitialCandidate(function_addr)
            # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
            for match_count, match in enumerate(re.finditer(b"\xff\x15", self.disassembly.binary_info.binary)):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                    return
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(
                        function_addr,
                        self.disassembly.binary_info.base_addr + match.start(),
                    )
                    self.setInitialCandidate(function_addr)

    def _seedPrologueMatches(self, pattern):
        """returns True once the analysis timeout trips, so callers can stop scanning
        further patterns instead of each one re-discovering the timeout on its own first match."""
        binary = self.disassembly.binary_info.binary
        for match_count, prologue_match in enumerate(re.finditer(pattern, binary)):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return True
            offset = prologue_match.start()
            candidate_addr = (self.disassembly.binary_info.base_addr + offset) & self.getBitMask()
            if not self._passesCodeFilter(candidate_addr):
                continue
            # MSVC precedes `push ebp; mov ebp, esp` with a `mov edi, edi` hotpatch pad, and the
            # pad is the function's entry -- a bare prologue match two bytes into one names the
            # body, not a function start. The pad is itself a DEFAULT_PROLOGUES entry scanned
            # before the bare form, so it is already a candidate here; requiring that keeps the
            # body seed whenever the pad was rejected (outside a code area, candidate cap).
            if (
                offset >= 2
                and self.isHotpatchPrologue(binary[offset - 2 : offset + 3])
                and (candidate_addr - 2) & self.getBitMask() in self.candidates
            ):
                continue
            self.addPrologueCandidate(candidate_addr)
            self.setInitialCandidate(candidate_addr)
        return False

    def locatePrologueCandidates(self):
        # next check for the default function prologue regardless of references
        for re_prologue in DEFAULT_PROLOGUES:
            if self._seedPrologueMatches(re.escape(re_prologue)):
                return
        if self.bitness == 64:
            # extended GCC/Clang/MSVC AMD64 prologue family: a CET landing pad (endbr64) that may
            # prefix the real prologue, plus exact stack-frame openers.
            if self._seedPrologueMatches(re.escape(ENDBR64_BYTES)):
                return
            for re_prologue in DEFAULT_PROLOGUES_64:
                if self._seedPrologueMatches(re.escape(re_prologue)):
                    return

    def locateStubChainCandidates(self):
        # binaries often contain long sequences of stubs, consisting only of jmp dword ptr <offset>, add such chains as candidates
        for block in _RE_STUB_BLOCK.finditer(self.disassembly.binary_info.binary):
            for match in _RE_STUB_ENTRY.finditer(block.group(0)):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
        # structure for plt entries is similar but interleaved with additional code not considered functions
        for block in _RE_PLT_BLOCK.finditer(self.disassembly.binary_info.binary):
            for match in _RE_STUB_ENTRY.finditer(block.group(0)):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
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
        for block in _RE_PLTSEC_BLOCK.finditer(self.disassembly.binary_info.binary):
            for match in _RE_PLTSEC_ENTRY.finditer(block.group(0)):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
                # define data bytes inbetween
                for offset in range(5):
                    self.disassembly.data_map.add(stub_addr + 7 + offset)

    def locateExceptionHandlerCandidates(self):
        # 64bit only - if we have a .pdata section describing exception handlers, we extract entries of guaranteed function starts from it.
        if self.disassembly.binary_info.bitness == 64:
            self.pdata_start_addresses = set()
            self.pdata_end_addresses = set()
            record_pdata_ends = self.config.USE_PE_X64_PDATA_ENDS
            base_addr = self.disassembly.binary_info.base_addr
            for section_info in self.disassembly.binary_info.getSections():
                section_name, section_va_start, section_va_end = section_info
                if section_name == ".pdata":
                    rva_start = section_va_start - self.disassembly.binary_info.base_addr
                    rva_end = section_va_end - self.disassembly.binary_info.base_addr
                    # .pdata entries are 12 bytes long (3 DWORDs): BeginAddress, EndAddress, UnwindInfoAddress
                    for offset in range(rva_start, rva_end - 11, 12):
                        packed_entry = self.disassembly.getRawBytes(offset, 12)
                        if len(packed_entry) < 12:
                            break
                        rva_function_candidate, _rva_function_end, rva_unwind_info = struct.unpack("<III", packed_entry)
                        if rva_function_candidate == 0:
                            break
                        if self._isChainedUnwindInfo(rva_unwind_info):
                            # UNW_FLAG_CHAININFO: this entry is a secondary fragment (e.g. a
                            # split-off cold/epilogue chunk) chained to another function's
                            # primary RUNTIME_FUNCTION entry, not an independent function start.
                            continue
                        self.addExceptionCandidate(base_addr + rva_function_candidate)
                        if record_pdata_ends and _rva_function_end > rva_function_candidate:
                            # record .pdata EndAddresses as candidate split points; skip degenerate
                            # (EndAddress <= BeginAddress) entries and keep them as VAs.
                            self.pdata_start_addresses.add(base_addr + rva_function_candidate)
                            self.pdata_end_addresses.add(base_addr + _rva_function_end)

    def _isChainedUnwindInfo(self, rva_unwind_info):
        # x64 UNWIND_INFO header byte 0 packs Version (bits 0-2) and Flags (bits 3-7);
        # UNW_FLAG_CHAININFO (0x4) means this RUNTIME_FUNCTION entry chains to another
        # function's primary entry instead of describing an independent function.
        header_byte = self.disassembly.getRawBytes(rva_unwind_info, 1)
        if not header_byte:
            return False
        return bool((header_byte[0] >> 3) & 0x4)
