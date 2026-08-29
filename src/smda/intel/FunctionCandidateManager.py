"""x86/x64 function-candidate discovery.

The candidate registry, priority queue, evidence bookkeeping and gap
bookkeeping live in the architecture-neutral base under :mod:`smda.common`;
this subclass supplies the x86 byte-level scans: 0xE8 call-reference discovery,
prologue byte-pattern seeding, jmp/call-pointer and PLT stub-chain discovery,
PE x64 ``.pdata`` exception-record seeding, and the NOP/padding-aware gap scan.
"""

import bisect
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

# Byte pairs GAP_SEQUENCES treats as skippable filler that a function is also emitted with as
# its own first instruction. Per bitness and deliberately narrow: on x86 only `mov edi, edi`,
# the hotpatch landing pad; widening either set was measured to cost true positives. `mov ecx,
# ecx` is not inert in 64-bit mode -- it truncates rcx, and MSVC opens argument-forwarding
# thunks with it.
_ENTRY_PAD_SEQUENCES = {
    32: frozenset({b"\x8b\xff", b"\x89\xff"}),
    64: frozenset({b"\x66\x90", b"\x8b\xc9"}),
}

# MSVC aligns function entries to 16 bytes.
_CODE_ALIGNMENT = 16

# Delphi method tables are runs of 32-bit pointers into code. A run is only read as a table
# when most of its entries are already recovered functions and code takes a data reference to
# it; measured on a PE corpus, the self-validation test alone admits a thousand addresses that
# point at data. The scan polls the analysis budget once per 64 KiB rather than per entry.
_POINTER_TABLE_ENTRY_SIZE = 4
_POINTER_TABLE_MIN_RUN = 4
_POINTER_TABLE_MIN_KNOWN_RATIO = 0.8
_POINTER_TABLE_POLL_BYTES = 0x10000

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

_PDATA_ENTRY_SIZE = 12
# items (candidates, matches or exception records) a scan steps over between budget polls, mirroring
# _TIMEOUT_POLL_BLOCKS in the engine. A whole exception table is walked inside one call, so
# the poll in the pass around it never comes round again while that walk is running
_TIMEOUT_POLL_INTERVAL = 4096
_PUSH_RBP = 0x55
_PUSH_PAIR_PROLOGUE = b"\x41\x57\x41\x56"  # push r15; push r14
# How far back a declared entry has to sit for the byte in question to be inside it rather
# than an entry itself: one instruction's worth of the openings this pattern appears behind.
_DECLARED_START_WINDOW = 8
_PDATA_MIN_ENTRIES = 16
_PDATA_SEED_ENTRIES = 4
# A sample only finds a table if it lands inside one with a whole seed window left, so this
# must stay <= (_PDATA_MIN_ENTRIES - _PDATA_SEED_ENTRIES) * _PDATA_ENTRY_SIZE.
_PDATA_SAMPLE_STRIDE = 128
_PDATA_MAX_FUNCTION_SIZE = 0x100000
# UNWIND_INFO byte 0 packs Version (bits 0-2, always 1) and Flags (bits 3-7), and only
# EHANDLER/UHANDLER/CHAININFO are defined -- so just these eight byte values are legal.
_UNWIND_INFO_FIRST_BYTES = frozenset(0x01 | (flags << 3) for flags in range(8))


class FunctionCandidateManager(_CommonFunctionCandidateManager):
    CANDIDATE_CLASS = FunctionCandidate

    def __init__(self, config):
        super().__init__(config)
        self.pdata_start_addresses = set()
        self.pdata_end_addresses = set()
        #: (start, end, is_chained) for every RUNTIME_FUNCTION record the image declares,
        #: sorted lazily on first lookup because seeding appends in table order. Uncapped,
        #: unlike the candidate registry: one tuple per record is about 145 bytes, so an
        #: image with 200,000 functions holds ~29 MB here, and capping it would silently
        #: stop suppressing on exactly the largest images rather than bounding anything
        #: that matters.
        self._pdata_ranges = []
        self._pdata_range_starts = None
        self._pdata_range_reach = []
        self._retained_pad = None

    def init(self, disassembly, cbAnalysisTimeout=None):
        self._retained_pad = None
        self._pdata_ranges = []
        self._pdata_range_starts = None
        self._pdata_range_reach = []
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

    def isUnalignedEntryPad(self, byte_sequence, next_addr, next_bytes):
        # Filler exists only to reach the next 16-byte boundary and is always the tail of the
        # NOP run, so a pad that ends off that boundary with real code behind it is an entry.
        if byte_sequence not in _ENTRY_PAD_SEQUENCES.get(self.bitness, frozenset()):
            return False
        if next_addr % _CODE_ALIGNMENT == 0:
            return False
        return not any(next_bytes[:length] in sequences for length, sequences in GAP_SEQUENCES.items())

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
            # A retained pad that produced no function was padding after all; resuming past it
            # keeps getNextGap() from abandoning the rest of this gap over the wrong guess.
            if (
                self._retained_pad is not None
                and start_gap_pointer > self._retained_pad
                and self._retained_pad not in self.disassembly.code_map
            ):
                start_gap_pointer = self._retained_pad + 2
            self.gap_pointer = start_gap_pointer
        self._retained_pad = None
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

        scanned = 0
        while True:
            scanned += 1
            if scanned % 4096 == 0 and self._candidateTimeoutTripped():
                return None
            unskipped_pad = False
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
                sequence = get_window_slice(gap_offset, gap_length)
                if sequence in GAP_SEQUENCES[gap_length]:
                    # Do not skip a `mov edi, edi` effective NOP when it is the landing pad of
                    # a hotpatch stub: that byte pair is the function's true start, and skipping
                    # it would mislocate the function two bytes late (at the `push ebp`).
                    if self.isHotpatchPrologue(get_window_slice(gap_offset, 5)):
                        break
                    if self.isUnalignedEntryPad(
                        sequence,
                        self.gap_pointer + gap_length,
                        get_window_slice(gap_offset + gap_length, max(GAP_SEQUENCES.keys())),
                    ):
                        unskipped_pad = True
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
            if self._pdata_ranges and self.config.USE_PE_X64_PDATA_INTERIOR_GAPS:
                # the emptiness test comes first: this runs once per scanned gap byte, and on
                # a 32-bit or non-PE image there is no table to consult at all
                containing = self.declaredExceptionRangeContaining(self.gap_pointer)
                if containing is not None and (containing[2] or containing[0] in self.disassembly.functions):
                    # A chained record is evidence on its own -- it says the whole extent is
                    # part of another function. A primary record only speaks once the function
                    # it names has actually been recovered; until then the record says nothing
                    # about what covers this address. Resuming at the extent's end skips the
                    # body rather than the one byte, which is what the record describes.
                    LOGGER.debug(
                        "nextGapCandidate() gap_ptr is inside a declared .pdata extent: 0x%08x",
                        self.gap_pointer,
                    )
                    self.gap_pointer = containing[1]
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
                if unskipped_pad:
                    self._retained_pad = self.gap_pointer
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

    def locateDeferredCandidates(self):
        yield from self.locateEhFrameCandidates()
        yield from self.locateMachoFunctionStartCandidates()

    def locateLateCandidates(self):
        yield from self.locatePointerTableCandidates()

    def locatePointerTableCandidates(self):
        """Entries of a function-pointer table that the primary pass did not recover.

        The entries a Delphi program only ever calls through its method table are reachable no
        other way - no call names them, so nothing seeds them. A run of aligned dwords is read
        as a table only when most of its entries are already recovered functions and code takes
        a data reference to the run itself; both facts are products of the passes before this
        one, which is why it runs after gap analysis rather than at the deferred hook.
        """
        if not self._delphi_detected or self.bitness != 32:
            return
        functions = self.disassembly.functions
        if not functions:
            return
        buffer = memoryview(self.disassembly.binary_info.binary)
        base_addr = self.disassembly.binary_info.base_addr
        lowest, highest = min(functions), max(functions)
        referenced = set()
        for targets in self.disassembly.data_refs_from.values():
            referenced.update(targets)
        is_code = self.disassembly.isCode
        # insertion-ordered set: a table can be laid out twice, and re-analyzing a start
        # the previous run already accepted would be wasted work
        accepted = {}
        run_start = None
        scan_end = len(buffer) - (len(buffer) % _POINTER_TABLE_ENTRY_SIZE)
        for entry_addr, value in self._pointerTableEntries(buffer, 0, scan_end):
            if lowest <= value <= highest and not is_code(entry_addr):
                if run_start is None:
                    run_start = entry_addr - base_addr
            elif run_start is not None:
                self._admitPointerTableRun(buffer, run_start, entry_addr - base_addr, referenced, accepted)
                run_start = None
        if self._candidateTimeoutTripped():
            return
        if run_start is not None:
            self._admitPointerTableRun(buffer, run_start, scan_end, referenced, accepted)
        # register every accepted start before analyzing any of them, so an earlier one cannot
        # absorb a later one it branches into
        self._candidate_offsets.update(accepted)
        for start in accepted:
            if self._candidateTimeoutTripped():
                return
            if is_code(start):
                continue
            yield start

    def _pointerTableEntries(self, buffer, start, end):
        """Walk aligned dwords of [start, end), polling the analysis budget between chunks.

        Every traversal of the image and of a single run goes through here, so no one of them
        can run for seconds without the budget being consulted: a crafted image can make one
        run as long as the image itself, and a run is walked twice more after it is found.
        """
        base_addr = self.disassembly.binary_info.base_addr
        offset = start
        while offset < end:
            if self._candidateTimeoutTripped():
                return
            chunk_end = min(offset + _POINTER_TABLE_POLL_BYTES, end)
            entry_addr = base_addr + offset
            for (value,) in struct.iter_unpack("<I", buffer[offset:chunk_end]):
                yield entry_addr, value
                entry_addr += _POINTER_TABLE_ENTRY_SIZE
            offset = chunk_end

    def _admitPointerTableRun(self, buffer, run_start, run_end, referenced, accepted):
        """Read one run of code-pointer-shaped dwords as a method table, or decline it.

        The run is re-read from the image rather than carried along as a list of entries, so
        what a single run costs is bounded time rather than memory proportional to the image.
        """
        entries = (run_end - run_start) // _POINTER_TABLE_ENTRY_SIZE
        if entries < _POINTER_TABLE_MIN_RUN:
            return
        functions = self.disassembly.functions
        known = 0
        is_referenced = False
        for entry_addr, value in self._pointerTableEntries(buffer, run_start, run_end):
            if value in functions:
                known += 1
            if not is_referenced and entry_addr in referenced:
                is_referenced = True
        if self._candidateTimeoutTripped() or not is_referenced:
            return
        if known < _POINTER_TABLE_MIN_KNOWN_RATIO * entries:
            return
        for _, value in self._pointerTableEntries(buffer, run_start, run_end):
            if value in functions or self.disassembly.isCode(value):
                continue
            if not self._passesCodeFilter(value):
                continue
            self.ensureCandidate(value)
            if value in self.candidates:
                accepted[value] = None

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
            if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
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
                if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
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
                if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
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

    def _followsDeclaredStart(self, addr):
        """Whether a function the image itself declares begins in the bytes just before addr.

        Symbols, call references and exception records are all located before the prologue
        scan runs, so this asks a question the raw bytes cannot: if a declared entry sits a
        few bytes back, addr is inside that entry's opening instruction rather than being an
        entry of its own. The window is one instruction's worth of the shortest openings -
        widening it to a full 15 costs a real shift on the reference images, and eight covers
        every shape measured.
        """
        for candidate_addr in range(max(0, addr - _DECLARED_START_WINDOW), addr):
            candidate = self.candidates.get(candidate_addr & self.getBitMask())
            if candidate is not None and (
                candidate.call_ref_sources or candidate.is_symbol or candidate.is_exception_handler
            ):
                return True
        return False

    def _seedPrologueMatches(self, pattern):
        """returns True once the analysis timeout trips, so callers can stop scanning
        further patterns instead of each one re-discovering the timeout on its own first match."""
        binary = self.disassembly.binary_info.binary
        for match_count, prologue_match in enumerate(re.finditer(pattern, binary)):
            if match_count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return True
            offset = prologue_match.start()
            # `push r15; push r14` is a run of callee-saved pushes rather than a distinguishing
            # first instruction, so it matches wherever such a run reaches r15. clang orders
            # `push rbp` first in a function that keeps no frame pointer, and the pair then
            # matches one byte into the prologue and names the body instead of the entry - the
            # same shape as the hotpatch adjustment below, where the match is real and its
            # address is one instruction late.
            # The scan reads raw bytes and establishes no instruction boundary, so a 0x55 here
            # is equally `push rbp` or the last byte of something else - `push 0x55` spells the
            # same byte, and shifting onto it books an address one byte inside the real entry.
            # The image itself settles it: symbols, call references and exception records are
            # all located before this scan runs, so a declared entry opening in the bytes just
            # before that 0x55 places it inside that entry's first instruction. That is the
            # same kind of evidence the hotpatch adjustment below defers to.
            if offset and prologue_match.group() == _PUSH_PAIR_PROLOGUE and binary[offset - 1] == _PUSH_RBP:
                if self._followsDeclaredStart(
                    (self.disassembly.binary_info.base_addr + offset - 1) & self.getBitMask()
                ):
                    # A declared entry opens in the bytes just before that 0x55, so the byte is
                    # inside its first instruction - `push 0x55` spells one - and neither this
                    # match nor the byte before it starts a function. Seeding either books an
                    # address inside a function the image already names.
                    continue
                offset -= 1
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
            self._pdata_ranges = []
            self._pdata_range_starts = None
            # A RUNTIME_FUNCTION table is a PE construct. Nothing else in this walk says so -
            # it looks for a section named `.pdata`, and `getSections` yields for ELF and
            # Mach-O too, so a 64-bit ELF carrying a section of that name would otherwise
            # have its regions removed on the strength of bytes that mean something else.
            is_pe = self.disassembly.binary_info._getLiefType() == "PE"
            record_pdata_ends = self.config.USE_PE_X64_PDATA_ENDS
            base_addr = self.disassembly.binary_info.base_addr
            has_sections = False
            for section_info in self.disassembly.binary_info.getSections():
                has_sections = True
                section_name, section_va_start, section_va_end = section_info
                if is_pe and section_name == ".pdata":
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
                        self._admitExceptionRecord(
                            base_addr,
                            rva_function_candidate,
                            _rva_function_end,
                            rva_unwind_info,
                            record_pdata_ends,
                        )
            if not has_sections:
                self._carveExceptionRecords(base_addr, record_pdata_ends)

    def _admitExceptionRecord(
        self, base_addr, rva_function_candidate, rva_function_end, rva_unwind_info, ends, declared=True
    ):
        chained = self._isChainedUnwindInfo(rva_unwind_info)
        if declared and self._isTrustworthyExceptionExtent(rva_function_candidate, rva_function_end, rva_unwind_info):
            # Every record's extent is kept, chained or not: the unwinder is naming the bytes
            # that belong to a routine, which is as true of a fragment as of a whole function.
            # Only the first byte differs, and the flag is what says which case this is.
            self._pdata_ranges.append((base_addr + rva_function_candidate, base_addr + rva_function_end, chained))
            self._pdata_range_starts = None
        if chained:
            # UNW_FLAG_CHAININFO: this entry is a secondary fragment (e.g. a
            # split-off cold/epilogue chunk) chained to another function's
            # primary RUNTIME_FUNCTION entry, not an independent function start.
            return
        self.addExceptionCandidate(base_addr + rva_function_candidate)
        if ends and rva_function_end > rva_function_candidate:
            # record .pdata EndAddresses as candidate split points; skip degenerate
            # (EndAddress <= BeginAddress) entries and keep them as VAs.
            self.pdata_start_addresses.add(base_addr + rva_function_candidate)
            self.pdata_end_addresses.add(base_addr + rva_function_end)

    def _isTrustworthyExceptionExtent(self, rva_function_candidate, rva_function_end, rva_unwind_info):
        """Whether a record's extent may be used to skip a region of the image.

        Seeding a candidate from a record costs one bad address when the record is wrong.
        Skipping a region on one costs every gap-only function it covers, because a gap
        pointer sent past the end of the image ends gap analysis rather than resuming it.
        That asymmetry decides both of the things this function is.

        Only records from a table the image declares reach it at all. A dump keeps its
        mapped bytes but usually not a section header, so the table has to be found in the
        bytes instead, and a table located by searching for one is a reconstruction: good
        enough to add candidates, not good enough to remove regions. That is why `declared`
        gates this rather than the checks below being made stricter.

        A declared table still has to earn it. The section-table path reads twelve bytes
        wherever the section header points with nothing checking that they describe a
        function, and a truncated or deliberately malformed table is ordinary input for
        this disassembler. These are the bounds `_readExceptionRecord` already applies when
        the table has to be found in a headerless dump instead of being pointed at. The
        unwind record is among them because `_isChainedUnwindInfo` reads its first byte,
        and a chained record is the one case whose extent suppresses without the analysis
        having recovered the function it names.

        A record that fails this is still seeded as a candidate exactly as before. It only
        stops speaking for the bytes around it.
        """
        if rva_function_end <= rva_function_candidate:
            return False
        if rva_function_end > len(self.disassembly.binary_info.binary):
            return False
        if rva_function_end - rva_function_candidate > _PDATA_MAX_FUNCTION_SIZE:
            return False
        if rva_unwind_info & 3:
            return False
        header_byte = self.disassembly.getRawBytes(rva_unwind_info, 1)
        return bool(header_byte) and header_byte[0] in _UNWIND_INFO_FIRST_BYTES

    def _readExceptionRecord(self, binary, size, offset, previous_end):
        """returns a validated RUNTIME_FUNCTION triple at offset, or None."""
        if offset + _PDATA_ENTRY_SIZE > size:
            return None
        rva_start, rva_end, rva_unwind_info = struct.unpack_from("<III", binary, offset)
        # .pdata is sorted and its entries do not overlap, which is what makes a run of them
        # separable from data that merely happens to hold three plausible RVAs.
        if rva_start == 0 or rva_start >= rva_end or rva_end > size or rva_start < previous_end:
            return None
        if rva_end - rva_start > _PDATA_MAX_FUNCTION_SIZE:
            return None
        if rva_unwind_info == 0 or rva_unwind_info >= size or rva_unwind_info & 3:
            return None
        if binary[rva_unwind_info] not in _UNWIND_INFO_FIRST_BYTES:
            return None
        return rva_start, rva_end, rva_unwind_info

    def _countExceptionRecords(self, binary, size, offset, limit):
        count = 0
        previous_end = 0
        while count < limit:
            if count and count % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                break
            record = self._readExceptionRecord(binary, size, offset, previous_end)
            if record is None:
                break
            previous_end = record[1]
            offset += _PDATA_ENTRY_SIZE
            count += 1
        return count

    def _locateExceptionRecordTable(self, binary):
        """returns (offset, count) of the longest RUNTIME_FUNCTION run, or (0, 0) if none qualifies."""
        size = len(binary)
        best_offset = best_count = 0
        offset = 0
        samples = 0
        while offset + _PDATA_SEED_ENTRIES * _PDATA_ENTRY_SIZE <= size:
            if samples % 4096 == 0 and self._candidateTimeoutTripped():
                break
            samples += 1
            for phase in (0, 4, 8):
                seed = offset + phase
                if self._countExceptionRecords(binary, size, seed, _PDATA_SEED_ENTRIES) < _PDATA_SEED_ENTRIES:
                    continue
                # a sample lands anywhere inside the table, so walk back to its real first entry
                start = seed
                while start >= _PDATA_ENTRY_SIZE:
                    previous = self._readExceptionRecord(binary, size, start - _PDATA_ENTRY_SIZE, 0)
                    if previous is None or previous[1] > struct.unpack_from("<I", binary, start)[0]:
                        break
                    start -= _PDATA_ENTRY_SIZE
                count = self._countExceptionRecords(binary, size, start, size)
                if count > best_count:
                    best_offset, best_count = start, count
                offset = max(offset, start + count * _PDATA_ENTRY_SIZE)
                break
            offset += _PDATA_SAMPLE_STRIDE
        if best_count < _PDATA_MIN_ENTRIES:
            return 0, 0
        return best_offset, best_count

    def _carveExceptionRecords(self, base_addr, record_pdata_ends):
        # A memory dump carries the mapped image but usually not a parseable header, so the
        # section table -- and with it .pdata -- is gone, costing every guaranteed x64 function
        # start. The table is self-describing enough to find without one.
        binary = self.disassembly.binary_info.binary
        table_offset, table_count = self._locateExceptionRecordTable(binary)
        if not table_count:
            return
        LOGGER.debug("carved %d RUNTIME_FUNCTION entries at 0x%08x", table_count, table_offset)
        for index in range(table_count):
            if index and index % _TIMEOUT_POLL_INTERVAL == 0 and self._candidateTimeoutTripped():
                return
            rva_start, rva_end, rva_unwind_info = struct.unpack_from(
                "<III", binary, table_offset + index * _PDATA_ENTRY_SIZE
            )
            self._admitExceptionRecord(
                base_addr, rva_start, rva_end, rva_unwind_info, record_pdata_ends, declared=False
            )

    def declaredExceptionRangeContaining(self, addr):
        """The RUNTIME_FUNCTION extent `addr` sits inside without being an entry, or None.

        `(start, end, is_chained)`. A primary record's own start is the function's entry, so
        only a strictly interior address answers; a chained record describes a fragment of
        some other function, so its first byte is interior too and answers as well.

        Extents are deliberately not merged. Functions are laid out end-to-start, so merging
        adjacent records would collapse the text section into a handful of spans in which
        every address but the first reads as interior.
        """
        if self._pdata_range_starts is None:
            self._pdata_ranges.sort()
            self._pdata_range_starts = [start for start, _, _ in self._pdata_ranges]
            # Sorting by start does not order the ends, so "the previous record ends before
            # `addr`" says nothing about the one before that. Two short records in front of
            # a long one would end the walk on top of the extent that actually covers the
            # address. The running maximum is what can be tested in one step: once no record
            # at or before this index reaches past `addr`, none of them contains it.
            highest = 0
            self._pdata_range_reach = []
            for _, end, _chained in self._pdata_ranges:
                highest = max(highest, end)
                self._pdata_range_reach.append(highest)
        index = bisect.bisect_right(self._pdata_range_starts, addr) - 1
        while index >= 0 and self._pdata_range_reach[index] > addr:
            start, end, chained = self._pdata_ranges[index]
            if addr < end and (start < addr or chained):
                return start, end, chained
            index -= 1
        return None

    def _isChainedUnwindInfo(self, rva_unwind_info):
        # x64 UNWIND_INFO header byte 0 packs Version (bits 0-2) and Flags (bits 3-7);
        # UNW_FLAG_CHAININFO (0x4) means this RUNTIME_FUNCTION entry chains to another
        # function's primary entry instead of describing an independent function.
        header_byte = self.disassembly.getRawBytes(rva_unwind_info, 1)
        if not header_byte:
            return False
        return bool((header_byte[0] >> 3) & 0x4)
