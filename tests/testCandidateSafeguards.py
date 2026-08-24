#!/usr/bin/python

import logging
import re
import struct
import types
import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64FunctionCandidateManager
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)


def _make_manager(config, binary=b"\x55\x8b\xec" * 1024, base_addr=0x1000, bitness=32):
    """build a minimal FunctionCandidateManager wired with just enough state to exercise the caps."""
    manager = FunctionCandidateManager(config)
    binary_info = types.SimpleNamespace(bitness=bitness, base_addr=base_addr, binary=binary)
    manager.disassembly = types.SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
    manager.bitness = bitness
    return manager


def _make_full_manager(config, binary, base_addr=0x1000, bitness=32):
    """build a FunctionCandidateManager wired with a disassembly stub that mirrors
    DisassemblyResult's real getRawBytes/isAddrWithinMemoryImage semantics (no bounds
    checking on getRawBytes, range-checked isAddrWithinMemoryImage), enough to drive
    locateReferenceCandidates()/resolvePointerReference() directly."""
    manager = FunctionCandidateManager(config)
    binary_info = types.SimpleNamespace(
        bitness=bitness, base_addr=base_addr, binary=binary, binary_size=len(binary), code_areas=[]
    )

    def _get_raw_bytes(offset, num_bytes):
        return binary_info.binary[offset : offset + num_bytes]

    def _is_addr_within_memory_image(destination):
        if destination is None:
            return False
        return binary_info.base_addr <= destination < (binary_info.base_addr + binary_info.binary_size)

    def _dereference_dword(addr):
        if _is_addr_within_memory_image(addr):
            rel_start = addr - binary_info.base_addr
            extracted = binary_info.binary[rel_start : rel_start + 4]
            if len(extracted) < 4:
                return None
            return struct.unpack("I", extracted)[0]
        return None

    manager.disassembly = types.SimpleNamespace(
        binary_info=binary_info,
        analysis_timeout=False,
        getRawBytes=_get_raw_bytes,
        isAddrWithinMemoryImage=_is_addr_within_memory_image,
        dereferenceDword=_dereference_dword,
    )
    manager.bitness = bitness
    manager._code_areas = []
    return manager


def _make_aarch64_manager(config, binary, base_addr=0x1000):
    manager = AArch64FunctionCandidateManager(config)
    binary_info = types.SimpleNamespace(bitness=64, base_addr=base_addr, binary=binary)
    manager.disassembly = types.SimpleNamespace(
        binary_info=binary_info,
        analysis_timeout=False,
        isAddrWithinMemoryImage=lambda addr: base_addr <= addr < base_addr + len(binary),
        getBytes=lambda addr, size: (
            binary[addr - base_addr : addr - base_addr + size] if 0 <= addr - base_addr < len(binary) else None
        ),
    )
    manager.bitness = 64
    manager._code_areas = []
    return manager


class CandidateSafeguardsTestSuite(unittest.TestCase):
    """Tests for the memory-usage-explosion safeguards added for issue #85."""

    def test_max_function_candidates_cap_is_honored(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 10
        manager = _make_manager(config)
        # request far more candidates than the cap allows
        for offset in range(1000):
            manager.ensureCandidate(0x1000 + offset)
        self.assertEqual(len(manager.candidates), 10)

    def test_refused_candidate_does_not_raise_keyerror(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 1
        manager = _make_manager(config)
        # the first candidate is accepted, every later distinct address is refused; none of the
        # add-helpers must raise a KeyError when their candidate gets refused.
        for offset in range(5):
            addr = 0x1000 + offset * 4
            manager.addReferenceCandidate(addr, 0x2000 + offset)
            manager.addGapCandidate(addr + 1)
            manager.addTailcallCandidate(addr + 2)
            manager.addSymbolCandidate(addr + 3)
            manager.addExceptionCandidate(addr + 3)
            manager.addLanguageSpecCandidate(addr + 3, "go")
        self.assertEqual(len(manager.candidates), 1)

    def test_unlimited_when_cap_is_zero(self):
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 0
        manager = _make_manager(config)
        for offset in range(500):
            manager.ensureCandidate(0x1000 + offset)
        self.assertEqual(len(manager.candidates), 500)

    def test_max_call_refs_per_candidate_cap_is_honored(self):
        config = SmdaConfig()
        config.MAX_CALL_REFS_PER_CANDIDATE = 5
        manager = _make_manager(config)
        for source in range(1000):
            manager.addReferenceCandidate(0x1000, 0x9000 + source)
        self.assertEqual(len(manager.candidates[0x1000].call_ref_sources), 5)

    def test_call_refs_unlimited_when_cap_is_zero(self):
        config = SmdaConfig()
        config.MAX_CALL_REFS_PER_CANDIDATE = 0
        manager = _make_manager(config)
        for source in range(200):
            manager.addReferenceCandidate(0x1000, 0x9000 + source)
        self.assertEqual(len(manager.candidates[0x1000].call_ref_sources), 200)

    def test_default_config_values(self):
        config = SmdaConfig()
        self.assertEqual(config.MAX_FUNCTION_CANDIDATES, 200000)
        self.assertEqual(config.MAX_CALL_REFS_PER_CANDIDATE, 2000)

    def test_aarch64_reference_scan_honors_analysis_timeout(self):
        # BL imm26=1 targets base+4; without timeout this seeds a reference candidate.
        bl_to_next = (0x94000000 | 1).to_bytes(4, "little")
        ret = (0xD65F03C0).to_bytes(4, "little")
        binary = bl_to_next + ret + b"\x00" * 0x100
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 0
        manager = _make_aarch64_manager(config, binary)
        manager.locateReferenceCandidates()
        self.assertIn(0x1004, manager.candidates)

        manager_timeout = _make_aarch64_manager(config, binary)
        manager_timeout.disassembly.analysis_timeout = True
        manager_timeout.locateReferenceCandidates()
        self.assertEqual(manager_timeout.candidates, {})

    def test_aarch64_locate_candidates_aborts_between_passes(self):
        # stp x29, x30, [sp, #-16]! is a recognized prologue; timeout after symbols
        # must skip the prologue pass entirely.
        stp_fp_lr = (0xA9BF7BFD).to_bytes(4, "little")
        ret = (0xD65F03C0).to_bytes(4, "little")
        binary = stp_fp_lr + ret
        config = SmdaConfig()
        config.MAX_FUNCTION_CANDIDATES = 0
        manager = _make_aarch64_manager(config, binary)
        manager.symbol_addresses = []
        manager.disassembly.analysis_timeout = True
        manager.locateCandidates()
        self.assertEqual(manager.candidates, {})

    def test_reference_candidate_with_exactly_five_bytes_remaining_is_registered(self):
        # the 0xE8 opcode byte is at offset 0x10; exactly 5 bytes remain in the binary
        # (1 opcode byte + 4 relative-offset bytes), which is a fully in-bounds read.
        base_addr = 0x1000
        call_offset_in_binary = 0x10
        rel_call_offset = -(call_offset_in_binary + 5)  # makes call_destination == base_addr
        binary = b"\x90" * call_offset_in_binary + b"\xe8" + struct.pack("<i", rel_call_offset)
        self.assertEqual(len(binary) - call_offset_in_binary, 5)

        config = SmdaConfig()
        manager = _make_full_manager(config, binary, base_addr=base_addr, bitness=32)
        manager.locateReferenceCandidates()

        self.assertIn(
            base_addr,
            manager.candidates,
            "the last valid 0xE8 call candidate (exactly 5 bytes remaining) must not be dropped",
        )

    def test_delphi_kb_relocation_skips_out_of_bounds_offsets(self):
        base_addr = 0x400000
        binary = b"\x90" * 0x20
        config = SmdaConfig()
        manager = _make_full_manager(config, binary, base_addr=base_addr, bitness=32)
        manager.symbol_addresses = []
        manager.lang_analyzer = types.SimpleNamespace(
            checkGo=lambda: False,
            checkDelphiKb=lambda: True,
            checkDelphi=lambda: False,
            getDelphiKbObjects=list,
            delphi_kb_resolver=types.SimpleNamespace(
                getRelocations=lambda: [-5, 0, len(binary) - 3, len(binary) - 2, len(binary) - 1, len(binary), 1000]
            ),
        )
        original_binary = manager.disassembly.binary_info.binary

        # must not raise (IndexError/etc.) despite the out-of-bounds relocation offsets
        manager.locateLangSpecCandidates()

        # every offending offset was skipped, so the underlying bytes are untouched
        self.assertEqual(manager.disassembly.binary_info.binary, original_binary)

    def test_resolve_pointer_reference_returns_none_on_short_tail_read(self):
        base_addr = 0x1000
        # only 2 bytes remain after offset+2, so getRawBytes(offset + 2, 4) is short
        binary = b"\xff\x25\x11\x22"
        offset = 0  # offset + 2 == 2, only 2 bytes left in the 4-byte binary

        config = SmdaConfig()
        manager_32 = _make_full_manager(config, binary, base_addr=base_addr, bitness=32)
        self.assertIsNone(manager_32.resolvePointerReference(offset))

        manager_64 = _make_full_manager(config, binary, base_addr=base_addr, bitness=64)
        self.assertIsNone(manager_64.resolvePointerReference(offset))


if __name__ == "__main__":
    unittest.main()


class DeclaredStartAlignmentExemptionTest(unittest.TestCase):
    """The alignment floor is inferred from where call-referenced candidates happen to sit, so
    it bounds a guess about an unknown function. An exception record and a direct call are both
    the image's own declaration of a start, and neither must be filtered out of the queue."""

    def _manager(self, alignment):
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 32
        manager.identified_alignment = alignment
        manager._code_areas = []
        # a real prologue at the unaligned address, so a candidate can score without an
        # inbound call and the floor is the only thing that can filter it
        binary = bytearray(b"\x00" * 0x1000)
        binary[0x1001:0x1004] = b"\x55\x8b\xec"  # push ebp; mov ebp, esp
        binary_info = types.SimpleNamespace(bitness=32, base_addr=0, binary=bytes(binary))
        manager.disassembly = types.SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        return manager

    def _yielded(self, alignment, mark):
        manager = self._manager(alignment)
        manager.addCandidate(0x1001)
        mark(manager.candidates[0x1001])
        manager._buildQueue()
        return [candidate.addr for candidate in manager.getNextFunctionStartCandidate()]

    def test_unaligned_exception_record_is_still_analyzed(self):
        self.assertEqual(self._yielded(4, lambda c: c.setIsExceptionHandler(True)), [0x1001])

    def test_unaligned_call_referenced_candidate_is_analyzed(self):
        """The inference itself tolerates a twentieth of the call-referenced population sitting
        off the alignment, so filtering all of it discards what the inference allowed for:
        `abort` in a static glibc is at an odd address and is reached by 37 direct calls."""
        self.assertEqual(self._yielded(4, lambda c: c.addCallRef(0x2000)), [0x1001])

    def test_unaligned_candidate_with_no_inbound_call_is_still_filtered(self):
        """Control: the floor still bounds a guess. A byte pattern matching a prologue at an
        odd address is exactly the guess it exists to refuse."""
        self.assertEqual(self._yielded(4, lambda c: c.setInitialCandidate(True)), [])

    def test_alignment_floor_of_zero_filters_nothing(self):
        self.assertEqual(self._yielded(0, lambda c: c.setInitialCandidate(True)), [0x1001])


class PushPairPrologueOffsetTest(unittest.TestCase):
    """`push r15; push r14` is seeded as a prologue, but it is a run of callee-saved pushes
    rather than a distinguishing first instruction. clang orders `push rbp` first in a
    function that keeps no frame pointer, and the pair then matches one byte in and names the
    body: `main` in every clang -O1 and above build of the reference corpus was recovered one
    byte late, counted as a body split rather than as the function it is."""

    BASE = 0x400000
    PUSH_PAIR = b"\x41\x57\x41\x56"

    def _seeded(self, binary, pattern=PUSH_PAIR):
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 64
        manager._code_areas = []
        binary_info = types.SimpleNamespace(bitness=64, base_addr=self.BASE, binary=binary)
        manager.disassembly = types.SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        manager._seedPrologueMatches(re.escape(pattern))
        return sorted(manager.candidates)

    def test_a_leading_push_rbp_moves_the_seed_to_the_entry(self):
        self.assertEqual(self._seeded(b"\x00" * 0x10 + b"\x55" + self.PUSH_PAIR + b"\xc3"), [self.BASE + 0x10])

    def test_another_leading_byte_leaves_the_seed_where_it_matched(self):
        """Control: only a `push rbp` immediately before the pair can be the same prologue."""
        self.assertEqual(self._seeded(b"\x00" * 0x10 + b"\x90" + self.PUSH_PAIR + b"\xc3"), [self.BASE + 0x11])

    def test_a_match_at_the_very_start_of_the_image_is_left_alone(self):
        self.assertEqual(self._seeded(self.PUSH_PAIR + b"\xc3"), [self.BASE])

    def _seededWithDeclared(self, binary, declared):
        """As _seeded, but with addresses the image declares already registered - the state the
        prologue scan actually runs in, since symbols, call references and exception records
        are all located before it."""
        manager = FunctionCandidateManager(SmdaConfig())
        manager.bitness = 64
        manager._code_areas = []
        binary_info = types.SimpleNamespace(bitness=64, base_addr=self.BASE, binary=binary)
        manager.disassembly = types.SimpleNamespace(binary_info=binary_info, analysis_timeout=False)
        for addr in declared:
            manager.ensureCandidate(addr)
            manager.candidates[addr].addCallRef(addr - 0x100)
        manager._seedPrologueMatches(re.escape(self.PUSH_PAIR))
        return sorted(a for a in manager.candidates if a not in declared)

    def test_a_declared_entry_just_before_the_0x55_suppresses_the_seed(self):
        """`push 0x55` ends in the same byte a `push rbp` is spelled with, so the raw-byte
        check cannot tell them apart and the shift books an address one byte inside the real
        entry. The image settles it: a declared start in the bytes just before means the 0x55
        is inside its opening instruction, so neither address begins a function and no seed
        belongs here at all."""
        binary = b"\x00" * 0x10 + b"\x6a\x55" + self.PUSH_PAIR + b"\xc3"

        self.assertEqual(self._seededWithDeclared(binary, [self.BASE + 0x10]), [])

    def test_a_declared_entry_far_from_the_0x55_still_moves_the_seed(self):
        """Control: the suppression keys on a declared entry being close enough for the 0x55 to
        sit inside its first instruction. One further back is an ordinary neighbouring function
        and must not stop a genuine `push rbp` entry being seeded."""
        binary = b"\x00" * 0x10 + b"\x55" + self.PUSH_PAIR + b"\xc3"

        self.assertEqual(self._seededWithDeclared(binary, [self.BASE]), [self.BASE + 0x10])

    def test_an_entry_packed_behind_a_tail_jump_still_moves_the_seed(self):
        """Requiring the byte before the 0x55 to end a function was tried and reverted. A
        function can end with a tail `jmp` or a `ud2`, whose last byte is arbitrary, and Rust
        packs the next entry straight behind one: keying on that byte cost four real functions
        on the bundled Rust PE. These are the endings it got wrong."""
        for label, ending in (
            ("jmp short", b"\xeb\xc6"),
            ("jmp rel32", b"\xe9\x30\xed\xff\xff"),
            ("ud2", b"\x0f\x0b"),
        ):
            with self.subTest(ending=label):
                binary = b"\x00" * 0x10 + ending + b"\x55" + self.PUSH_PAIR + b"\xc3"
                self.assertEqual(self._seeded(binary), [self.BASE + 0x10 + len(ending)])

    def test_another_seeded_prologue_keeps_its_own_address(self):
        """Control: the adjustment is scoped to the one seeded pattern that is a run of
        callee-saved pushes. The other two open with `sub rsp` behind a single push, which is
        a frame setup rather than a run, so a stray 0x55 in front of one does not extend it
        and must not move the seed."""
        opener = b"\x40\x53\x48\x83\xec"  # push rbx; sub rsp, imm8
        self.assertEqual(self._seeded(b"\x00" * 0x10 + b"\x55" + opener, pattern=opener), [self.BASE + 0x11])
