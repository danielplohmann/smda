import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer
from smda.SmdaConfig import SmdaConfig


def _makeAnalyzer(binary=b"", base_addr=0x1000, binary_size=0x100, bitness=32):
    """Build a JumpTableAnalyzer against a minimal disassembler/disassembly double.

    binary_info.binary is real bytes (needed because __init__ runs a real regex
    match against it), everything else on the disassembly double is a MagicMock
    that individual tests can further configure.
    """
    disassembler = MagicMock()
    disassembly = MagicMock()
    disassembly.binary_info = SimpleNamespace(
        binary=binary,
        base_addr=base_addr,
        binary_size=binary_size,
        bitness=bitness,
    )
    disassembler.disassembly = disassembly
    disassembler.getBitMask.return_value = 0xFFFFFFFF
    analyzer = JumpTableAnalyzer(disassembler)
    return analyzer


class JumpTableAnalyzerTestSuite(unittest.TestCase):
    """Regression tests: near-tail getBytes/getRawBytes reads must not raise
    struct.error/TypeError, they must be treated as "no data" and skipped."""

    def test_findJumpTables_short_raw_bytes_does_not_raise(self):
        # A minimal match for the lea/movsxd jump-table pattern (the "\x77" branch
        # of the alternation keeps the whole match at the theoretical minimum
        # length of 8 bytes): (\x48|\x4c) \x8d .{5} \x77
        binary = b"\x48\x8d\x00\x00\x00\x00\x00\x77"
        analyzer = _makeAnalyzer(binary=binary)
        # Simulate the tail-of-image case: the raw offset bytes read near
        # match_offset.start() + 3 come back short (fewer than 4 bytes).
        analyzer.disassembly.getRawBytes = MagicMock(return_value=b"\x01\x02")

        result = analyzer._findJumpTables()

        self.assertEqual(result, set())

    def test_findJumpTables_matches_displacement_containing_newline_byte(self):
        # `lea r11, [rip + 0xa1234]; movsxd` — the displacement contains 0x0a,
        # which a bytes regex without re.DOTALL never matches ('.' excludes \n),
        # silently dropping the jump table from table_offsets.
        binary = b"\x4c\x8d\x1d\x34\x12\x0a\x00\x48\x63\xc0"
        analyzer = _makeAnalyzer(binary=binary, base_addr=0x1000)
        analyzer.disassembly.getRawBytes = MagicMock(return_value=b"\x34\x12\x0a\x00")
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)

        result = analyzer._findJumpTables()

        self.assertEqual(result, {0x1000 + 0xA1234 + 7})

    def test_extractDirectTableOffsets_none_bytes_does_not_raise(self):
        analyzer = _makeAnalyzer()
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # Simulate getBytes() returning None, as it does for out-of-image reads.
        analyzer.disassembly.getBytes = MagicMock(return_value=None)

        result = analyzer._extractDirectTableOffsets(jumptable_size=4, off_jumptable=0x1050)

        self.assertEqual(result, [])

    def test_extractDirectTableOffsets_short_bytes_does_not_raise(self):
        analyzer = _makeAnalyzer()
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # Simulate a short read near the tail of the mapped image.
        analyzer.disassembly.getBytes = MagicMock(return_value=b"\x01\x02")

        result = analyzer._extractDirectTableOffsets(jumptable_size=4, off_jumptable=0x1050)

        self.assertEqual(result, [])

    def test_extractRelativeTableOffsets_short_raw_bytes_does_not_raise(self):
        analyzer = _makeAnalyzer()
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # rebased = off_jumptable + bonus_offset - base_addr stays >= 0 here,
        # but the raw bytes read back is short (tail-of-image case).
        analyzer.disassembly.getRawBytes = MagicMock(return_value=b"\x01\x02")

        result = analyzer._extractRelativeTableOffsets(
            jumptable_size=4, off_jumptable=0x1050, alternative_base=None, bonus_offset=0
        )

        self.assertEqual(result, [])

    def test_extractRelativeTableOffsets_negative_rebase_does_not_raise(self):
        analyzer = _makeAnalyzer(base_addr=0x1000)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # off_jumptable + bonus_offset - base_addr < 0: negative-index territory.
        analyzer.disassembly.getRawBytes = MagicMock(
            side_effect=AssertionError("getRawBytes must not be called with a negative rebased offset")
        )

        result = analyzer._extractRelativeTableOffsets(
            jumptable_size=4, off_jumptable=0x1000, alternative_base=None, bonus_offset=-0x100
        )

        self.assertEqual(result, [])

    def test_resolveExplicitTable_none_bytes_does_not_raise(self):
        analyzer = _makeAnalyzer(bitness=32)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # Simulate getBytes() returning None near the tail of the mapped image.
        analyzer.disassembly.getBytes = MagicMock(return_value=None)
        state = MagicMock()

        result = analyzer._resolveExplicitTable(
            jump_instruction_address=0x2000, state=state, jumptable_address=0x1090, jumptable_size=4
        )

        self.assertEqual(result, [])
        state.addDataRef.assert_not_called()

    def test_findJumpTableSize_stops_at_prefixed_ret(self):
        """A CET-hardened "bnd ret" must be recognized as a backtrack boundary just like a
        plain "ret" (capstone prepends the mandatory "bnd" prefix to the mnemonic string).
        The scan walks backward (backtracked[::-1], from the highest address down): here it
        first sees an unrelated "mov" (no match, keeps going), then the "bnd ret" boundary,
        which must stop the scan before it ever reaches the earlier "cmp eax, 0x9" -- picking
        that up would be the unrelated-code false bound the bug produced."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 2, "cmp", "eax, 0x9"),
            (0x1002, 1, "bnd ret", ""),
            (0x1004, 2, "mov", "ecx, 0x1"),
        ]

        result = analyzer._findJumpTableSize(backtracked)

        self.assertEqual(result, 0)

    def test_findJumpTableSize_stops_at_plain_ret(self):
        """Baseline: an unprefixed "ret" already worked before the fix; isolates the
        prefix-handling regression from ordinary boundary detection."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 2, "cmp", "eax, 0x9"),
            (0x1002, 1, "ret", ""),
            (0x1004, 2, "mov", "ecx, 0x1"),
        ]

        result = analyzer._findJumpTableSize(backtracked)

        self.assertEqual(result, 0)

    def test_resolveExplicitTable_short_bytes_does_not_raise(self):
        analyzer = _makeAnalyzer(bitness=32)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        # Simulate a short read (fewer bytes than entry_size) near the tail.
        analyzer.disassembly.getBytes = MagicMock(return_value=b"\x01\x02")
        state = MagicMock()

        result = analyzer._resolveExplicitTable(
            jump_instruction_address=0x2000, state=state, jumptable_address=0x1090, jumptable_size=4
        )

        self.assertEqual(result, [])
        state.addDataRef.assert_not_called()

    def test_resolveExplicitTable_scans_when_the_size_was_not_recovered(self):
        # _findJumpTableSize reports "no bound found" as 0, which MSVC /Od reaches routinely
        # because it spills the switch value and compares a stack slot. Treating that 0 as a
        # real size abandoned the table; it must fall back to a bounded scan instead, and the
        # per-entry image check is what ends it -- here after the three in-image entries.
        analyzer = _makeAnalyzer(bitness=32)
        entries = [0x1100, 0x1200, 0x1300]
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(side_effect=lambda addr: addr in (0x1090, *entries))
        table = b"".join(struct.pack("<I", entry) for entry in entries) + struct.pack("<I", 0xDEADBEEF)
        analyzer.disassembly.getBytes = MagicMock(
            side_effect=lambda addr, size: table[addr - 0x1090 : addr - 0x1090 + size]
        )

        result = analyzer._resolveExplicitTable(
            jump_instruction_address=0x2000, state=MagicMock(), jumptable_address=0x1090, jumptable_size=0
        )

        self.assertEqual(result, entries)

    def test_resolveExplicitTable_honours_a_recovered_size(self):
        # a real bound must still cap the scan, so the entry past the switch is not claimed
        analyzer = _makeAnalyzer(bitness=32)
        entries = [0x1100, 0x1200, 0x1300]
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        table = b"".join(struct.pack("<I", entry) for entry in entries)
        analyzer.disassembly.getBytes = MagicMock(
            side_effect=lambda addr, size: table[addr - 0x1090 : addr - 0x1090 + size]
        )

        result = analyzer._resolveExplicitTable(
            jump_instruction_address=0x2000, state=MagicMock(), jumptable_address=0x1090, jumptable_size=2
        )

        self.assertEqual(result, entries[:2])


if __name__ == "__main__":
    unittest.main()


class TestJumpTableSignedness(unittest.TestCase):
    """Regression for audit finding 27: jump-table signedness.

    The lea disp32 and relative table entries are signed int32; treating them as
    unsigned drops backward-referencing tables (and the whole switch) or computes
    wrong targets. These fail on pre-fix code (struct.unpack("I", ...))."""

    def test_findJumpTables_backward_lea_signed_disp_not_dropped(self):
        # lea r11, [rip - 0x1000] (disp32 0xFFFFF000) must unpack as a signed
        # displacement so the table is found instead of overflowing and being dropped.
        binary = b"\x00" * 0x2000 + b"\x4c\x8d\x1d\x00\xf0\xff\xff\x48\x63\xc0"
        analyzer = _makeAnalyzer(binary=binary, base_addr=0x1000, binary_size=0x3000)
        analyzer.disassembly.getRawBytes = MagicMock(return_value=b"\x00\xf0\xff\xff")
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(side_effect=lambda a: 0x1000 <= a < 0x4000)
        # ins_offset = base_addr + match.start() = 0x1000 + 0x2000 = 0x3000;
        # table_offset = 0x3000 + (-0x1000) + 7 = 0x2007
        self.assertEqual(analyzer._findJumpTables(), {0x2007})

    def test_extractRelativeTableOffsets_negative_entry_recovered(self):
        # A switch whose bodies precede the table stores negative int32 entries
        # (target - table_base). These must unpack signed and be masked before the
        # bounds check, or every target of the switch is lost.
        analyzer = _makeAnalyzer(base_addr=0x1000, binary_size=0x2000)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(side_effect=lambda a: 0x1000 <= a < 0x3000)
        analyzer.disassembly.getRawBytes = MagicMock(return_value=b"\x00\xf0\xff\xff")  # -0x1000
        # jump_base = off_jumptable = 0x2000; masked target = 0x2000 - 0x1000 = 0x1000
        result = analyzer._extractRelativeTableOffsets(
            jumptable_size=4, off_jumptable=0x2000, alternative_base=None, bonus_offset=0
        )
        self.assertEqual(result, [0x1000])


class X64BonusOffsetTestSuite(unittest.TestCase):
    def test_bonus_offset_taken_from_the_first_matching_mov(self):
        analyzer = _makeAnalyzer(bitness=64)
        analyzer.disassembler.getReferencedAddr.return_value = 0x140
        backtracked = [
            ("ignored", 0, "lea", "rax, [rip + 0x10]"),
            (0x2000, 7, "mov", "eax, dword ptr [rcx + rax*4 + 0x140]"),
        ]

        self.assertEqual(0x140, analyzer._getx64BonusOffset(backtracked))

    def test_no_bonus_offset_without_a_matching_mov(self):
        analyzer = _makeAnalyzer(bitness=64)
        backtracked = [(0x2000, 3, "add", "rax, rcx")]

        self.assertEqual(0, analyzer._getx64BonusOffset(backtracked))


class RelativeTableDataClaimTest(unittest.TestCase):
    """A relative jump table's own bytes must be claimed as data, or the gap scan seeds
    function candidates inside the table."""

    def _walk(self, bonus_offset=0):
        analyzer = _makeAnalyzer(base_addr=0x1000)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        entries = b"".join(struct.pack("<i", 0x40 + index * 4) for index in range(3)) + b"\x00\x00\x00\x00"
        analyzer.disassembly.getRawBytes = MagicMock(
            side_effect=lambda offset, size: entries[offset - 0x100 - bonus_offset :][:size]
        )
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))
        targets = analyzer._extractRelativeTableOffsets(
            jumptable_size=3,
            off_jumptable=0x1100,
            bonus_offset=bonus_offset,
            state=state,
            jump_instruction_address=0x2000,
        )
        return targets, state.refs

    def test_each_consumed_entry_is_claimed_as_data_at_its_real_address(self):
        targets, refs = self._walk()
        self.assertEqual(len(targets), 3)
        # the table sits at off_jumptable, NOT at the image offset used to read it
        self.assertEqual(refs, [(0x2000, 0x1100, 4), (0x2000, 0x1104, 4), (0x2000, 0x1108, 4)])

    def test_the_bonus_offset_shifts_the_claimed_address(self):
        _targets, refs = self._walk(bonus_offset=0x10)
        self.assertEqual([ref[1] for ref in refs], [0x1110, 0x1114, 0x1118])

    def test_no_state_means_no_data_claim_and_no_crash(self):
        analyzer = _makeAnalyzer(base_addr=0x1000)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        analyzer.disassembly.getRawBytes = MagicMock(return_value=struct.pack("<i", 0x40))
        self.assertEqual(analyzer._extractRelativeTableOffsets(jumptable_size=1, off_jumptable=0x1100), [0x1140])

    def test_add_mov_sequence_claims_the_table_at_its_bonus_offset(self):
        # the `add-mov` x64 shape carries a bonus offset, so getJumpTargets must forward both
        # the state and that offset for the entries to be claimed at the right addresses
        analyzer = _makeAnalyzer(base_addr=0x1000, bitness=64)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(return_value=True)
        entries = b"".join(struct.pack("<i", 0x40 + index * 4) for index in range(2))
        analyzer.disassembly.getRawBytes = MagicMock(side_effect=lambda offset, size: entries[offset - 0x110 :][:size])
        analyzer._x64Handler = MagicMock(return_value=0x1100)
        analyzer.disassembler.getReferencedAddr = MagicMock(return_value=0x10)

        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))
        # getJumpTargets reverses this list, so "add" must come last for an add-mov sequence
        state.backtrackInstructions = MagicMock(
            return_value=[
                (0x1FF0, 4, "mov", "eax, dword ptr [rcx + 0x10]"),
                (0x1FF8, 3, "add", "rax, rdx"),
            ]
        )

        analyzer.getJumpTargets((0x2000, 2, "jmp", "rax"), state)

        self.assertEqual([ref[1] for ref in state.refs], [0x1110, 0x1114])


class DirectTableScanTest(unittest.TestCase):
    """The 32-bit `mov <reg>, dword ptr [<reg>*4 + table]` / `jmp <reg>` shape, whose
    extractor lacked both the unrecovered-bound fallback and the per-entry image bound
    its two siblings already had."""

    ENTRIES = [0x1100, 0x1200, 0x1300]
    OUT_OF_IMAGE = struct.pack("<I", 0xDEADBEEF)

    def _analyzer(self, trailing=OUT_OF_IMAGE):
        analyzer = _makeAnalyzer(bitness=32)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(
            side_effect=lambda addr: addr in (0x1090, *self.ENTRIES)
        )
        table = b"".join(struct.pack("<I", entry) for entry in self.ENTRIES) + trailing
        analyzer.disassembly.getBytes = MagicMock(
            side_effect=lambda addr, size: table[addr - 0x1090 : addr - 0x1090 + size]
        )
        return analyzer

    def test_scans_when_the_size_was_not_recovered(self):
        # an unrecovered bound arrives as 0 and abandoned the table outright; the
        # per-entry image check is what ends the scan
        analyzer = self._analyzer()
        self.assertEqual(analyzer._extractDirectTableOffsets(0, 0x1090), self.ENTRIES)

    def test_stops_at_the_first_out_of_image_entry(self):
        # without the bound, a too-large size walked past the table and turned
        # whatever followed it into jump targets
        analyzer = self._analyzer()
        self.assertEqual(analyzer._extractDirectTableOffsets(0xFF, 0x1090), self.ENTRIES)

    def test_honours_a_recovered_size(self):
        analyzer = self._analyzer()
        self.assertEqual(analyzer._extractDirectTableOffsets(2, 0x1090), self.ENTRIES[:2])

    def test_a_recovered_size_scans_past_an_entry_outside_the_image(self):
        # one case dispatching outside the mapped image - a partially mapped dump, or a
        # tailcall into another module - must not truncate the rest of a declared table
        analyzer = self._analyzer()
        table = struct.pack("<I", self.ENTRIES[0]) + self.OUT_OF_IMAGE + struct.pack("<I", self.ENTRIES[2])
        analyzer.disassembly.getBytes = MagicMock(
            side_effect=lambda addr, size: table[addr - 0x1090 : addr - 0x1090 + size]
        )
        self.assertEqual(
            analyzer._extractDirectTableOffsets(3, 0x1090),
            [self.ENTRIES[0], self.ENTRIES[2]],
        )

    def test_stops_at_a_short_read(self):
        analyzer = self._analyzer(trailing=b"\x01\x02")
        self.assertEqual(analyzer._extractDirectTableOffsets(0xFF, 0x1090), self.ENTRIES)

    def test_each_consumed_entry_is_claimed_as_data(self):
        analyzer = self._analyzer()
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))
        analyzer._extractDirectTableOffsets(0, 0x1090, state=state, jump_instruction_address=0x2000)
        self.assertEqual(state.refs, [(0x2000, 0x1090, 4), (0x2000, 0x1094, 4), (0x2000, 0x1098, 4)])

    def test_getJumpTargets_forwards_the_state_for_the_direct_shape(self):
        analyzer = self._analyzer()
        analyzer._directHandler = MagicMock(return_value=0x1090)
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))
        state.backtrackInstructions = MagicMock(
            return_value=[(0x1FF0, 5, "mov", "eax, dword ptr [eax*4 + 0x1090]")],
        )

        targets = analyzer.getJumpTargets((0x2000, 2, "jmp", "eax"), state)

        self.assertEqual(targets, self.ENTRIES)
        self.assertEqual([ref[1] for ref in state.refs], [0x1090, 0x1094, 0x1098])


class DirectTableRecoveryTest(unittest.TestCase):
    """End to end: an abandoned table leaves the switch bodies unreferenced, so the gap
    scan recovers each of them as a function of its own instead of as blocks."""

    BASE = 0x400000
    TABLE = 0x401000

    def _buffer(self):
        buffer = bytearray(0x2000)
        code = bytes.fromhex("55")  # push ebp
        code += bytes.fromhex("89e5")  # mov ebp, esp
        code += bytes.fromhex("8b048500104000")  # mov eax, dword ptr [eax*4 + 0x401000]
        code += bytes.fromhex("ffe0")  # jmp eax
        buffer[0 : len(code)] = code
        offset = self.TABLE - self.BASE
        for index, target in enumerate((0x400010, 0x400020, 0x400030)):
            struct.pack_into("<I", buffer, offset + index * 4, target)
        struct.pack_into("<I", buffer, offset + 12, 0xDEADBEEF)  # out of image: ends the scan
        for case in (0x10, 0x20, 0x30):
            buffer[case : case + 3] = bytes.fromhex("31c0c3")  # xor eax, eax; ret
        return bytes(buffer)

    def test_switch_bodies_become_blocks_of_the_dispatching_function(self):
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleBuffer(self._buffer(), self.BASE, bitness=32)

        self.assertEqual([function.offset for function in report.getFunctions()], [self.BASE])
        function = next(iter(report.getFunctions()))
        self.assertEqual(
            sorted(block.offset for block in function.getBlocks()),
            [self.BASE, 0x400010, 0x400020, 0x400030],
        )
        # the three consumed entries are claimed as data, so the gap scan cannot seed
        # candidates inside the table
        self.assertEqual(sorted(report.data_refs_from[0x40000A]), [0x401000, 0x401004, 0x401008])


class ZeroTableEntryTest(unittest.TestCase):
    """A table entry of zero is what a run of zero bytes reads back as, and in an image
    mapped at base 0 it is also inside the mapped range, so the image bound admits it."""

    IMAGE_SIZE = 0x2000
    LIVE = 0x1100
    OUT_OF_IMAGE = 0xDEADBEEF

    def _analyzer(self, entries, bitness=32):
        analyzer = _makeAnalyzer(base_addr=0, binary_size=self.IMAGE_SIZE, bitness=bitness)
        analyzer.disassembly.isAddrWithinMemoryImage = MagicMock(
            side_effect=lambda addr: addr is not None and 0 <= addr < self.IMAGE_SIZE
        )
        entry_format = "<I" if bitness == 32 else "<Q"
        entry_size = struct.calcsize(entry_format)
        table = b"".join(struct.pack(entry_format, entry) for entry in entries)
        analyzer.disassembly.getBytes = MagicMock(
            side_effect=lambda addr, size: table[addr - 0x1090 : addr - 0x1090 + size]
        )
        return analyzer, entry_size

    def test_a_base_zero_image_really_admits_address_zero(self):
        """Positive control for the class, asserted against the real predicate: without this
        the tests below could pass because the image bound already rejected zero, which is
        the case they exist for."""
        disassembly = DisassemblyResult()
        disassembly.binary_info = SimpleNamespace(base_addr=0, binary_size=self.IMAGE_SIZE)

        self.assertTrue(disassembly.isAddrWithinMemoryImage(0))

    def test_direct_scan_without_a_bound_stops_at_a_zero_entry(self):
        analyzer, _ = self._analyzer([0, self.LIVE])

        self.assertEqual(analyzer._extractDirectTableOffsets(0, 0x1090), [])

    def test_direct_scan_without_a_bound_reads_a_live_entry(self):
        """Positive control: the same harness terminated out of the image instead of by a
        zero must collect the live entry, and must do so on either side of the fix, so an
        empty result above cannot come from the scan never running."""
        analyzer, _ = self._analyzer([self.LIVE, self.OUT_OF_IMAGE])

        self.assertEqual(analyzer._extractDirectTableOffsets(0, 0x1090), [self.LIVE])

    def test_a_recovered_bound_skips_a_zero_entry_and_keeps_scanning(self):
        analyzer, _ = self._analyzer([0, self.LIVE])

        self.assertEqual(analyzer._extractDirectTableOffsets(2, 0x1090), [self.LIVE])

    def test_explicit_table_stops_at_a_zero_entry(self):
        analyzer, _ = self._analyzer([0, self.LIVE], bitness=64)
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))

        self.assertEqual(analyzer._resolveExplicitTable(0x2000, state, 0x1090), [])
        self.assertEqual(state.refs, [])

    def test_explicit_table_refuses_a_table_base_of_zero(self):
        """The base reaches the scan through the same operand reader, which returns its
        "nothing found" 0 for a dispatch naming no displacement (`jmp qword ptr [rax*8]`)."""
        analyzer, _ = self._analyzer([self.LIVE, self.LIVE], bitness=64)
        analyzer.disassembly.getBytes = MagicMock(side_effect=lambda addr, size: struct.pack("<Q", self.LIVE)[:size])
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))

        self.assertEqual(analyzer._resolveExplicitTable(0x2000, state, 0), [])
        self.assertEqual(state.refs, [])

    def test_explicit_table_reads_a_live_entry(self):
        """Positive control for the explicit-table arm, terminated out of the image so it
        reads the same on either side of the fix."""
        analyzer, entry_size = self._analyzer([self.LIVE, self.OUT_OF_IMAGE], bitness=64)
        state = SimpleNamespace(refs=[])
        state.addDataRef = lambda addr_from, addr_to, size=1: state.refs.append((addr_from, addr_to, size))

        self.assertEqual(analyzer._resolveExplicitTable(0x2000, state, 0x1090), [self.LIVE])
        self.assertEqual(state.refs, [(0x2000, 0x1090, entry_size)])


class ZeroTableEntryRecoveryTest(unittest.TestCase):
    """End to end, in an image mapped at base 0: a dispatch whose derived table base lands
    on zero bytes read address 0 as its only case target, and the function reaching the
    dispatch was discarded whole rather than kept with an unresolved jump."""

    FUNCTION = 0x100
    TABLE = 0x1000
    CASES = (0x40, 0x50, 0x60)

    def _buffer(self, table_is_populated):
        buffer = bytearray(0x2000)
        code = bytes.fromhex("55")  # push ebp
        code += bytes.fromhex("89e5")  # mov ebp, esp
        code += bytes.fromhex("8b0485") + struct.pack("<I", self.TABLE)  # mov eax, [eax*4 + table]
        code += bytes.fromhex("ffe0")  # jmp eax
        buffer[self.FUNCTION : self.FUNCTION + len(code)] = code
        for case in self.CASES:
            buffer[self.FUNCTION + case : self.FUNCTION + case + 3] = bytes.fromhex("31c0c3")  # xor eax, eax; ret
        if table_is_populated:
            for index, case in enumerate(self.CASES):
                struct.pack_into("<I", buffer, self.TABLE + index * 4, self.FUNCTION + case)
            struct.pack_into("<I", buffer, self.TABLE + len(self.CASES) * 4, 0xDEADBEEF)
        return bytes(buffer)

    def _functions(self, table_is_populated):
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = False
        report = Disassembler(config).disassembleBuffer(self._buffer(table_is_populated), 0, bitness=32)
        self.assertEqual(report.status, "ok")
        return report

    def test_a_populated_table_dispatches_as_one_function(self):
        """Positive control: the same image with a readable table must recover the dispatch
        and its cases as one function, and does so on either side of the fix."""
        report = self._functions(table_is_populated=True)

        functions = list(report.getFunctions())
        self.assertEqual([function.offset for function in functions], [self.FUNCTION])
        self.assertEqual(
            sorted(block.offset for block in functions[0].getBlocks()),
            [self.FUNCTION] + [self.FUNCTION + case for case in self.CASES],
        )

    def test_a_zero_table_leaves_the_dispatching_function_recovered(self):
        report = self._functions(table_is_populated=False)

        self.assertIn(self.FUNCTION, [function.offset for function in report.getFunctions()])


class PushRetZeroRecoveryTest(unittest.TestCase):
    """End to end: `push <reg>; ret` names no literal, so the operand reader returns its
    "nothing found" 0, which a base-0 image accepts - and address 0 was queued for decoding
    as the return's destination, taking the whole function with it."""

    FUNCTION = 0x100

    def _report(self, through_a_register):
        buffer = bytearray(0x400)
        code = bytes.fromhex("55")  # push ebp
        code += bytes.fromhex("89e5")  # mov ebp, esp
        if through_a_register:
            code += bytes.fromhex("31c0")  # xor eax, eax
            code += bytes.fromhex("50")  # push eax
        else:
            code += b"\x68" + struct.pack("<I", 0x200)  # push 0x200
        code += bytes.fromhex("c3")  # ret
        buffer[self.FUNCTION : self.FUNCTION + len(code)] = code
        buffer[0x200:0x203] = bytes.fromhex("31c0c3")  # xor eax, eax; ret
        config = SmdaConfig()
        config.TIMEOUT = 30
        config.WITH_STRINGS = False
        config.CALCULATE_HASHING = False
        return Disassembler(config).disassembleBuffer(bytes(buffer), 0, bitness=32)

    def test_a_register_destination_leaves_the_function_recovered(self):
        report = self._report(through_a_register=True)

        self.assertIn(self.FUNCTION, [function.offset for function in report.getFunctions()])

    def test_a_literal_destination_is_still_followed(self):
        """Positive control: the push-ret idiom naming a real address must keep working,
        and reads the same on either side of the change."""
        report = self._report(through_a_register=False)

        self.assertIn(self.FUNCTION, [function.offset for function in report.getFunctions()])
