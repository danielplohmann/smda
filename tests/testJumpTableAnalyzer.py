import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer


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


if __name__ == "__main__":
    unittest.main()
