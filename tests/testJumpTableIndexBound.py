import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from smda.Disassembler import Disassembler
from smda.intel.definitions import canonicalRegister
from smda.intel.JumpTableAnalyzer import JumpTableAnalyzer
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
TEXT_RVA = 0x1000
TABLE_RVA = 0x2000
IMAGE_SIZE = 0x3000


def _makeAnalyzer(binary=b"", base_addr=0x1000, bitness=64):
    disassembler = MagicMock()
    disassembly = MagicMock()
    disassembly.binary_info = SimpleNamespace(
        binary=binary,
        base_addr=base_addr,
        binary_size=len(binary) or 0x100,
        bitness=bitness,
        # a binary with no section table - a memory dump - has no code areas, and BinaryInfo
        # then answers for the whole image; tests needing the section-bounded answer set it
        isInCodeAreas=MagicMock(return_value=True),
        # an executable, the permissive case: an image the loader relocates holds no absolute
        # table a compiler emitted, so tests for that arm set it
        isPositionIndependentElf=MagicMock(return_value=False),
    )
    disassembler.disassembly = disassembly
    disassembler.getBitMask.return_value = 0xFFFFFFFFFFFFFFFF
    return JumpTableAnalyzer(disassembler)


class CanonicalRegisterTestSuite(unittest.TestCase):
    def test_every_spelling_maps_to_the_widest_name(self):
        for spelling, expected in (
            ("al", "rax"),
            ("ah", "rax"),
            ("ax", "rax"),
            ("eax", "rax"),
            ("rax", "rax"),
            ("EAX", "rax"),
            ("sil", "rsi"),
            ("bpl", "rbp"),
            ("r8d", "r8"),
            ("r15b", "r15"),
            ("r10w", "r10"),
        ):
            with self.subTest(spelling=spelling):
                self.assertEqual(canonicalRegister(spelling), expected)

    def test_non_registers_map_to_none(self):
        for spelling in ("rip", "xmm0", "qword ptr [rax]", "0x10", ""):
            with self.subTest(spelling=spelling):
                self.assertIsNone(canonicalRegister(spelling))


class DispatchIndexKeyTestSuite(unittest.TestCase):
    def test_scaled_memory_operand_indexes_with_its_scaled_register(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._dispatchIndexKeys("qword ptr [rax*8 + 0x402018]"), {"rax"})
        self.assertEqual(analyzer._dispatchIndexKeys("dword ptr [r11 + rdx*4]"), {"rdx"})

    def test_register_operand_is_its_own_index(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._dispatchIndexKeys("rcx"), {"rcx"})

    def test_unscaled_memory_operand_is_read_whole(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._dispatchIndexKeys("byte ptr [rdi + rcx]"), {"byte ptr [rdi + rcx]"})

    def test_operand_naming_nothing_trackable_yields_no_key(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._dispatchIndexKeys("0x401000"), set())


class IndexTiedBoundTestSuite(unittest.TestCase):
    """The bound that sizes a jump table is the one testing whatever the dispatch indexes
    with. Taking the first `cmp <reg>, <imm>` instead finds an unrelated compare that happens
    to sit closer to the dispatch, and misses a bound checked against the memory cell the
    index is loaded from."""

    def test_bound_is_followed_through_a_load_into_the_index_register(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "byte ptr [rdi + rcx], 0x19"),
            (0x1003, 6, "ja", "0x1100"),
            (0x1009, 3, "movzx", "eax, byte ptr [rdi + rcx]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0x1A)

    def test_a_compare_on_an_unrelated_register_is_not_taken_as_the_bound(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "byte ptr [rdi + rcx], 0x19"),
            (0x1003, 3, "movzx", "eax, byte ptr [rdi + rcx]"),
            (0x1006, 3, "cmp", "edx, 0x3"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0x1A)

    def test_a_sub_register_write_still_counts_as_the_index(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "byte ptr [rsi], 0x7"),
            (0x1003, 3, "mov", "al, byte ptr [rsi]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 8)

    def test_scaled_source_switches_tracking_to_the_scaled_register(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "edx, 0x5"),
            (0x1003, 4, "movsxd", "rcx, dword ptr [r11 + rdx*4]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 6)

    def test_a_shift_of_the_index_drops_the_tie(self):
        """`shr eax, 8` redefines the index, so the compare further back bounds the value
        before the shift and not what the dispatch ends up indexing with. Reporting it tied
        would size the table at 1001 entries where the truth is 4."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 2, "ja", "0x1100"),
            (0x1007, 3, "shr", "eax, 8"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0x3E9)

    def test_any_non_copy_write_drops_the_tie(self):
        """Several x86 instructions write a register they do not name first - xchg and xadd
        write both operands, mul and div write rdx:rax, cpuid writes four - so a tie carried
        across any non-copy write can bound a value the dispatch never indexes with. The tie
        is dropped whole and the untied scan answers: here the nearer compare, not the tied
        one further back."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 3, "add", "edx, 8"),
            (0x1008, 5, "cmp", "esi, 0x3"),
            (0x100D, 2, "mov", "ecx, eax"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 4)

    def test_a_call_between_the_index_and_its_bound_drops_the_tie(self):
        """A call returns its value in rax and clobbers whatever the ABI allows, but its
        operand is a bare address, so the destination parse reads no key from it and the tie
        used to survive it - reporting a compare from before the call as this dispatch's
        bound. A recovered bound is trusted as exact, so an overlarge one runs the entry scan
        past the end of its own table."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 5, "call", "0x2000"),
            (0x100A, 5, "cmp", "esi, 0x3"),
            (0x100F, 2, "mov", "ecx, eax"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 4)

    def test_a_sign_extension_between_the_index_and_its_bound_keeps_the_tie(self):
        """Control for the case above: an operand-less instruction is not a reason to drop the
        tie by itself. `cdqe` widens the index in place and sits between the table read and
        its bound in ordinary compiler output, so severing there would lose the bound outright
        rather than fall back to the nearer compare."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 2, "cdqe", ""),
            (0x1007, 2, "mov", "ecx, eax"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 1001)

    def test_a_copy_between_the_index_and_its_bound_keeps_the_tie(self):
        """Positive control: a copy is the one thing that carries the index forward, so the
        same shape with a mov in place of the add still reaches the tied compare - without
        this, the case above would pass even if the tie never worked at all."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 3, "mov", "edx, 8"),
            (0x1008, 5, "cmp", "esi, 0x3"),
            (0x100D, 2, "mov", "ecx, eax"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 0x3E9)

    def test_a_write_to_a_tracked_cells_base_register_drops_the_tie(self):
        """`add rax, 8` leaves the text "[rax]" naming a different cell, so the compare
        against the old one is no longer a bound on what is loaded."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 6, "cmp", "dword ptr [rax], 0x3ff"),
            (0x1006, 4, "add", "rax, 8"),
            (0x100A, 2, "mov", "ecx, dword ptr [rax]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 0)

    def test_the_same_cell_with_no_intervening_write_is_still_tied(self):
        """Positive control for the rule above: without the `add` the cell is the same one
        the compare bounds, so the tie must still be made."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 6, "cmp", "dword ptr [rax], 0x3ff"),
            (0x1006, 2, "mov", "ecx, dword ptr [rax]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 0x400)

    def test_a_compare_of_a_different_width_on_the_same_cell_is_not_the_bound(self):
        """A dword compare does not bound a byte read of the same address - a byte index can
        only reach 256 whatever the dword holds."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 7, "cmp", "dword ptr [rbp - 8], 0x3e8"),
            (0x1007, 2, "ja", "0x1100"),
            (0x1009, 4, "movzx", "eax, byte ptr [rbp - 8]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0)

    def test_untied_compare_is_still_used_when_the_index_is_unknown(self):
        """Without an index to tie to, the first register compare is the only evidence there
        is; dropping that fallback would abandon tables that the old scan sized correctly."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 0x9"),
            (0x1003, 2, "mov", "ecx, 0x1"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, set()), 0xA)

    def test_untied_compare_is_used_when_no_tied_one_exists(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "edx, 0x9"),
            (0x1003, 2, "mov", "ecx, 0x1"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0xA)

    def test_a_return_still_bounds_the_backtrack(self):
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "eax, 0x9"),
            (0x1003, 1, "bnd ret", ""),
            (0x1004, 2, "mov", "ecx, 0x1"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0)

    def test_a_bare_decimal_immediate_is_read_as_decimal(self):
        """capstone prints an immediate below 10 without the 0x prefix, so parsing it as
        base 16 would silently agree only for 0-9 and the parse has to say which it is."""
        analyzer = _makeAnalyzer()
        backtracked = [(0x1000, 3, "cmp", "eax, 9")]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 10)

    def test_a_non_immediate_compare_is_ignored(self):
        analyzer = _makeAnalyzer()
        backtracked = [(0x1000, 3, "cmp", "eax, ecx")]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0)


class OperandKeyTestSuite(unittest.TestCase):
    def test_a_flat_segment_is_normalized_away_and_the_width_is_kept(self):
        """The override names the same cell; the width does not. A dword compare and a byte
        load of the same address read different values, so they must not share a key."""
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._operandKey("byte ptr ds:[rdi + rcx]"), "byte ptr [rdi + rcx]")
        self.assertNotEqual(analyzer._operandKey("dword ptr [rbp - 8]"), analyzer._operandKey("byte ptr [rbp - 8]"))

    def test_registers_normalize_to_their_family(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._operandKey(" EAX "), "rax")

    def test_an_immediate_has_no_key(self):
        analyzer = _makeAnalyzer()

        self.assertIsNone(analyzer._operandKey("0x19"))


class UnboundedTableOverreadTestSuite(unittest.TestCase):
    """A table whose bound cannot be recovered is scanned to a 0xFF fallback, which walks
    straight out of the table and into whatever follows it. With the bound recovered the scan
    stops at the real end, so the functions stored behind the table stay their own."""

    def _image(self, bound_is_tied):
        image = bytearray(IMAGE_SIZE)
        cases = 4
        body = bytearray()
        body += b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
        if bound_is_tied:
            body += b"\x80\x3f" + bytes([cases - 1])  # cmp byte ptr [rdi], 3
        else:
            body += b"\x83\xfa" + bytes([cases - 1])  # cmp edx, 3 -- not the dispatch index
        ja_at = len(body)
        body += b"\x0f\x87" + struct.pack("<i", 0)
        body += b"\x0f\xb6\x07"  # movzx eax, byte ptr [rdi]
        body += b"\x3e\xff\x24\xc5" + struct.pack("<I", BASE + TABLE_RVA)
        case_offsets = []
        for index in range(cases):
            case_offsets.append(len(body))
            body += b"\xb8" + struct.pack("<I", index) + b"\x5d\xc3"
        default_offset = len(body)
        body += b"\x31\xc0\x5d\xc3"
        struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))
        neighbour_offset = len(body)
        body += b"\x55\x48\x89\xe5\x5d\xc3"  # a separate function stored behind the switch
        image[TEXT_RVA : TEXT_RVA + len(body)] = body

        table = b"".join(struct.pack("<Q", BASE + TEXT_RVA + offset) for offset in case_offsets)
        image[TABLE_RVA : TABLE_RVA + len(table)] = table
        # what follows the table in .rodata: more in-image addresses, as a second table
        # would be. An unbounded scan reads these as further jump targets.
        trailing = b"".join(struct.pack("<Q", BASE + TEXT_RVA + neighbour_offset) for _ in range(8))
        image[TABLE_RVA + len(table) : TABLE_RVA + len(table) + len(trailing)] = trailing
        return bytes(image), BASE + TEXT_RVA + neighbour_offset

    def _functions(self, bound_is_tied):
        image, neighbour = self._image(bound_is_tied)
        config = SmdaConfig()
        config.CALCULATE_HASHING = False
        config.TIMEOUT = 0
        report = Disassembler(config=config).disassembleBuffer(image, BASE, bitness=64)
        self.assertEqual(report.status, "ok")
        return {function.offset for function in report.getFunctions()}, neighbour

    def test_a_tied_bound_stops_the_scan_at_the_end_of_the_table(self):
        functions, neighbour = self._functions(bound_is_tied=True)

        self.assertIn(neighbour, functions)

    def test_the_neighbour_is_a_function_either_way_when_the_bound_is_untied(self):
        """Positive control: the untied shape must still analyse, so a difference between the
        two cannot come from one of them failing outright."""
        functions, _neighbour = self._functions(bound_is_tied=False)

        self.assertIn(BASE + TEXT_RVA, functions)


if __name__ == "__main__":
    unittest.main()
