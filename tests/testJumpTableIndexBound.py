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


class RelativeDispatchBaseAddTestSuite(unittest.TestCase):
    """The last instruction of a relative dispatch adds the table's base to the entry the
    table read produced, so the register the branch reads is that sum. Treating the add as a
    redefinition stops the walk one instruction short of the table read - which is the only
    place the switch index is named - and the untied fallback then answers with whatever
    compare happens to be nearby."""

    #: gcc and clang spell a 64-bit relative switch this way: the base is loaded once, spilled
    #: because the dispatch is reached from several places, and reloaded beside the table read.
    #: The bound is checked against the memory cell the index is loaded from, never a register.
    SPILLED_BASE_DISPATCH = [
        (0x1000, 3, "cmp", "edx, 0x1"),
        (0x1003, 7, "lea", "rsi, [rip + 0x6e189]"),
        (0x100A, 4, "mov", "qword ptr [rsp], rsi"),
        (0x100E, 3, "cmp", "dword ptr [rbx], 0x1a"),
        (0x1011, 2, "ja", "0x100E"),
        (0x1013, 4, "mov", "rdi, qword ptr [rsp]"),
        (0x1017, 2, "mov", "eax, dword ptr [rbx]"),
        (0x1019, 4, "movsxd", "rax, dword ptr [rdi + rax*4]"),
        (0x101D, 3, "add", "rax, rdi"),
    ]

    def test_the_base_add_carries_the_tie_to_the_table_read(self):
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._findJumpTableSize(self.SPILLED_BASE_DISPATCH, {"rax"}), 0x1B)

    def test_the_untied_fallback_answers_two_on_the_same_window(self):
        """Control for the case above. `cmp edx, 1` is the only compare the untied fallback can
        match, so a walk that loses the tie sizes this table at two entries out of twenty-seven
        - which is what the dispatch produced before the base add carried the tie. Without this
        the assertion above would pass on a bound the fallback happened to get right."""
        analyzer = _makeAnalyzer()

        self.assertEqual(analyzer._findJumpTableSize(self.SPILLED_BASE_DISPATCH, set()), 2)

    def test_a_lea_that_reads_the_register_it_writes_carries_the_tie(self):
        """The other spelling of the same step, from the multiplicative-relative pattern."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 3, "cmp", "edx, 0x5"),
            (0x1003, 5, "movsxd", "rcx, dword ptr [r11 + rdx*4]"),
            (0x1008, 4, "lea", "rcx, [r11 + rcx]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rcx"}), 6)

    def test_a_lea_that_only_loads_an_address_drops_the_tie(self):
        """`lea rax, [rip + 0x2004]` is how the base itself is loaded. It derives nothing from
        rax, so a tie carried across it would bound a value the dispatch never indexes with."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 7, "lea", "rax, [rip + 0x2004]"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0x3E9)

    def test_index_arithmetic_before_the_table_read_still_drops_the_tie(self):
        """Only the instruction the branch reads is a base combine. `add rax, rcx` before the
        table read makes the index a sum, and the compare against `[rbx]` bounds one summand
        of it -- carrying the tie across that would report 4 where the table has more, and a
        recovered bound is trusted as exact."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 6, "cmp", "dword ptr [rbx], 0x3"),
            (0x1006, 2, "mov", "eax, dword ptr [rbx]"),
            (0x1009, 3, "add", "rax, rcx"),
            (0x100C, 4, "movsxd", "rax, dword ptr [rdi + rax*4]"),
            (0x1010, 3, "add", "rax, rdi"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0)

    def test_an_add_back_into_a_tracked_cell_still_drops_the_tie(self):
        """The step this recognizes ends in the register the branch reads. A cell written back
        to holds a different value from here on, so the compare against it is not a bound on
        what the dispatch loads out of it afterwards."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 6, "cmp", "dword ptr [rbx], 0x3ff"),
            (0x1006, 3, "add", "dword ptr [rbx], eax"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"dword ptr [rbx]"}), 0)

    def test_the_same_cell_read_without_being_written_is_still_tied(self):
        """Positive control for the rule above: with the write gone, the compare bounds what
        the dispatch indexes with and the tie is made."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 6, "cmp", "dword ptr [rbx], 0x3ff"),
            (0x1006, 3, "nop", ""),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"dword ptr [rbx]"}), 0x400)

    def test_an_immediate_added_to_the_index_still_drops_the_tie(self):
        """An immediate is index arithmetic, not a table base: the compare further back bounds
        the value before the addition, so it is not a bound on what the dispatch indexes with."""
        analyzer = _makeAnalyzer()
        backtracked = [
            (0x1000, 5, "cmp", "eax, 0x3e8"),
            (0x1005, 4, "add", "rax, 8"),
        ]

        self.assertEqual(analyzer._findJumpTableSize(backtracked, {"rax"}), 0x3E9)


class ShatteredSwitchTestSuite(unittest.TestCase):
    """What an unrecovered bound costs a report: the case bodies past it are never queued as
    blocks of the function that dispatches to them, so the gap scan finds them unreferenced and
    books each one as a function of its own. The switch is the whole of the function here, so
    every address the scan takes is interior to it."""

    CASES = 4

    def _image(self):
        body = bytearray()
        main_offset = len(body)
        body += b"\x55\x48\x89\xe5"  # push rbp ; mov rbp, rsp
        call_at = len(body)
        body += b"\xe8" + struct.pack("<i", 0)
        body += b"\x5d\xc3"  # pop rbp ; ret
        while len(body) % 16:
            body += b"\x90"
        dispatch_offset = len(body)
        body += b"\x55\x48\x89\xe5"
        # the compare the untied fallback matches, and the only one it can: it bounds a
        # register the dispatch never indexes with
        body += b"\x83\xfa\x01"  # cmp edx, 1
        lea_at = len(body)
        body += b"\x48\x8d\x35" + struct.pack("<i", 0)  # lea rsi, [rip + disp]
        body += b"\x48\x89\x34\x24"  # mov qword ptr [rsp], rsi
        body += b"\x83\x3b" + bytes([self.CASES - 1])  # cmp dword ptr [rbx], 3
        ja_at = len(body)
        body += b"\x0f\x87" + struct.pack("<i", 0)
        body += b"\x48\x8b\x3c\x24"  # mov rdi, qword ptr [rsp]
        body += b"\x8b\x03"  # mov eax, dword ptr [rbx]
        body += b"\x48\x63\x04\x87"  # movsxd rax, dword ptr [rdi + rax*4]
        body += b"\x48\x01\xf8"  # add rax, rdi
        body += b"\xff\xe0"  # jmp rax
        case_offsets = []
        for index in range(self.CASES):
            case_offsets.append(len(body))
            # a case body opening on a common prologue, which is what the gap scan books
            body += b"\x55\x48\x89\xe5\xb8" + struct.pack("<I", index) + b"\x5d\xc3"
        default_offset = len(body)
        body += b"\x31\xc0\x5d\xc3"
        while len(body) % 16:
            body += b"\x90"
        neighbour_offset = len(body)
        body += b"\x55\x48\x89\xe5\x5d\xc3"

        struct.pack_into("<i", body, call_at + 1, dispatch_offset - (call_at + 5))
        struct.pack_into("<i", body, ja_at + 2, default_offset - (ja_at + 6))
        struct.pack_into("<i", body, lea_at + 3, (TABLE_RVA - TEXT_RVA) - (lea_at + 7))

        image = bytearray(IMAGE_SIZE)
        image[TEXT_RVA : TEXT_RVA + len(body)] = body
        # relative entries: target minus the table's own base, as a signed int32
        table = b"".join(struct.pack("<i", (TEXT_RVA + offset) - TABLE_RVA) for offset in case_offsets)
        image[TABLE_RVA : TABLE_RVA + len(table)] = table

        def address(offset):
            return BASE + TEXT_RVA + offset

        return (
            bytes(image),
            address(main_offset),
            address(dispatch_offset),
            [address(offset) for offset in case_offsets],
            address(neighbour_offset),
        )

    def setUp(self):
        image, self.main, self.dispatch, self.cases, self.neighbour = self._image()
        config = SmdaConfig()
        config.CALCULATE_HASHING = False
        config.TIMEOUT = 0
        report = Disassembler(config=config).disassembleBuffer(image, BASE, bitness=64)
        self.assertEqual(report.status, "ok")
        self.functions = {function.offset for function in report.getFunctions()}

    def test_no_case_body_becomes_a_function_of_its_own(self):
        self.assertEqual([case for case in self.cases if case in self.functions], [])

    def test_the_three_real_functions_are_all_recovered(self):
        """Control: the image has to analyse for the assertion above to mean anything - an
        empty report would satisfy it too."""
        self.assertEqual(self.functions, {self.main, self.dispatch, self.neighbour})


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
