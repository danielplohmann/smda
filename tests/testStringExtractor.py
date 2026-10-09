import datetime
import types
import unittest

from capstone import CS_AC_WRITE

from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyStatistics import DisassemblyStatistics
from smda.synthesis.BinarySynthesizer import BinarySynthesizer
from smda.utility.StringExtractor import derefs, extract_strings, read_go_string, read_sized_string


def _make_minimal_report(buffer, bitness=64, base_addr=0x1000, binary_size=0x100):
    """Build the smallest SmdaReport that read_go_string()/read_bytes() need.

    binary_size is deliberately allowed to claim more memory than buffer actually
    holds, so isAddrWithinMemoryImage() (which only checks base_addr/binary_size) can
    say "yes" for an offset whose word-sized read would run past the real buffer end.
    """
    report = SmdaReport(None)
    report.architecture = "intel"
    report.base_addr = base_addr
    report.binary_size = binary_size
    report.bitness = bitness
    report.confidence_threshold = 0.0
    report.disassembly_errors = {}
    report.execution_time = 0.0
    report.identified_alignment = 0
    report.message = "ok"
    report.sha256 = "ab" * 32
    report.smda_version = "1.0"
    report.status = "ok"
    report.timestamp = datetime.datetime(2024, 1, 1)
    report.statistics = DisassemblyStatistics(None)
    report.xcfg = {}
    report.xmetadata = None
    report.data_refs_from = {}
    report.data_refs_to = {}
    report.buffer = buffer
    return report


class TestStringExtractorReadGoString(unittest.TestCase):
    def test_short_first_word_read_returns_none_64bit(self):
        # buffer is far shorter than the 8-byte string-pointer word that would be
        # read at offset, but binary_size still lets isAddrWithinMemoryImage pass
        report = _make_minimal_report(buffer=bytes(4), bitness=64)
        self.assertIsNone(read_go_string(report, report.base_addr))

    def test_short_second_word_read_returns_none_64bit(self):
        # the first 8-byte word (string pointer) reads fully, but the second 8-byte
        # word (length) runs past the end of the buffer
        report = _make_minimal_report(buffer=bytes(12), bitness=64)
        self.assertIsNone(read_go_string(report, report.base_addr))

    def test_short_first_word_read_returns_none_32bit(self):
        report = _make_minimal_report(buffer=bytes(2), bitness=32)
        self.assertIsNone(read_go_string(report, report.base_addr))

    def test_short_second_word_read_returns_none_32bit(self):
        report = _make_minimal_report(buffer=bytes(6), bitness=32)
        self.assertIsNone(read_go_string(report, report.base_addr))


class _StubInstruction:
    def __init__(self, offset, mnemonic, operands, data_refs=()):
        self.offset = offset
        self.mnemonic = mnemonic
        self.operands = operands
        self._data_refs = list(data_refs)

    def getDataRefs(self):
        return list(self._data_refs)

    def getDetailed(self):
        destination = self.operands.split(",")[0].strip()
        access = 0 if self.mnemonic in ("cmp", "test", "push", "nop") else CS_AC_WRITE
        written = [destination] if access and "[" not in destination else []
        return types.SimpleNamespace(
            groups=[],
            regs_access=lambda: ([], written),
            reg_name=lambda register: register,
            operands=[types.SimpleNamespace(access=access, size=8 if destination.startswith("qword ptr") else 4)],
        )


class _StubFunction:
    def __init__(self, smda_report, instructions):
        self.smda_report = smda_report
        self._instructions = instructions

    def getInstructions(self):
        return list(self._instructions)

    def getBlocks(self):
        return [self]


class TestStringExtractorDerefs(unittest.TestCase):
    def test_derefs_reads_a_full_width_pointer_on_64bit(self):
        base = 0x100000000
        buffer = bytearray(0x40)
        buffer[0x10:0x18] = (base + 0x20).to_bytes(8, "little")
        report = _make_minimal_report(bytes(buffer), bitness=64, base_addr=base, binary_size=0x40)

        self.assertEqual(list(derefs(report, base + 0x10)), [base + 0x10, base + 0x20])

    def test_derefs_reads_a_full_width_pointer_on_32bit(self):
        base = 0x400000
        buffer = bytearray(0x40)
        buffer[0x10:0x14] = (base + 0x20).to_bytes(4, "little")
        report = _make_minimal_report(bytes(buffer), bitness=32, base_addr=base, binary_size=0x40)

        self.assertEqual(list(derefs(report, base + 0x10)), [base + 0x10, base + 0x20])


class TestStringExtractorGoStackStrings(unittest.TestCase):
    def test_hex_length_operand_is_accepted(self):
        base = 0x400000
        buffer = bytearray(0x40)
        buffer[0x20:0x2A] = b"HELLOWORLD"
        report = _make_minimal_report(bytes(buffer), bitness=32, base_addr=base, binary_size=0x40)
        function = _StubFunction(
            report,
            [
                _StubInstruction(0x10, "lea", "eax, [0x400020]", data_refs=[base + 0x20]),
                _StubInstruction(0x16, "mov", "dword ptr [esp], eax"),
                _StubInstruction(0x19, "mov", "dword ptr [esp + 4], 0xa"),
            ],
        )

        self.assertEqual(
            list(extract_strings(function, mode="go")),
            [("HELLOWORLD", 0x10, base + 0x20, "ascii")],
        )


_RUSTC_PATH = b"/rustc/" + b"0123456789abcdef0123456789abcdef01234567" + b"/library"


def _report_with(blobs, bitness=64, base=0x400000, size=0x100):
    """A report whose buffer holds each (rva, bytes) pair; strings are packed back to back like Go/Rust rodata."""
    buffer = bytearray(size)
    for rva, blob in blobs:
        buffer[rva : rva + len(blob)] = blob
    return _make_minimal_report(bytes(buffer), bitness=bitness, base_addr=base, binary_size=size)


class TestStringExtractorSizedStrings(unittest.TestCase):
    def test_reads_exactly_length_bytes_of_packed_literals(self):
        report = _report_with([(0x20, b"truefalsenil")])
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 4), ("true", "ascii"))
        self.assertEqual(read_sized_string(report, report.base_addr + 0x24, 5), ("false", "ascii"))

    def test_non_ascii_utf8_is_typed_utf8(self):
        report = _report_with([(0x20, "größe".encode())])
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 7), ("größe", "utf8"))

    def test_length_counting_a_nul_terminator(self):
        # Go passes C strings for syscall.Proc lookups as byte slices that include the NUL
        report = _report_with([(0x20, b"ProcessPrng\x00bad g0 stack")])
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 12), ("ProcessPrng", "ascii"))
        self.assertIsNone(read_sized_string(report, report.base_addr + 0x60, 4))

    def test_rejects_invalid_utf8_control_bytes_and_bad_lengths(self):
        report = _report_with([(0x20, b"ab\xffcd"), (0x30, b"ab\x01cd"), (0x40, b"abcd")])
        self.assertIsNone(read_sized_string(report, report.base_addr + 0x20, 5))
        self.assertIsNone(read_sized_string(report, report.base_addr + 0x30, 5))
        self.assertIsNone(read_sized_string(report, report.base_addr + 0x40, 0))
        self.assertIsNone(read_sized_string(report, report.base_addr + 0x40, 0x100000))
        self.assertIsNone(read_sized_string(report, report.base_addr + 0xF0, 0x20))

    def test_escapes_nbsp_and_bom_are_kept_other_controls_are_not(self):
        for text, accepted in (("\x1b[31mred", True), ("a\u00a0b", True), ("\ufeffbom", True), ("a\x01b", False)):
            with self.subTest(text=text):
                encoded = text.encode()
                report = _report_with([(0x20, encoded)])
                result = read_sized_string(report, report.base_addr + 0x20, len(encoded))
                self.assertEqual(result is not None, accepted)

    def test_sized_reads_are_cached(self):
        report = _report_with([(0x20, b"cached")])
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 6), ("cached", "ascii"))
        self.assertIn(("sized", report.base_addr + 0x20, 6), report._string_cache)
        report.buffer = bytes(len(report.buffer))
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 6), ("cached", "ascii"))

    def test_literal_reading_as_an_address_in_a_high_32bit_image(self):
        # "abcj" is 0x6a636261, inside an image based at 0x6a000000
        report = _report_with([(0x20, b"abcjk")], bitness=32, base=0x6A000000)
        report.binary_size = 0x1000000
        self.assertEqual(read_sized_string(report, report.base_addr + 0x20, 5), ("abcjk", "ascii"))

    def test_rejects_targets_in_unmapped_sections(self):
        # a zero-based ELF lists .comment/.debug_* at address 0; the header there is not a literal
        report = _report_with([(0x01, b"ELF"), (0x40, b"text")], base=0)
        report.code_sections = [(".comment", 0, 0x20), (".rodata", 0x40, 0x80)]
        self.assertIsNone(read_sized_string(report, 0x01, 3))
        self.assertEqual(read_sized_string(report, 0x40, 4), ("text", "ascii"))

    def test_literal_at_buffer_end_does_not_require_a_full_pointer_word(self):
        report = _report_with([(0x40, b"last")], size=0x44)
        self.assertEqual(read_sized_string(report, report.base_addr + 0x40, 4), ("last", "ascii"))

    def test_header_outside_the_image_is_rejected(self):
        pointer = (0x400040).to_bytes(8, "little")
        report = _report_with([(0x40, b"hello"), (0xE0, pointer + (5).to_bytes(8, "little"))])
        for address in (report.base_addr - 0x20, report.base_addr + report.binary_size):
            with self.subTest(address=address):
                self.assertIsNone(read_go_string(report, address))

    def test_string_header_in_data_is_dereferenced(self):
        base = 0x400000
        report = _report_with(
            [(0x10, (base + 0x40).to_bytes(8, "little") + (5).to_bytes(8, "little")), (0x40, b"helloworld")], base=base
        )
        self.assertEqual(read_go_string(report, base + 0x10), ("hello", "ascii"))

    def test_string_header_on_32bit(self):
        base = 0x400000
        report = _report_with(
            [(0x10, (base + 0x40).to_bytes(4, "little") + (5).to_bytes(4, "little")), (0x40, b"helloworld")],
            bitness=32,
            base=base,
        )
        self.assertEqual(read_go_string(report, base + 0x10), ("hello", "ascii"))

    def test_header_pointing_at_another_pointer_is_rejected(self):
        # a []string slice header points at an array of string headers; its first bytes are an
        # address whose low bytes can be printable ("nTK" for 0x4b546e)
        base = 0x400000
        report = _report_with(
            [
                (0x10, (base + 0x40).to_bytes(8, "little") + (3).to_bytes(8, "little")),
                (0x40, (base + 0x546E).to_bytes(8, "little")),
            ],
            base=base,
            size=0x6000,
        )
        self.assertIsNone(read_go_string(report, base + 0x10))


class TestStringExtractorLengthFromCode(unittest.TestCase):
    base = 0x400000

    def _extract(self, instructions, mode="go", bitness=64, blobs=None, architecture="intel"):
        report = _report_with(blobs or [(0x40, b"smdaGoMarkerhello there ")], bitness=bitness, base=self.base)
        report.architecture = architecture
        return list(extract_strings(_StubFunction(report, instructions), mode=mode))

    def test_go_register_abi_length_in_next_register(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rax, [rip + 0x2303a]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "ebx, 0xc"),
                _StubInstruction(0x1C, "call", "0x491ae0"),
            ]
        )
        self.assertEqual(result, [("smdaGoMarker", 0x10, self.base + 0x40, "ascii")])

    def test_length_loaded_before_the_pointer(self):
        result = self._extract(
            [
                _StubInstruction(0x0, "mov", "ecx, 0xc"),
                _StubInstruction(0x5, "mov", "rdi, rax"),
                _StubInstruction(0x8, "xor", "eax, eax"),
                _StubInstruction(0xA, "lea", "rbx, [rip + 0x23080]", data_refs=[self.base + 0x4C]),
                _StubInstruction(0x11, "call", "0x451a00"),
            ]
        )
        self.assertEqual(result, [("hello there ", 0xA, self.base + 0x4C, "ascii")])

    def test_rust_sysv_pointer_and_length_pair(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rsi, [rip - 0xba11]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "lea", "rdi, [rsp + 8]"),
                _StubInstruction(0x1C, "mov", "edx, 4"),
                _StubInstruction(0x21, "call", "qword ptr [rip + 0x41027]"),
            ],
            mode="rust",
        )
        self.assertEqual(result, [("smda", 0x10, self.base + 0x40, "ascii")])

    def test_go_stack_abi_through_a_stored_register(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rax, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "qword ptr [rsp], rax"),
                _StubInstruction(0x1B, "mov", "qword ptr [rsp + 8], 4"),
            ]
        )
        self.assertEqual(result, [("smda", 0x10, self.base + 0x40, "ascii")])

    def test_32bit_pushed_length_and_pointer(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "push", "4"),
                _StubInstruction(0x12, "push", "0x400040", data_refs=[self.base + 0x40]),
            ],
            mode="rust",
            bitness=32,
        )
        self.assertEqual(result, [("smda", 0x12, self.base + 0x40, "ascii")])

    def test_aarch64_length_in_next_register(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "adrp", "x0, #0x400000"),
                _StubInstruction(0x14, "add", "x0, x0, #0x40", data_refs=[self.base + 0x40]),
                _StubInstruction(0x18, "mov", "w1, #4"),
                _StubInstruction(0x1C, "bl", "#0x1000"),
            ],
            architecture="aarch64",
        )
        self.assertEqual(result, [("smda", 0x14, self.base + 0x40, "ascii")])

    def test_unpaired_register_is_not_taken_as_length(self):
        # rdi pairs with rsi, so the immediate in edx is some other argument
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "edx, 4"),
            ]
        )
        self.assertEqual(result, [])

    def test_scan_stops_at_a_call(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rax, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "call", "0x1000"),
                _StubInstruction(0x1C, "mov", "ebx, 4"),
            ]
        )
        self.assertEqual(result, [])

    def test_length_register_overwritten_by_non_immediate_stops_scan(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rax, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "rbx, rcx"),
                _StubInstruction(0x1A, "mov", "ebx, 4"),
            ]
        )
        self.assertEqual(result, [])

    def test_mode_follows_report_language(self):
        report = _report_with([(0x3F, b"xsmdaRustMarkerNext"), (0x80, _RUSTC_PATH)], base=self.base)
        report.language = {"rust": 0.6, "go": 0.0}
        function = _StubFunction(
            report,
            [
                _StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "esi, 0xe"),
            ],
        )
        self.assertEqual(list(extract_strings(function)), [("smdaRustMarker", 0x10, self.base + 0x40, "ascii")])

    def test_rust_score_without_a_rustc_path_keeps_the_generic_path(self):
        # LanguageAnalyzer scores Rust on a bare "/rustc/" substring, which any sample can carry
        report = _report_with([(0x40, b"/dev/watchdog\x00"), (0x80, b"/rustc/")], base=self.base)
        report.language = {"rust": 0.6, "go": 0.0}
        function = _StubFunction(
            report,
            [
                _StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "esi, 2"),
            ],
        )
        self.assertEqual(list(extract_strings(function)), [("/dev/watchdog", 0x10, self.base + 0x40, "ascii")])

    def test_rust_unpaired_reference_reads_a_c_string(self):
        report = _report_with([(0x40, b"Mingw-w64 runtime failure:\n\x00")], base=self.base)
        function = _StubFunction(
            report, [_StubInstruction(0x10, "lea", "rcx, [rip + 0x30]", data_refs=[self.base + 0x40])]
        )
        self.assertEqual(
            list(extract_strings(function, mode="rust")),
            [("Mingw-w64 runtime failure:\n", 0x10, self.base + 0x40, "ascii")],
        )

    def test_unpaired_reference_inside_a_packed_run_reads_nothing(self):
        report = _report_with([(0x3F, b"xkindtruemain\x00")], base=self.base)
        function = _StubFunction(
            report, [_StubInstruction(0x10, "lea", "rcx, [rip + 0x30]", data_refs=[self.base + 0x40])]
        )
        for mode in ("go", "rust"):
            with self.subTest(mode=mode):
                self.assertEqual(list(extract_strings(function, mode=mode)), [])

    def test_go_unpaired_reference_keeps_no_nul_terminated_path(self):
        report = _report_with([(0x40, b"plainCString\x00")], base=self.base)
        function = _StubFunction(
            report, [_StubInstruction(0x10, "lea", "rcx, [rip + 0x30]", data_refs=[self.base + 0x40])]
        )
        self.assertEqual(list(extract_strings(function, mode="go")), [])

    def test_rust_str_returned_in_rax_rdx(self):
        result = self._extract(
            [
                _StubInstruction(0x10, "lea", "rax, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "edx, 4"),
                _StubInstruction(0x1C, "ret", ""),
            ],
            mode="rust",
            blobs=[(0x3F, b"xsmdaGoMarker")],
        )
        self.assertEqual(result, [("smda", 0x10, self.base + 0x40, "ascii")])

    def test_header_reference_records_the_string_address(self):
        base = self.base
        report = _report_with(
            [(0x10, (base + 0x41).to_bytes(8, "little") + (5).to_bytes(8, "little")), (0x40, b"xhelloworld")],
            base=base,
        )
        function = _StubFunction(report, [_StubInstruction(0x30, "lea", "rax, [rip]", data_refs=[base + 0x10])])
        self.assertEqual(list(extract_strings(function, mode="go")), [("hello", 0x30, base + 0x41, "ascii")])

    def test_failing_pairing_costs_only_that_reference(self):
        class _Undecodable(_StubInstruction):
            def getDetailed(self):
                raise ValueError("capstone could not re-decode the instruction")

        report = _report_with(
            [(0x10, (self.base + 0x41).to_bytes(8, "little") + (5).to_bytes(8, "little")), (0x40, b"xhelloworld")],
            base=self.base,
        )
        function = _StubFunction(
            report,
            [
                _StubInstruction(0x30, "lea", "rax, [rip]", data_refs=[self.base + 0x10]),
                _Undecodable(0x37, "mov", "ebx, 4"),
            ],
        )
        self.assertEqual(list(extract_strings(function, mode="go")), [("hello", 0x30, self.base + 0x41, "ascii")])

    def test_unknown_language_keeps_nul_terminated_reads(self):
        report = _report_with([(0x40, b"plainCString\x00")], base=self.base)
        function = _StubFunction(
            report, [_StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40])]
        )
        self.assertEqual(list(extract_strings(function)), [("plainCString", 0x10, self.base + 0x40, "ascii")])


class TestStringExtractorDecodedPairs(unittest.TestCase):
    base = 0x400000

    def _extract(self, code, mode="go", header=None, abi=None, split_at=None, architecture="intel", bitness=64):
        # the byte before the literal makes it sit inside a packed run, as Go and Rust lay them out, so
        # the C-string fallback for unpaired references leaves it alone
        report = _report_with([(0x3F, b"xhelloworldotherstring")], base=self.base, bitness=bitness)
        report.architecture = architecture
        report.xheader = header
        report.abi = abi
        function = _StubFunction(report, [])
        function._instructions = [
            SmdaInstruction([insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str], smda_function=function)
            for insn in report.getCapstone().disasm(bytes.fromhex(code), self.base)
        ]
        if split_at is not None:
            instructions = function._instructions
            function.getBlocks = lambda: [
                _StubFunction(report, instructions[:split_at]),
                _StubFunction(report, instructions[split_at:]),
            ]
        return list(extract_strings(function, mode=mode))

    def test_unpaired_32bit_push_is_not_a_string(self):
        self.assertEqual(self._extract("6840004000c3", mode="rust", bitness=32), [])

    def test_indexed_memory_destination_is_not_a_pointer_load(self):
        self.assertEqual(self._extract("48891cc540004000c3"), [])

    def test_stack_pair_with_a_negative_displacement(self):
        self.assertEqual(
            self._extract("488d053900000048894424f848c7042405000000c3"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_backward_pairing_does_not_cross_into_a_previous_block(self):
        # the pointer's block may be a join point, where another predecessor set a different length
        self.assertEqual(self._extract("bb05000000488d0534000000c3", split_at=1), [])

    def test_forward_pairing_follows_a_fallthrough_block(self):
        # a block also ends where a later jump lands; the pointer keeps its value on the path into it
        self.assertEqual(
            self._extract("488d0539000000bb05000000c3", split_at=1),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_forward_pairing_stops_at_a_block_ending_in_a_jump(self):
        self.assertEqual(self._extract("488d0539000000eb00bb05000000c3", split_at=2), [])

    def test_loop_and_interrupt_stop_pairing(self):
        for boundary in ("e205", "cd80"):
            with self.subTest(boundary=boundary):
                self.assertEqual(self._extract("488d0539000000" + boundary + "bb05000000c3"), [])

    def test_pointer_clobbers_block_pairing(self):
        for clobber in ("31c0", "b001", "4893", "f7e1"):
            with self.subTest(clobber=clobber):
                self.assertEqual(self._extract("488d0539000000" + clobber + "bb0a000000c3"), [])

    def test_length_clobbers_do_not_reuse_backward_values(self):
        for clobber in ("31db", "b301", "6683c301", "480fc1c3"):
            with self.subTest(clobber=clobber):
                self.assertEqual(self._extract("bb05000000488d0534000000" + clobber + "c3"), [])

    def test_implicit_length_clobber_blocks_forward_pairing(self):
        self.assertEqual(self._extract("b905000000488d1d34000000f3a4c3"), [])

    def test_implicit_length_clobber_blocks_backward_pairing(self):
        self.assertEqual(self._extract("b905000000f3a4488d1d32000000c3"), [])

    def test_backward_scan_stops_at_a_length_write(self):
        self.assertEqual(self._extract("bb0500000031db488d0532000000c3"), [])

    def test_partial_length_load_is_not_a_full_length(self):
        for length_load in ("b305", "66bb0500"):
            with self.subTest(length_load=length_load):
                self.assertEqual(self._extract("488d0539000000" + length_load + "c3"), [])

    def test_comparison_does_not_clobber_a_length(self):
        self.assertEqual(
            self._extract("bb05000000488d053400000083fb00c3"),
            [("hello", self.base + 5, self.base + 0x40, "ascii")],
        )

    def test_stored_pointer_survives_register_reuse(self):
        self.assertEqual(
            self._extract("488d05390000004889042431c048c744240805000000c3"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_full_width_register_copy_survives_register_reuse(self):
        self.assertEqual(
            self._extract("488d05390000004889c731c0be05000000c3"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_pointer_copy_into_the_old_length_register(self):
        self.assertEqual(
            self._extract("488d05390000004889c3b905000000c3"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )
        self.assertEqual(self._extract("bb05000000488d05340000004889c3c3"), [])

    def test_copied_pointer_does_not_reuse_the_dead_registers_length(self):
        self.assertEqual(self._extract("bb05000000488d05340000004889c731c0c3"), [])

    def test_copied_pointer_uses_a_previously_loaded_length(self):
        for mode in ("go", "rust"):
            for code in ("be05000000488d05340000004889c7c3", "488d0539000000be050000004889c7c3"):
                with self.subTest(mode=mode, code=code):
                    self.assertEqual(
                        self._extract(code, mode=mode, header=b"\x7fELF"),
                        [("hello", self.base + (5 if code.startswith("be") else 0), self.base + 0x40, "ascii")],
                    )

    def test_stored_pointer_uses_a_previously_loaded_length(self):
        self.assertEqual(
            self._extract("48c744240805000000488d053000000048890424c3"),
            [("hello", self.base + 9, self.base + 0x40, "ascii")],
        )

    def test_copied_pointer_does_not_reuse_a_clobbered_length(self):
        self.assertEqual(self._extract("be05000000488d053400000031f64889c7c3", mode="rust", header=b"\x7fELF"), [])

    def test_stored_pointer_does_not_reuse_length_after_stack_base_changes(self):
        self.assertEqual(self._extract("48c744240805000000488d05300000004883c40848890424c3"), [])

    def test_copied_pointer_is_not_also_used_as_its_length(self):
        self.base = 0
        for mode, code in (("go", "bb400000004889d8c3"), ("rust", "be400000004889f7c3")):
            with self.subTest(mode=mode):
                self.assertEqual(self._extract(code, mode=mode, header=b"\x7fELF"), [])

    def test_truncated_pointer_copies_are_not_followed(self):
        for copy in ("4088c7", "6689c7", "89c7"):
            with self.subTest(copy=copy):
                self.assertEqual(self._extract("488d0539000000" + copy + "31c0be05000000c3"), [])

    def test_decoded_aarch64_pair_and_pointer_clobber(self):
        for mode in ("go", "rust"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    self._extract("00020010a1008052c0035fd6", mode=mode, architecture="aarch64"),
                    [("hello", self.base, self.base + 0x40, "ascii")],
                )
                self.assertEqual(
                    self._extract("00020010e0031f2aa1008052c0035fd6", mode=mode, architecture="aarch64"), []
                )

    def test_stack_base_write_invalidates_the_stored_pair(self):
        self.assertEqual(self._extract("488d05390000004889042431c04883c40848c744240805000000c3"), [])

    def test_overlapping_stack_write_invalidates_the_stored_pointer(self):
        self.assertEqual(self._extract("488d053900000048890424c64424010031c048c744240805000000c3"), [])

    def test_narrow_stack_length_write_is_not_a_full_length(self):
        self.assertEqual(self._extract("488d053900000048890424c744240805000000c3"), [])

    def test_go_ignores_scratch_register_as_length(self):
        self.assertEqual(
            self._extract("488d0d39000000ba0a000000bf05000000c3"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_rust_sysv_ignores_go_length_register(self):
        self.assertEqual(
            self._extract("488d353900000041b80a000000ba05000000c3", mode="rust", header=b"\x7fELF"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )

    def test_rust_platform_selects_the_rdx_pair(self):
        code = "488d1539000000b90a00000041b805000000c3"
        for header, length in ((b"MZ", "hello"), (b"\x7fELF", "helloworld"), (b"\xcf\xfa\xed\xfe", "helloworld")):
            with self.subTest(header=header):
                self.assertEqual(
                    self._extract(code, mode="rust", header=header),
                    [(length, self.base, self.base + 0x40, "ascii")],
                )

    def test_rust_unknown_platform_rejects_ambiguous_register_pairs(self):
        self.assertEqual(self._extract("488d1539000000b90a00000041b805000000c3", mode="rust"), [])

    def test_rust_elf_abi_selects_sysv_without_a_header(self):
        self.assertEqual(
            self._extract("488d1539000000b905000000c3", mode="rust", abi="SYSTEMV"),
            [("hello", self.base, self.base + 0x40, "ascii")],
        )


class TestSynthesizedUtf8Strings(unittest.TestCase):
    def test_utf8_string_keeps_its_bytes(self):
        function = types.SimpleNamespace(
            stringrefs=[
                {"string": "größe", "ins_addr": 0x10, "data_addr": 0x40, "type": "utf8"},
                {"string": "plain", "ins_addr": 0x20, "data_addr": 0x50, "type": "ascii"},
            ]
        )
        report = types.SimpleNamespace(getFunctions=lambda: [function])
        self.assertEqual(
            list(BinarySynthesizer(report)._iterStringRefs()),
            [(0x40, "größe".encode() + b"\x00"), (0x50, b"plain\x00")],
        )


if __name__ == "__main__":
    unittest.main()
