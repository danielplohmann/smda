import datetime
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyStatistics import DisassemblyStatistics
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


class _StubFunction:
    def __init__(self, smda_report, instructions):
        self.smda_report = smda_report
        self._instructions = instructions

    def getInstructions(self):
        return list(self._instructions)


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

    def test_rejects_targets_in_unmapped_sections(self):
        # a zero-based ELF lists .comment/.debug_* at address 0; the header there is not a literal
        report = _report_with([(0x01, b"ELF"), (0x40, b"text")], base=0)
        report.code_sections = [(".comment", 0, 0x20), (".rodata", 0x40, 0x80)]
        self.assertIsNone(read_sized_string(report, 0x01, 3))
        self.assertEqual(read_sized_string(report, 0x40, 4), ("text", "ascii"))

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

    def _extract(self, instructions, mode="go", bitness=64, blobs=None):
        report = _report_with(blobs or [(0x40, b"smdaGoMarkerhello there ")], bitness=bitness, base=self.base)
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
            ]
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
        report = _report_with([(0x40, b"smdaRustMarker")], base=self.base)
        report.language = {"rust": 0.6, "go": 0.0}
        function = _StubFunction(
            report,
            [
                _StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40]),
                _StubInstruction(0x17, "mov", "esi, 0xe"),
            ],
        )
        self.assertEqual(list(extract_strings(function)), [("smdaRustMarker", 0x10, self.base + 0x40, "ascii")])

    def test_unknown_language_keeps_nul_terminated_reads(self):
        report = _report_with([(0x40, b"plainCString\x00")], base=self.base)
        function = _StubFunction(
            report, [_StubInstruction(0x10, "lea", "rdi, [rip + 0x30]", data_refs=[self.base + 0x40])]
        )
        self.assertEqual(list(extract_strings(function)), [("plainCString", 0x10, self.base + 0x40, "ascii")])


if __name__ == "__main__":
    unittest.main()
