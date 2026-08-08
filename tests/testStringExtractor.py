import datetime
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyStatistics import DisassemblyStatistics
from smda.utility.StringExtractor import derefs, extract_strings, read_go_string


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


if __name__ == "__main__":
    unittest.main()
