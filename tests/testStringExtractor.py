import datetime
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.DisassemblyStatistics import DisassemblyStatistics
from smda.utility.StringExtractor import read_go_string


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


if __name__ == "__main__":
    unittest.main()
