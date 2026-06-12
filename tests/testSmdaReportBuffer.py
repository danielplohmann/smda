import datetime
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.DisassemblyStatistics import DisassemblyStatistics


def _make_minimal_report(buffer=None):
    """Build the smallest SmdaReport that round-trips through toDict()/fromDict()."""
    report = SmdaReport(None)
    report.architecture = "intel"
    report.base_addr = 0x1000
    report.binary_size = 0x100
    report.bitness = 32
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


class TestSmdaReportBufferPacking(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        for payload in (b"", b"hello world", bytes(range(256)) * 8):
            packed = SmdaReport._packBuffer(payload)
            self.assertIsInstance(packed, str)
            self.assertEqual(SmdaReport._unpackBuffer(packed), payload)

    def test_packed_buffer_is_ascii_and_compresses(self):
        payload = b"\x00" * 4096
        packed = SmdaReport._packBuffer(payload)
        # base85 output must stay JSON/ASCII-safe and shrink highly compressible input
        packed.encode("ascii")
        self.assertLess(len(packed), len(payload))

    def test_todict_omits_buffer_when_absent(self):
        self.assertNotIn("buffer", _make_minimal_report(buffer=None).toDict())

    def test_buffer_survives_serialization_roundtrip(self):
        payload = b"MZ\x90\x00" + bytes(range(64))
        report_dict = _make_minimal_report(buffer=payload).toDict()
        self.assertIn("buffer", report_dict)
        restored = SmdaReport.fromDict(report_dict)
        self.assertEqual(restored.getBuffer(), payload)

    def test_legacy_report_without_buffer_field_loads(self):
        report_dict = _make_minimal_report(buffer=None).toDict()
        self.assertNotIn("buffer", report_dict)
        restored = SmdaReport.fromDict(report_dict)
        self.assertIsNone(restored.getBuffer())

    def test_empty_buffer_roundtrips_as_empty_not_none(self):
        # an intentionally stored empty buffer must survive as b"" and not collapse to None
        report_dict = _make_minimal_report(buffer=b"").toDict()
        self.assertIn("buffer", report_dict)
        restored = SmdaReport.fromDict(report_dict)
        self.assertEqual(restored.getBuffer(), b"")

    def test_packed_buffer_is_deterministic(self):
        # packing the same bytes twice must produce identical output (reproducible reports/caching)
        payload = b"reproducible payload" * 16
        self.assertEqual(SmdaReport._packBuffer(payload), SmdaReport._packBuffer(payload))

    def test_corrupt_buffer_field_does_not_abort_load(self):
        # a corrupt/tampered buffer field degrades to buffer=None instead of failing the whole load
        report_dict = _make_minimal_report(buffer=None).toDict()
        report_dict["buffer"] = "this is not valid packed buffer data!!!"
        restored = SmdaReport.fromDict(report_dict)
        self.assertIsNone(restored.getBuffer())

    def test_string_extraction_buffer_is_not_retained(self):
        # a buffer handed to string extraction must not linger on the report and get serialized;
        # only STORE_BUFFER (which sets report.buffer afterwards) should persist it.
        report = _make_minimal_report(buffer=None)
        Disassembler()._addStringsToReport(report, b"transient buffer for string extraction")
        self.assertIsNone(report.getBuffer())
        self.assertNotIn("buffer", report.toDict())


if __name__ == "__main__":
    unittest.main()
