import datetime
import unittest

from smda.common.SmdaReport import SmdaReport
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


if __name__ == "__main__":
    unittest.main()
