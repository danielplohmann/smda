import base64
import datetime
import io
import struct
import unittest
import zipfile
import zlib
from unittest import mock

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.DisassemblyStatistics import DisassemblyStatistics
from smda.SmdaConfig import SmdaConfig


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


def _pack_zip(entries, compression=zipfile.ZIP_DEFLATED):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=compression) as zip_file:
        for name, payload in entries:
            zip_file.writestr(name, payload)
    return base64.b85encode(zip_buffer.getvalue()).decode("ascii")


def _forge_uncompressed_metadata(packed, payload):
    archive = bytearray(base64.b85decode(packed))
    local_header = archive.index(b"PK\x03\x04")
    central_header = archive.index(b"PK\x01\x02")
    for header, crc_offset, size_offset in ((local_header, 14, 22), (central_header, 16, 24)):
        struct.pack_into("<L", archive, header + crc_offset, zlib.crc32(payload))
        struct.pack_into("<L", archive, header + size_offset, len(payload))
    return base64.b85encode(archive).decode("ascii")


class TestSmdaReportBufferPacking(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        for payload in (b"", b"hello world", bytes(range(256)) * 8):
            packed = SmdaReport._packBuffer(payload)
            self.assertIsInstance(packed, str)
            self.assertEqual(SmdaReport._unpackBuffer(packed), payload)

    def test_unpack_accepts_payload_at_configured_limit(self):
        payload = b"A" * 32
        packed = SmdaReport._packBuffer(payload)

        with mock.patch.object(SmdaConfig, "MAX_IMAGE_SIZE", len(payload)):
            self.assertEqual(SmdaReport._unpackBuffer(packed), payload)

    def test_unpack_rejects_payload_above_configured_limit(self):
        payload = b"A" * 33
        packed = SmdaReport._packBuffer(payload)

        with mock.patch.object(SmdaConfig, "MAX_IMAGE_SIZE", len(payload) - 1), self.assertRaises(ValueError):
            SmdaReport._unpackBuffer(packed)

    def test_unpack_rejects_stream_larger_than_forged_metadata(self):
        payload = b"A" * 33
        declared_payload = payload[:-1]
        packed = _forge_uncompressed_metadata(SmdaReport._packBuffer(payload), declared_payload)

        for max_size in (len(declared_payload), len(payload)):
            with (
                self.subTest(max_size=max_size),
                mock.patch.object(SmdaConfig, "MAX_IMAGE_SIZE", max_size),
                self.assertRaises(ValueError),
            ):
                SmdaReport._unpackBuffer(packed)

    def test_oversized_buffer_field_degrades_to_none(self):
        payload = b"A" * 33
        report_dict = _make_minimal_report(buffer=None).toDict()
        report_dict["buffer"] = SmdaReport._packBuffer(payload)

        with mock.patch.object(SmdaConfig, "MAX_IMAGE_SIZE", len(payload) - 1):
            restored = SmdaReport.fromDict(report_dict)

        self.assertIsNone(restored.getBuffer())

    def test_unpack_rejects_non_native_compression(self):
        packed = _pack_zip([("buffer", b"payload")], compression=zipfile.ZIP_STORED)

        with self.assertRaises(ValueError):
            SmdaReport._unpackBuffer(packed)

    def test_unpack_rejects_archives_with_extra_members(self):
        packed = _pack_zip([("buffer", b"payload"), ("metadata", b"unexpected")])

        with self.assertRaises(ValueError):
            SmdaReport._unpackBuffer(packed)

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


class TestSmdaReportGetCapstone(unittest.TestCase):
    def test_supported_architectures_return_engine(self):
        for architecture in ("intel", "aarch64", None):
            report = _make_minimal_report()
            report.architecture = architecture
            self.assertIsNotNone(report.getCapstone())

    def test_unsupported_architectures_raise(self):
        for architecture in ("cil", "dalvik"):
            report = _make_minimal_report()
            report.architecture = architecture
            with self.assertRaises(NotImplementedError):
                report.getCapstone()


if __name__ == "__main__":
    unittest.main()
