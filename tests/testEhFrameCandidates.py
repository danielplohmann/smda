#!/usr/bin/python
"""ELF .eh_frame FDE decoding and the deferred AArch64 candidate pass (opt-in).

Decoder unit tests craft raw .eh_frame byte streams; the integration tests run
the real aarch64_static_xored fixture, where the conservative opt-in pass must
recover exactly the one wrapper the primary pass leaves unclaimed (278 -> 279)
without disturbing any existing function.
"""

import struct
import unittest

from smda.common.EhFrameDecoder import decodeEhFrameFdeRanges
from smda.Disassembler import Disassembler
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelFunctionCandidateManager
from smda.SmdaConfig import SmdaConfig
from tests.testAArch64Disassembler import AARCH64_STATIC_FIXTURE, _load_xored_fixture

SECTION_VA = 0x10000


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _cie(augmentation=b"zR", fde_encoding=0x00, version=1, aug_extra=b""):
    body = bytes([version]) + augmentation + b"\x00"
    body += _uleb(1)  # code alignment factor
    body += b"\x7c"  # data alignment factor: SLEB -4
    body += bytes([30]) if version == 1 else _uleb(30)  # return address register
    if augmentation.startswith(b"z"):
        aug_data = aug_extra + bytes([fde_encoding]) if b"R" in augmentation else aug_extra
        body += _uleb(len(aug_data)) + aug_data
    return _record(0, body)


def _record(cie_id, body):
    payload = struct.pack("<I", cie_id) + body
    if len(payload) % 4:
        payload += b"\x00" * (4 - len(payload) % 4)  # DW_CFA_nop padding
    return struct.pack("<I", len(payload)) + payload


def _fde(cie_offset_from_stream_start, stream_pos, initial_location, address_range, fmt):
    # the CIE pointer counts back from the FDE's own id field (stream_pos + 4)
    body = struct.pack(fmt, initial_location) + struct.pack(fmt, address_range)
    return _record(stream_pos + 4 - cie_offset_from_stream_start, body)


class EhFrameDecoderTestSuite(unittest.TestCase):
    def test_absptr_encoding(self):
        stream = _cie(fde_encoding=0x00)
        stream += _fde(0, len(stream), 0x401000, 0x40, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x40)])

    def test_pcrel_sdata4_encoding(self):
        cie = _cie(fde_encoding=0x1B)  # pcrel | sdata4
        stream = cie
        fde_field_va = SECTION_VA + len(stream) + 8  # length + id precede the pointer
        stream += _fde(0, len(stream), 0x401000 - fde_field_va, 0x40, "<i")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x40)])

    def test_multiple_cies_with_distinct_encodings(self):
        stream = _cie(fde_encoding=0x00)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        second_cie_at = len(stream)
        stream += _cie(fde_encoding=0x03)  # absolute udata4
        stream += _fde(second_cie_at, len(stream), 0x402000, 0x20, "<I")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x10), (0x402000, 0x20)])

    def test_zero_terminator_stops_scan(self):
        stream = _cie(fde_encoding=0x00)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        terminated = stream + b"\x00\x00\x00\x00"
        ignored_cie_at = len(terminated)
        terminated += _cie(fde_encoding=0x00)
        terminated += _fde(ignored_cie_at, len(terminated), 0x402000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(terminated, SECTION_VA), [(0x401000, 0x10)])

    def test_dangling_cie_reference_skips_fde_only(self):
        # a record whose CIE back-pointer resolves to no parsed CIE is skipped,
        # but the well-formed sibling after it still decodes
        stream = _cie(fde_encoding=0x00)
        stream += _record(0xDEAD, struct.pack("<QQ", 0x999000, 0x10))
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x10)])

    def test_unsupported_pointer_encoding_skips_cie_fdes(self):
        stream = _cie(fde_encoding=0x01)  # uleb128-encoded pointers: unsupported
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        supported_cie_at = len(stream)
        stream += _cie(fde_encoding=0x00)
        stream += _fde(supported_cie_at, len(stream), 0x402000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x402000, 0x10)])

    def test_datarel_application_mode_is_unsupported(self):
        stream = _cie(fde_encoding=0x33)  # datarel | udata4
        stream += _fde(0, len(stream), 0x1000, 0x10, "<I")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [])

    def test_length_overflow_terminates_scan(self):
        stream = _cie(fde_encoding=0x00)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        truncated = stream + struct.pack("<I", 0x1000) + b"\x00" * 8  # claims bytes past the end
        self.assertEqual(decodeEhFrameFdeRanges(truncated, SECTION_VA), [(0x401000, 0x10)])

    def test_extended_length_record_is_skipped_safely(self):
        # 0xFFFFFFFF escape with an 8-byte length covering an opaque record
        extended = struct.pack("<I", 0xFFFFFFFF) + struct.pack("<Q", 8) + b"\x00" * 8
        stream = extended + _cie(fde_encoding=0x00)
        stream += _fde(len(extended), len(stream), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x10)])

    def test_personality_and_lsda_augmentation_parses(self):
        # zPLR: personality encoding 0x03 (udata4) + 4-byte pointer, LSDA encoding byte
        aug_extra = bytes([0x03]) + struct.pack("<I", 0x5000) + bytes([0x03])
        stream = _cie(augmentation=b"zPLR", fde_encoding=0x00, aug_extra=aug_extra)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x10)])

    def test_truncated_cie_header_marks_cie_unsupported(self):
        # CIE body ends inside the code-alignment ULEB (continuation bit set on the
        # record's last byte); the CIE must be rejected and its FDE skipped
        truncated_cie = _record(0, bytes([1]) + b"\x00" + b"\x80\x80")
        stream = truncated_cie + _fde(0, len(truncated_cie), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [])

    def test_unsupported_personality_encoding_marks_cie_unsupported(self):
        # zPR with a uleb128-encoded personality pointer (0x01): its size is unknown,
        # so the cursor cannot reach the R byte reliably - the CIE must be rejected
        # rather than misreading a data byte as the FDE encoding
        aug_extra = bytes([0x01, 0x00])
        stream = _cie(augmentation=b"zPR", fde_encoding=0x00, aug_extra=aug_extra)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [])

    def test_version3_cie_with_uleb_return_register(self):
        stream = _cie(fde_encoding=0x00, version=3)
        stream += _fde(0, len(stream), 0x401000, 0x10, "<Q")
        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x10)])

    def test_record_cap_bounds_work(self):
        stream = _cie(fde_encoding=0x00)
        for index in range(8):
            stream += _fde(0, len(stream), 0x401000 + index * 0x10, 0x10, "<Q")
        capped = decodeEhFrameFdeRanges(stream, SECTION_VA, max_records=3)
        self.assertEqual(len(capped), 2)  # cap includes the CIE record
        self.assertEqual(len(decodeEhFrameFdeRanges(stream, SECTION_VA)), 8)

    def test_intel_manager_has_no_deferred_sources(self):
        self.assertEqual(tuple(IntelFunctionCandidateManager(SmdaConfig()).locateDeferredCandidates()), ())


class EhFrameFixtureTestSuite(unittest.TestCase):
    """Real-fixture behavior: default off is covered by the 278-function
    assertions in testAArch64Disassembler; opting in must add exactly the one
    unclaimed wrapper (0x411f50) and change nothing else."""

    def test_opt_in_recovers_unclaimed_wrapper(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.USE_ELF_EH_FRAME_CANDIDATES = True
        report = Disassembler(config).disassembleUnmappedBuffer(_load_xored_fixture(AARCH64_STATIC_FIXTURE))
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.num_functions, 279)
        self.assertIn(0x411F50, {function.offset for function in report.getFunctions()})


if __name__ == "__main__":
    unittest.main()
