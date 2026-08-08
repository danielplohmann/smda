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


def _build_aarch64_elf_with_ehframe(code, eh_frame, base=0x400000, vaddr=0x401000, eh_vaddr=0x402000):
    """ELF64/AArch64 with one R+X PT_LOAD plus a real .eh_frame section (non-exec)."""
    em_aarch64, ehsize, phentsize, shentsize = 183, 64, 56, 64
    shstrtab = b"\x00.text\x00.eh_frame\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text")
    name_eh = shstrtab.index(b".eh_frame")
    name_str = shstrtab.index(b".shstrtab")

    text_off = ehsize + phentsize
    eh_off = eh_vaddr - base  # keep file offset == vaddr - base for the whole segment
    shstr_off = eh_off + len(eh_frame)
    sh_off = shstr_off + len(shstrtab)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,
        em_aarch64,
        1,
        vaddr,  # e_entry
        ehsize,
        sh_off,
        0,
        ehsize,
        phentsize,
        1,
        shentsize,
        4,  # e_shnum
        3,  # e_shstrndx
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, sh_off, sh_off, 0x1000)

    def shdr(name, sh_type, flags, addr, offset, size, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, 0, 0, align, entsize)

    blob = bytearray(sh_off + 4 * shentsize)
    blob[0:ehsize] = ehdr
    blob[ehsize : ehsize + phentsize] = phdr
    blob[text_off : text_off + len(code)] = code
    blob[eh_off : eh_off + len(eh_frame)] = eh_frame
    blob[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    sections = (
        shdr(0, 0, 0, 0, 0, 0, 0, 0)
        + shdr(name_text, 1, 0x2 | 0x4, vaddr, text_off, len(code), 4, 0)  # ALLOC|EXECINSTR
        + shdr(name_eh, 1, 0x2, eh_vaddr, eh_off, len(eh_frame), 8, 0)  # ALLOC only
        + shdr(name_str, 3, 0, 0, shstr_off, len(shstrtab), 1, 0)
    )
    blob[sh_off : sh_off + len(sections)] = sections
    return bytes(blob)


class EhFrameDeferredOrderingTestSuite(unittest.TestCase):
    def test_earlier_deferred_function_does_not_absorb_later_fde_start(self):
        # f1 (0x401004) tail-branches into f2 (0x40100c); both are reachable only
        # via .eh_frame. All accepted FDE starts must be registered as function
        # starts BEFORE f1 is analyzed, or f1 absorbs f2's bytes and f2 is then
        # skipped as already-claimed code.
        # the branch must not be f1's first instruction (a lone-branch stub is
        # already left unabsorbed by the STUB-TAILCALL case) and the target must
        # be forward and nearby (backward / far targets hit the tailcall cases)
        code = b"".join(
            word.to_bytes(4, "little")
            for word in [
                0xD65F03C0,  # 0x401000 entry: ret (claimed by the OEP/symbol pass)
                0xD2800020,  # 0x401004 f1: mov x0, #1
                0x14000001,  # 0x401008     b 0x40100c (tail-branch into f2)
                0xD65F03C0,  # 0x40100c f2: ret
            ]
        )
        eh_vaddr = 0x402000
        eh_frame = _cie(fde_encoding=0x00)
        eh_frame += _fde(0, len(eh_frame), 0x401004, 8, "<Q")
        eh_frame += _fde(0, len(eh_frame), 0x40100C, 4, "<Q")
        blob = _build_aarch64_elf_with_ehframe(code, eh_frame, eh_vaddr=eh_vaddr)

        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.USE_ELF_EH_FRAME_CANDIDATES = True
        report = Disassembler(config).disassembleUnmappedBuffer(blob)
        self.assertEqual(report.status, "ok")
        offsets = {function.offset for function in report.getFunctions()}
        self.assertIn(0x401004, offsets)
        self.assertIn(0x40100C, offsets)


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


def _record64(cie_id, body):
    payload = struct.pack("<Q", cie_id) + body
    if len(payload) % 4:
        payload += b"\x00" * (4 - len(payload) % 4)
    return struct.pack("<I", 0xFFFFFFFF) + struct.pack("<Q", len(payload)) + payload


def _cie64(fde_encoding=0x00):
    body = bytes([1]) + b"zR" + b"\x00"
    body += _uleb(1) + b"\x7c" + bytes([30])
    aug_data = bytes([fde_encoding])
    body += _uleb(len(aug_data)) + aug_data
    return _record64(0, body)


def _fde64(cie_offset_from_stream_start, stream_pos, initial_location, address_range, fmt):
    # the CIE pointer counts back from the FDE's own id field (4-byte marker + 8-byte length)
    body = struct.pack(fmt, initial_location) + struct.pack(fmt, address_range)
    return _record64(stream_pos + 12 - cie_offset_from_stream_start, body)


class EhFrameAugmentationTestSuite(unittest.TestCase):
    def test_data_free_augmentation_chars_do_not_exhaust_the_cursor(self):
        for augmentation in (b"zR", b"zRS", b"zRB", b"zRSB"):
            with self.subTest(augmentation=augmentation):
                stream = _cie(augmentation=augmentation, fde_encoding=0x00)
                stream += _fde(0, len(stream), 0x401000, 0x40, "<Q")

                self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x40)])

    def test_signal_frame_only_augmentation_keeps_the_default_encoding(self):
        stream = _cie(augmentation=b"zS")
        stream += _fde(0, len(stream), 0x401000, 0x40, "<Q")

        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x40)])


class EhFrameDwarf64TestSuite(unittest.TestCase):
    def test_64bit_format_records_use_an_eight_byte_cie_pointer(self):
        stream = _cie64(fde_encoding=0x00)
        stream += _fde64(0, len(stream), 0x401000, 0x40, "<Q")

        self.assertEqual(decodeEhFrameFdeRanges(stream, SECTION_VA), [(0x401000, 0x40)])


if __name__ == "__main__":
    unittest.main()
