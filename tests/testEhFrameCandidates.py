#!/usr/bin/python
"""ELF .eh_frame FDE decoding and the deferred candidate pass it feeds (opt-in).

Decoder unit tests craft raw .eh_frame byte streams. The integration tests run
real fixtures: aarch64_static_xored, where the conservative opt-in pass must
recover exactly the one wrapper the primary pass leaves unclaimed (278 -> 279)
without disturbing any existing function, and the x86-64 fixture below, which is
the only bundled image whose .eh_frame_hdr search table can be decoded at all -
the route a memory image has to take, since it keeps its program headers but not
its section table.
"""

import struct
import unittest
from pathlib import Path

import lief

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64FunctionCandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.common.EhFrameDecoder import PT_GNU_EH_FRAME, decodeEhFrameFdeRanges, decodeEhFrameHdrStarts
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelFunctionCandidateManager
from smda.SmdaConfig import SmdaConfig
from smda.utility.MemoryFileLoader import MemoryFileLoader
from tests.testAArch64Disassembler import AARCH64_STATIC_FIXTURE, _load_xored_fixture

SECTION_VA = 0x10000
# x86-64 ELF carrying a real .eh_frame_hdr search table, built with
#   gcc -O1 -static -nostdlib -fasynchronous-unwind-tables -Wl,--eh-frame-hdr
# from five small functions, then stripped (gcc 13.3.0); no bundled malware fixture
# has the segment, and -nostdlib alone does not link the search table in
EH_FRAME_HDR_FIXTURE = "elf_ehframe_hdr_x64_xored"


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

    def test_intel_manager_yields_nothing_while_the_sources_are_off(self):
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


class IntelEhFrameCandidateTestSuite(unittest.TestCase):
    """The decoder has always been in the tree; until now only AArch64 read it."""

    # the only bundled intel ELF with a populated .eh_frame; every malware fixture
    # is either built without unwind tables or keeps a 4-byte terminator section
    ELF_FIXTURE = EH_FRAME_HDR_FIXTURE
    FDE_STARTS = {0x401000, 0x401006, 0x40101F, 0x40103B, 0x401048}

    def _report(self, opt_in, mapped=False):
        config = SmdaConfig()
        config.TIMEOUT = 300
        config.USE_ELF_EH_FRAME_CANDIDATES = opt_in
        buffer = _load_xored_fixture(Path(__file__).resolve().parent / self.ELF_FIXTURE)
        if mapped:
            loader = MemoryFileLoader(buffer, map_file=True)
            return Disassembler(config).disassembleBuffer(loader.getData(), loader.getBaseAddress(), bitness=64)
        return Disassembler(config).disassembleUnmappedBuffer(buffer)

    def testTheIntelManagerReadsTheSectionItNeverUsedToRead(self):
        buffer = _load_xored_fixture(Path(__file__).resolve().parent / self.ELF_FIXTURE)
        config = SmdaConfig()
        config.USE_ELF_EH_FRAME_CANDIDATES = True
        loader = MemoryFileLoader(buffer, map_file=True)
        binary_info = BinaryInfo(loader.getData())
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = 64
        manager = IntelFunctionCandidateManager(config)
        manager.disassembly = DisassemblyResult()
        manager.disassembly.setBinaryInfo(binary_info)
        self.assertEqual(set(manager.locateEhFrameCandidates()), self.FDE_STARTS)

    def testOptInIsAnIntelCandidateSourceToo(self):
        off = self._report(False)
        on = self._report(True)
        self.assertEqual(off.architecture, "intel")
        self.assertEqual(on.architecture, "intel")
        self.assertGreaterEqual(on.num_functions, off.num_functions)
        self.assertEqual(
            {function.offset for function in off.getFunctions()} - {function.offset for function in on.getFunctions()},
            set(),
        )
        # positive control: an .eh_frame the decoder cannot read would make the
        # comparison above true no matter what the candidate source does
        self.assertTrue(self.FDE_STARTS.issubset({function.offset for function in on.getFunctions()}))

    def testIntelAcceptsUnalignedStarts(self):
        self.assertEqual(IntelFunctionCandidateManager.CANDIDATE_ALIGNMENT, 1)


class EhFrameHdrTestSuite(unittest.TestCase):
    """A memory image keeps its program headers but not its section table, so the
    FDE starts have to come from the search table PT_GNU_EH_FRAME points at."""

    def _disassembly(self, buffer, base_addr):
        binary_info = BinaryInfo(buffer)
        binary_info.base_addr = base_addr
        binary_info.bitness = 64
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        return disassembly

    def testMappedImageYieldsTheSameStartsAsTheSectionTable(self):
        buffer = _load_xored_fixture(Path(__file__).resolve().parent / EH_FRAME_HDR_FIXTURE)
        loader = MemoryFileLoader(buffer, map_file=True)
        disassembly = self._disassembly(loader.getData(), loader.getBaseAddress())
        starts = decodeEhFrameHdrStarts(disassembly, pointer_size=8)
        parsed = lief.ELF.parse(list(buffer))
        section = next((s for s in parsed.sections if s.name == ".eh_frame"), None)
        self.assertIsNotNone(section)
        expected = {
            fde_range[0]
            for fde_range in decodeEhFrameFdeRanges(bytes(section.content), section.virtual_address, pointer_size=8)
        }
        # positive control: an empty search table would make the comparison vacuous
        self.assertEqual(len(expected), 5)
        self.assertEqual(starts, expected)

    def testMappedImageReachesTheFallbackThroughTheCandidateManager(self):
        # the section table is not covered by any PT_LOAD, so a mapped image has to
        # reach the same starts through .eh_frame_hdr
        buffer = _load_xored_fixture(Path(__file__).resolve().parent / EH_FRAME_HDR_FIXTURE)
        loader = MemoryFileLoader(buffer, map_file=True)
        manager = IntelFunctionCandidateManager(SmdaConfig())
        manager.disassembly = self._disassembly(loader.getData(), loader.getBaseAddress())
        self.assertEqual(manager._ehFrameFunctionStarts(), IntelEhFrameCandidateTestSuite.FDE_STARTS)

    def testBigEndianImageIsRejected(self):
        # every header word is read little-endian, so a big-endian image would produce
        # byte-swapped offsets rather than no answer
        buffer = _load_xored_fixture(Path(__file__).resolve().parent / "mirai_openrisc_xored")
        loader = MemoryFileLoader(buffer, map_file=True)
        disassembly = self._disassembly(loader.getData(), loader.getBaseAddress())
        self.assertEqual(buffer[5], 2)  # EI_DATA == ELFDATA2MSB
        self.assertEqual(decodeEhFrameHdrStarts(disassembly, pointer_size=4), set())

    def testNonElfBufferYieldsNothing(self):
        disassembly = self._disassembly(b"MZ" + b"\x00" * 0x200, 0x400000)
        self.assertEqual(decodeEhFrameHdrStarts(disassembly, pointer_size=8), set())

    def testEmptyBufferYieldsNothing(self):
        disassembly = self._disassembly(b"", 0)
        self.assertEqual(decodeEhFrameHdrStarts(disassembly, pointer_size=8), set())

    def testElfWithoutTheSegmentYieldsNothing(self):
        header = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
        struct.pack_into("<Q", header, 0x20, 64)
        struct.pack_into("<HH", header, 0x36, 56, 1)
        program_header = bytearray(56)
        struct.pack_into("<I", program_header, 0, 1)
        disassembly = self._disassembly(bytes(header + program_header), 0)
        self.assertEqual(decodeEhFrameHdrStarts(disassembly, pointer_size=8), set())

    def test32BitElfHeaderIsRead(self):
        header = bytearray(b"\x7fELF\x01\x01\x01" + b"\x00" * 45)
        struct.pack_into("<I", header, 0x1C, 52)
        struct.pack_into("<HH", header, 0x2A, 32, 1)
        program_header = bytearray(32)
        struct.pack_into("<I", program_header, 0, 1)
        disassembly = self._disassembly(bytes(header + program_header), 0)
        self.assertEqual(decodeEhFrameHdrStarts(disassembly, pointer_size=4), set())


def _image_with_hdr(hdr_vaddr, hdr_bytes, phnum=1, phoff=0x40, size=0x2000, entry_type=PT_GNU_EH_FRAME):
    """Mapped-image bytes whose PT_GNU_EH_FRAME points at hdr_bytes."""
    image = bytearray(size)
    image[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<Q", image, 0x20, phoff)
    struct.pack_into("<HH", image, 0x36, 56, phnum)
    if phnum and phoff + 56 <= size:
        struct.pack_into("<I", image, phoff, entry_type)
        struct.pack_into("<Q", image, phoff + 0x10, hdr_vaddr)
    if hdr_bytes and hdr_vaddr + len(hdr_bytes) <= size:
        image[hdr_vaddr : hdr_vaddr + len(hdr_bytes)] = hdr_bytes
    return bytes(image)


def _hdr_bytes(version=1, count_enc=0x03, table_enc=0x3B, fde_count=1):
    return bytes([version, 0x1B, count_enc, table_enc]) + struct.pack("<i", 0) + struct.pack("<I", fde_count)


class EhFrameHdrRejectionTestSuite(unittest.TestCase):
    """Every way a search table can be unusable; base_addr 0 makes both candidate
    addresses the decoder tries identical, so each case ends the scan."""

    def _starts(self, image):
        binary_info = BinaryInfo(image)
        binary_info.base_addr = 0
        binary_info.bitness = 64
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        return decodeEhFrameHdrStarts(disassembly, pointer_size=8)

    def testProgramHeaderTableOutsideTheReadWindowIsIgnored(self):
        # the header walk only reads the first page, so entries past it are unreadable
        image = _image_with_hdr(0x1000, _hdr_bytes(), phnum=8, phoff=0xF00, entry_type=1)
        self.assertEqual(self._starts(image), set())

    def testHeaderWithoutProgramHeadersIsIgnored(self):
        self.assertEqual(self._starts(_image_with_hdr(0x1000, _hdr_bytes(), phnum=0)), set())

    def testUnreadableSearchTableAddressEndsTheScan(self):
        self.assertEqual(self._starts(_image_with_hdr(0x9000, b"")), set())

    def testUnknownVersionEndsTheScan(self):
        self.assertEqual(self._starts(_image_with_hdr(0x1000, _hdr_bytes(version=2))), set())

    def testUnsupportedTableEncodingEndsTheScan(self):
        self.assertEqual(self._starts(_image_with_hdr(0x1000, _hdr_bytes(table_enc=0x1B))), set())

    def testTruncatedTableEndsTheScan(self):
        # the header sits at the very end of the image, so its table cannot be read
        self.assertEqual(self._starts(_image_with_hdr(0x2000 - 12, _hdr_bytes())), set())


def _image_with_sections_and_hdr(eh_frame, hdr, eh_vaddr=0x1000, hdr_vaddr=0x1200, size=0x2000):
    """Mapped-image bytes carrying both a parseable .eh_frame section and a search table."""
    image = bytearray(size)
    image[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHI", image, 0x10, 2, 0x3E, 1)
    struct.pack_into("<Q", image, 0x20, 0x40)
    struct.pack_into("<Q", image, 0x28, 0x1800)
    struct.pack_into("<HHHHHH", image, 0x34, 64, 56, 1, 64, 3, 2)
    struct.pack_into("<I", image, 0x40, PT_GNU_EH_FRAME)
    struct.pack_into("<Q", image, 0x50, hdr_vaddr)
    names = b"\x00.eh_frame\x00.shstrtab\x00"
    image[0x1700 : 0x1700 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", image, 0x1840, 1, 1, 2, eh_vaddr, eh_vaddr, len(eh_frame), 0, 0, 8, 0)
    struct.pack_into("<IIQQQQIIQQ", image, 0x1880, 11, 3, 0, 0, 0x1700, len(names), 0, 0, 1, 0)
    image[eh_vaddr : eh_vaddr + len(eh_frame)] = eh_frame
    image[hdr_vaddr : hdr_vaddr + len(hdr)] = hdr
    return bytes(image)


class EhFrameSourceUnionTestSuite(unittest.TestCase):
    """The section decoder skips records whose CIE it cannot read, so a non-empty
    section result is not necessarily a complete one and cannot stand in for the
    search table."""

    DECODABLE_START = 0x1400
    SKIPPED_START = 0x1500
    HDR_VADDR = 0x1200

    def _ehFrame(self):
        # two CIE/FDE pairs; the second CIE declares version 4, which the decoder
        # refuses, so its FDE is skipped while the first pair still decodes
        readable_cie = _cie()
        readable_fde = _fde(0, len(readable_cie), self.DECODABLE_START, 0x10, "<Q")
        unreadable_offset = len(readable_cie) + len(readable_fde)
        unreadable_cie = _cie(version=4)
        unreadable_fde = _fde(
            unreadable_offset, unreadable_offset + len(unreadable_cie), self.SKIPPED_START, 0x10, "<Q"
        )
        return readable_cie + readable_fde + unreadable_cie + unreadable_fde

    def _hdr(self):
        table = b""
        for start in (self.DECODABLE_START, self.SKIPPED_START):
            table += struct.pack("<ii", start - self.HDR_VADDR, 0)
        return _hdr_bytes(fde_count=2) + table

    def _manager(self, image):
        binary_info = BinaryInfo(image)
        binary_info.base_addr = 0
        binary_info.bitness = 64
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        manager = IntelFunctionCandidateManager(SmdaConfig())
        manager.disassembly = disassembly
        return manager

    def testSectionAloneMissesTheRecordItCannotDecode(self):
        # positive control for the test below: the section really is a partial answer
        starts = {fde_range[0] for fde_range in decodeEhFrameFdeRanges(self._ehFrame(), 0x1000, pointer_size=8)}
        self.assertEqual(starts, {self.DECODABLE_START})

    def testSearchTableAloneNamesBoth(self):
        manager = self._manager(_image_with_sections_and_hdr(self._ehFrame(), self._hdr()))
        self.assertEqual(
            decodeEhFrameHdrStarts(manager.disassembly, pointer_size=8),
            {self.DECODABLE_START, self.SKIPPED_START},
        )

    def testPartialSectionResultIsUnionedWithTheSearchTable(self):
        manager = self._manager(_image_with_sections_and_hdr(self._ehFrame(), self._hdr()))
        self.assertEqual(
            manager._ehFrameFunctionStarts(),
            {self.DECODABLE_START, self.SKIPPED_START},
        )

    def testSectionStartsSurviveAnUnusableSearchTable(self):
        manager = self._manager(_image_with_sections_and_hdr(self._ehFrame(), _hdr_bytes(version=2)))
        self.assertEqual(manager._ehFrameFunctionStarts(), {self.DECODABLE_START})


class _TimeoutAfter:
    """analysis_timeout that flips to True after a fixed number of reads."""

    def __init__(self, reads):
        self.remaining = reads

    def __bool__(self):
        if self.remaining <= 0:
            return True
        self.remaining -= 1
        return False


class EhFrameCandidateFilterTestSuite(unittest.TestCase):
    """The filters an FDE start has to clear, driven through a stub unwind table."""

    IMAGE_SIZE = 0x1000
    BASE = 0x400000

    def _manager(self, starts, manager_class=IntelFunctionCandidateManager, code_areas=None):
        config = SmdaConfig()
        config.USE_ELF_EH_FRAME_CANDIDATES = True
        binary_info = BinaryInfo(b"\x90" * self.IMAGE_SIZE)
        binary_info.base_addr = self.BASE
        binary_info.bitness = 64
        binary_info.binary_size = self.IMAGE_SIZE
        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info
        manager = manager_class(config)
        manager.disassembly = disassembly
        manager.bitness = 64
        manager._code_areas = code_areas or []
        manager._ehFrameFunctionStarts = lambda: set(starts)
        return manager

    def testStartsInsideTheCodeAreasAreYielded(self):
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200])
        self.assertEqual(
            list(manager.locateEhFrameCandidates()),
            [self.BASE + 0x100, self.BASE + 0x200],
        )
        self.assertEqual(manager._executableRanges(), [])

    def testAnEmptyTableEndsThePass(self):
        self.assertEqual(list(self._manager([]).locateEhFrameCandidates()), [])

    def testStartsOutsideTheExecutableRangesAreDropped(self):
        areas = [(self.BASE + 0x180, self.BASE + 0x280)]
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200], code_areas=areas)
        self.assertEqual(list(manager.locateEhFrameCandidates()), [self.BASE + 0x200])

    def testMisalignedStartsAreDroppedOnAArch64(self):
        manager = self._manager(
            [self.BASE + 0x102, self.BASE + 0x200],
            manager_class=AArch64FunctionCandidateManager,
        )
        manager._cachedExecutableSectionRanges = list
        self.assertEqual(list(manager.locateEhFrameCandidates()), [self.BASE + 0x200])

    def testStartsOutsideTheCodeAreasAreDropped(self):
        # AArch64 filters on executable SECTIONS while the code filter uses the loader's
        # code areas, so a start can clear one and fail the other
        manager = self._manager(
            [self.BASE + 0x100, self.BASE + 0x200],
            manager_class=AArch64FunctionCandidateManager,
            code_areas=[(self.BASE + 0x180, self.BASE + 0x280)],
        )
        manager._cachedExecutableSectionRanges = lambda: [(self.BASE, self.BASE + self.IMAGE_SIZE)]
        self.assertEqual(list(manager.locateEhFrameCandidates()), [self.BASE + 0x200])

    def testStartsTheAnalysisAlreadyClaimedAreLeftAlone(self):
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200])
        manager.disassembly.code_map[self.BASE + 0x100] = None
        self.assertEqual(list(manager.locateEhFrameCandidates()), [self.BASE + 0x200])

    def testAStartClaimedByAnEarlierDeferredFunctionIsNotYielded(self):
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200])
        candidates = manager.locateEhFrameCandidates()
        self.assertEqual(next(candidates), self.BASE + 0x100)
        manager.disassembly.code_map[self.BASE + 0x200] = None
        self.assertEqual(list(candidates), [])

    def testTimeoutStopsTheCollectionPass(self):
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200])
        manager.disassembly.analysis_timeout = True
        self.assertEqual(list(manager.locateEhFrameCandidates()), [])
        self.assertEqual(manager.candidates, {})

    def testTimeoutStopsTheYieldPass(self):
        manager = self._manager([self.BASE + 0x100, self.BASE + 0x200])
        manager.disassembly.analysis_timeout = _TimeoutAfter(2)
        self.assertEqual(list(manager.locateEhFrameCandidates()), [])
        self.assertEqual(sorted(manager.candidates), [self.BASE + 0x100, self.BASE + 0x200])


if __name__ == "__main__":
    unittest.main()
