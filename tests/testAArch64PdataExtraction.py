#!/usr/bin/python
"""PE ARM64 exception-directory candidate discovery (opt-in).

Builds a minimal spec-valid PE32+ ARM64 image in memory (4-byte e_lfanew,
real PE\\0\\0 signature per the repo's PE fixture convention) with .text,
.pdata and .xdata sections, loads it through FileLoader(map_file=True), and
drives the AArch64 FunctionCandidateManager directly.

ARM64 .pdata records are 8 bytes: <BeginRVA, UnwindData>, where UnwindData
bits 0-1 select the format: 0 = RVA of a full .xdata record, 1 = packed
unwind data (primary), 2 = packed fragment, 3 = reserved.
"""

import struct
import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

IMAGE_BASE = 0x140000000
TEXT_RVA, PDATA_RVA, XDATA_RVA = 0x1000, 0x2000, 0x3000
FILE_ALIGN, SECT_ALIGN = 0x200, 0x1000

# minimal valid ARM64 .xdata header: CodeWords=1, Vers=0, FunctionLength=0x10 words
VALID_XDATA = struct.pack("<I", (1 << 27) | 0x10)


def _build_arm64_pe(
    pdata_bytes,
    xdata_bytes=VALID_XDATA,
    machine=0xAA64,
    image_base=IMAGE_BASE,
    exc_rva=PDATA_RVA,
    exc_size=None,
    text_bytes=None,
):
    """Minimal PE32+ image: .text (RX) @0x1000, .pdata @0x2000, .xdata @0x3000."""
    if exc_size is None:
        exc_size = len(pdata_bytes)
    if text_bytes is None:
        # stp x29,x30,[sp,#-16]!; ret filler: every 8-aligned word is entry-shaped,
        # so records targeting TEXT_RVA+8k pass the funclet/fragment begin-word gate
        text_bytes = struct.pack("<II", 0xA9BF7BFD, 0xD65F03C0) * 64

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)  # e_lfanew

    coff = struct.pack("<HHIIIHH", machine, 3, 0, 0, 0, 240, 0x0022)

    data_dirs = [(0, 0)] * 16
    data_dirs[3] = (exc_rva, exc_size)  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # magic PE32+
        14,
        0,  # linker versions
        len(text_bytes),
        0,
        0,  # sizes of code / initialized / uninitialized data
        TEXT_RVA,  # entrypoint
        TEXT_RVA,  # base of code
        image_base,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # win32 version
        0x4000,  # size of image
        FILE_ALIGN,  # size of headers
        0,  # checksum
        3,
        0,  # subsystem CUI, dll characteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,  # stack/heap reserve+commit
        0,  # loader flags
        16,  # number of rva and sizes
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)

    def shdr(name, rva, vsize, raw_off, raw_size, characteristics):
        return struct.pack("<8sIIIIIIHHI", name, vsize, rva, raw_size, raw_off, 0, 0, 0, 0, characteristics)

    sections = (
        shdr(b".text", TEXT_RVA, len(text_bytes), 0x200, 0x200, 0x60000020)  # CODE|EXECUTE|READ
        + shdr(b".pdata", PDATA_RVA, max(len(pdata_bytes), 1), 0x400, 0x200, 0x40000040)  # IDATA|READ
        + shdr(b".xdata", XDATA_RVA, max(len(xdata_bytes), 1), 0x600, 0x200, 0x40000040)
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    assert len(headers) <= FILE_ALIGN
    blob = bytearray(0x800)
    blob[0 : len(headers)] = headers
    blob[0x200 : 0x200 + len(text_bytes)] = text_bytes
    blob[0x400 : 0x400 + len(pdata_bytes)] = pdata_bytes
    blob[0x600 : 0x600 + len(xdata_bytes)] = xdata_bytes
    return bytes(blob)


def _record(begin_rva, unwind_data):
    return struct.pack("<II", begin_rva, unwind_data)


def _candidates_for(blob, use_pdata=True, cb_timeout=None):
    loader = FileLoader("/", map_file=True)
    loader._loadFile(blob)
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    config = SmdaConfig()
    config.USE_PE_ARM64_PDATA_CANDIDATES = use_pdata
    fcm = FunctionCandidateManager(config)
    fcm.init(disassembly, cb_timeout)
    return fcm


def _exception_candidates(fcm):
    # entry-shaped begin words are also picked up by the prologue scanner, so
    # membership in fcm.candidates alone cannot prove the exception path ran
    return {addr for addr, candidate in fcm.candidates.items() if candidate.is_exception_handler}


class AArch64PdataExtractionTestSuite(unittest.TestCase):
    def test_accepts_xdata_and_packed_primary_records(self):
        records = _record(TEXT_RVA, XDATA_RVA) + _record(TEXT_RVA + 8, (0x10 << 2) | 1)
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))
        self.assertIn(IMAGE_BASE + TEXT_RVA + 8, _exception_candidates(fcm))

    def test_skips_records_with_non_entry_shaped_begin_words(self):
        # funclets/fragments: .pdata names them too, but their begin word is a
        # mid-body instruction, not a prologue/BTI — they must not be seeded
        # (covers both the xdata-RVA and the packed-primary record forms)
        records = (
            _record(TEXT_RVA + 4, XDATA_RVA)  # -> ret (mid-body word)
            + _record(TEXT_RVA + 12, (0x10 << 2) | 1)  # packed primary -> ret
        )
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 4, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 12, _exception_candidates(fcm))

    def test_accepts_bti_landing_pad_begin_word(self):
        text = struct.pack("<III", 0xD503245F, 0xD2800020, 0xD65F03C0)  # bti c; mov x0,#1; ret
        records = _record(TEXT_RVA, XDATA_RVA)
        fcm = _candidates_for(_build_arm64_pe(records, text_bytes=text))
        self.assertIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))

    def test_accepts_thunk_shaped_begin_words(self):
        # MSVC emits .pdata records for thunk-shaped functions too: bare indirect
        # branch, callee-saved single-register save, veneer immediate setup
        text = struct.pack(
            "<IIIIII",
            0xD61F0120,  # +0x00: br x9
            0xD503201F,  # +0x04: nop
            0xF81F0FF3,  # +0x08: str x19, [sp, #-0x10]!
            0xD65F03C0,  # +0x0C: ret
            0xD2B00010,  # +0x10: mov x16, #0x80000000
            0xD65F03C0,  # +0x14: ret
        )
        records = _record(TEXT_RVA, XDATA_RVA) + _record(TEXT_RVA + 8, XDATA_RVA) + _record(TEXT_RVA + 16, XDATA_RVA)
        fcm = _candidates_for(_build_arm64_pe(records, text_bytes=text))
        for offset in (0, 8, 16):
            self.assertIn(IMAGE_BASE + TEXT_RVA + offset, _exception_candidates(fcm))

    def test_default_off_produces_no_exception_candidates(self):
        records = _record(TEXT_RVA, XDATA_RVA)
        self.assertFalse(SmdaConfig().USE_PE_ARM64_PDATA_CANDIDATES)
        fcm = _candidates_for(_build_arm64_pe(records), use_pdata=False)
        self.assertNotIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))

    def test_skips_fragment_and_reserved_flags(self):
        records = _record(TEXT_RVA, (0x10 << 2) | 2) + _record(TEXT_RVA + 8, (0x10 << 2) | 3)
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 8, _exception_candidates(fcm))

    def test_skips_invalid_xdata_records(self):
        bad_version = struct.pack("<I", (1 << 27) | (1 << 18) | 0x10)  # Vers=1
        zero_length = struct.pack("<I", 1 << 27)  # FunctionLength=0
        records = (
            _record(TEXT_RVA, XDATA_RVA + len(bad_version))  # -> zero_length record
            + _record(TEXT_RVA + 8, XDATA_RVA + 2)  # unaligned .xdata RVA
            + _record(TEXT_RVA + 16, 0x00080000)  # .xdata RVA outside the image
            + _record(TEXT_RVA + 24, XDATA_RVA)  # -> bad_version record
        )
        fcm = _candidates_for(_build_arm64_pe(records, xdata_bytes=bad_version + zero_length))
        for offset in (0, 8, 16, 24):
            self.assertNotIn(IMAGE_BASE + TEXT_RVA + offset, _exception_candidates(fcm))

    def test_skips_misaligned_and_non_executable_starts(self):
        records = (
            _record(TEXT_RVA + 2, XDATA_RVA)  # not 4-aligned
            + _record(XDATA_RVA, XDATA_RVA)  # aligned but in a non-executable section
            + _record(0x8000, XDATA_RVA)  # aligned but outside any section
        )
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 2, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + XDATA_RVA, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + 0x8000, _exception_candidates(fcm))

    def test_rebased_image_seeds_candidates_at_new_base(self):
        new_base = 0x180000000
        records = _record(TEXT_RVA, XDATA_RVA)
        fcm = _candidates_for(_build_arm64_pe(records, image_base=new_base))
        self.assertIn(new_base + TEXT_RVA, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))

    def test_truncated_directory_stops_at_image_end(self):
        # the directory claims 3 records but the mapped image ends after the first;
        # the valid prefix is kept and the scan stops without raising
        blob = bytearray(_build_arm64_pe(b"", exc_rva=0x31F8, exc_size=24))
        blob[0x7F8:0x800] = _record(TEXT_RVA, (0x10 << 2) | 1)
        fcm = _candidates_for(bytes(blob))
        self.assertIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))

    def test_zero_record_terminates_scan(self):
        records = _record(TEXT_RVA, XDATA_RVA) + _record(0, 0) + _record(TEXT_RVA + 8, (0x10 << 2) | 1)
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 8, _exception_candidates(fcm))

    def test_duplicate_records_yield_single_candidate(self):
        records = _record(TEXT_RVA, XDATA_RVA) * 2
        fcm = _candidates_for(_build_arm64_pe(records))
        self.assertIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))
        self.assertEqual(sum(1 for addr in fcm.candidates if addr == IMAGE_BASE + TEXT_RVA), 1)

    def test_non_arm64_machine_is_ignored(self):
        # ARM64EC images carry machine AMD64 (0x8664); the classic-machine gate skips them
        records = _record(TEXT_RVA, XDATA_RVA)
        fcm = _candidates_for(_build_arm64_pe(records, machine=0x8664))
        self.assertNotIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))

    def test_tripped_timeout_skips_scan(self):
        records = _record(TEXT_RVA, XDATA_RVA)
        fcm = _candidates_for(_build_arm64_pe(records), cb_timeout=lambda: True)
        self.assertNotIn(IMAGE_BASE + TEXT_RVA, _exception_candidates(fcm))


class AArch64CallFallthroughAlignmentTestSuite(unittest.TestCase):
    """MSVC ARM64 nop-aligns loop heads MID-function; on PE images an aligned word
    after a bl-fallthrough gap must only be treated as a new function start when it
    actually looks like a function entry (stp/str prologue, PAC, or BTI). A plain
    16-aligned non-entry word (e.g. a mid-body ldr) must stay inside the calling
    function instead of being promoted to a bogus function start."""

    # stp x29,x30,[sp,#-16]!
    STP_PROLOGUE = 0xA9BF7BFD
    # bl <delta=0x28> -> targets the stp prologue at .text+0x2C
    BL_TO_0x2C = 0x9400000A
    NOP = 0xD503201F
    # ldr x0,[x29,#0x20]: 16-aligned, but NOT a recognized function prologue
    LDR_MID_BODY = 0xF94013A0
    MOV_X0_1 = 0xD2800020
    RET = 0xD65F03C0

    def _words(self):
        return [
            self.STP_PROLOGUE,  # +0x00: function entry
            self.BL_TO_0x2C,  # +0x04: bl call
            self.NOP,  # +0x08: skipped padding
            self.NOP,  # +0x0C: skipped padding
            self.LDR_MID_BODY,  # +0x10: 16-aligned, NOT an entry -> must stay in caller
            self.MOV_X0_1,  # +0x14
            self.RET,  # +0x18: caller's own return
            self.NOP,  # +0x1C
            self.NOP,  # +0x20
            self.NOP,  # +0x24
            self.NOP,  # +0x28
            self.STP_PROLOGUE,  # +0x2C: bl target, a real function entry
            self.RET,  # +0x30
        ]

    def _disassemble_pe(self):
        code = b"".join(w.to_bytes(4, "little") for w in self._words())
        blob = _build_arm64_pe(b"", text_bytes=code)
        config = SmdaConfig()
        config.WITH_STRINGS = False
        return Disassembler(config).disassembleUnmappedBuffer(blob)

    def test_aligned_mid_body_word_does_not_split_pe_function(self):
        report = self._disassemble_pe()
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")
        starts = {f.offset for f in report.getFunctions()}
        # the aligned ldr at +0x10 must NOT be its own function start
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 0x10, starts)
        caller = report.getFunction(IMAGE_BASE + TEXT_RVA)
        self.assertEqual(
            [ins.mnemonic for ins in caller.getInstructions()],
            ["stp", "bl", "nop", "nop", "ldr", "mov", "ret"],
        )
        # the bl's real target (a genuine prologue) is still recovered as its own function
        self.assertIn(IMAGE_BASE + TEXT_RVA + 0x2C, starts)


class AArch64CondBranchExceptionBoundaryTestSuite(unittest.TestCase):
    """A conditional-branch taken edge into a .pdata-named start must only be treated
    as an authoritative boundary (left for its own analysis) when that start also
    opens like a real function entry. .pdata also names funclets/fragments whose
    record start is a mid-body word — those must still be absorbed into the caller."""

    # cmp x0, #0
    CMP_X0_0 = 0xF100001F
    # b.ne +0xC (from the b.ne word itself at +0x04, targets +0x10)
    BNE_TO_0x10 = 0x54000061
    RET = 0xD65F03C0
    NOP = 0xD503201F
    # stp x29,x30,[sp,#-0x20]!: a real function entry
    STP_PROLOGUE = 0xA9BE7BFD
    # ldp x29,x30,[sp],#0x20
    LDP_EPILOGUE = 0xA8C27BFD
    # mov w8, #0: 16-aligned mid-body word, NOT a recognized function entry
    MOV_W8_0 = 0x52800008

    def _pdata_records(self):
        return _record(TEXT_RVA, (0x10 << 2) | 1) + _record(TEXT_RVA + 0x10, (0x10 << 2) | 1)

    def _disassemble(self, words):
        code = b"".join(w.to_bytes(4, "little") for w in words)
        blob = _build_arm64_pe(self._pdata_records(), text_bytes=code)
        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.USE_PE_ARM64_PDATA_CANDIDATES = True
        return Disassembler(config).disassembleUnmappedBuffer(blob)

    def test_pdata_named_prologue_target_splits_out_of_guard_stub(self):
        words = [
            self.CMP_X0_0,  # +0x00: guard stub A (also named by a .pdata record)
            self.BNE_TO_0x10,  # +0x04: b.ne into B's real entry
            self.RET,  # +0x08: A's own fall-through return
            self.NOP,  # +0x0C: padding up to B's 16-aligned start
            self.STP_PROLOGUE,  # +0x10: B, a real function entry, also named by .pdata
            self.LDP_EPILOGUE,  # +0x14
            self.RET,  # +0x18
        ]
        report = self._disassemble(words)
        self.assertEqual(report.status, "ok")
        starts = {f.offset for f in report.getFunctions()}
        # both the guard stub and the real function it conditionally branches into
        # must be recovered as their own functions, not merged into one
        self.assertIn(IMAGE_BASE + TEXT_RVA, starts)
        self.assertIn(IMAGE_BASE + TEXT_RVA + 0x10, starts)
        guard = report.getFunction(IMAGE_BASE + TEXT_RVA)
        self.assertEqual(
            [ins.mnemonic for ins in guard.getInstructions()],
            ["cmp", "b.ne", "ret"],
        )

    def test_pdata_named_funclet_continuation_stays_absorbed(self):
        words = [
            self.CMP_X0_0,  # +0x00: guard stub A (also named by a .pdata record)
            self.BNE_TO_0x10,  # +0x04: b.ne into the funclet's .pdata-named start
            self.RET,  # +0x08: A's own fall-through return
            self.NOP,  # +0x0C: padding
            self.MOV_W8_0,  # +0x10: .pdata names this word, but it is NOT an entry shape
            self.RET,  # +0x14
        ]
        report = self._disassemble(words)
        self.assertEqual(report.status, "ok")
        starts = {f.offset for f in report.getFunctions()}
        # the .pdata record at +0x10 names a funclet/fragment continuation, not an
        # independent function start -- it must stay absorbed into the guard stub
        self.assertNotIn(IMAGE_BASE + TEXT_RVA + 0x10, starts)
        self.assertIn(IMAGE_BASE + TEXT_RVA, starts)
        guard = report.getFunction(IMAGE_BASE + TEXT_RVA)
        self.assertEqual(
            [ins.mnemonic for ins in guard.getInstructions()],
            ["cmp", "b.ne", "ret", "mov", "ret"],
        )


if __name__ == "__main__":
    unittest.main()
