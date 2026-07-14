#!/usr/bin/python
"""Mach-O function-pointer metadata candidates and the opt-in address-ref scan.

Builds minimal thin (and fat-wrapped) MH_EXECUTE arm64 Mach-O images in memory:
__TEXT holds __text (pure instructions) and __stubs, __DATA holds whatever
metadata sections each test needs. Loaded through FileLoader(map_file=True) and
driven via the AArch64 FunctionCandidateManager directly, mirroring the PE
exception-directory tests.

The committed Mach-O corpus contains no mod-init/init-offsets/interposing
sections at all, so these synthetic images are the only coverage exercising
the metadata scan (a zero corpus delta says nothing about it).
"""

import struct
import unittest

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

BASE = 0x100000000
TEXT_VA = BASE + 0x1000
STUBS_VA = BASE + 0x1800
DATA_VA = BASE + 0x2000

MH_MAGIC_64 = 0xFEEDFACF
CPU_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_REGULAR = 0x0
S_SYMBOL_STUBS = 0x8
S_MOD_INIT_FUNC_POINTERS = 0x9
S_MOD_TERM_FUNC_POINTERS = 0xA
S_INTERPOSING = 0xD
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15
S_INIT_FUNC_OFFSETS = 0x16

RET = 0xD65F03C0


def _section(sectname, segname, addr, size, offset, flags):
    return struct.pack("<16s16sQQIIIIIIII", sectname, segname, addr, size, offset, 3, 0, 0, flags, 0, 0, 0)


def _segment(segname, vmaddr, vmsize, fileoff, filesize, prot, sections):
    cmdsize = 72 + 80 * len(sections)
    return struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        cmdsize,
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        prot,
        prot,
        len(sections),
        0,
    ) + b"".join(sections)


def _build_arm64_macho(data_sections, text_words=None, fat=False):
    """Thin (or fat-wrapped) arm64 Mach-O; __DATA sections are laid out from
    DATA_VA in 0x100 strides as (name, type/attr flags, content) tuples."""
    text_words = text_words or [RET] * 64
    text_bytes = b"".join(word.to_bytes(4, "little") for word in text_words)
    text_bytes += b"\x00" * (0x800 - len(text_bytes))
    stub_bytes = b"".join(word.to_bytes(4, "little") for word in [RET] * 8)

    data_blob = bytearray(0x1000)
    section_headers = []
    for index, (name, type_flags, content) in enumerate(data_sections):
        section_va = DATA_VA + 0x100 * index
        data_blob[0x100 * index : 0x100 * index + len(content)] = content
        section_headers.append(
            _section(name, b"__DATA", section_va, max(len(content), 1), 0x2000 + 0x100 * index, type_flags)
        )

    text_seg = _segment(
        b"__TEXT",
        BASE,
        0x2000,
        0,
        0x2000,
        5,
        [
            _section(
                b"__text",
                b"__TEXT",
                TEXT_VA,
                len(text_bytes),
                0x1000,
                S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            ),
            _section(
                b"__stubs",
                b"__TEXT",
                STUBS_VA,
                len(stub_bytes),
                0x1800,
                S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            ),
        ],
    )
    data_seg = _segment(b"__DATA", DATA_VA, 0x1000, 0x2000, 0x1000, 3, section_headers)

    commands = text_seg + data_seg
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_ARM64, 0, 2, 2, len(commands), 0, 0)
    blob = bytearray(0x3000)
    blob[0 : len(header)] = header
    blob[len(header) : len(header) + len(commands)] = commands
    blob[0x1000 : 0x1000 + len(text_bytes)] = text_bytes
    blob[0x1800 : 0x1800 + len(stub_bytes)] = stub_bytes
    blob[0x2000:0x3000] = data_blob
    thin = bytes(blob)
    if not fat:
        return thin
    # big-endian FAT_MAGIC header with one arm64 slice at offset 0x4000
    fat_header = struct.pack(">II", 0xCAFEBABE, 1)
    fat_arch = struct.pack(">iiIII", CPU_ARM64, 0, 0x4000, len(thin), 14)
    return fat_header + fat_arch + b"\x00" * (0x4000 - len(fat_header) - len(fat_arch)) + thin


def _ptr(value):
    return struct.pack("<Q", value)


def _manager_for(blob, use_address_refs=False):
    loader = FileLoader("/", map_file=True)
    loader._loadFile(blob)
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    config = SmdaConfig()
    config.USE_MACHO_ADDRESS_REF_CANDIDATES = use_address_refs
    fcm = FunctionCandidateManager(config)
    fcm.init(disassembly)
    return fcm


class MachoMetadataPointerTestSuite(unittest.TestCase):
    def test_mod_init_term_and_tlv_pointers_are_seeded(self):
        blob = _build_arm64_macho(
            [
                (b"__mod_init_func", S_MOD_INIT_FUNC_POINTERS, _ptr(TEXT_VA + 8)),
                (b"__mod_term_func", S_MOD_TERM_FUNC_POINTERS, _ptr(TEXT_VA + 16)),
                (b"__thread_init", S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, _ptr(TEXT_VA + 24)),
            ]
        )
        fcm = _manager_for(blob)
        for target in (TEXT_VA + 8, TEXT_VA + 16, TEXT_VA + 24):
            self.assertIn(target, fcm.candidates)
            self.assertTrue(fcm.candidates[target].is_initial_candidate)

    def test_regular_data_sections_are_not_swept(self):
        # the same pointer in a REGULAR section must NOT seed a candidate:
        # Mach-O discovery is metadata-only, without broad data sweeps
        blob = _build_arm64_macho([(b"__data", S_REGULAR, _ptr(TEXT_VA + 8))])
        self.assertNotIn(TEXT_VA + 8, _manager_for(blob).candidates)

    def test_init_offsets_resolve_from_image_base(self):
        blob = _build_arm64_macho([(b"__init_offsets", S_INIT_FUNC_OFFSETS, struct.pack("<II", 0x1008, 0x1010))])
        fcm = _manager_for(blob)
        self.assertIn(BASE + 0x1008, fcm.candidates)
        self.assertIn(BASE + 0x1010, fcm.candidates)

    def test_interposing_seeds_only_the_replacement_of_each_pair(self):
        blob = _build_arm64_macho([(b"__interpose", S_INTERPOSING, _ptr(TEXT_VA + 0x10) + _ptr(TEXT_VA + 0x20))])
        fcm = _manager_for(blob)
        self.assertIn(TEXT_VA + 0x10, fcm.candidates)
        self.assertNotIn(TEXT_VA + 0x20, fcm.candidates)

    def test_stub_misaligned_and_data_targets_are_excluded(self):
        blob = _build_arm64_macho(
            [
                (
                    b"__mod_init_func",
                    S_MOD_INIT_FUNC_POINTERS,
                    _ptr(STUBS_VA) + _ptr(TEXT_VA + 2) + _ptr(DATA_VA + 0x40) + _ptr(0),
                )
            ]
        )
        fcm = _manager_for(blob)
        self.assertNotIn(STUBS_VA, fcm.candidates)  # stub island, not a local function
        self.assertNotIn(TEXT_VA + 2, fcm.candidates)  # not instruction-aligned
        self.assertNotIn(DATA_VA + 0x40, fcm.candidates)  # not in instruction sections

    def test_fat_slice_pointers_are_seeded(self):
        blob = _build_arm64_macho([(b"__mod_init_func", S_MOD_INIT_FUNC_POINTERS, _ptr(TEXT_VA + 8))], fat=True)
        self.assertIn(TEXT_VA + 8, _manager_for(blob).candidates)


class MachoStoredPointerResolutionTestSuite(unittest.TestCase):
    """Fixup-aware slot resolution: bindings are imports, chained slots hold
    packed metadata unless a RelocationFixup names their target."""

    def _bare_manager(self, blob):
        loader = FileLoader("/", map_file=True)
        loader._loadFile(blob)
        disassembly = DisassemblyResult()
        disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
        fcm = FunctionCandidateManager(SmdaConfig())
        fcm.disassembly = disassembly
        fcm.bitness = disassembly.binary_info.bitness
        return fcm

    def test_binding_slot_is_never_a_local_pointer(self):
        fcm = self._bare_manager(_build_arm64_macho([]))
        fixup_state = ({}, {DATA_VA}, False)
        self.assertIsNone(fcm._resolveMachoStoredPointer(DATA_VA, 0, fixup_state))

    def test_rebase_target_wins_over_raw_bytes_and_gets_adjusted(self):
        fcm = self._bare_manager(_build_arm64_macho([]))
        fixup_state = ({DATA_VA: TEXT_VA + 8}, set(), True)
        self.assertEqual(fcm._resolveMachoStoredPointer(DATA_VA, 0x1000, fixup_state), TEXT_VA + 8 + 0x1000)

    def test_unresolved_chained_slot_is_skipped(self):
        blob = _build_arm64_macho([(b"__data", S_REGULAR, _ptr(TEXT_VA + 8))])
        fcm = self._bare_manager(blob)
        fixup_state = ({}, set(), True)
        self.assertIsNone(fcm._resolveMachoStoredPointer(DATA_VA, 0, fixup_state))

    def test_classic_slot_reads_raw_mapped_bytes(self):
        blob = _build_arm64_macho([(b"__data", S_REGULAR, _ptr(TEXT_VA + 8))])
        fcm = self._bare_manager(blob)
        fixup_state = ({}, set(), False)
        self.assertEqual(fcm._resolveMachoStoredPointer(DATA_VA, 0, fixup_state), TEXT_VA + 8)


class MachoAddressRefCandidateTestSuite(unittest.TestCase):
    """Opt-in adr/adrp+add discovery over pure-instruction Mach-O sections."""

    @staticmethod
    def _adr_blob():
        # adr x1, #0x40 -> TEXT_VA + 0x40; adrp x2, #0 (page = BASE + 0x1000) +
        # add x2, x2, #0x50 -> TEXT_VA + 0x50
        words = [
            0x10000201,  # 0x...1000  adr x1, #0x40
            0x90000002,  # 0x...1004  adrp x2, #0
            0x91014042,  # 0x...1008  add x2, x2, #0x50
            RET,
        ]
        return _build_arm64_macho([], text_words=words + [RET] * 4)

    def test_default_off_records_no_address_refs(self):
        self.assertFalse(SmdaConfig().USE_MACHO_ADDRESS_REF_CANDIDATES)
        fcm = _manager_for(self._adr_blob(), use_address_refs=False)
        self.assertNotIn(TEXT_VA + 0x40, fcm.candidates)
        self.assertNotIn(TEXT_VA + 0x50, fcm.candidates)

    def test_opt_in_records_targets_as_weak_evidence(self):
        fcm = _manager_for(self._adr_blob(), use_address_refs=True)
        for target in (TEXT_VA + 0x40, TEXT_VA + 0x50):
            self.assertIn(target, fcm.candidates)
            # weak address evidence: no inbound call references were recorded
            self.assertEqual(fcm.candidates[target].call_ref_sources, set())


if __name__ == "__main__":
    unittest.main()
