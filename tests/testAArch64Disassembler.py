#!/usr/bin/python
"""Golden tests for the AArch64 backend (issue #2: arch-agnostic CFG engine).

Two synthetic functions exercise the full pipeline without committing a binary
fixture:

    f1 @ 0x401000:  stp x29, x30, [sp, #-16]!   ; frame-record prologue
                    bl  0x401010                ; direct call into f2
                    ldp x29, x30, [sp], #16
                    ret
    f2 @ 0x401010:  cbz x0, 0x401018            ; conditional branch
                    mov x0, #1
                    ret

Encodings were verified against capstone (CS_ARCH_ARM64). The ELF case is built
in-memory and exercised through FileLoader(map_file=True) per the repo's ELF
metadata testing convention.
"""

import hashlib
import struct
import unittest
from pathlib import Path

import lief

from smda.aarch64.AArch64Backend import AArch64Backend
from smda.aarch64.definitions import adrp_page_value
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.FileLoader import FileLoader

BASE = 0x401000
AARCH64_STATIC_FIXTURE = "aarch64_static_xored"
AARCH64_STATIC_SHA256 = "90e3b997161e33c6485b48182073a864dd3d0775ab96cadbf1b7c9dd4821c6d1"


def _load_xored_fixture(fixture_name):
    data = (Path(__file__).resolve().parent / fixture_name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


# little-endian 32-bit AArch64 encodings (verified via capstone disasm)
FIXTURE_WORDS = [
    0xA9BF7BFD,  # 0x401000  stp x29, x30, [sp, #-16]!
    0x94000003,  # 0x401004  bl  0x401010
    0xA8C17BFD,  # 0x401008  ldp x29, x30, [sp], #16
    0xD65F03C0,  # 0x40100c  ret
    0xB4000040,  # 0x401010  cbz x0, 0x401018
    0xD2800020,  # 0x401014  mov x0, #1
    0xD65F03C0,  # 0x401018  ret
]


def _fixture_code():
    return b"".join(w.to_bytes(4, "little") for w in FIXTURE_WORDS)


def _encode_b(source, target):
    return 0x14000000 | (((target - source) // 4) & 0x03FFFFFF)


def _encode_bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _build_aarch64_elf(code, base=0x400000, vaddr=0x401000):
    """Minimal little-endian ELF64/AArch64 object with one R+X PT_LOAD segment."""
    em_aarch64 = 183
    ehsize, phentsize = 64, 56
    code_off = ehsize + phentsize
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT
        2,  # e_type = ET_EXEC
        em_aarch64,  # e_machine = EM_AARCH64
        1,  # e_version
        vaddr,  # e_entry
        ehsize,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        ehsize,  # e_ehsize
        phentsize,  # e_phentsize
        1,  # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type = PT_LOAD
        5,  # p_flags = R+X
        code_off,  # p_offset
        vaddr,  # p_vaddr
        vaddr,  # p_paddr
        len(code),  # p_filesz
        len(code),  # p_memsz
        0x1000,  # p_align
    )
    return ehdr + phdr + code


def _build_aarch64_elf_with_init_array(text, init_pointers, base=0x400000, text_va=0x401000):
    """ELF64/AArch64 object carrying an .init_array of function pointers.

    Builds a section header table (.text exec + .init_array + .shstrtab) plus a
    single covering PT_LOAD, so the loader exposes sections and the candidate
    manager can read the .init_array entries.
    """
    em_aarch64, ehsize, phentsize, shentsize = 183, 64, 56, 64
    shstrtab = b"\x00.text\x00.init_array\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text")
    name_init = shstrtab.index(b".init_array")
    name_str = shstrtab.index(b".shstrtab")
    init_data = b"".join(struct.pack("<Q", p) for p in init_pointers)

    text_off = ehsize + phentsize
    init_off = text_off + len(text)
    shstr_off = init_off + len(init_data)
    sh_off = shstr_off + len(shstrtab)
    init_va = text_va + len(text)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,  # ET_EXEC
        em_aarch64,
        1,
        text_va,  # e_entry
        ehsize,  # e_phoff
        sh_off,  # e_shoff
        0,
        ehsize,
        phentsize,
        1,  # e_phnum
        shentsize,
        4,  # e_shnum
        3,  # e_shstrndx
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, sh_off, sh_off, 0x1000)

    def shdr(name, sh_type, flags, addr, offset, size, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, 0, 0, align, entsize)

    section_headers = (
        shdr(0, 0, 0, 0, 0, 0, 0, 0)  # SHT_NULL
        + shdr(name_text, 1, 0x6, text_va, text_off, len(text), 4, 0)  # PROGBITS, ALLOC|EXECINSTR
        + shdr(name_init, 14, 0x3, init_va, init_off, len(init_data), 8, 8)  # INIT_ARRAY, ALLOC|WRITE
        + shdr(name_str, 3, 0, 0, shstr_off, len(shstrtab), 1, 0)  # STRTAB
    )
    return ehdr + phdr + text + init_data + shstrtab + section_headers


class TestAArch64Disassembler(unittest.TestCase):
    def _disassemble_fixture(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = _fixture_code()
        disasm = Disassembler(config, backend="aarch64")
        return disasm.disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            architecture="aarch64",
        )

    def test_recovers_both_functions(self):
        report = self._disassemble_fixture()
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")
        self.assertEqual(report.bitness, 64)
        self.assertEqual({f.offset for f in report.getFunctions()}, {0x401000, 0x401010})

    def test_call_does_not_split_block_and_records_edge(self):
        report = self._disassemble_fixture()
        f1 = report.getFunction(0x401000)
        # the bl must NOT terminate the basic block: f1 is a single block of 4 ins
        self.assertEqual(f1.num_blocks, 1)
        self.assertEqual(f1.num_instructions, 4)
        # the call edge 0x401004 -> 0x401010 is recorded
        self.assertIn(0x401010, f1.outrefs[0x401004])
        # ... and f2 sees the inbound reference
        self.assertIn(0x401004, report.getFunction(0x401010).inrefs)

    def test_conditional_branch_has_two_successors(self):
        report = self._disassemble_fixture()
        f2 = report.getFunction(0x401010)
        self.assertEqual(f2.num_blocks, 3)
        blocks = {b.offset: b for b in f2.getBlocks()}
        self.assertEqual(set(blocks), {0x401010, 0x401014, 0x401018})
        # cbz x0, 0x401018 -> taken (0x401018) + fall-through (0x401014)
        self.assertEqual(set(blocks[0x401010].getSuccessors()), {0x401014, 0x401018})

    def test_returns_terminate_functions(self):
        report = self._disassemble_fixture()
        mnemonics = {ins.offset: ins.mnemonic for f in report.getFunctions() for ins in f.getInstructions()}
        self.assertEqual(mnemonics[0x40100C], "ret")
        self.assertEqual(mnemonics[0x401018], "ret")


class TestAArch64AuthenticatedReturns(unittest.TestCase):
    def _disassemble_words(self, words):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(w.to_bytes(4, "little") for w in words)
        return Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            architecture="aarch64",
        )

    def _assert_pac_return_terminates_before_next_prologue(self, return_word, return_mnemonic):
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                return_word,
                0xD503233F,  # paciasp
                0xD2800040,  # mov x0, #2
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0xC})

        first_function = report.getFunction(BASE)
        second_function = report.getFunction(BASE + 0xC)
        self.assertEqual(
            [ins.mnemonic for ins in first_function.getInstructions()], ["paciasp", "mov", return_mnemonic]
        )
        self.assertEqual([ins.mnemonic for ins in second_function.getInstructions()], ["paciasp", "mov", "ret"])

    def test_retaa_terminates_before_next_pac_prologue(self):
        self._assert_pac_return_terminates_before_next_prologue(0xD65F0BFF, "retaa")

    def test_retab_terminates_before_next_pac_prologue(self):
        self._assert_pac_return_terminates_before_next_prologue(0xD65F0FFF, "retab")

    def test_svc_remains_sequential(self):
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD4000001,  # svc #0
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        function = report.getFunction(BASE)
        self.assertEqual(function.num_blocks, 1)
        self.assertEqual([ins.mnemonic for ins in function.getInstructions()], ["paciasp", "svc", "mov", "ret"])


class TestAArch64PacAndAlwaysBranches(unittest.TestCase):
    """PAC branch families and always-true conditional branches.

    Verified live against capstone 5.0.7: braa/brab/braaz/brabz are indirect jumps
    (must end a block), blraa/blrab/blraaz/blrabz are indirect calls (must fall
    through), b.al/b.nv always branch (no live fall-through), and eret returns from
    an exception level (must terminate)."""

    def _disassemble_words(self, words):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(w.to_bytes(4, "little") for w in words)
        return Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            architecture="aarch64",
        )

    def test_pac_indirect_branch_terminates_block(self):
        # braa x1, x0 is an indirect jump: it ends the function, so the paciasp that
        # follows is recovered as a separate function (not booked into the first).
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD71F0820,  # braa x1, x0   (indirect jump)
                0xD503233F,  # paciasp
                0xD2800040,  # mov x0, #2
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0xC})
        self.assertEqual(
            [ins.mnemonic for ins in report.getFunction(BASE).getInstructions()],
            ["paciasp", "mov", "braa"],
        )

    def test_pac_indirect_call_falls_through(self):
        # blraa x1, x0 is an indirect call: it must NOT end the block, so the whole
        # routine stays a single function with the post-call instructions booked.
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD73F0820,  # blraa x1, x0  (indirect call)
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE})
        function = report.getFunction(BASE)
        self.assertEqual(function.num_blocks, 1)
        self.assertEqual(
            [ins.mnemonic for ins in function.getInstructions()],
            ["paciasp", "blraa", "mov", "ret"],
        )

    def test_always_branch_has_no_fallthrough(self):
        # b.al is spelled b.<cond> but always branches: the instruction it skips over
        # (the would-be fall-through) must NOT be booked into the function.
        report = self._disassemble_words(
            [
                0xD503233F,  # 0x401000 paciasp
                0x5400004E,  # 0x401004 b.al 0x40100c
                0xD2800060,  # 0x401008 mov x0, #3  (unreachable fall-through)
                0xD65F03C0,  # 0x40100c ret
            ]
        )
        self.assertEqual(report.status, "ok")
        instruction_offsets = [ins.offset for ins in report.getFunction(BASE).getInstructions()]
        self.assertEqual(instruction_offsets, [BASE, BASE + 0x4, BASE + 0xC])
        self.assertNotIn(BASE + 0x8, instruction_offsets)

    def test_exception_return_terminates_block(self):
        # eret returns from an exception level and carries no capstone groups; it must
        # still terminate the function like ret.
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD69F03E0,  # eret
                0xD503233F,  # paciasp
                0xD2800040,  # mov x0, #2
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0xC})
        self.assertEqual(
            [ins.mnemonic for ins in report.getFunction(BASE).getInstructions()],
            ["paciasp", "mov", "eret"],
        )


class TestAArch64BranchTarget(unittest.TestCase):
    """The branch destination is the LAST immediate operand (tbz/tbnz trap)."""

    def test_single_immediate_target(self):
        self.assertEqual(AArch64Backend._branchTarget("x0, #0x401018"), 0x401018)

    def test_last_immediate_wins_for_test_and_branch(self):
        # tbz <reg>, #<bit>, <target>: capstone renders the bit position before the
        # destination; taking the first immediate would mis-resolve the target.
        self.assertEqual(AArch64Backend._branchTarget("w0, #1, #0x401234"), 0x401234)
        self.assertEqual(AArch64Backend._branchTarget("w0, #0x1, #0x401234"), 0x401234)

    def test_indirect_branch_has_no_immediate_target(self):
        self.assertIsNone(AArch64Backend._branchTarget("x8"))


class TestAArch64PrologueDiscovery(unittest.TestCase):
    """Frame-less prologues are discovered with no inbound call reference.

    Beyond the frame-record store (stp x29,x30) the scanner recognizes the
    callee-saved GPR-pair save (stp x{19..28},x{19..28},[sp,#-imm]!) and the
    link-register save (str x30,[sp,#-imm]!) — verified against capstone 5.0.7.
    Both functions below are reachable only via the prologue scan (no BL targets
    them), mirroring functions reached through pointer tables in real binaries.
    """

    def _disassemble_words(self, words):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(w.to_bytes(4, "little") for w in words)
        return Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            architecture="aarch64",
        )

    def test_calleesaved_and_lr_save_prologues_are_function_starts(self):
        report = self._disassemble_words(
            [
                0xA9BE53F3,  # 0x401000 stp x19, x20, [sp, #-0x20]!   (callee-saved pair)
                0x52800000,  # 0x401004 mov w0, #0
                0xA8C253F3,  # 0x401008 ldp x19, x20, [sp], #0x20
                0xD65F03C0,  # 0x40100c ret
                0xF81F0FFE,  # 0x401010 str x30, [sp, #-0x10]!        (link-register save)
                0x52800020,  # 0x401014 mov w0, #1
                0xF84107FE,  # 0x401018 ldr x30, [sp], #0x10
                0xD65F03C0,  # 0x40101c ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0x10})


class TestAArch64FunctionBoundaries(unittest.TestCase):
    def _disassemble_words(self, words, oep=None):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(w.to_bytes(4, "little") for w in words)
        return Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            oep=oep,
            architecture="aarch64",
        )

    def test_backward_direct_branch_is_tailcall_candidate(self):
        wrapper = BASE + 0x10
        report = self._disassemble_words(
            [
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
                0xD503201F,  # nop
                0xD503201F,  # nop
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x910003FD,  # mov x29, sp
                _encode_b(wrapper + 0x8, BASE),  # b 0x401000
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, wrapper})
        self.assertEqual([ins.offset for ins in report.getFunction(BASE).getInstructions()], [BASE, BASE + 4])
        self.assertEqual(
            [ins.offset for ins in report.getFunction(wrapper).getInstructions()], [wrapper, wrapper + 4, wrapper + 8]
        )

    def test_conditional_branch_to_prologue_like_block_stays_in_function(self):
        report = self._disassemble_words(
            [
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x35000060,  # cbnz w0, 0x401010
                0x52800000,  # mov w0, #0
                0xD65F03C0,  # ret
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x910003FD,  # mov x29, sp
                0xA8C17BFD,  # ldp x29, x30, [sp], #16
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE})
        function = report.getFunction(BASE)
        self.assertEqual(function.num_blocks, 3)
        self.assertEqual(
            {block.offset for block in function.getBlocks()},
            {BASE, BASE + 0x8, BASE + 0x10},
        )

    def test_short_no_frame_branch_stub_promotes_target(self):
        target = BASE + 0x80
        report = self._disassemble_words(
            [
                0x52800001,  # mov w1, #0
                _encode_b(BASE + 4, target),  # b 0x401080
                *([0xD503201F] * 30),  # alignment / padding gap
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ],
            oep=0,
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, target})
        self.assertEqual([ins.offset for ins in report.getFunction(BASE).getInstructions()], [BASE, BASE + 4])
        self.assertEqual([ins.offset for ins in report.getFunction(target).getInstructions()], [target, target + 4])

    def test_nearby_no_frame_branch_stays_in_function(self):
        target = BASE + 0x10
        report = self._disassemble_words(
            [
                0x52800001,  # mov w1, #0
                _encode_b(BASE + 4, target),  # b 0x401010
                0xD503201F,  # nop
                0xD503201F,  # nop
                0xA9005013,  # stp x19, x20, [x0]
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ],
            oep=0,
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE})
        self.assertEqual(
            [block.offset for block in report.getFunction(BASE).getBlocks()],
            [BASE, target],
        )

    def test_call_fallthrough_padding_before_prologue_terminates_function(self):
        second = BASE + 0x10
        report = self._disassemble_words(
            [
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                _encode_bl(BASE + 4, BASE),  # bl 0x401000
                0xD503201F,  # nop
                0xD503201F,  # nop
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x910003FD,  # mov x29, sp
                0xA8C17BFD,  # ldp x29, x30, [sp], #16
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, second})
        self.assertEqual([ins.offset for ins in report.getFunction(BASE).getInstructions()], [BASE, BASE + 4])
        self.assertEqual(
            [ins.offset for ins in report.getFunction(second).getInstructions()],
            [second, second + 4, second + 8, second + 0xC],
        )

    def test_call_fallthrough_padding_before_aligned_non_frame_function(self):
        second = BASE + 0x10
        report = self._disassemble_words(
            [
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                _encode_bl(BASE + 4, BASE),  # bl 0x401000
                0xD503201F,  # nop
                0xD503201F,  # nop
                0xA9BC53F3,  # stp x19, x20, [sp, #-64]!
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, second})
        self.assertEqual([ins.offset for ins in report.getFunction(BASE).getInstructions()], [BASE, BASE + 4])
        self.assertEqual(
            [ins.offset for ins in report.getFunction(second).getInstructions()],
            [second, second + 4, second + 8],
        )

    def test_call_fallthrough_directly_before_prologue_terminates_function(self):
        second = BASE + 0x8
        report = self._disassemble_words(
            [
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                _encode_bl(BASE + 4, BASE),  # bl 0x401000
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x910003FD,  # mov x29, sp
                0xA8C17BFD,  # ldp x29, x30, [sp], #16
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, second})
        self.assertEqual([ins.offset for ins in report.getFunction(BASE).getInstructions()], [BASE, BASE + 4])
        self.assertEqual(
            [ins.offset for ins in report.getFunction(second).getInstructions()],
            [second, second + 4, second + 8, second + 0xC],
        )


class TestAArch64ElfLoader(unittest.TestCase):
    """Issue #2 core bug: getBitness returned 0 for AArch64 (machine type unmapped)."""

    def setUp(self):
        self.blob = _build_aarch64_elf(_fixture_code())

    def test_machine_type_is_aarch64(self):
        parsed = lief.parse(self.blob)
        self.assertEqual(parsed.header.machine_type, lief.ELF.ARCH.AARCH64)

    def test_loader_reports_aarch64_and_64bit(self):
        loader = FileLoader("/", map_file=True)
        loader._loadFile(self.blob)
        self.assertEqual(loader.getArchitecture(), "aarch64")
        self.assertEqual(loader.getBitness(), 64)

    def test_static_loader_accessors(self):
        self.assertEqual(ElfFileLoader.getArchitecture(self.blob), "aarch64")
        self.assertEqual(ElfFileLoader.getBitness(self.blob), 64)
        code_areas = ElfFileLoader.getCodeAreas(self.blob)
        self.assertTrue(any(start <= 0x401000 < end for start, end in code_areas))


class TestAArch64DataPointerRecovery(unittest.TestCase):
    """Functions reachable only through stored pointers are recovered.

    The constructor below has no recognized prologue and no inbound BL; it is
    discoverable only via its .init_array entry, so its recovery proves the
    data-pointer pass works end to end through FileLoader(map_file=True).
    """

    def test_init_array_pointer_is_recovered(self):
        text_va = 0x401000
        ctor_va = text_va + 0x10
        text = b"".join(
            w.to_bytes(4, "little")
            for w in [
                0xA9BF7BFD,  # 0x401000 main: stp x29, x30, [sp, #-16]!
                0x52800000,  # 0x401004      mov w0, #0
                0xA8C17BFD,  # 0x401008      ldp x29, x30, [sp], #16
                0xD65F03C0,  # 0x40100c      ret
                0xD2800020,  # 0x401010 ctor: mov x0, #1   (no prologue, no BL target)
                0xD65F03C0,  # 0x401014      ret
                0xD503201F,  # 0x401018      nop
                0xD503201F,  # 0x40101c      nop
            ]
        )
        blob = _build_aarch64_elf_with_init_array(text, [ctor_va], text_va=text_va)

        loader = FileLoader("/", map_file=True)
        loader._loadFile(blob)
        self.assertEqual(loader.getArchitecture(), "aarch64")

        config = SmdaConfig()
        config.WITH_STRINGS = False
        report = Disassembler(config).disassembleUnmappedBuffer(blob)
        self.assertEqual(report.status, "ok")
        self.assertIsNotNone(report.getFunction(text_va))
        self.assertIsNotNone(report.getFunction(ctor_va))


class TestAArch64AddressMaterialization(unittest.TestCase):
    """adrp page resolution used by the address-reference recovery pass."""

    def test_adrp_page_value_matches_capstone(self):
        # real .text adrp encodings from the fixture, cross-checked vs capstone 5.0.7
        self.assertEqual(adrp_page_value(0xF00000E0, 0x400630), 0x41F000)  # adrp x0, #0x41f000
        self.assertEqual(adrp_page_value(0x900000E0, 0x400644), 0x41C000)  # adrp x0, #0x41c000

    def test_adrp_page_value_rounds_to_pc_page(self):
        # the page is relative to the PC's 4 KiB page (low 12 bits cleared)
        self.assertEqual(adrp_page_value(0xF00000E0, 0x400630) & 0xFFF, 0)
        # a zero immediate yields the PC's own page regardless of PC offset within it
        self.assertEqual(adrp_page_value(0x90000000, 0x401ABC), 0x401000)


class TestAArch64GapScan(unittest.TestCase):
    """A function reached by nothing else is recovered by the gap scan.

    f2 below has no recognized prologue, no inbound BL, and no stored pointer; it
    sits in the gap after f1 and is discoverable only by the linear gap sweep.
    """

    def test_unreferenced_function_recovered_in_gap(self):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(
            w.to_bytes(4, "little")
            for w in [
                0xA9BF7BFD,  # 0x401000 f1: stp x29, x30, [sp, #-16]!  (prologue -> found)
                0x52800000,  # 0x401004     mov w0, #0
                0xA8C17BFD,  # 0x401008     ldp x29, x30, [sp], #16
                0xD65F03C0,  # 0x40100c     ret
                0xD503201F,  # 0x401010     nop  (inter-function padding)
                0xD2800CE0,  # 0x401014 f2: mov x0, #0x67   (no prologue / ref / pointer)
                0xD65F03C0,  # 0x401018     ret
            ]
        )
        report = Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            architecture="aarch64",
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0x14})


class TestAArch64StaticFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_path = Path(__file__).resolve().parent / AARCH64_STATIC_FIXTURE
        cls.xored_binary = cls.fixture_path.read_bytes()
        cls.binary = _load_xored_fixture(AARCH64_STATIC_FIXTURE)
        cls.loader = FileLoader("/", map_file=True)
        cls.loader._loadFile(cls.binary)

        config = SmdaConfig()
        config.TIMEOUT = 20
        config.WITH_STRINGS = False
        config.STORE_BUFFER = False
        cls.report = Disassembler(config).disassembleUnmappedBuffer(cls.binary)

    def test_fixture_is_xored_aarch64_elf(self):
        self.assertNotEqual(self.xored_binary[:4], b"\x7fELF")
        self.assertEqual(self.binary[:4], b"\x7fELF")
        self.assertEqual(len(self.binary), 128592)
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), AARCH64_STATIC_SHA256)

    def test_real_fixture_loader_metadata(self):
        self.assertEqual(self.loader.getArchitecture(), "aarch64")
        self.assertEqual(self.loader.getBitness(), 64)
        self.assertEqual(self.loader.getBaseAddress(), 0x400000)
        self.assertEqual(self.loader.getAbi(), "SYSTEMV")
        self.assertEqual(len(self.loader.getData()), 151552)
        self.assertTrue(any(start <= 0x400534 < end for start, end in self.loader.getCodeAreas()))

    def test_real_fixture_disassembly_summary(self):
        self.assertEqual(self.report.status, "ok")
        self.assertEqual(self.report.architecture, "aarch64")
        self.assertEqual(self.report.bitness, 64)
        self.assertEqual(self.report.base_addr, 0x400000)
        self.assertEqual(self.report.oep, 0x400534)
        self.assertEqual(len(self.report.xcfg), 278)
        self.assertEqual(sum(1 for f in self.report.getFunctions() for _ in f.getInstructions()), 19881)
        self.assertEqual(sum(1 for f in self.report.getFunctions() for _ in f.getBlocks()), 3525)
        self.assertIsNotNone(self.report.getFunction(0x400534))

    def test_real_fixture_gap_scan_recovery(self):
        # Functions recovered only by the gap scan (#3): unreferenced / indirect-only
        # routines that no BL, prologue, or stored pointer reaches. With the gap scan
        # every Binary Ninja function start is now recovered.
        for function_start in (0x40CFE0, 0x40DD78, 0x40DF34, 0x40F370, 0x410B24, 0x41150C, 0x411590, 0x4134D0):
            self.assertIsNotNone(self.report.getFunction(function_start), f"missing 0x{function_start:x}")

    def test_real_fixture_data_pointer_recovery(self):
        # init_array / data pointer-table functions recovered by #2, none of which
        # is reachable via a direct BL or a recognized prologue.
        for function_start in (0x400180, 0x400630, 0x401600, 0x401670):
            self.assertIsNotNone(self.report.getFunction(function_start), f"missing 0x{function_start:x}")
        # the .init_array pointer anchors _INIT_0's true entry (0x400630), so the
        # prologue scan no longer mislabels its inner frame-record block (0x40063c).
        self.assertIsNone(self.report.getFunction(0x40063C))

    def test_real_fixture_binja_boundary_regressions(self):
        expected_function_starts = {
            0x400570,
            0x4005A0,
            0x402740,
            0x401F60,
            0x4108DC,
            0x412200,
            0x412230,
            0x412260,
            0x412384,
            0x413758,
        }
        for function_start in expected_function_starts:
            self.assertIsNotNone(self.report.getFunction(function_start), f"missing 0x{function_start:x}")

        self.assertIsNone(self.report.getFunction(0x40CA70))
        self.assertIsNone(self.report.getFunction(0x410218))

        entry_instructions = {ins.offset for ins in self.report.getFunction(0x400534).getInstructions()}
        self.assertNotIn(0x400570, entry_instructions)

        caller_instructions = {ins.offset for ins in self.report.getFunction(0x4031E0).getInstructions()}
        self.assertNotIn(0x402740, caller_instructions)

    def test_real_fixture_report_roundtrip(self):
        roundtrip = SmdaReport.fromDict(self.report.toDict())
        self.assertEqual(roundtrip.status, "ok")
        self.assertEqual(roundtrip.architecture, "aarch64")
        self.assertEqual(roundtrip.bitness, 64)
        self.assertEqual(roundtrip.oep, 0x400534)
        self.assertEqual(len(roundtrip.xcfg), 278)


if __name__ == "__main__":
    unittest.main()
