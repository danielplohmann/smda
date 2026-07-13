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
from types import SimpleNamespace

import lief

from smda.aarch64.AArch64Backend import AArch64Backend
from smda.aarch64.AArch64CapstoneVerification import is_control_flow_mnemonic
from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.aarch64.definitions import EXCEPTION_RETURN_INS, adrp_page_value, is_conditional_branch
from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
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
    """Minimal little-endian ELF64/AArch64 object with one R+X PT_LOAD segment and sections."""
    em_aarch64, ehsize, phentsize, shentsize = 183, 64, 56, 64
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text")
    name_str = shstrtab.index(b".shstrtab")

    text_off = ehsize + phentsize
    shstr_off = text_off + len(code)
    sh_off = shstr_off + len(shstrtab)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT
        2,  # e_type = ET_EXEC
        em_aarch64,  # e_machine = EM_AARCH64
        1,  # e_version
        vaddr,  # e_entry
        ehsize,  # e_phoff
        sh_off,  # e_shoff
        0,  # e_flags
        ehsize,  # e_ehsize
        phentsize,  # e_phentsize
        1,  # e_phnum
        shentsize,  # e_shentsize
        3,  # e_shnum
        2,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type = PT_LOAD
        5,  # p_flags = R+X
        0,  # p_offset
        base,  # p_vaddr
        base,  # p_paddr
        sh_off,  # p_filesz
        sh_off,  # p_memsz
        0x1000,  # p_align
    )

    def shdr(name, sh_type, flags, addr, offset, size, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, 0, 0, align, entsize)

    section_headers = (
        shdr(0, 0, 0, 0, 0, 0, 0, 0)  # SHT_NULL
        + shdr(name_text, 1, 0x6, vaddr, text_off, len(code), 4, 0)  # PROGBITS, ALLOC|EXECINSTR
        + shdr(name_str, 3, 0, 0, shstr_off, len(shstrtab), 1, 0)  # STRTAB
    )
    return ehdr + phdr + code + shstrtab + section_headers


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


class TestAArch64HintedConditionalBranch(unittest.TestCase):
    """FEAT_HBC's hinted conditional branch bc.<cond> (ARMv8.8/9.3).

    Capstone decodes bc.eq/bc.ne/... distinctly from b.eq/b.ne/... (mnemonic
    prefix "bc." instead of "b."), with the encoding differing only in bit 4
    (o1/hint bit). Every "is this a conditional branch" check in the AArch64
    backend must recognize both prefixes, and the raw-encoding gap-scan mask
    must match bit 4 set or unset. Verified live against capstone 5.0.7:
    bytes 10 00 00 54 decode to mnemonic 'bc.eq', op_str '#0x401000', groups [].
    """

    @staticmethod
    def _encode_bc_cond(source, target, cond, hint=1):
        imm19 = ((target - source) // 4) & 0x7FFFF
        return 0x54000000 | (imm19 << 5) | (hint << 4) | cond

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

    def test_is_control_flow_mnemonic_recognizes_bc_cond_forms(self):
        for mnemonic in ("bc.eq", "bc.ne", "bc.al", "bc.nv", "bc.gt"):
            self.assertTrue(is_control_flow_mnemonic(mnemonic), mnemonic)

    def test_is_conditional_branch_matches_hinted_encoding(self):
        # bc.eq: bit 4 (hint/o1) is set, distinguishing it from plain b.eq.
        word = self._encode_bc_cond(BASE, BASE + 0xC, cond=0x0, hint=1)
        self.assertEqual(word, 0x54000070)
        self.assertTrue(is_conditional_branch(word))
        # This is exactly the bit-4-set case the pre-fix BCOND_MASK (0xFF000010,
        # which required bit 4 clear) excluded: confirm the bit really is set,
        # i.e. the old mask would have missed this word.
        self.assertNotEqual(word & 0xFF000010, 0x54000000)
        self.assertEqual(word & 0x10, 0x10)

    def test_conditional_branch_has_two_successors(self):
        # mirrors TestAArch64Disassembler.test_conditional_branch_has_two_successors,
        # substituting bc.eq (hinted) for cbz.
        target = BASE + 0xC
        report = self._disassemble_words(
            [
                self._encode_bc_cond(BASE, target, cond=0x0),  # bc.eq 0x40100c
                0xD2800020,  # 0x401004 mov x0, #1
                0xD65F03C0,  # 0x401008 ret
                0xD65F03C0,  # 0x40100c ret
            ],
            oep=0,
        )
        self.assertEqual(report.status, "ok")
        function = report.getFunction(BASE)
        self.assertEqual(function.num_blocks, 3)
        blocks = {b.offset: b for b in function.getBlocks()}
        self.assertEqual(set(blocks), {BASE, BASE + 0x4, target})
        # bc.eq #0x40100c -> taken (target) + fall-through (BASE + 0x4)
        self.assertEqual(set(blocks[BASE].getSuccessors()), {BASE + 0x4, target})

    def test_bc_always_branch_has_no_fallthrough(self):
        # bc.al always branches (like b.al): the skipped-over fall-through
        # instruction must NOT be booked into the function.
        report = self._disassemble_words(
            [
                0xD503233F,  # 0x401000 paciasp
                self._encode_bc_cond(BASE + 0x4, BASE + 0xC, cond=0xE),  # 0x401004 bc.al 0x40100c
                0xD2800060,  # 0x401008 mov x0, #3  (unreachable fall-through)
                0xD65F03C0,  # 0x40100c ret
            ]
        )
        self.assertEqual(report.status, "ok")
        instruction_offsets = [ins.offset for ins in report.getFunction(BASE).getInstructions()]
        self.assertEqual(instruction_offsets, [BASE, BASE + 0x4, BASE + 0xC])
        self.assertNotIn(BASE + 0x8, instruction_offsets)

    def test_escaper_classifies_bc_cond_as_control_flow(self):
        target = BASE + 0xC
        report = self._disassemble_words(
            [
                self._encode_bc_cond(BASE, target, cond=0x0),  # bc.eq 0x40100c
                0xD2800020,  # mov x0, #1
                0xD65F03C0,  # ret
                0xD65F03C0,  # ret
            ],
            oep=0,
        )
        self.assertEqual(report.status, "ok")
        instruction = next(iter(report.getFunction(BASE).getInstructions()))
        self.assertEqual(instruction.mnemonic, "bc.eq")
        self.assertEqual(AArch64InstructionEscaper.escapeMnemonicForInstruction(instruction), "C")


class TestAArch64DrpsExceptionReturn(unittest.TestCase):
    """drps (Debug Restore PState) carries no capstone groups and 0 operands,
    same class as eret/brk/hlt/udf: it must be special-cased by mnemonic since
    capstone gives no group signal, and it transfers control to ELR_ELx."""

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

    def test_drps_in_exception_return_ins(self):
        self.assertIn("drps", EXCEPTION_RETURN_INS)

    def test_is_control_flow_mnemonic_recognizes_drps(self):
        self.assertTrue(is_control_flow_mnemonic("drps"))

    def test_drps_terminates_block(self):
        # mirrors TestAArch64PacAndAlwaysBranches.test_exception_return_terminates_block,
        # substituting drps for eret.
        report = self._disassemble_words(
            [
                0xD503233F,  # paciasp
                0xD2800020,  # mov x0, #1
                0xD6BF03E0,  # drps
                0xD503233F,  # paciasp
                0xD2800040,  # mov x0, #2
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0xC})
        self.assertEqual(
            [ins.mnemonic for ins in report.getFunction(BASE).getInstructions()],
            ["paciasp", "mov", "drps"],
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


class TestAArch64PltResolution(unittest.TestCase):
    def _build_disassembler(self, prefixes=None):
        base = 0x400000
        plt = 0x402000
        got_slot = 0x403018
        mapped = bytearray(got_slot - base + 8)
        prefixes = prefixes or []
        plt_words = prefixes + [
            0xB0000010,  # adrp x16, #0x403000
            0xF9400E11,  # ldr x17, [x16, #0x18]
            0x91006210,  # add x16, x16, #0x18
            0xD61F0220,  # br x17
        ]
        for index, word in enumerate(plt_words):
            offset = plt - base + index * 4
            mapped[offset : offset + 4] = word.to_bytes(4, "little")

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.raw_data = b""
        binary_info._lief_binary = SimpleNamespace(
            sections=[SimpleNamespace(name=".plt", virtual_address=plt, size=len(plt_words) * 4)]
        )

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info

        class FakeDisassembler:
            def __init__(self, disassembly_result):
                self.disassembly = disassembly_result
                self.api_targets = []
                self.call_targets = []

            def _handleApiTarget(self, from_addr, to_addr, dereferenced):
                self.api_targets.append((from_addr, to_addr, dereferenced))
                return ("GLIBC_2.2.5", "puts")

            def _handleCallTarget(self, state, from_addr, to_addr):
                self.call_targets.append((from_addr, to_addr))

        return FakeDisassembler(disassembly), plt, got_slot

    def test_elf_loader_reports_plt_ranges(self):
        fake_elf = SimpleNamespace(
            sections=[
                SimpleNamespace(name=".text", virtual_address=0x401000, size=0x100),
                SimpleNamespace(name=".plt", virtual_address=0x402000, size=0x40),
            ]
        )
        self.assertEqual(ElfFileLoader.getPltRanges(b"", parsed=fake_elf), [(0x402000, 0x402040)])

    def test_aarch64_plt_stub_resolves_got_slot(self):
        fake_disassembler, plt, got_slot = self._build_disassembler()

        self.assertEqual(AArch64Backend._resolvePltGotSlot(fake_disassembler, plt), got_slot)

    def test_aarch64_plt_stub_resolves_after_bti_and_nop_prefixes(self):
        fake_disassembler, plt, got_slot = self._build_disassembler(
            prefixes=[
                0xD503245F,  # bti c
                0xD503201F,  # nop
            ]
        )

        self.assertEqual(AArch64Backend._resolvePltGotSlot(fake_disassembler, plt), got_slot)

    def test_bl_to_plt_stub_records_api_reference(self):
        fake_disassembler, plt, got_slot = self._build_disassembler()

        class FakeState:
            def __init__(self):
                self.leaf = True
                self.code_refs = []

            def setLeaf(self, value):
                self.leaf = value

            def addCodeRef(self, from_addr, to_addr, by_jump=False):
                self.code_refs.append((from_addr, to_addr, by_jump))

        state = FakeState()
        call_addr = BASE
        backend = AArch64Backend()
        backend.analyzeInstruction(fake_disassembler, (call_addr, 4, "bl", f"#0x{plt:x}"), state, None, call_addr)

        self.assertFalse(state.leaf)
        self.assertEqual(fake_disassembler.api_targets, [(call_addr, got_slot, got_slot)])
        self.assertEqual(fake_disassembler.call_targets, [])
        self.assertEqual(state.code_refs, [(call_addr, plt, False)])

    def test_analyzing_plt_stub_as_function_records_api_on_br(self):
        # When the PLT entry itself is recovered as a function, the terminal br
        # must attribute the GOT import (so isApiThunk can see the apiref).
        fake_disassembler, plt, got_slot = self._build_disassembler()
        br_addr = plt + 12  # adrp; ldr; add; br

        class FakeState:
            def __init__(self, start_addr):
                self.start_addr = start_addr
                self.sanely_ending = False
                self.next_reachable = True
                self.block_ending = False
                self.thunk_call = False
                self.queue = []
                self.code_refs = []

            def setSanelyEnding(self, value=True):
                self.sanely_ending = value

            def setNextInstructionReachable(self, value):
                self.next_reachable = value

            def setBlockEndingInstruction(self, value=True):
                self.block_ending = value

            def setThunkCall(self, value=True):
                self.thunk_call = value

            def addBlockToQueue(self, addr):
                self.queue.append(addr)

            def addCodeRef(self, from_addr, to_addr, by_jump=False):
                self.code_refs.append((from_addr, to_addr, by_jump))

        state = FakeState(plt)
        backend = AArch64Backend()
        backend.analyzeInstruction(fake_disassembler, (br_addr, 4, "br", "x17"), state, None, plt)

        self.assertEqual(fake_disassembler.api_targets, [(br_addr, got_slot, got_slot)])
        self.assertTrue(state.sanely_ending)
        self.assertFalse(state.next_reachable)
        self.assertTrue(state.block_ending)
        # the whole function body is exactly the adrp/ldr/add/br thunk shape, so
        # the merged upstream thunk_functions classification must also fire here.
        self.assertTrue(state.thunk_call)
        self.assertEqual(state.queue, [])
        self.assertEqual(state.code_refs, [])

    def test_uncond_branch_tailcall_to_plt_stub_records_api_reference(self):
        # A thin wrapper that tail-calls an import via a bare unconditional branch
        # (instead of "bl") must resolve through the same PLT/Mach-O-stub decode as
        # the bl-call case (sibling of PAT-SMDA-004, caught by the mandatory sweep).
        fake_disassembler, plt, got_slot = self._build_disassembler()
        fake_disassembler.tailcall_analyzer = SimpleNamespace(addJump=lambda *args, **kwargs: None)
        fake_disassembler.fc_manager = SimpleNamespace(getFunctionStartCandidates=lambda: set())

        class FakeState:
            def __init__(self, start_addr):
                self.start_addr = start_addr
                self.num_blocks_analyzed = 1
                self.sanely_ending = False
                self.code_refs = []

            def setSanelyEnding(self, value):
                self.sanely_ending = value

            def setNextInstructionReachable(self, value):
                pass

            def setBlockEndingInstruction(self, value):
                pass

            def addCodeRef(self, from_addr, to_addr, by_jump=False):
                self.code_refs.append((from_addr, to_addr, by_jump))

        branch_addr = BASE
        state = FakeState(branch_addr)
        backend = AArch64Backend()
        backend.analyzeInstruction(fake_disassembler, (branch_addr, 4, "b", f"#0x{plt:x}"), state, None, branch_addr)

        self.assertTrue(state.sanely_ending)
        self.assertEqual(fake_disassembler.api_targets, [(branch_addr, got_slot, got_slot)])
        self.assertEqual(state.code_refs, [(branch_addr, plt, True)])


class TestAArch64ApiThunkDetection(unittest.TestCase):
    """danielplohmann/smda#172: a function whose entire body is the canonical
    adrp; [add;] ldr; br GOT/API-import thunk (optionally nop/bti-prefixed) is
    flagged via state.setThunkCall(True), landing in disassembly.thunk_functions."""

    def _disassemble_words(self, words, oep=0):
        config = SmdaConfig()
        config.WITH_STRINGS = False
        code = b"".join(w.to_bytes(4, "little") for w in words)
        disassembler = Disassembler(config, backend="aarch64")
        report = disassembler.disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            oep=oep,
            architecture="aarch64",
        )
        return report, disassembler.disassembly

    def test_walk_got_thunk_three_instructions(self):
        words = [
            0x90000010,  # adrp x16, #0
            0xF9400210,  # ldr x16, [x16]
            0xD61F0200,  # br x16
        ]
        code = b"".join(w.to_bytes(4, "little") for w in words)
        binary_info = BinaryInfo(code)
        binary_info.base_addr = BASE
        fake_disassembler = SimpleNamespace(disassembly=SimpleNamespace(binary_info=binary_info))
        fake_disassembler.disassembly.isAddrWithinMemoryImage = lambda addr: BASE <= addr < BASE + len(code)

        result = AArch64Backend._walkGotThunk(fake_disassembler, BASE)

        self.assertIsNotNone(result)
        end_addr, _target = result
        self.assertEqual(end_addr, BASE + len(words) * 4)

    def test_three_instruction_thunk_is_flagged(self):
        report, disassembly = self._disassemble_words(
            [
                0x90000010,  # adrp x16, #0
                0xF9400210,  # ldr x16, [x16]
                0xD61F0200,  # br x16
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertIn(BASE, disassembly.thunk_functions)

    def test_four_instruction_thunk_with_add_is_flagged(self):
        report, disassembly = self._disassemble_words(
            [
                0x90000010,  # adrp x16, #0
                0x91000210,  # add x16, x16, #0
                0xF9400210,  # ldr x16, [x16]
                0xD61F0200,  # br x16
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertIn(BASE, disassembly.thunk_functions)

    def test_bti_prefixed_thunk_is_flagged(self):
        report, disassembly = self._disassemble_words(
            [
                0xD503245F,  # bti c
                0x90000010,  # adrp x16, #0
                0xF9400210,  # ldr x16, [x16]
                0xD61F0200,  # br x16
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertIn(BASE, disassembly.thunk_functions)

    def test_normal_function_with_more_than_thunk_body_is_not_flagged(self):
        # a real prologue precedes the adrp/ldr/br shape: not a thunk.
        report, disassembly = self._disassemble_words(
            [
                0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
                0x90000010,  # adrp x16, #0
                0xF9400210,  # ldr x16, [x16]
                0xD61F0200,  # br x16
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertNotIn(BASE, disassembly.thunk_functions)


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

    def test_pac_and_bti_entries_are_function_starts(self):
        report = self._disassemble_words(
            [
                0xD503231F,  # 0x401000 paciaz
                0x52800000,  # 0x401004 mov w0, #0
                0xD65F03C0,  # 0x401008 ret
                0xD503245F,  # 0x40100c bti c
                0x52800020,  # 0x401010 mov w0, #1
                0xD65F03C0,  # 0x401014 ret
                0xD503237F,  # 0x401018 pacibsp
                0x52800040,  # 0x40101c mov w0, #2
                0xD65F03C0,  # 0x401020 ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertEqual({f.offset for f in report.getFunctions()}, {BASE, BASE + 0xC, BASE + 0x18})


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

    def test_bti_landing_pad_inside_function_does_not_split(self):
        report = self._disassemble_words(
            [
                0xD503233F,  # 0x401000 paciasp
                0x35000060,  # 0x401004 cbnz w0, 0x401010
                0x52800021,  # 0x401008 mov w1, #1
                0xD503245F,  # 0x40100c bti c
                0x52800000,  # 0x401010 mov w0, #0
                0xD65F03C0,  # 0x401014 ret
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
        self.assertIsNone(report.getFunction(BASE + 0xC))

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


class TestAArch64StringExtraction(unittest.TestCase):
    def test_adr_data_reference_recovers_ascii_string(self):
        config = SmdaConfig()
        config.WITH_STRINGS = True
        code = b"".join(
            word.to_bytes(4, "little")
            for word in [
                0x10000080,  # adr x0, #0x401010
                0xD65F03C0,  # ret
            ]
        )
        blob = code + b"\x00" * 8 + b"hello-a64\x00"

        report = Disassembler(config, backend="aarch64").disassembleBuffer(
            blob,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            oep=0,
            architecture="aarch64",
        )

        self.assertEqual(report.status, "ok")
        function = report.getFunction(BASE)
        self.assertEqual(report.data_refs_from[BASE], [BASE + 0x10])
        self.assertEqual(
            function.stringrefs,
            [{"string": "hello-a64", "ins_addr": BASE, "data_addr": BASE + 0x10, "type": "ascii"}],
        )


class TestAArch64StackStringRecovery(unittest.TestCase):
    """danielplohmann/smda#173: strings built byte-by-byte on the stack via
    tracked-register stores (str/strb/strh/stur* and stp) are reconstructed and
    recorded into disassembly.stringrefs / SmdaFunction.stringrefs, same as
    dalvik/cil's own addStringRef-backed (non-buffer) strings."""

    def _disassemble_words(self, words, with_strings=True):
        config = SmdaConfig()
        config.WITH_STRINGS = with_strings
        code = b"".join(w.to_bytes(4, "little") for w in words)
        return Disassembler(config, backend="aarch64").disassembleBuffer(
            code,
            base_addr=BASE,
            bitness=64,
            code_areas=[[BASE, BASE + len(code)]],
            oep=0,
            architecture="aarch64",
        )

    def test_string_built_byte_by_byte_via_strb_is_recovered(self):
        report = self._disassemble_words(
            [
                0x52800908,  # mov w8, #0x48 ('H')
                0x390003E8,  # strb w8, [sp]
                0x52800CA8,  # mov w8, #0x65 ('e')
                0x390007E8,  # strb w8, [sp, #1]
                0x52800D88,  # mov w8, #0x6c ('l')
                0x39000BE8,  # strb w8, [sp, #2]
                0x52800D88,  # mov w8, #0x6c ('l')
                0x39000FE8,  # strb w8, [sp, #3]
                0x52800DE8,  # mov w8, #0x6f ('o')
                0x390013E8,  # strb w8, [sp, #4]
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertIn(
            {"string": "Hello", "ins_addr": BASE + 4, "data_addr": None, "type": "stack"},
            report.getFunction(BASE).stringrefs,
        )

    def test_string_built_via_stp_register_pair_is_recovered(self):
        report = self._disassemble_words(
            [
                0x528CA908,  # mov w8, #0x6548
                0x72AD8D88,  # movk w8, #0x6c6c, lsl #16   (w8 = 0x6C6C6548 = "Hell", little-endian)
                0x52842DE9,  # mov w9, #0x216f
                0x72A00009,  # movk w9, #0, lsl #16        (w9 = 0x0000216F = "o!\0\0", little-endian)
                0x290027E8,  # stp w8, w9, [sp]
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        self.assertIn(
            {"string": "Hello!", "ins_addr": BASE + 0x10, "data_addr": None, "type": "stack"},
            report.getFunction(BASE).stringrefs,
        )

    def test_gated_by_with_strings_config(self):
        report = self._disassemble_words(
            [
                0x52800908,  # mov w8, #0x48 ('H')
                0x390003E8,  # strb w8, [sp]
                0x52800CA8,  # mov w8, #0x65 ('e')
                0x390007E8,  # strb w8, [sp, #1]
                0x52800D88,  # mov w8, #0x6c ('l')
                0x39000BE8,  # strb w8, [sp, #2]
                0x52800D88,  # mov w8, #0x6c ('l')
                0x39000FE8,  # strb w8, [sp, #3]
                0x52800DE8,  # mov w8, #0x6f ('o')
                0x390013E8,  # strb w8, [sp, #4]
                0xD65F03C0,  # ret
            ],
            with_strings=False,
        )
        self.assertEqual(report.status, "ok")
        self.assertFalse(report.getFunction(BASE).stringrefs)

    def test_stack_pointer_mutation_resets_stale_offsets(self):
        # "Test" is written at offsets 0-3 relative to the ORIGINAL sp; "sub sp,
        # sp, #16" then moves sp, so "Data" at offsets 0-3 afterwards is a
        # PHYSICALLY DIFFERENT stack slot even though the numeric offsets repeat.
        # Without resetting tracked offsets on the sp mutation, "Data"'s writes
        # would silently overwrite the same dict keys "Test" used, losing "Test"
        # entirely (never flushed) instead of producing two separate strings.
        report = self._disassemble_words(
            [
                0x52800A88,  # mov w8, #0x54 ('T')
                0x390003E8,  # strb w8, [sp]
                0x52800CA8,  # mov w8, #0x65 ('e')
                0x390007E8,  # strb w8, [sp, #1]
                0x52800E68,  # mov w8, #0x73 ('s')
                0x39000BE8,  # strb w8, [sp, #2]
                0x52800E88,  # mov w8, #0x74 ('t')
                0x39000FE8,  # strb w8, [sp, #3]
                0xD10043FF,  # sub sp, sp, #0x10
                0x52800888,  # mov w8, #0x44 ('D')
                0x390003E8,  # strb w8, [sp]
                0x52800C28,  # mov w8, #0x61 ('a')
                0x390007E8,  # strb w8, [sp, #1]
                0x52800E88,  # mov w8, #0x74 ('t')
                0x39000BE8,  # strb w8, [sp, #2]
                0x52800C28,  # mov w8, #0x61 ('a')
                0x39000FE8,  # strb w8, [sp, #3]
                0xD65F03C0,  # ret
            ]
        )
        self.assertEqual(report.status, "ok")
        stringrefs = report.getFunction(BASE).stringrefs
        self.assertIn({"string": "Test", "ins_addr": BASE + 4, "data_addr": None, "type": "stack"}, stringrefs)
        self.assertIn({"string": "Data", "ins_addr": BASE + 0x28, "data_addr": None, "type": "stack"}, stringrefs)


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

    def test_adrp_ldr_ref_recovery(self):
        base = 0x400000
        words = [
            0x90000008,  # adrp x8, #0x401000
            0xF9400909,  # ldr x9, [x8, #0x10]
        ]
        code = b"".join(w.to_bytes(4, "little") for w in words)
        code_padded = code + b"\x00" * 8 + struct.pack("<Q", 0x402000)
        code_padded = code_padded + b"\x00" * (0x2000 - len(code_padded))
        elf_bytes = _build_aarch64_elf(code_padded, base=base, vaddr=0x401000)

        loader = FileLoader("/", map_file=True)
        loader._loadFile(elf_bytes)
        disassembly = DisassemblyResult()
        disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)

        fcm = FunctionCandidateManager(SmdaConfig())
        fcm.init(disassembly)
        fcm.locateAddressRefCandidates()

        self.assertIn(0x402000, fcm.candidates)


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

    def test_bti_after_authenticated_return_is_not_suppressed_as_interior(self):
        binary = b"".join(
            word.to_bytes(4, "little")
            for word in [
                0xD65F0BFF,  # retaa
                0xD503245F,  # bti c
            ]
        )
        binary_info = BinaryInfo(binary)
        binary_info.base_addr = BASE
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, code_map={})
        manager._candidate_offsets = set()

        self.assertFalse(manager._isLikelyInteriorBtiCandidate(BASE + 4))

    def test_bti_after_drps_is_not_suppressed_as_interior(self):
        # drps (Debug Restore PState) transfers control to ELR_ELx like eret*, so a BTI
        # right after it is a legitimate landing pad, not fragmentation of straight-line code.
        binary = b"".join(
            word.to_bytes(4, "little")
            for word in [
                0xD6BF03E0,  # drps
                0xD503245F,  # bti c
            ]
        )
        binary_info = BinaryInfo(binary)
        binary_info.base_addr = BASE
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = SimpleNamespace(binary_info=binary_info, code_map={})
        manager._candidate_offsets = set()

        self.assertFalse(manager._isLikelyInteriorBtiCandidate(BASE + 4))


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
        self.assertEqual(self.report.oep, 0x534)
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
        self.assertEqual(roundtrip.oep, 0x534)
        self.assertEqual(len(roundtrip.xcfg), 278)


class TestAArch64Analyzers(unittest.TestCase):
    def test_aarch64_jump_table_resolution(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64JumpTableAnalyzer

        base = 0x400000
        words = [
            0x90000093,  # adrp x19, #0x411000
            0x91040273,  # add x19, x19, #0x100 (x19 = 0x411100)
            0xF8617A73,  # ldr x19, [x19, x1, lsl #3]
            0xD61F0260,  # br x19
        ]

        mapped = bytearray(0x15000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        struct.pack_into("<Q", mapped, 0x411100 - base, 0x411120)
        struct.pack_into("<Q", mapped, 0x411108 - base, 0x411140)
        struct.pack_into("<Q", mapped, 0x411110 - base, 0x4110E0)

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.binary_size = len(mapped)
        binary_info.isInCodeAreas = lambda addr: 0x400000 <= addr < 0x415000

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True

        class FakeDisassembler:
            def __init__(self, disassembly_result, capstone):
                self.disassembly = disassembly_result
                self.capstone = capstone

            def getBitMask(self):
                return 0xFFFFFFFFFFFFFFFF

        fake_disassembler = FakeDisassembler(disassembly, capstone)

        class FakeState:
            def __init__(self, instructions):
                self.instructions = instructions
                self.data_refs = []

            def backtrackInstructions(self, addr_from, num_instructions):
                return self.instructions

            def addDataRef(self, from_addr, to_addr, size=1):
                self.data_refs.append((from_addr, to_addr, size))

        instructions = []
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            inst = next(capstone.disasm(w.to_bytes(4, "little"), addr))
            instructions.append((addr, 4, inst.mnemonic, inst.op_str, inst.bytes))

        fake_state = FakeState(instructions)
        analyzer = AArch64JumpTableAnalyzer(fake_disassembler)

        targets = analyzer.getJumpTargets(instructions[-1], fake_state)
        self.assertEqual(targets[:3], [0x411120, 0x411140, 0x4110E0])

    def test_aarch64_indirect_call_resolution(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64IndirectCallAnalyzer

        base = 0x400000
        words = [
            0x90000008,  # adrp x8, #0x401000
            0xF9400908,  # ldr x8, [x8, #0x10]
            0xD63F0100,  # blr x8
            0xD65F03C0,  # ret
        ]

        mapped = bytearray(0x5000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        struct.pack_into("<Q", mapped, 0x401010 - base, 0x401020)

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.binary_size = len(mapped)

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info
        disassembly.apis = {}

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True

        class FakeDisassembler:
            def __init__(self, disassembly_result, capstone):
                self.disassembly = disassembly_result
                self.capstone = capstone
                self.config = SimpleNamespace(WITH_STRINGS=False)

            def resolveApi(self, to_addr, api_addr):
                if to_addr == 0x401020:
                    return ("GLIBC_2.2.5", "puts")
                return ("", "")

            @property
            def fc_manager(self):
                class FakeFC:
                    def addCandidate(self, addr, reference_source=None):
                        pass

                return FakeFC()

        fake_disassembler = FakeDisassembler(disassembly, capstone)

        class FakeState:
            def __init__(self, instructions):
                self.instructions = instructions
                self.call_register_ins = [0x401008]
                self.start_addr = 0x401000
                self.leaf = True

            def getBlocks(self):
                return [self.instructions]

            def setLeaf(self, leaf):
                self.leaf = leaf

        instructions = []
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            inst = next(capstone.disasm(w.to_bytes(4, "little"), addr))
            instructions.append((addr, 4, inst.mnemonic, inst.op_str, inst.bytes))

        fake_state = FakeState(instructions)
        analyzer = AArch64IndirectCallAnalyzer(fake_disassembler)

        analyzer.resolveRegisterCalls(fake_state)
        self.assertIn(0x401020, disassembly.apis)
        self.assertEqual(disassembly.apis[0x401020]["api_name"], "puts")
        self.assertFalse(fake_state.leaf)

    def test_aarch64_indirect_call_clears_stale_register_after_unknown_mov(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64IndirectCallAnalyzer

        base = 0x400000
        words = [
            0x90000008,  # adrp x8, #0x401000
            0xF9400908,  # ldr x8, [x8, #0x10]
            0xAA0003F0,  # mov x16, x0
            0xD63F0200,  # blr x16
            0xD65F03C0,  # ret
        ]

        mapped = bytearray(0x5000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        struct.pack_into("<Q", mapped, 0x401010 - base, 0x401020)

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.binary_size = len(mapped)

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info
        disassembly.apis = {}

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True

        class FakeDisassembler:
            def __init__(self, disassembly_result, capstone):
                self.disassembly = disassembly_result
                self.capstone = capstone
                self.config = SimpleNamespace(WITH_STRINGS=False)

            def resolveApi(self, to_addr, api_addr):
                if to_addr == 0x401020:
                    return ("GLIBC_2.2.5", "puts")
                return ("", "")

            @property
            def fc_manager(self):
                class FakeFC:
                    def addCandidate(self, addr, reference_source=None):
                        pass

                return FakeFC()

        fake_disassembler = FakeDisassembler(disassembly, capstone)

        class FakeState:
            def __init__(self, instructions):
                self.instructions = instructions
                self.call_register_ins = [0x40100C]
                self.start_addr = 0x401000
                self.leaf = True

            def getBlocks(self):
                return [self.instructions]

            def setLeaf(self, leaf):
                self.leaf = leaf

        instructions = []
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            inst = next(capstone.disasm(w.to_bytes(4, "little"), addr))
            instructions.append((addr, 4, inst.mnemonic, inst.op_str, inst.bytes))

        fake_state = FakeState(instructions)
        analyzer = AArch64IndirectCallAnalyzer(fake_disassembler)

        analyzer.resolveRegisterCalls(fake_state)
        self.assertNotIn(0x401020, disassembly.apis)
        self.assertTrue(fake_state.leaf)

    def test_aarch64_ldrsw_jump_table_resolution(self):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.aarch64.analyzers import AArch64JumpTableAnalyzer

        base = 0x400000
        words = [
            0x90000089,  # adrp x9, #0x411000
            0x91040129,  # add x9, x9, #0x100
            0xB8A1D92A,  # ldrsw x10, [x9, w1, sxtw #2]
            0x8B0A012A,  # add x10, x9, x10
            0xD61F0140,  # br x10
        ]

        mapped = bytearray(0x15000)
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            mapped[addr - base : addr - base + 4] = w.to_bytes(4, "little")

        struct.pack_into("<i", mapped, 0x411100 - base, 0x20)
        struct.pack_into("<i", mapped, 0x411104 - base, 0x40)
        struct.pack_into("<i", mapped, 0x411108 - base, -0x20)

        binary_info = BinaryInfo(bytes(mapped))
        binary_info.base_addr = base
        binary_info.binary_size = len(mapped)
        binary_info.isInCodeAreas = lambda addr: 0x400000 <= addr < 0x415000

        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        capstone.detail = True

        class FakeDisassembler:
            def __init__(self, disassembly_result, capstone):
                self.disassembly = disassembly_result
                self.capstone = capstone

            def getBitMask(self):
                return 0xFFFFFFFFFFFFFFFF

        fake_disassembler = FakeDisassembler(disassembly, capstone)

        class FakeState:
            def __init__(self, instructions):
                self.instructions = instructions
                self.data_refs = []

            def backtrackInstructions(self, addr_from, num_instructions):
                return self.instructions

            def addDataRef(self, from_addr, to_addr, size=1):
                self.data_refs.append((from_addr, to_addr, size))

        instructions = []
        for i, w in enumerate(words):
            addr = 0x401000 + i * 4
            inst = next(capstone.disasm(w.to_bytes(4, "little"), addr))
            instructions.append((addr, 4, inst.mnemonic, inst.op_str, inst.bytes))

        fake_state = FakeState(instructions)
        analyzer = AArch64JumpTableAnalyzer(fake_disassembler)

        targets = analyzer.getJumpTargets(instructions[-1], fake_state)
        self.assertEqual(targets[:3], [0x411120, 0x411140, 0x4110E0])


class TestAArch64MovMacroSplit(unittest.TestCase):
    """IDA's MOV-macro feature collapses MOVZ+MOVK pairs (materialising a 32-bit
    constant in a Wn register across two 4-byte AArch64 instructions) into one
    logical "head" whose reported size is 8 bytes.  Without splitting,
    IdaExporter._convertIdaInsToSmda would feed all 8 bytes to capstone and
    take only ``cache[0]`` (the MOVZ), silently dropping the MOVK and producing
    an exported report that drifted from SMDA's own per-instruction AArch64 output.

    These tests exercise IdaExporter._splitInstructionBytes directly (no IDA
    mocking required), verifying that an 8-byte macro head from IDA is correctly
    unpacked into two 4-byte sub-instructions.
    """

    def _split(self, offset, instruction_bytes):
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

        from smda.ida.IdaExporter import IdaExporter

        capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        errors = {}
        return (
            IdaExporter._splitInstructionBytes(capstone, offset, instruction_bytes, "aarch64", errors),
            errors,
        )

    def test_movz_movk_macro_splits_into_two_4_byte_instructions(self):
        # The IDA export example:
        #   03 20 80 52   MOVZ W3, #0x100 -> capstone: 'mov' w3, #0x100
        #   03 00 A1 72   MOVK W3, #0x800, LSL #16 -> capstone: 'movk' w3, #0x800, lsl #16
        # originally shown by IDA as one 8-byte "MOV W3, #0x8000100" macro at 0x100004838.
        macro_bytes = bytes.fromhex("032080520300A172")
        insns, errors = self._split(0x100004838, macro_bytes)

        self.assertEqual(errors, {})
        self.assertEqual(len(insns), 2)

        addr, size, mnem, ops, raw = insns[0]
        self.assertEqual(addr, 0x100004838)
        self.assertEqual(size, 4)
        self.assertEqual(mnem, "mov")
        self.assertEqual(ops, "w3, #0x100")
        self.assertEqual(raw, bytes.fromhex("03208052"))

        addr, size, mnem, ops, raw = insns[1]
        self.assertEqual(addr, 0x10000483C)
        self.assertEqual(size, 4)
        self.assertEqual(mnem, "movk")
        self.assertEqual(ops, "w3, #0x800, lsl #16")
        self.assertEqual(raw, bytes.fromhex("0300A172"))

    def test_single_4_byte_instruction_still_returns_one_tuple(self):
        # Non-macro AArch64 instructions return exactly 4 bytes from
        # IdaInterface.getInstructionBytes; the split helper must preserve
        # the single-instruction output shape (a one-element list).
        single = bytes.fromhex("200080D2")  # mov x0, #1
        insns, errors = self._split(0x401000, single)

        self.assertEqual(errors, {})
        self.assertEqual(len(insns), 1)
        addr, size, mnem, ops, raw = insns[0]
        self.assertEqual(addr, 0x401000)
        self.assertEqual(size, 4)
        self.assertEqual(mnem, "mov")
        self.assertEqual(ops, "x0, #1")
        self.assertEqual(raw, single)


if __name__ == "__main__":
    unittest.main()
