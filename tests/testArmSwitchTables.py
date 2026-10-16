"""Switch tables of the 32-bit ARM backend: Thumb-2 ``tbb``/``tbh`` dispatches, the IT block
clang guards a large switch with, and the bound a conditional dispatch states by its own
condition.
"""

import unittest

import pytest
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

from smda.arm.analyzers import ArmJumpTableAnalyzer
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000


def _disassemble(buffer):
    config = SmdaConfig()
    config.TIMEOUT = 0
    return Disassembler(config).disassembleBuffer(buffer, BASE, architecture="arm")


def _thumbContext(encoding):
    engine = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    engine.detail = True
    return [
        ((ins.address, ins.size, ins.mnemonic, ins.op_str, bytes(ins.bytes)), ins)
        for ins in engine.disasm(bytes.fromhex(encoding), BASE)
    ]


class ArmTableBranchTest(unittest.TestCase):
    """``llvm-mc -triple=thumbv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    entry    push {r4, lr}; bl bytes; bl halves; bl guarded; pop {r4, pc}
    bytes    cmp r0, #3; bhi 9f; tbb [pc, r0]; 1: .byte (c0 - 1b) / 2 .. (c3 - 1b) / 2
             c0..c3: movs r0, #N; bx lr; 9: movs r0, #0; bx lr
    halves   nop; cmp r0, #2; bhi 9f; tbh [pc, r0, lsl #1] (at a halfword, not a word, boundary)
             1: .short (h0 - 1b) / 2 .. (h2 - 1b) / 2; h0..h2: movs r0, #N; bx lr; 9: ...
    guarded  cmp r0, #2; itt hi; movhi.w r0, #-1; bxhi lr; adr r1, 2f; tbh [r1, r0, lsl #1]
             1: g0..g2: movs r0, #N; bx lr
             .p2align 2; 2: .short (g0 - 1b) / 2 .. (g2 - 1b) / 2; .short 3, 3
    """

    BUFFER = bytes.fromhex(
        "10b500f005f800f013f800f021f810bd03280bd8dfe800f0020406080a2070470b2070470c2070470d207047"
        "0020704700bf02280ad8dfe810f003000500070014207047152070471620704700207047022884bf4ff0ff30"
        "704704a1d1e810f01e2070471f2070472020704700000200040003000300"
    )

    @classmethod
    def setUpClass(cls):
        cls.report = _disassemble(cls.BUFFER)

    def test_a_byte_table_branch_names_every_case(self):
        function = self.report.getFunction(0x10010)
        self.assertEqual(sorted(function.blockrefs[0x10014]), [0x1001C, 0x10020, 0x10024, 0x10028])

    def test_a_halfword_table_branch_off_a_word_boundary_names_every_case(self):
        function = self.report.getFunction(0x10030)
        self.assertEqual(sorted(function.blockrefs[0x10036]), [0x10040, 0x10044, 0x10048])

    def test_an_it_guarded_exit_keeps_the_bound_of_an_out_of_line_table(self):
        # the halfwords behind the table would name the middle of g1
        function = self.report.getFunction(0x10050)
        self.assertEqual(sorted(function.blockrefs[0x1005A]), [0x10060, 0x10064, 0x10068])
        self.assertNotIn(0x10066, function.blocks)


class ArmConditionalDispatchBoundTest(unittest.TestCase):
    """``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    entry  push {r4, lr}; bl lo; bl ls; bl addlo; pop {r4, pc}; a0..a3: mov r0, #N; bx lr
    lo     cmp r0, #3; ldrlo pc, [pc, r0, lsl #2]; b 9f; .word a0, a1, a2, a3; 9: mov r0, #0; bx lr
           b0..b3: mov r0, #N; bx lr
    ls     cmp r0, #2; ldrls pc, [pc, r0, lsl #2]; b 9f; .word b0, b1, b2, b3; 9: mov r0, #0; bx lr
    addlo  cmp r0, #2; addlo pc, pc, r0, lsl #2; b 9f; b 1f; b 2f; b 3f
           1..3: mov r0, #N; bx lr; 9: mov r0, #0; bx lr

    Each table holds one entry more than its guard admits.
    """

    BUFFER = bytes.fromhex(
        "10402de90a0000eb1a0000eb220000eb1080bde80a00a0e31eff2fe10b00a0e31eff2fe10c00a0e31eff2fe1"
        "0d00a0e31eff2fe1030050e300f19f37030000ea140001001c000100240001002c0001000000a0e31eff2fe1"
        "1400a0e31eff2fe11500a0e31eff2fe11600a0e31eff2fe11700a0e31eff2fe1020050e300f19f97030000ea"
        "580001006000010068000100700001000000a0e31eff2fe1020050e300f18f30080000ea010000ea020000ea"
        "030000ea1e00a0e31eff2fe11f00a0e31eff2fe12000a0e31eff2fe10000a0e31eff2fe1"
    )

    @classmethod
    def setUpClass(cls):
        cls.report = _disassemble(cls.BUFFER)

    def test_a_lower_dispatch_does_not_admit_its_immediate(self):
        function = self.report.getFunction(0x10034)
        self.assertEqual(sorted(function.blockrefs[0x10034]), [0x10014, 0x1001C, 0x10024, 0x1003C])

    def test_a_lower_or_same_dispatch_admits_its_immediate(self):
        function = self.report.getFunction(0x10078)
        self.assertEqual(sorted(function.blockrefs[0x10078]), [0x10058, 0x10060, 0x10068, 0x10080])

    def test_a_lower_pc_add_does_not_admit_its_immediate(self):
        function = self.report.getFunction(0x1009C)
        self.assertEqual(sorted(function.blockrefs[0x1009C]), [0x100A4, 0x100A8, 0x100AC])


@pytest.mark.parametrize(
    ("encoding", "bound"),
    [
        # cmp r0, #2; itt hi; movhi.w r0, #-1; bxhi lr
        ("022884bf4ff0ff307047", 3),
        # cmp r0, #2; it hs; bxhs lr
        ("022828bf7047", 2),
        # cmp r0, #2; ite ls; movls r0, r1; bxhi lr: the write is on the way to the dispatch
        ("022894bf08467047", 0),
        # cmp r0, #2; itt hi; movhi r0, #0; bxhi lr; adds r0, #1
        ("022884bf002070470130", 0),
    ],
)
def test_switch_bounds_ignore_writes_only_on_the_way_out(encoding, bound):
    assert ArmJumpTableAnalyzer._bound(_thumbContext(encoding), "r0") == bound
