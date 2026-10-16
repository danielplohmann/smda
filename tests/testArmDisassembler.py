"""The 32-bit ARM backend on hand-written A32/T32 code: the compiler idioms GCC and clang
emit for switches, interworking, linked register branches, IT-predicated returns, linker
veneers and calls that do not return.

IDIOMS is ``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    entry           push {r4, lr}; bl each of the below (blx into the Thumb one); pop {r4, pc}
    ldrls_switch    cmp r0, #3; ldrls pc, [pc, r0, lsl #2]; b default; .word case0..case3
    addls_switch    cmp r0, #2; addls pc, pc, r0, lsl #2; b default; b case0; b case1; b case2
    linked_call     ldr r3, =callee; mov lr, pc; bx r3; cmp r0, #0; popeq {r4, pc}; ...
    callee          mov r0, #7; bx lr
    veneer          ldr pc, [pc, #-4]; .word far_target
    far_target      mov r0, #9; bx lr
    noreturn_caller push {r4, lr}; movw r0, #0x1234; bl abort_like; .word callee (literal pool)
    abort_like      b abort_like
    thumb_it_return (T32) cmp r0, #0; it eq; bxeq lr; adds r0, #1; bx lr
"""

import unittest
from pathlib import Path

from capstone.arm import ARM_CC_AL, ARM_CC_EQ, ARM_CC_NE

from smda.arm.ArmInstructionEscaper import ArmInstructionEscaper
from smda.arm.definitions import (
    a32_branch_target,
    countModeMarkers,
    is_return_instruction,
    looksLikeArm,
    split_mnemonic,
    t32_call_target,
)
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000
IDIOMS = bytes.fromhex(
    "10402de9050000eb160000eb230000eb350000fa2b0000eb2e0000eb1080bde810402de9030050e300f19f97"
    "0b0000ea400001004800010050000100580001000100a0e31080bde80200a0e31080bde80300a0e31080bde8"
    "0400a0e31080bde80000a0e31080bde8020050e300f18f90080000ea010000ea020000ea030000ea0a00a0e3"
    "1eff2fe11400a0e31eff2fe11e00a0e31eff2fe10000a0e31eff2fe110402de938309fe50fe0a0e113ff2fe1"
    "000050e31080bd08010080e21080bde80700a0e31eff2fe104f01fe5d00001000900a0e31eff2fe110402de9"
    "340201e3000000ebc0000100feffffea002808bf704701307047"
)
# function start -> Thumb, from the linker's symbol table
EXPECTED_FUNCTIONS = {
    0x10000: False,
    0x10020: False,
    0x10068: False,
    0x100A0: False,
    0x100C0: False,
    0x100C8: False,
    0x100D0: False,
    0x100D8: False,
    0x100E8: False,
    0x100EC: True,
}


def _config():
    config = SmdaConfig()
    config.CALCULATE_HASHING = True
    config.TIMEOUT = 0
    return config


def _disassemble(buffer=IDIOMS, base=BASE, architecture="arm"):
    return Disassembler(_config()).disassembleBuffer(buffer, base, architecture=architecture)


class ArmIdiomRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = _disassemble()

    def _function(self, address):
        function = self.report.getFunction(address)
        self.assertIsNotNone(function, f"no function at 0x{address:x}")
        return function

    def _blockStarts(self, address):
        return sorted(block.offset for block in self._function(address).getBlocks())

    def test_every_function_is_recovered_in_its_own_instruction_set(self):
        self.assertEqual(self.report.status, "ok")
        self.assertEqual(self.report.architecture, "arm")
        self.assertEqual(self.report.bitness, 32)
        found = {function.offset: function.architecture_metadata["thumb"] for function in self.report.getFunctions()}
        self.assertEqual(found, EXPECTED_FUNCTIONS)

    def test_an_absolute_table_behind_a_conditional_pc_load_is_followed(self):
        self.assertEqual(self._function(0x10020).blockrefs[0x10020], [0x1002C, 0x10040, 0x10048, 0x10050, 0x10058])

    def test_a_table_of_branches_entered_by_a_pc_add_is_followed(self):
        self.assertEqual(
            self._blockStarts(0x10068),
            [0x10068, 0x10070, 0x10074, 0x10078, 0x1007C, 0x10080, 0x10088, 0x10090, 0x10098],
        )

    def test_mov_lr_pc_before_a_register_branch_is_a_call_to_the_loaded_address(self):
        function = self._function(0x100A0)
        self.assertEqual(function.outrefs, {0x100AC: [0x100C0]})
        self.assertEqual(function.num_calls, 0)
        self.assertEqual(function.num_returns, 2)
        self.assertEqual(self._blockStarts(0x100A0), [0x100A0, 0x100B8])

    def test_an_it_predicated_return_keeps_its_condition(self):
        function = self._function(0x100EC)
        self.assertEqual(
            [(ins.mnemonic, ins.operands) for ins in function.getInstructions()],
            [("cmp", "r0, #0"), ("it", "eq"), ("bxeq", "lr"), ("adds", "r0, #1"), ("bx", "lr")],
        )
        self.assertEqual(self._blockStarts(0x100EC), [0x100EC, 0x100F2])

    def test_a_veneer_ends_its_function_and_names_its_target(self):
        self.assertEqual(self._function(0x100C8).num_instructions, 1)
        self.assertIsNotNone(self.report.getFunction(0x100D0))

    def test_a_call_followed_by_a_literal_pool_does_not_return(self):
        function = self._function(0x100D8)
        self.assertEqual([ins.offset for ins in function.getInstructions()], [0x100D8, 0x100DC, 0x100E0])

    def test_pic_hashes_do_not_depend_on_the_load_address(self):
        moved = _disassemble(base=0x80000)
        # ldrls_switch dispatches through absolute addresses, which only resolve at the
        # address the image was linked for; every other function is position independent
        for offset in EXPECTED_FUNCTIONS:
            if offset == 0x10020:
                continue
            with self.subTest(function=hex(offset)):
                original = self.report.getFunction(offset)
                relocated = moved.getFunction(offset - BASE + 0x80000)
                self.assertEqual(original.pic_hash, relocated.pic_hash)


class ArmLiteralAndGapTest(unittest.TestCase):
    """``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    caller          push {r4, lr}; bl literal_user; pop {r4, pc}
    literal_user    push {r4, lr}; vldr s0, [pc, #4]; bl callee; pop {r4, pc}; .word 0x3f800000
    callee          push {r4, lr}; mov r4, r0; add r0, r4, #1; pop {r4, pc}
    (unreferenced)  bl <32 MB past the image>; bx lr
    """

    BUFFER = bytes.fromhex(
        "10402de9000000eb1080bde810402de9010a9fed010000eb1080bde80000803f10402de90040a0e1010084e2"
        "1080bde8ffff7feb1eff2fe1"
    )

    def test_a_single_precision_literal_is_one_word(self):
        report = _disassemble(self.BUFFER)
        self.assertEqual(
            {function.offset: function.num_instructions for function in report.getFunctions()},
            {0x10000: 3, 0x1000C: 4, 0x10020: 4},
        )


class ArmThumbOneIdiomTest(unittest.TestCase):
    """``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    entry       (A32) push {r4, lr}; blx dispatch; blx veneer; pop {r4, pc}
    dispatch    (T32) push {r4, lr}; cmp r0, #4; bls 1f; default: movs r0, #0; b 9f
                1: bl case_sqi; .byte (c0-table)/2 .. (c3-table)/2, (default-table)/2
                c0..c3: movs r0, #N; b 9f; 9: pop {r4, pc}
    case_sqi    (T32) libgcc's __gnu_thumb1_case_sqi: push {r1}; mov r1, lr; lsrs r1, r1, #1;
                lsls r1, r1, #1; ldrsb r1, [r1, r0]; lsls r1, r1, #1; add lr, r1; pop {r1}; bx lr
    veneer      (T32) bx pc; nop; (A32) b arm_target
    arm_target  (A32) mov r0, #7; bx lr
    """

    BUFFER = bytes.fromhex(
        "10402de9010000fa0e0000fa1080bde810b5042801d900200be000f00bf803050709fc000a2004e00b2002e0"
        "0c2000e00d2010bd02b4714649084900095649008e4402bc70470000784700bfffffffea0700a0e31eff2fe1"
    )

    @classmethod
    def setUpClass(cls):
        cls.report = _disassemble(cls.BUFFER)

    def test_a_case_helper_call_dispatches_into_its_inline_table(self):
        dispatch = self.report.getFunction(0x10010)
        # every case, the negative entry naming the default included, and no table bytes
        self.assertEqual(
            sorted(block.offset for block in dispatch.getBlocks()),
            [0x10010, 0x10016, 0x1001A, 0x10024, 0x10028, 0x1002C, 0x10030, 0x10032],
        )
        self.assertEqual(dispatch.blockrefs[0x1001A], [0x10016, 0x10024, 0x10028, 0x1002C, 0x10030])
        self.assertIsNotNone(self.report.getFunction(0x10034))

    def test_a_thumb_to_a32_veneer_is_one_function(self):
        self.assertEqual(
            {function.offset: function.architecture_metadata["thumb"] for function in self.report.getFunctions()},
            {0x10000: False, 0x10010: True, 0x10034: True, 0x10048: True, 0x10050: False},
        )
        self.assertEqual(self.report.getFunction(0x10048).num_instructions, 1)


class ArmGccIdiomTest(unittest.TestCase):
    """Shapes GCC emits that the Debian armel/armhf builds showed, each ``llvm-mc
    -triple=armv7a-none-eabi`` (``thumbv7a`` for the first) + ``ld.lld -Ttext=0x10000``.
    """

    # entry  (T32) push {r4, lr}; bl dispatch; pop {r4, pc}
    # dispatch (T32) cmp r0, #3; bhi 9f; adr r1, 1f; ldr.w r0, [r1, r0, lsl #2]; add r1, r0; bx r1
    #        1: .word (c0 - 1b) + 1 .. (c3 - 1b) + 1; c0..c3: movs r0, #N; bx lr; 9: movs r0, #0; bx lr
    THUMB_RELATIVE_SWITCH = bytes.fromhex(
        "10b500f001f810bd032815d802a151f820000144084700bf1100000015000000190000001d0000000a207047"
        "0b2070470c2070470d20704700207047"
    )
    # entry   push {r4, lr}; ldr r0, =...; bl leaf; pop {r4, pc}; .word 0x0001d664, 0x254
    # hoisted ldr r2, 2f; ldr r3, 3f; add r2, pc, r2; push {r4, lr}; ...; pop {r4, pc}; 2: .word ..; 3: .word ..
    # early   cmp r0, #0; push {r4, r5, r6, lr}; ldr r4, [r1]; mov r5, r1; mov r6, r2; beq 4f; ...; 4: pop
    # leaf    mov r0, #7; bx lr
    HOISTED_ENTRIES = bytes.fromhex(
        "10402de904009fe5140000eb1080bde864d601005402000018209fe518309fe502208fe010402de9030092e7"
        "0040a0e1010084e21080bde8e8d4010054020000000050e370402de9004091e50150a0e10260a0e10000000a"
        "050084e07080bde80700a0e31eff2fe1"
    )
    # entry   push {r4, lr}; mov r0, #1; bl fatal; .word 0, 0, 0x10000
    # fatal   push {r4, lr}; mov r4, r0; bl fatal; pop {r4, pc}
    ZERO_AFTER_CALL = bytes.fromhex("10402de90100a0e3020000eb00000000000000000000010010402de90040a0e1fcffffeb1080bde8")

    def test_a_thumb_offset_table_behind_add_and_bx_is_followed(self):
        report = _disassemble(self.THUMB_RELATIVE_SWITCH)
        self.assertEqual(sorted(function.offset for function in report.getFunctions()), [0x10000, 0x10008])
        self.assertEqual(
            sorted(block.offset for block in report.getFunction(0x10008).getBlocks()),
            [0x10008, 0x1000C, 0x10028, 0x1002C, 0x10030, 0x10034, 0x10038],
        )

    def test_code_scheduled_ahead_of_the_push_starts_the_function(self):
        report = _disassemble(self.HOISTED_ENTRIES)
        self.assertEqual(
            {function.offset: function.num_instructions for function in report.getFunctions()},
            {0x10000: 4, 0x10018: 8, 0x10040: 8, 0x10060: 2},
        )

    def test_a_zero_word_after_a_call_ends_the_function_instead_of_aborting_it(self):
        report = _disassemble(self.ZERO_AFTER_CALL)
        self.assertEqual(
            {function.offset: function.num_instructions for function in report.getFunctions()},
            {0x10000: 3, 0x10018: 4},
        )


class ArmMsvcIdiomTest(unittest.TestCase):
    """MSVC's Thumb-2 switch, ``llvm-mc -triple=thumbv7a-none-eabi`` + ``ld.lld -Ttext=0x10000``."""

    # entry  push {r4, lr}; bl bytes; bl halves; pop {r4, pc}
    # bytes  cmp r0, #3; bhi 9f; b 4f; b0: movs r0, #10; bx lr
    #        4: adr r3, 1f; ldrsb r3, [r3, r0]; 2: add pc, r3
    #        1: .byte b0 - 2b - 4, b1 - 2b - 4, b2 - 2b - 4, b3 - 2b - 4; b1..b3: movs r0, #N; bx lr
    #        9: movs r0, #0; bx lr
    # halves cmp r0, #2; bhi.w 9f; adr r3, 1f; ldrsh.w r3, [r3, r0, lsl #1]; nop; 2: add pc, r3
    #        1: .short h0 - 2b - 4, h1 - 2b - 4, h2 - 2b - 4; h0..h2: movs r0, #N; bx lr
    #        9: movs r0, #0; bx lr
    ADD_PC_SWITCH = bytes.fromhex(
        "10b500f003f800f013f810bd03280dd801e00a20704701a31b569f44f402060a0b2070470c2070470d207047"
        "00207047022800f20e8002a333f9103000bf9f44040008000c0014207047152070471620704700207047"
    )

    def test_a_signed_offset_table_behind_add_pc_is_followed(self):
        report = _disassemble(self.ADD_PC_SWITCH)
        self.assertEqual(sorted(function.offset for function in report.getFunctions()), [0x10000, 0x1000C, 0x10030])
        self.assertEqual(sorted(report.getFunction(0x1000C).blockrefs[0x10016]), [0x10012, 0x10020, 0x10024, 0x10028])
        self.assertEqual(sorted(report.getFunction(0x10030).blockrefs[0x10036]), [0x10046, 0x1004A, 0x1004E])


class ArmSwitchBoundTest(unittest.TestCase):
    """``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000``."""

    # entry push {r4, lr}; bl f; bl g; pop {r4, pc}; c0..c3: mov r0, #N; bx lr; def: mov r0, #0; bx lr
    # f     cmp r0, #4; bhs def; ldr pc, [pc, r0, lsl #2]; nop; .word c0, c1, c2, c3
    # g     .word msg (pool); ldr r0, pool; bx lr; msg: .asciz "hello world, this is a string not code"
    HS_GUARD = bytes.fromhex(
        "10402de90b0000eb130000eb1080bde80a00a0e31eff2fe10b00a0e31eff2fe10c00a0e31eff2fe10d00a0e3"
        "1eff2fe10000a0e31eff2fe1040050e3fbffff2a00f19fe700f020e31000010018000100200001002800010064"
        "0001000c001fe51eff2fe168656c6c6f20776f726c642c2074686973206973206120737472696e67206e6f7420"
        "636f646500"
    )

    def test_a_higher_or_same_guard_does_not_admit_its_immediate(self):
        report = _disassemble(self.HS_GUARD)
        function = report.getFunction(0x10038)
        self.assertEqual(sorted(function.blockrefs[0x10040]), [0x10010, 0x10018, 0x10020, 0x10028])
        self.assertFalse([ins.offset for ins in function.getInstructions() if ins.offset >= 0x10064])


class ArmPieImportTest(unittest.TestCase):
    """A stripped PIE, ``llvm-mc -triple=armv7a-linux-gnueabi`` + ``ld.lld -pie -Ttext=0x150``
    against a shared object exporting ``puts`` and ``__stack_chk_fail``:

    main      push {r4, lr}; bl guarded; bl pic_user; pop {r4, pc}
    guarded   push {r4, lr}; cmp r0, #0; beq 1f; bl puts; pop {r4, pc}; 1: bl __stack_chk_fail
              .word 0x254, 0x1234 (literal pool right behind the call through the PLT)
    pic_user  push {r4, lr}; ldr r0, 2f; 3: add r0, pc, r0; bl puts; pop {r4, pc}
              2: .word message - (3b + 8), an offset that happens to equal other + 0x10
    other     push {r4, lr}; mov r4, r0; add r0, r4, #1; add r0, r0, #2 .. #6; pop {r4, pc}
    """

    @classmethod
    def setUpClass(cls):
        data = (Path(__file__).resolve().parent / "arm_pie_noreturn_plt_xored").read_bytes()
        raw = bytes(byte ^ (index % 256) for index, byte in enumerate(data))
        cls.report = Disassembler(_config()).disassembleUnmappedBuffer(raw)

    def test_a_call_to_a_noreturn_import_ends_the_block(self):
        guarded = self.report.getFunction(0x160)
        self.assertEqual(guarded.num_instructions, 6)
        self.assertIsNotNone(self.report.getFunction(0x180))

    def test_a_pc_relative_offset_is_not_taken_for_a_code_address(self):
        text = {function.offset: function.num_instructions for function in self.report.getFunctions()}
        self.assertNotIn(0x1A8, text)
        self.assertEqual(text[0x198], 9)


class ArmBlockEndTest(unittest.TestCase):
    # f: cmp r0, #0; beq L; mov r0, #1; bx lr, with L: mov r0, #0; bx lr right ahead of f
    BUFFER = bytes.fromhex("0000a0e31eff2fe1000050e3fbffff0a0100a0e31eff2fe1")

    def test_a_block_ends_at_a_return(self):
        report = Disassembler(_config()).disassembleBuffer(self.BUFFER, BASE, 32, oep=8, architecture="arm")
        function = report.getFunction(BASE + 8)
        self.assertEqual(
            [[instruction.offset for instruction in block.getInstructions()] for block in function.getBlocks()],
            [[0x10000, 0x10004], [0x10008, 0x1000C], [0x10010, 0x10014]],
        )
        self.assertEqual(function.num_instructions, 6)


class ArmDetailedInItBlockTest(unittest.TestCase):
    def _detailed(self, code, oep=1):
        report = Disassembler(_config()).disassembleBuffer(bytes.fromhex(code), BASE, 32, oep=oep, architecture="arm")
        for serialized in (False, True):
            if serialized:
                report = SmdaReport.fromDict(report.toDict())
            instructions = list(report.getFunction(BASE).getInstructions())
            for instruction in instructions:
                detailed = instruction.getDetailed()
                self.assertEqual((detailed.mnemonic, detailed.op_str), (instruction.mnemonic, instruction.operands))
        return {instruction.mnemonic: instruction.getDetailed().cc for instruction in instructions}

    def test_it(self):
        # cmp r0, #0; it eq; moveq r0, #1; bx lr
        self.assertEqual(self._detailed("002808bf01207047")["moveq"], ARM_CC_EQ)

    def test_itt(self):
        # cmp r0, #0; itt eq; moveq r0, #1; bxeq lr; movs r0, #2; bx lr
        conditions = self._detailed("002804bf0120704702207047")
        self.assertEqual(
            (conditions["moveq"], conditions["bxeq"], conditions["movs"]), (ARM_CC_EQ, ARM_CC_EQ, ARM_CC_AL)
        )

    def test_ite(self):
        # cmp r0, #0; ite eq; moveq r0, #1; movne r0, #2; bx lr
        conditions = self._detailed("00280cbf012002207047")
        self.assertEqual((conditions["moveq"], conditions["movne"]), (ARM_CC_EQ, ARM_CC_NE))

    def test_itttt_over_a_wide_instruction(self):
        # cmp r0, #0; itttt eq; moveq r0, #1; moveq.w r1, #1; moveq r2, #1; moveq r3, #1; movs r0, #2; bx lr
        conditions = self._detailed("002801bf01204ff001010122012302207047")
        self.assertEqual((conditions["moveq.w"], conditions["movs"]), (ARM_CC_EQ, ARM_CC_AL))

    def test_an_it_block_at_the_function_start(self):
        # ite eq; moveq r0, #1; movne r0, #2; bx lr
        conditions = self._detailed("0cbf012002207047")
        self.assertEqual((conditions["moveq"], conditions["movne"]), (ARM_CC_EQ, ARM_CC_NE))

    def test_a_corrupt_it_leaves_the_instruction_decoded_alone(self):
        report = Disassembler(_config()).disassembleBuffer(
            bytes.fromhex("002804bf0120704702207047"), BASE, 32, oep=1, architecture="arm"
        )
        serialized = report.toDict()
        for block in serialized["xcfg"][BASE]["blocks"].values():
            for instruction in block:
                if instruction[0] == BASE + 2:
                    instruction[1] = "zzzz"
        function = SmdaReport.fromDict(serialized).getFunction(BASE)
        self.assertEqual(function.getInstructionAt(BASE + 4).getDetailed().mnemonic, "movs")

    def test_a32_conditions_are_unchanged(self):
        # cmp r0, #0; moveq r0, #1; bxeq lr; mov r0, #2; bx lr
        conditions = self._detailed("000050e30100a0031eff2f010200a0e31eff2fe1", oep=0)
        self.assertEqual(
            (conditions["moveq"], conditions["bxeq"], conditions["mov"]), (ARM_CC_EQ, ARM_CC_EQ, ARM_CC_AL)
        )


class ArmLiteralAfterCallTest(unittest.TestCase):
    """``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000`` of:

    entry    mov fp, #0; ldr r1, 1f; add r1, pc, r1; bl start_c; 1: .word 0xfffefcdc
             (musl's _start: the word after the call decodes as no A32 instruction)
    start_c  push {r4, lr}; bl f; bl g; pop {r4, pc}
    f        push {r4, lr}; cmp r0, #0; beq 2f; ldr r0, 3f; pop {r4, pc}; 2: bl die
             3: .word 0x12345678, 0x13579bdf (the pool behind the call, loaded by the other path)
    g        push {r4, lr}; mov r0, #1; bl leaf; pop {r4, pc}
    die      b die
    leaf     mov r0, #0; bx lr
    """

    BUFFER = bytes.fromhex(
        "00b0a0e304109fe501108fe0000000ebdcfcfeff10402de9010000eb080000eb1080bde810402de9000050e3"
        "0100000a04009fe51080bde8050000eb78563412df9b571310402de90100a0e3010000eb1080bde8feffffea"
        "0000a0e31eff2fe1"
    )

    def test_a_call_followed_by_data_ends_the_function(self):
        report = _disassemble(self.BUFFER)
        self.assertEqual(
            {function.offset: function.num_instructions for function in report.getFunctions()},
            {0x10000: 4, 0x10014: 4, 0x10024: 6, 0x10044: 4, 0x10054: 1, 0x10058: 2},
        )


class ArmElfReferenceTest(unittest.TestCase):
    # clang -O2 --target=armv7a-linux-gnueabi -nostdlib, ld.lld --no-rosegment (``.rodata`` shares
    # the executable segment, as old GNU ld and the Android NDK lay it out), stripped, of:
    #   const char msg[] = "\x2d\xe9\xf0\x41 hello, this is rodata, not code";
    #   const char tbl[] = "\x10\xb5 some other string";
    #   const char *get(int i) { return i ? msg : tbl; }
    #   void _start(void) { volatile const char *p = get(1); (void)p; for (;;) ; }
    RODATA_POINTERS = bytes.fromhex(
        "7f454c4601010100000000000000000002002800010000006001010034000000e40100000002000534002000"
        "050028000700060006000000340000003400010034000100a0000000a0000000040000000400000001000000"
        "0000000000000100000001006401000064010000050000000000010051e57464000000000000000000000000"
        "0000000000000000060000000000000004000000d4000000d4000100d4000100180000001800000004000000"
        "0400000001000070ec000000ec000100ec000100180000001800000004000000040000000400000008000000"
        "03000000474e5500e7e6763a6772503a54000000010000006c0000000100000068000000010000002de9f041"
        "2068656c6c6f2c207468697320697320726f646174612c206e6f7420636f64650010b520736f6d65206f7468"
        "657220737472696e6700000010209fe510109fe5000050e30210a0010100a0e11eff2fe12901010004010100"
        "feffffea4135000000616561626900012b00000043322e303900060a0741080109020e001101120414011500"
        "1703180119011a021e0122012601002e41524d2e6578696478002e74657874002e41524d2e61747472696275"
        "746573002e6e6f74652e676e752e6275696c642d6964002e7368737472746162002e726f6461746100000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000022000000"
        "0700000002000000d4000100d400000018000000000000000000000004000000000000000100000001000070"
        "82000000ec000100ec00000018000000040000000000000004000000000000003f0000000100000002000000"
        "04010100040100003a000000000000000000000001000000000000000c000000010000000600000040010100"
        "4001000024000000000000000000000004000000000000001200000003000070000000000000000064010000"
        "3600000000000000000000000100000000000000350000000300000000000000000000009a01000047000000"
        "00000000000000000100000000000000"
    )
    # ``llvm-mc -triple=thumbv7a-none-eabi`` + ``ld.lld -Ttext=0x10000``, stripped, of:
    #   entry (T32) push {r7, lr}; movw r0, #0x30; movt r0, #1; add r0, pc; adr.w r1, message
    #               ldr r0, [r0]; blx work; pop {r7, pc}; .word 0x11111111
    #   work  (A32) push {r4-r6, lr}; mov r4, #0; mov r5, #10; 1: add r4, r4, r5
    #               subs r5, r5, #1 (0x10030, the value movw/movt build); bne 1b; mov r0, r4; pop
    #   message     .asciz "hello" in .rodata
    THUMB_PIC = bytes.fromhex(
        "7f454c46010101000000000000000000020028000100000001000100340000006c0100000002000534002000"
        "050028000400030006000000340000003400010034000100a0000000a0000000040000000400000001000000"
        "000000000000010000000100d4000000d4000000040000000001000001000000000100000000010000000100"
        "4c0000004c0000000500000000010000010000004c0100004c0101004c010100060000000600000004000000"
        "0001000051e57464000000000000000000000000000000000000000006000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000080b540f23000c0f2"
        "010078440ff23c11006800f015f880bd1111111100f020e370402de90040a0e30a50a0e3054084e0015055e2"
        "fcffff1a0400a0e17080bde87847fde704f01fe52000010068656c6c6f00002e74657874002e736873747274"
        "6162002e726f6461746100000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000001000000010000000600000000000100000100004c000000000000000000000010000000"
        "000000001100000001000000020000004c0101004c0100000600000000000000000000000100000000000000"
        "07000000030000000000000000000000520100001900000000000000000000000100000000000000"
    )
    # ``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000``, symbols kept, of:
    #   entry push {r4, lr}; bl f; pop {r4, pc}
    #   f     cmp r0, #0; bne g; mov r0, #1; bx lr
    #   g     cmp r0, #2; moveq r0, #0; add r0, r0, #3 (falls through into h)
    #   h     add r0, r0, #4; bx lr
    DECLARED_STARTS = bytes.fromhex(
        "7f454c4601010100000000000000000002002800010000000000010034000000e80100000002000534002000"
        "0400280006000400060000003400000034000100340001008000000080000000040000000400000001000000"
        "000000000000010000000100b4000000b4000000040000000001000001000000000100000000010000000100"
        "3000000030000000050000000001000051e57464000000000000000000000000000000000000000006000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000010402de9000000eb"
        "1080bde8000050e30100001a0100a0e31eff2fe1020050e30000a003030080e2040080e21eff2fe14c696e6b"
        "65723a205562756e7475204c4c442031382e312e33000000000000000000000000000000000000000d000000"
        "0000010000000000000001000b0000000c0001000000000002000100090000001c0001000000000002000100"
        "0700000028000100000000000200010001000000000001000000000012000100002e74657874002e636f6d6d"
        "656e74002e7368737472746162002e737472746162002e73796d7461620000656e7472790068006700660024"
        "612e300000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0100000001000000060000000000010000010000300000000000000000000000040000000000000007000000"
        "010000003000000000000000300100001a000000000000000000000001000000010000002200000002000000"
        "00000000000000004c0100006000000005000000050000000400000010000000100000000300000000000000"
        "00000000ac0100002a000000000000000000000001000000000000001a000000030000000000000000000000"
        "d60100001200000000000000000000000100000000000000"
    )

    @staticmethod
    def _functions(buffer):
        report = Disassembler(_config()).disassembleUnmappedBuffer(buffer)
        return {function.offset: function for function in report.getFunctions()}

    def test_a_pointer_into_rodata_is_not_a_function(self):
        functions = self._functions(self.RODATA_POINTERS)
        self.assertEqual(sorted(functions), [0x10140, 0x10160])

    def test_movw_movt_building_a_pc_offset_is_not_a_code_address(self):
        functions = self._functions(self.THUMB_PIC)
        self.assertEqual(
            {
                offset: (function.architecture_metadata["thumb"], function.num_instructions)
                for offset, function in functions.items()
            },
            {0x10000: (True, 8), 0x10020: (False, 8), 0x10040: (True, 1)},
        )
        adr_w = next(
            instruction for instruction in functions[0x10000].getInstructions() if instruction.offset == 0x1000C
        )
        self.assertEqual(list(adr_w.getDataRefs()), [0x1014C])

    def test_branches_and_fall_through_into_a_symbol_reach_another_function(self):
        functions = self._functions(self.DECLARED_STARTS)
        self.assertEqual(
            {offset: function.num_instructions for offset, function in functions.items()},
            {0x10000: 3, 0x1000C: 4, 0x1001C: 3, 0x10028: 2},
        )


def _loadXored(name):
    data = (Path(__file__).resolve().parent / name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _functionModes(report):
    return {
        function.offset: (function.architecture_metadata["thumb"], function.num_instructions)
        for function in report.getFunctions()
    }


class ArmInstructionSetEvidenceTest(unittest.TestCase):
    """Where an image states the instruction set of its code, and where the bytes around a
    start would mislead. Fixtures are ``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -N
    --strip-all -Ttext=0x10000`` with ``.comment`` removed, unless stated otherwise."""

    def test_unwind_entries_in_a32_code_are_thumb_by_their_push_or_alignment(self):
        """``arm_exidx_thumb_in_a32_xored``; only ``.ARM.exidx`` names the Thumb functions:

        _start            (A32) bl leaf0; bl leaf1; bl leaf2; bl leaf3; b .
        leaf0..leaf3      (A32) add r0, r0, #N; bx lr
        word_aligned      (T32) push {r4, r5, r7, lr}; movs r4, r0; adds r5, r1, #2
                                muls r4, r5, r4; pop {r4, r5, r7, pc}
        halfword_aligned  (T32) adds r0, r0, r1; lsls r0, r0, #2; b word_aligned
        """
        report = Disassembler(_config()).disassembleUnmappedBuffer(_loadXored("arm_exidx_thumb_in_a32_xored"))
        self.assertEqual(
            _functionModes(report),
            {
                0x10000: (False, 5),
                0x10014: (False, 2),
                0x1001C: (False, 2),
                0x10024: (False, 2),
                0x1002C: (False, 2),
                0x10034: (True, 5),
                0x1003E: (True, 3),
            },
        )

    def test_unwind_entries_in_thumb_code_are_a32_by_their_code(self):
        """``arm_exidx_a32_in_thumb_xored``; A32 helpers without a push, as crtbegin has:

        _start            (T32) push {r4, lr}; bl t0; bl t1; bl t2; pop {r4, pc}
        t0..t2            (T32) adds r0, #N; bx lr
        call_if_set       (A32) cmp r0, #0; bxeq lr; bx r0
        register_handler  (A32) mov r1, r0; ldr r0, 1f; ldr r2, 2f; add r0, pc, r0
                                add r2, pc, r2; b call_if_set; 1: .word 0x40; 2: .word 0x44
        """
        report = Disassembler(_config()).disassembleUnmappedBuffer(_loadXored("arm_exidx_a32_in_thumb_xored"))
        self.assertEqual(
            _functionModes(report),
            {
                0x10000: (True, 5),
                0x10010: (True, 2),
                0x10014: (True, 2),
                0x10018: (True, 2),
                0x1001C: (False, 3),
                0x10028: (False, 6),
            },
        )

    def test_function_symbols_decide_the_instruction_set_of_unlabelled_code(self):
        """``arm_dynsym_thumb_default_xored``, linked ``-shared``: no mode markers in
        ``.text`` and A32 ``bx lr`` words in ``.rodata`` next to it; ``api`` is exported.

            opcodes  .rodata: .word 0xe12fff1e, 0xe12fff1e, 0xe1a0f00e
            api      (T32) push {r4, lr}; movs r4, r0; adds r0, r4, #5; pop {r4, pc}
            hidden   (T32) push {r4, r5, r7, lr}; movs r4, r0; adds r5, r1, #2; muls r4, r5, r4
                           subs r0, r4, r5; pop {r4, r5, r7, pc}
        """
        report = Disassembler(_config()).disassembleUnmappedBuffer(_loadXored("arm_dynsym_thumb_default_xored"))
        self.assertEqual(_functionModes(report), {0x120: (True, 4), 0x128: (True, 6)})

    def test_mapping_symbols_name_the_instruction_set_and_the_data(self):
        """``arm_mapping_symbols_xored``, ``clang --target=armv7-linux-gnueabihf -fuse-ld=lld
        -ffreestanding -nostdlib -static -Wl,-N,-Ttext=0x10000,--build-id=none,--entry=0`` of an
        assembly file with local labels only, ``.comment`` removed: no entry point and no function
        symbols, ``.symtab`` holds ``$a`` at 0x10000, ``$d`` at 0x10018 and ``$t`` at 0x10028:

            (A32)  push {r4, lr}; adr r1, table; ldr r0, [r1, r0, lsl #2]; ldr r1, pool
                   add r0, r0, r1; pop {r4, pc}
            pool   .word 0xe92d4ff0 (reads as push {r4-r11, lr})
            table  .word 0xe92d4010, 0xe3a00007, 0xe8bd8010 (push {r4, lr}; mov r0, #7; pop {r4, pc})
            (T32)  push {r7, lr}; movs r0, #42; adds r0, r0, r1; pop {r7, pc}, reached by nothing
        """
        report = Disassembler(_config()).disassembleUnmappedBuffer(_loadXored("arm_mapping_symbols_xored"))
        modes = _functionModes(report)
        self.assertEqual(modes[0x10000], (False, 6))
        self.assertEqual(modes[0x10028], (True, 4))
        decoded = {ins.offset for function in report.getFunctions() for ins in function.getInstructions()}
        self.assertNotIn(0x10018, decoded)
        # the adr names the table, which $d declares data
        self.assertEqual(sorted(modes), [0x10000, 0x10028])

    def test_an_adr_to_a_switch_table_is_no_a32_function_in_a_thumb_only_pe(self):
        """``armnt_adr_switch_table_xored``, ``llvm-mc -triple=thumbv7-windows-msvc`` +
        ``lld-link /machine:arm /dll /noentry /export:entry``; the byte table reads as an
        A32 ``b``:

            entry     push {r4, lr}; bl dispatch; pop {r4, pc}
            c0..c3    movs r0, #N (adds r0, #1); bx lr - c2: b 9f
            dispatch  cmp r0, #3; bhi 9f; adr r3, 1f; ldrsb r3, [r3, r0]; add pc, r3
                      1: .byte c0 - 1b, c1 - 1b, c2 - 1b, c3 - 1b; 9: movs r0, #0; bx lr
        """
        report = Disassembler(_config()).disassembleUnmappedBuffer(_loadXored("armnt_adr_switch_table_xored"))
        modes = _functionModes(report)
        # the resolved table brings c0..c3 into dispatch
        self.assertEqual(modes[0x10001018], (True, 15))
        self.assertEqual([hex(start) for start, (thumb, _) in modes.items() if not thumb], [])

    # A minimal armv7 MH_BUNDLE wrapped around the __text of ``llvm-mc
    # -triple=thumbv7-apple-ios`` of the PE source above with ``.data_region jt8`` around the
    # table, plus ``_arm_helper`` (A32: cmp r0, #0; bxeq lr; bx r0); LC_SYMTAB has
    # N_ARM_THUMB_DEF on _entry and _dispatch only, LC_DATA_IN_CODE names the table.
    MACHO_ARMV7 = bytes.fromhex(
        "cefaedfe0c000000090000000800000003000000a400000000000000010000007c0000005f5f544558540000"
        "000000000000000000400000001000000000000042010000050000000500000001000000000000005f5f7465"
        "7874000000000000000000005f5f5445585400000000000000000000c040000038000000c000000002000000"
        "000000000000000000040080000000000000000002000000180000000001000003000000240100001e000000"
        "2900000010000000f80000000800000010b500f009f810bd0a20013070470d2070470b20704707e0032805d8"
        "01a31b569f440000e4eef2ea00207047000050e31eff2f0110ff2fe1e400000004000200010000000f010800"
        "d84000000b0000000f010000ec400000170000000f010800c0400000005f6469737061746368005f61726d5f"
        "68656c706572005f656e74727900"
    )

    def test_a_thumb_only_macho_has_a32_code_only_where_a_symbol_states_it(self):
        report = Disassembler(_config()).disassembleUnmappedBuffer(self.MACHO_ARMV7)
        modes = _functionModes(report)
        self.assertNotIn(0x40E4, modes)
        self.assertEqual(modes[0x40D8], (True, 15))
        self.assertEqual(modes[0x40EC], (False, 3))
        self.assertEqual([hex(start) for start, (thumb, _) in modes.items() if not thumb], ["0x40ec"])


class ArmRoutingTest(unittest.TestCase):
    def test_a_headerless_arm_buffer_is_recognised(self):
        body = IDIOMS * 64
        self.assertTrue(looksLikeArm(body))
        self.assertEqual(Disassembler(_config()).disassembleBuffer(body, BASE).architecture, "arm")

    def test_x86_code_is_not_mistaken_for_arm(self):
        self.assertFalse(looksLikeArm(bytes.fromhex("554889e55dc3") * 4096))

    def test_mode_markers_separate_the_instruction_sets(self):
        self.assertEqual(countModeMarkers(bytes.fromhex("1eff2fe1") * 4), (4, 0))
        self.assertEqual(countModeMarkers(bytes.fromhex("7047") * 4), (0, 4))

    def test_explicit_backend(self):
        report = Disassembler(_config(), backend="arm").disassembleBuffer(IDIOMS, BASE)
        self.assertEqual(report.architecture, "arm")
        self.assertEqual(report.num_functions, len(EXPECTED_FUNCTIONS))


class ArmDefinitionsTest(unittest.TestCase):
    def test_split_mnemonic(self):
        cases = {
            "addeq.w": ("add", "eq", False),
            "adds": ("add", None, True),
            "movs": ("mov", None, True),
            "subs": ("sub", None, True),
            "bls": ("b", "ls", False),
            "bleq": ("bl", "eq", False),
            "bics": ("bic", None, True),
            "teq": ("teq", None, False),
            "vadd.f32": ("vadd.f32", None, False),
        }
        for mnemonic, expected in cases.items():
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(split_mnemonic(mnemonic), expected)

    def test_a32_branch_targets(self):
        # bl 0x10020 at 0x10004; blx 0x100ec (H bit set) at 0x10010
        self.assertEqual(a32_branch_target(0xEB000005, 0x10004), (0x10020, False))
        self.assertEqual(a32_branch_target(0xFA000035, 0x10010), (0x100EC, True))

    def test_t32_call_targets(self):
        # bl +0 and blx +0: the A32 target of blx is word aligned
        self.assertEqual(t32_call_target(0xF000, 0xF800, 0x1000), (0x1004, True))
        self.assertEqual(t32_call_target(0xF000, 0xE800, 0x1002), (0x1004, False))

    def test_returns(self):
        self.assertTrue(is_return_instruction("bxeq", "lr"))
        self.assertTrue(is_return_instruction("pop.w", "{r4, pc}"))
        self.assertTrue(is_return_instruction("ldm", "sp!, {r4, pc}"))
        self.assertTrue(is_return_instruction("mov", "pc, lr"))
        self.assertFalse(is_return_instruction("bx", "r3"))
        self.assertFalse(is_return_instruction("pop", "{r4, lr}"))


class _Instruction:
    def __init__(self, raw, mnemonic, operands, thumb):
        self.bytes = raw
        self.mnemonic = mnemonic
        self.operands = operands
        self.smda_function = type("F", (), {"architecture_metadata": {"thumb": thumb}})()


class ArmEscaperTest(unittest.TestCase):
    def test_mnemonic_groups(self):
        cases = {
            "bl": "C",
            "bxeq": "C",
            "cbz": "C",
            "tbb": "C",
            "itte": "C",
            "push": "S",
            "vpop": "S",
            "ldr.w": "M",
            "strd": "M",
            "ldmia": "M",
            "vldr": "M",
            "adds": "A",
            "movw": "A",
            "umull": "A",
            "vadd.f64": "F",
            "nop": "N",
            "svc": "P",
            "mcr": "P",
            "dmb": "P",
        }
        for mnemonic, expected in cases.items():
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(ArmInstructionEscaper.escapeMnemonic(mnemonic), expected)

    def test_operand_escaping(self):
        cases = [
            ("ldr", "r0, [pc, #0x38]", "REG, PTR"),
            ("add", "r0, r1, r2, lsl #2", "REG, REG, REG"),
            ("push", "{r4, r5, lr}", "REG"),
            ("ldm", "sp!, {r4, pc} ^", "REG, REG"),
            ("mov", "r0, #7", "REG, CONST"),
            ("it", "eq", "COND"),
            ("dmb", "ish", "BARRIER"),
            ("vmov.32", "d0[1], r0", "REG, REG"),
        ]
        for mnemonic, operands, expected in cases:
            with self.subTest(instruction=f"{mnemonic} {operands}"):
                instruction = _Instruction("00000000", mnemonic, operands, False)
                self.assertEqual(ArmInstructionEscaper.escapeOperands(instruction), expected)
        branch = _Instruction("050000eb", "bl", "#0x10020", False)
        self.assertEqual(ArmInstructionEscaper.escapeOperands(branch, offsets_only=True), "OFFSET")

    def test_position_dependent_fields_are_wildcarded(self):
        cases = [
            # A32 bl: imm24
            ("050000eb", "bl", False, "??????eb"),
            # A32 movw r0, #0x1234: imm4 and imm12 around Rd
            ("340201e3", "movw", False, "??0?0?e3"),
            # A32 ldr r3, [pc, #0x38]: imm12
            ("38309fe5", "ldr", False, "??3?9fe5"),
            # A32 register move: nothing to wildcard
            ("0fe0a0e1", "mov", False, "0fe0a0e1"),
            # T16 beq and b
            ("00d0", "beq", True, "??d0"),
            ("fee7", "b", True, "??e?"),
            # T16 ldr r0, [pc, #imm]
            ("0148", "ldr", True, "??48"),
            # T32 bl
            ("00f000f8", "bl", True, "??f???f?"),
            # T32 movw r0, #0x1234
            ("41f23420", "movw", True, "4?f????0"),
        ]
        for raw, mnemonic, thumb, expected in cases:
            with self.subTest(instruction=raw):
                instruction = _Instruction(raw, mnemonic, "", thumb)
                self.assertEqual(ArmInstructionEscaper.escapeBinary(instruction), expected)


if __name__ == "__main__":
    unittest.main()
