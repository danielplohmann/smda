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

from smda.arm.ArmInstructionEscaper import ArmInstructionEscaper
from smda.arm.definitions import (
    a32_branch_target,
    countModeMarkers,
    is_return_instruction,
    looksLikeArm,
    split_mnemonic,
    t32_call_target,
)
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
