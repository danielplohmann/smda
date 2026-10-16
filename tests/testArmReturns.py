import unittest

from smda.arm.definitions import is_return_instruction
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000


def _config():
    config = SmdaConfig()
    config.TIMEOUT = 0
    return config


class ArmLoadMultipleReturnTest(unittest.TestCase):
    def test_a_load_multiple_into_pc_returns_whatever_its_base(self):
        self.assertTrue(is_return_instruction("pop", "{r4, pc}"))
        self.assertTrue(is_return_instruction("ldm", "sp!, {r4, pc}"))
        self.assertTrue(is_return_instruction("ldmdb", "fp, {fp, sp, pc}"))
        self.assertTrue(is_return_instruction("ldmdbne", "r11, {r11, sp, pc}"))
        self.assertTrue(is_return_instruction("ldm", "r0, {r4, r5, pc}"))

    def test_a_load_multiple_without_pc_does_not_return(self):
        self.assertFalse(is_return_instruction("pop", "{r4, lr}"))
        self.assertFalse(is_return_instruction("ldmdb", "fp, {fp, sp, lr}"))
        self.assertFalse(is_return_instruction("ldm", "r0, {r4, r5}"))


class ArmApcsFrameReturnTest(unittest.TestCase):
    """GCC ``-mapcs-frame`` epilogue, ``llvm-mc -triple=armv7a-none-eabi`` + ``ld.lld -Ttext=0x10000``."""

    # entry push {r4, lr}; bl frame; bl leaf; pop {r4, pc}
    # frame mov ip, sp; push {fp, ip, lr, pc}; sub fp, ip, #4; add r0, r0, #1; ldmdb fp, {fp, sp, pc}
    # leaf  mov r0, #0; bx lr
    APCS_FRAME = bytes.fromhex(
        "10402de9010000eb050000eb1080bde80dc0a0e100d82de904b04ce2010080e200a81be90000a0e31eff2fe1"
    )

    def test_ldmdb_through_the_frame_pointer_is_the_return(self):
        report = Disassembler(_config()).disassembleBuffer(self.APCS_FRAME, BASE, architecture="arm")
        self.assertEqual(sorted(function.offset for function in report.getFunctions()), [0x10000, 0x10010, 0x10024])
        frame = report.getFunction(0x10010)
        instructions = list(frame.getInstructions())
        self.assertEqual(instructions[-1].offset, 0x10020)
        self.assertEqual(instructions[-1].mnemonic, "ldmdb")
        self.assertEqual(frame.num_returns, 1)
        self.assertEqual(report.getFunction(0x10000).num_returns, 1)
        self.assertEqual(report.getFunction(0x10024).num_returns, 1)


if __name__ == "__main__":
    unittest.main()
