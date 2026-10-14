"""looksLikeArm on headerless buffers: what it must accept and the data it used to mistake for ARM.

Every buffer here is synthetic. The cases are reductions of misroutings measured on real files:
base64 text (a notebook with embedded images), the ``.eh_frame`` of i386 shared objects, a
Thumb-2 image carrying a few scattered A32 words, and MSVC-built Thumb-2 that returns through
``pop.w`` rather than ``bx lr``.
"""

import base64
import random
import struct
import unittest

from smda.arm.definitions import (
    A32_RETURN_BYTES,
    MIN_RETURN_SITES,
    MIN_T32_FRAME_SITES,
    T16_RETURN_BYTES,
    looksLikeArm,
)
from smda.common.instruction_set_probe import WINDOW_BYTES, countCodeReturnSites, hasDenseReturnRun
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

BASE = 0x10000

PUSH_W_R4_R8_LR = bytes.fromhex("2de9f041")  # push.w {r4-r8, lr}
POP_W_R4_R8_PC = bytes.fromhex("bde8f081")  # pop.w {r4-r8, pc}
PUSH_W_R4_R11_LR = bytes.fromhex("2de9f04f")  # push.w {r4-r11, lr}, MSVC's frame
POP_W_R4_R11_PC = bytes.fromhex("bde8f08f")  # pop.w {r4-r11, pc}, MSVC's return
MOV_R4_R0 = bytes.fromhex("0446")
ADDS_R0_1 = bytes.fromhex("0130")
BX_LR = T16_RETURN_BYTES
A32_BX_LR = A32_RETURN_BYTES[0]

#: a framed function followed by a leaf, as GCC emits them for armhf
GCC_THUMB_PAIR = PUSH_W_R4_R8_LR + MOV_R4_R0 * 4 + POP_W_R4_R8_PC + ADDS_R0_1 + BX_LR
#: an MSVC Thumb-2 function: no ``bx lr`` anywhere
MSVC_THUMB_FUNCTION = PUSH_W_R4_R11_LR + MOV_R4_R0 * 6 + POP_W_R4_R11_PC
#: a leaf: ``adds r0, #1; bx lr``
THUMB_LEAF = ADDS_R0_1 + BX_LR


def _config():
    config = SmdaConfig()
    config.TIMEOUT = 0
    config.WITH_STRINGS = False
    return config


def _route(buffer):
    return Disassembler(_config()).disassembleBuffer(buffer, BASE).architecture


def _base64_with_aligned_bx_lr(runs=256, spacing=512):
    """ASCII base64 holding an aligned "pG" (T16 ``bx lr``) every ``spacing`` bytes."""
    filler = base64.b64encode(random.Random(7).randbytes(runs * spacing)).replace(b"pG", b"pg")
    chunks = []
    for index in range(runs):
        chunk = filler[index * spacing : (index + 1) * spacing]
        chunks.append(BX_LR + chunk[len(BX_LR) :])
    return b"".join(chunks)


def _i386_eh_frame(records=512):
    """FDEs whose CFA programs step the offset through 0x70 the way i386 argument pushes do.

    ``0e 70`` is DW_CFA_def_cfa_offset 0x70 and ``47`` the DW_CFA_advance_loc 7 after it.
    """
    program = bytes.fromhex("0e64470e68450e6c470e70470e74450e78420e7c410e8001")
    out = bytearray()
    assert (16 + program.index(BX_LR)) % 2 == 0, "the CFA program's 70 47 must sit at an even offset"
    for index in range(records):
        fde = struct.pack("<IIII", 0x2C, len(out) + 4, 0x1000 + index * 0x90, 0x8C) + program
        fde += b"\x00" * (-len(fde) % 8)
        out += fde
    return bytes(out)


class ArmProbeAcceptsTest(unittest.TestCase):
    def test_gcc_thumb2_is_recognised(self):
        self.assertTrue(looksLikeArm(GCC_THUMB_PAIR * 64))

    def test_msvc_thumb2_returning_through_pop_w_is_recognised(self):
        buffer = MSVC_THUMB_FUNCTION * 64
        self.assertNotIn(BX_LR, buffer)
        self.assertTrue(looksLikeArm(buffer))
        self.assertEqual(_route(buffer), "arm")

    def test_scattered_a32_words_do_not_hide_thumb_code(self):
        # sixteen A32 ``bx lr`` 128 KiB apart: enough hits to engage the A32 test, far too
        # sparse for its dense run; the T32 test must still get its turn
        tail = bytearray(2 * 1024 * 1024)
        for index in range(MIN_RETURN_SITES):
            tail[index * 128 * 1024 : index * 128 * 1024 + 4] = A32_BX_LR
        buffer = GCC_THUMB_PAIR * 64 + bytes(tail)
        self.assertGreaterEqual(countCodeReturnSites(buffer, A32_BX_LR, 4, MIN_RETURN_SITES), MIN_RETURN_SITES)
        self.assertFalse(hasDenseReturnRun(buffer, A32_BX_LR, 4, MIN_RETURN_SITES))
        self.assertTrue(looksLikeArm(buffer))

    def test_a32_code_is_still_recognised(self):
        self.assertTrue(looksLikeArm((bytes.fromhex("0100a0e3") * 3 + A32_BX_LR) * 64))


class ArmProbeRejectsTest(unittest.TestCase):
    def test_base64_text_is_not_thumb_code(self):
        buffer = _base64_with_aligned_bx_lr()
        # dense enough for the old bare-density rule, which routed it to arm
        self.assertTrue(hasDenseReturnRun(buffer, BX_LR, 2, MIN_RETURN_SITES))
        self.assertFalse(looksLikeArm(buffer))
        self.assertEqual(_route(buffer), "intel")

    def test_i386_eh_frame_is_not_thumb_code(self):
        buffer = _i386_eh_frame()
        self.assertTrue(hasDenseReturnRun(buffer, BX_LR, 2, MIN_RETURN_SITES))
        self.assertFalse(looksLikeArm(buffer))
        self.assertEqual(_route(buffer), "intel")

    def test_x86_dump_holding_base64_stays_intel(self):
        x86 = bytes.fromhex("554889e54883ec10897dfc8b45fc83c0015dc3") * 2048
        buffer = x86 + b"\x00" * (-len(x86) % 4096) + _base64_with_aligned_bx_lr()
        self.assertFalse(looksLikeArm(buffer))

    def test_bx_lr_in_utf16_text_does_not_count(self):
        unit = BX_LR + "abcdefghi".encode("utf-16-le")
        self.assertFalse(looksLikeArm(unit * 4096))


class ArmProbeFrameEvidenceTest(unittest.TestCase):
    """A dense run of T32 returns counts only with MIN_T32_FRAME_SITES frames in its window."""

    def _leaves_with_frames(self, frames, gap=0):
        leaves = THUMB_LEAF * (MIN_RETURN_SITES * 2)
        return leaves + b"\x00" * gap + PUSH_W_R4_R8_LR * frames

    def test_leaves_alone_are_not_enough(self):
        self.assertFalse(looksLikeArm(THUMB_LEAF * 4096))

    def test_one_frame_short_is_rejected(self):
        self.assertFalse(looksLikeArm(self._leaves_with_frames(MIN_T32_FRAME_SITES - 1)))

    def test_enough_frames_are_accepted(self):
        self.assertTrue(looksLikeArm(self._leaves_with_frames(MIN_T32_FRAME_SITES)))

    def test_frames_outside_the_window_do_not_count(self):
        self.assertFalse(looksLikeArm(self._leaves_with_frames(MIN_T32_FRAME_SITES, gap=WINDOW_BYTES)))


if __name__ == "__main__":
    unittest.main()
