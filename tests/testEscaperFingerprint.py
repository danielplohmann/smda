"""Regression fingerprint for escaper output.

MCRIT (and anything else that persists escaped-operand signatures) consults
SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY to decide whether stored hashes are
stale. That marker did not move when 4.4.5 changed Intel escaping, so this
test hashes a committed corpus of escaped representations. If the digest
moves, bump ESCAPER_DOWNWARD_COMPATIBILITY to the current SmdaConfig.VERSION
in the same change.
"""

import hashlib
import logging
import unittest

logging.disable(logging.CRITICAL)

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper  # noqa: E402
from smda.cil.CilInstructionEscaper import CilInstructionEscaper  # noqa: E402
from smda.common.SmdaInstruction import SmdaInstruction  # noqa: E402
from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper  # noqa: E402
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper  # noqa: E402

# SHA-256 of the canonical escaped lines below. Update together with the
# compatibility marker when any InstructionEscaper changes its output.
ESCAPER_OUTPUT_FINGERPRINT = "3a0a318f568d282734a8879898d564b91914b25105f122c05f4efd657fca4233"

# (escaper, offset, bytes, mnemonic, operands) — bytes are unused; the
# fingerprint is mnemonic-group + escaped operands, the same pair MCRIT's
# EscapedBlockShingler indexes.
_CORPUS = [
    (IntelInstructionEscaper, (0, "", "nop", "")),
    (IntelInstructionEscaper, (0, "", "ret", "")),
    (IntelInstructionEscaper, (0, "", "push", "rbp")),
    (IntelInstructionEscaper, (0, "", "mov", "rax, qword ptr gs:[0x60]")),
    (IntelInstructionEscaper, (0, "", "mov", "eax, dword ptr es:[edi]")),
    (IntelInstructionEscaper, (0, "", "mov", "al, byte ptr es:[edi]")),
    (IntelInstructionEscaper, (0, "", "mov", "eax, dword ptr fs:[0]")),
    (IntelInstructionEscaper, (0, "", "mov", "rax, qword ptr gs:[0x28]")),
    (IntelInstructionEscaper, (0, "", "ljmp", "0x33:0x401000")),
    (IntelInstructionEscaper, (0, "", "movsq", "qword ptr es:[rdi], qword ptr ds:[rsi]")),
    (IntelInstructionEscaper, (0, "", "cmpsq", "qword ptr ds:[rsi], qword ptr es:[rdi]")),
    (IntelInstructionEscaper, (0, "", "popaw", "")),
    (IntelInstructionEscaper, (0, "", "pushaw", "")),
    (IntelInstructionEscaper, (0, "", "xgetbv", "")),
    (IntelInstructionEscaper, (0, "", "rorx", "eax, edx, 0x4")),
    (IntelInstructionEscaper, (0, "", "kmovq", "k0, rax")),
    (IntelInstructionEscaper, (0, "", "kmovq", "k7, rax")),
    (IntelInstructionEscaper, (0, "", "vmovdqa32", "zmm0 {k1}, zmmword ptr [rax]")),
    (IntelInstructionEscaper, (0, "", "vmovdqa32", "zmm0 {k1} {z}, zmm1")),
    (IntelInstructionEscaper, (0, "", "vpaddd", "zmm0, zmm1, dword ptr [rax]{1to16}")),
    (IntelInstructionEscaper, (0, "", "vmovdqa", "xmm20, xmm0")),
    (IntelInstructionEscaper, (0, "", "vmovdqa", "ymm18, ymm0")),
    (AArch64InstructionEscaper, (0, "", "ret", "")),
    (AArch64InstructionEscaper, (0, "", "stp", "x29, x30, [sp, #-0x10]!")),
    (AArch64InstructionEscaper, (0, "", "ldr", "x0, [x1, #0x10]")),
    (AArch64InstructionEscaper, (0, "", "bl", "#0x400800")),
    (AArch64InstructionEscaper, (0, "", "cbz", "w0, #0x14")),
    (CilInstructionEscaper, (0, "", "ldarg.0", "")),
    (CilInstructionEscaper, (0, "", "call", "0x06000001")),
    (CilInstructionEscaper, (0, "", "ldstr", "0x70000001")),
    (CilInstructionEscaper, (0, "", "br.s", "0x0a")),
    (CilInstructionEscaper, (0, "", "throw", "")),
    (DalvikInstructionEscaper, (0, "", "return-void", "")),
    (DalvikInstructionEscaper, (0, "", "invoke-virtual", "{v0, v1}, Lfoo;->m()V")),
    (DalvikInstructionEscaper, (0, "", "const-string", 'v0, "hello"')),
    (DalvikInstructionEscaper, (0, "", "goto", "+0xa")),
    (DalvikInstructionEscaper, (0, "", "add-int", "v0, v1, v2")),
]


def _escaped_line(escaper, ins_tuple):
    instruction = SmdaInstruction(ins_tuple)
    return f"{escaper.__name__}|{instruction.getMnemonicGroup(escaper)}|{instruction.getEscapedOperands(escaper)}\n"


def _fingerprint():
    digest = hashlib.sha256()
    for escaper, ins_tuple in _CORPUS:
        digest.update(_escaped_line(escaper, ins_tuple).encode("ascii"))
    return digest.hexdigest()


class EscaperFingerprintTestSuite(unittest.TestCase):
    def test_escaped_representation_fingerprint_is_stable(self):
        actual = _fingerprint()
        self.assertEqual(
            actual,
            ESCAPER_OUTPUT_FINGERPRINT,
            "escaper output changed; bump SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY "
            f"to the current package version and set ESCAPER_OUTPUT_FINGERPRINT to {actual}",
        )

    def test_the_4_4_5_intel_cases_in_the_corpus_escape_as_ptr_not_const(self):
        for operands in (
            "qword ptr gs:[0x60]",
            "dword ptr es:[edi]",
            "byte ptr es:[edi]",
            "dword ptr fs:[0]",
            "qword ptr gs:[0x28]",
        ):
            with self.subTest(operands=operands):
                self.assertEqual(IntelInstructionEscaper.escapeField(operands), "PTR")


if __name__ == "__main__":
    unittest.main()
