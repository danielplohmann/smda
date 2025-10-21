#!/usr/bin/python

import logging
import unittest

from smda.cil.CilInstructionEscaper import CilInstructionEscaper
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class DisassemblyTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testInstructionEscaping(self):
        test_data = [
            {
                "ins": (0, "55", "push", "ebp"),
                "mnemonic_group": "S",
                "escaped_operands": "REG",
            },
            {
                "ins": (1, "8365fc00", "and", "dword ptr [ebp - 4], 0"),
                "mnemonic_group": "A",
                "escaped_operands": "PTR, CONST",
            },
            {
                "ins": (2, "f30f1efa", "endbr64", ""),
                "mnemonic_group": "C",
                "escaped_operands": "",
            },
            {
                "ins": (3, "c58e5ad3", "vcvtss2sd", "xmm2, xmm14, xmm3"),
                "mnemonic_group": "X",
                "escaped_operands": "XREG, XREG, XREG",
            },
        ]
        for data in test_data:
            smda_ins = SmdaInstruction(data["ins"])
            self.assertEqual(
                smda_ins.getMnemonicGroup(IntelInstructionEscaper),
                data["mnemonic_group"],
            )
            self.assertEqual(
                smda_ins.getEscapedOperands(IntelInstructionEscaper),
                data["escaped_operands"],
            )

    def testIntelInstructionWildcarding(self):
        test_data = [
            # simple mov with IMM outside of address space
            {
                "ins": (0, "b803400080", "mov", "eax, 0x80004003"),
                "lower": 0x63300000,
                "upper": 0x63400000,
                "expected_bin": "b803400080",
                "bitness": 32,
                "expected_opc": "b8????????",
            },
            # simple mov with IMM within address space
            {
                "ins": (0, "ba2c893863", "mov", "edx, 0x6338892c"),
                "lower": 0x63300000,
                "upper": 0x63400000,
                "expected_bin": "ba????????",
                "bitness": 32,
                "expected_opc": "ba????????",
            },
            # mov with with address calc within address space
            {
                "ins": (0, "0fb681808f3b63", "mov", "eax, byte ptr [ecx + 0x633b8f80]"),
                "lower": 0x63300000,
                "upper": 0x63400000,
                "expected_bin": "0fb681????????",
                "bitness": 32,
                "expected_opc": "0fb6??????????",
            },
            # jump table calculation
            {
                "ins": (0, "ff2485788f3b63", "jmp", "dword ptr [eax*4 + 0x633b8f78]"),
                "lower": 0x63300000,
                "upper": 0x63400000,
                "expected_bin": "ff2485????????",
                "bitness": 32,
                "expected_opc": "ff????????????",
            },
            # should only wildcard last part as escaper doesn't know address space
            {
                "ins": (
                    0,
                    "c705ac974a00ac974a00",
                    "mov",
                    "dword ptr [0x4a97ac], 0x4a97ac",
                ),
                "lower": None,
                "upper": None,
                "expected_bin": "c705ac974a00????????",
                "bitness": 32,
                "expected_opc": "c7??????????????????",
            },
            # should escape both operands
            {
                "ins": (
                    0,
                    "c705ac974a00ac974a00",
                    "mov",
                    "dword ptr [0x4a97ac], 0x4a97ac",
                ),
                "lower": 0x400000,
                "upper": 0x4F0000,
                "expected_bin": "c705????????????????",
                "bitness": 32,
                "expected_opc": "c7??????????????????",
            },
            # should escape from the right side and only blank out one, despite finding two matches for the pattern
            {
                "ins": (0, "010505050505", "add", "dword ptr [0x5050505], eax"),
                "lower": 0x400000,
                "upper": 0x4F0000,
                "expected_bin": "0105????????",
                "bitness": 32,
                "expected_opc": "01??????????",
            },
            # should escape from the right side and only blank out one, despite finding two matches for the pattern
            {
                "ins": (
                    0,
                    "0f101515151515",
                    "movups",
                    "xmm2, xmmword ptr [0x15151515]",
                ),
                "lower": 0x400000,
                "upper": 0x4F0000,
                "expected_bin": "0f1015????????",
                "bitness": 32,
                "expected_opc": "0f10??????????",
            },
            # should ignore prefixes while wildcarding
            {
                "ins": (
                    0,
                    "666666660f008000224000",
                    "sldt",
                    "word ptr [rax + 0x402200]",
                ),
                "lower": 0x400000,
                "upper": 0x4F0000,
                "expected_bin": "666666660f0080????????",
                "bitness": 32,
                "expected_opc": "666666660f00??????????",
            },
            # should ignore prefixes and REX while wildcarding
            {
                "ins": (
                    0,
                    "66666666480f008000224000",
                    "sldt",
                    "word ptr [rax + 0x402200]",
                ),
                "lower": 0x400000,
                "upper": 0x4F0000,
                "expected_bin": "66666666480f0080????????",
                "bitness": 64,
                "expected_opc": "66666666480f00??????????",
            },
        ]
        for data in test_data:
            smda_report = SmdaReport()
            smda_report.bitness = data["bitness"]
            smda_function = SmdaFunction(smda_report=smda_report)
            smda_ins = SmdaInstruction(data["ins"], smda_function=smda_function)
            self.assertEqual(
                smda_ins.getEscapedBinary(
                    IntelInstructionEscaper,
                    lower_addr=data["lower"],
                    upper_addr=data["upper"],
                ),
                data["expected_bin"],
            )
            self.assertEqual(
                smda_ins.getEscapedToOpcodeOnly(IntelInstructionEscaper),
                data["expected_opc"],
            )

    def testCilInstructionWildcarding(self):
        test_data = [
            # call MemberRef
            {
                "ins": (0, "280a000006", "call", "SomeFunc"),
                "expected_bin": "28??????06",
                "expected_bin_intraprocedural": "28??????06",
                "expected_opc": "28????????",
                "bitness": 32,
            },
            {
                "ins": (0, "6fbb00000a", "callvirt", "SomeFunc"),
                "expected_bin": "6f??????0a",
                "expected_bin_intraprocedural": "6f??????0a",
                "expected_opc": "6f????????",
                "bitness": 32,
            },
            {
                "ins": (0, "2d3a", "brtrue.s", "0x5994"),
                "expected_bin": "2d3a",
                "expected_bin_intraprocedural": "2d??",
                "expected_opc": "2d??",
                "bitness": 32,
            },
            {
                "ins": (
                    0,
                    "450300000002000000060000000a000000",
                    "switch",
                    "[(0D50), (0D54), (0D58)]",
                ),
                "expected_bin": "450300000002000000060000000a000000",
                "expected_bin_intraprocedural": "45????????????????????????????????",
                "expected_opc": "45????????????????????????????????",
                "bitness": 32,
            },
            {
                "ins": (0, "20c48efb0e", "ldc.i4", "0xefb8ec4"),
                "expected_bin": "20c48efb0e",
                "expected_bin_intraprocedural": "20c48efb0e",
                "expected_opc": "20????????",
                "bitness": 32,
            },
        ]
        for data in test_data:
            smda_report = SmdaReport()
            smda_report.bitness = data["bitness"]
            smda_function = SmdaFunction(smda_report=smda_report)
            smda_ins = SmdaInstruction(data["ins"], smda_function=smda_function)
            self.assertEqual(CilInstructionEscaper.escapeToOpcodeOnly(smda_ins), data["expected_opc"])
            self.assertEqual(CilInstructionEscaper.escapeBinary(smda_ins), data["expected_bin"])
            self.assertEqual(
                CilInstructionEscaper.escapeBinary(smda_ins, escape_intraprocedural_jumps=True),
                data["expected_bin_intraprocedural"],
            )


if __name__ == "__main__":
    unittest.main()
