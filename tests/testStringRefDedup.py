#!/usr/bin/python
"""A string reached through more than one ref of the same instruction is reported once.

ARM records both the literal pool word and the value loaded from it as data refs of the
loading instruction, so the generic StringExtractor found every pool-loaded string twice.
"""

import types
import unittest
from pathlib import Path
from unittest import mock

from smda import Disassembler as disassembler_module
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

TESTS_DIR = Path(__file__).resolve().parent


def _load(name):
    raw = (TESTS_DIR / name).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def _stringrefs(report):
    return [
        (function.offset, entry["ins_addr"], entry["data_addr"], entry["string"])
        for function in report.getFunctions()
        for entry in function.stringrefs
    ]


class StringRefDedupTestSuite(unittest.TestCase):
    def testRepeatedRefIsReportedOnce(self):
        function = types.SimpleNamespace(stringrefs=None)
        report = types.SimpleNamespace(architecture="arm", getFunctions=lambda: [function])
        found = [
            ("hello", 0x1000, 0x2000, "string"),
            ("hello", 0x1000, 0x2000, "string"),
            ("hello", 0x1008, 0x2000, "string"),
        ]
        with mock.patch.object(disassembler_module, "extract_strings", return_value=iter(found)):
            Disassembler(SmdaConfig())._extractStrings(report)
        self.assertEqual(
            [(ref["ins_addr"], ref["data_addr"]) for ref in function.stringrefs], [(0x1000, 0x2000), (0x1008, 0x2000)]
        )

    def testArmLiteralPoolStringsAreNotDuplicated(self):
        config = SmdaConfig()
        config.WITH_STRINGS = True
        report = Disassembler(config).disassembleUnmappedBuffer(_load("mirai_arm_xored"))
        refs = _stringrefs(report)
        self.assertEqual(report.architecture, "arm")
        self.assertEqual(len(refs), 165)
        self.assertEqual(len(refs), len(set(refs)))


if __name__ == "__main__":
    unittest.main()
