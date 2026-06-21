#!/usr/bin/python
"""Regression gate: AArch64 escaping must cover every mnemonic/operand in the corpus."""

import json
import logging
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper as Escaper
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
STATIC_FIXTURE = Path(__file__).resolve().parent / "aarch64_static_xored"


def _xor_fixture(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _collect_escaping_gaps(report):
    unhandled_mnemonics = Counter()
    invalid_operand_tokens = Counter()
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            if Escaper.escapeMnemonicForInstruction(instruction) == "U":
                unhandled_mnemonics[instruction.mnemonic] += 1
            for token in Escaper.escapeOperands(instruction).split(", "):
                token = token.strip()
                if token and token not in Escaper._VALID_ESCAPED_OPERANDS:
                    invalid_operand_tokens[token] += 1
    return unhandled_mnemonics, invalid_operand_tokens


class TestAArch64EscaperCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text())
        cls.fixtures = cls.manifest["fixtures"]

    def _disassemble_fixture(self, fixture):
        raw = _xor_fixture((CORPUS_DIR / fixture["path"]).read_bytes())
        config = SmdaConfig()
        config.TIMEOUT = 120
        config.CALCULATE_HASHING = True
        config.STORE_BUFFER = False
        return Disassembler(config).disassembleUnmappedBuffer(raw)

    def _disassemble_static_fixture(self):
        config = SmdaConfig()
        config.TIMEOUT = 120
        config.CALCULATE_HASHING = True
        config.STORE_BUFFER = False
        return Disassembler(config).disassembleUnmappedBuffer(_xor_fixture(STATIC_FIXTURE.read_bytes()))

    def test_corpus_escaping_has_no_gaps(self):
        total_unhandled = 0
        total_unescaped = 0
        for fixture in self.fixtures:
            with self.subTest(fixture=fixture["id"]):
                report = self._disassemble_fixture(fixture)
                self.assertEqual(report.status, "ok")
                unhandled, unescaped = _collect_escaping_gaps(report)
                total_unhandled += sum(unhandled.values())
                total_unescaped += sum(unescaped.values())
                self.assertEqual(
                    unhandled,
                    Counter(),
                    msg=f"Unhandled mnemonics in {fixture['id']}: {unhandled.most_common(10)}",
                )
                self.assertEqual(
                    unescaped,
                    Counter(),
                    msg=f"Invalid operand tokens in {fixture['id']}: {unescaped.most_common(10)}",
                )
        self.assertEqual(total_unhandled, 0)
        self.assertEqual(total_unescaped, 0)

    def test_static_elf_escaping_has_no_gaps(self):
        report = self._disassemble_static_fixture()
        self.assertEqual(report.status, "ok")
        unhandled, unescaped = _collect_escaping_gaps(report)
        self.assertEqual(unhandled, Counter())
        self.assertEqual(unescaped, Counter())

    def test_fallback_classification_matches_capstone_on_corpus(self):
        mismatches = Counter()
        for fixture in self.fixtures:
            report = self._disassemble_fixture(fixture)
            for function in report.getFunctions():
                for instruction in function.getInstructions():
                    with patch.object(
                        type(instruction),
                        "getDetailed",
                        side_effect=AttributeError("simulated capstone failure"),
                    ):
                        fallback_group = Escaper.escapeMnemonicForInstruction(instruction)
                    capstone_group = Escaper.escapeMnemonicForInstruction(instruction)
                    if fallback_group != capstone_group:
                        mismatches[(fixture["id"], instruction.mnemonic, fallback_group, capstone_group)] += 1
        self.assertEqual(
            mismatches,
            Counter(),
            msg=f"Fallback mnemonic mismatches: {mismatches.most_common(5)}",
        )


if __name__ == "__main__":
    unittest.main()
