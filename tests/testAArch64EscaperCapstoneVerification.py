#!/usr/bin/python
"""Rigorous AArch64 escaping verification against live capstone disassembly.

These tests do not rely on static mnemonic tables alone. Every corpus instruction is
re-disassembled with capstone and checked for:

1. SMDA decode fidelity (bytes, mnemonic, operands match capstone op_str)
2. Mnemonic grouping aligned with capstone metadata and repo control-flow definitions
3. Operand escaping derived from capstone operand classes (ARM64_OP_*)
4. Opcode masking for PIC sequences when capstone reports immediates/branches
"""

import json
import logging
import unittest
from collections import Counter
from pathlib import Path

import pytest

from smda.aarch64.AArch64CapstoneVerification import (
    expected_escaped_operands,
    expected_mnemonic_group,
    expected_operand_tokens,
    should_opcode_mask_immediates,
    smda_instruction_matches_capstone,
)
from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper as Escaper
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

pytestmark = pytest.mark.slow

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
STATIC_FIXTURE = Path(__file__).resolve().parent / "aarch64_static_xored"


def _xor_fixture(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _disassemble_raw(raw):
    config = SmdaConfig()
    config.TIMEOUT = 120
    config.CALCULATE_HASHING = True
    config.STORE_BUFFER = False
    return Disassembler(config).disassembleUnmappedBuffer(raw)


def _collect_decode_mismatches(report, fixture_id):
    decode_mismatches = Counter()
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            capstone_instruction = instruction.getDetailed()
            if not smda_instruction_matches_capstone(instruction, capstone_instruction):
                decode_mismatches[(fixture_id, instruction.mnemonic, instruction.operands)] += 1
    return decode_mismatches


def _collect_group_mismatches(report, fixture_id):
    group_mismatches = Counter()
    capstone_engine = report.getCapstone()
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            capstone_instruction = instruction.getDetailed()
            expected_group = expected_mnemonic_group(capstone_instruction, capstone_engine)
            actual_group = Escaper.escapeMnemonicForInstruction(instruction)
            if actual_group != expected_group:
                group_mismatches[
                    (fixture_id, instruction.mnemonic, instruction.operands, actual_group, expected_group)
                ] += 1
    return group_mismatches


def _collect_operand_mismatches(report, fixture_id):
    operand_mismatches = Counter()
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            capstone_instruction = instruction.getDetailed()
            expected = expected_escaped_operands(capstone_instruction)
            actual = Escaper.escapeOperands(instruction)
            if actual != expected:
                operand_mismatches[(fixture_id, instruction.mnemonic, instruction.operands)] += 1
    return operand_mismatches


def _collect_missing_opcode_masks(report, fixture_id):
    missing_masks = Counter()
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            capstone_instruction = instruction.getDetailed()
            if not should_opcode_mask_immediates(capstone_instruction):
                continue
            masked = Escaper.escapeToOpcodeOnly(instruction)
            if "?" not in masked:
                missing_masks[(fixture_id, instruction.mnemonic, instruction.operands)] += 1
    return missing_masks


class _CapstoneVerificationGatesMixin:
    fixture_id = None

    def _disassemble(self):
        raise NotImplementedError

    def test_instructions_match_capstone_disassembly(self):
        report = self._disassemble()
        self.assertEqual(report.status, "ok", self.fixture_id)
        decode_mismatches = _collect_decode_mismatches(report, self.fixture_id)
        self.assertEqual(
            decode_mismatches,
            Counter(),
            msg=f"SMDA/capstone decode mismatches: {decode_mismatches.most_common(5)}",
        )

    def test_mnemonic_groups_match_capstone_expectation(self):
        report = self._disassemble()
        group_mismatches = _collect_group_mismatches(report, self.fixture_id)
        self.assertEqual(
            group_mismatches,
            Counter(),
            msg=f"Mnemonic group mismatches: {group_mismatches.most_common(5)}",
        )

    def test_operand_escaping_matches_capstone_operand_classes(self):
        report = self._disassemble()
        operand_mismatches = _collect_operand_mismatches(report, self.fixture_id)
        for function in report.getFunctions():
            for instruction in function.getInstructions():
                capstone_instruction = instruction.getDetailed()
                for token in expected_operand_tokens(capstone_instruction):
                    self.assertIn(token, Escaper._VALID_ESCAPED_OPERANDS)
        self.assertEqual(
            operand_mismatches,
            Counter(),
            msg=f"Operand escaping mismatches: {operand_mismatches.most_common(5)}",
        )

    def test_pic_opcode_masking_matches_capstone_operand_shape(self):
        report = self._disassemble()
        missing_masks = _collect_missing_opcode_masks(report, self.fixture_id)
        self.assertEqual(
            missing_masks,
            Counter(),
            msg=f"Instructions missing opcode masks: {missing_masks.most_common(5)}",
        )


class TestAArch64EscaperCapstoneVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.fixtures = cls.manifest["fixtures"]

    def _disassemble(self):
        reports = []
        for fixture in self.fixtures:
            raw = _xor_fixture((CORPUS_DIR / fixture["path"]).read_bytes())
            report = _disassemble_raw(raw)
            self.assertEqual(report.status, "ok", fixture["id"])
            reports.append((fixture["id"], report))
        return reports

    def test_corpus_instructions_match_capstone_disassembly(self):
        decode_mismatches = Counter()
        for fixture_id, report in self._disassemble():
            decode_mismatches.update(_collect_decode_mismatches(report, fixture_id))
        self.assertEqual(
            decode_mismatches,
            Counter(),
            msg=f"SMDA/capstone decode mismatches: {decode_mismatches.most_common(5)}",
        )

    def test_corpus_mnemonic_groups_match_capstone_expectation(self):
        group_mismatches = Counter()
        for fixture_id, report in self._disassemble():
            group_mismatches.update(_collect_group_mismatches(report, fixture_id))
        self.assertEqual(
            group_mismatches,
            Counter(),
            msg=f"Mnemonic group mismatches: {group_mismatches.most_common(5)}",
        )

    def test_corpus_operand_escaping_matches_capstone_operand_classes(self):
        operand_mismatches = Counter()
        for fixture_id, report in self._disassemble():
            operand_mismatches.update(_collect_operand_mismatches(report, fixture_id))
            for function in report.getFunctions():
                for instruction in function.getInstructions():
                    capstone_instruction = instruction.getDetailed()
                    for token in expected_operand_tokens(capstone_instruction):
                        self.assertIn(token, Escaper._VALID_ESCAPED_OPERANDS)
        self.assertEqual(
            operand_mismatches,
            Counter(),
            msg=f"Operand escaping mismatches: {operand_mismatches.most_common(5)}",
        )

    def test_corpus_pic_opcode_masking_matches_capstone_operand_shape(self):
        missing_masks = Counter()
        for fixture_id, report in self._disassemble():
            missing_masks.update(_collect_missing_opcode_masks(report, fixture_id))
        self.assertEqual(
            missing_masks,
            Counter(),
            msg=f"Instructions missing opcode masks: {missing_masks.most_common(5)}",
        )


class TestAArch64StaticEscaperCapstoneVerification(_CapstoneVerificationGatesMixin, unittest.TestCase):
    fixture_id = "aarch64_static_xored"

    def _disassemble(self):
        return _disassemble_raw(_xor_fixture(STATIC_FIXTURE.read_bytes()))


if __name__ == "__main__":
    unittest.main()
