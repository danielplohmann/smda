#!/usr/bin/python
"""Tests for experimental binary synthesis (SmdaReport.synthesizeBinary).

One fixture per format to keep runtime bounded: cutwail (PE), mirai x64 (ELF),
osx.hloader from the aarch64 Mach-O corpus. Structural assertions are made by
re-parsing the synthesized bytes with LIEF; planted bytes are verified per basic
block because blocks of a function are not necessarily contiguous.
"""

import json
import logging
import os
import unittest
from pathlib import Path

import lief

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.synthesis import FORMAT_ELF, FORMAT_MACHO, FORMAT_PE, sniffBinaryFormat

from .context import config

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"


def _load_xored_fixture(fixture_name):
    with open(os.path.join(config.PROJECT_ROOT, "tests", fixture_name), "rb") as f_binary:
        binary = f_binary.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(binary))


def _load_macho_fixture(fixture_id):
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text())
    fixture = next(entry for entry in manifest["fixtures"] if entry["id"] == fixture_id)
    raw = (CORPUS_DIR / fixture["path"]).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def _verify_planted_blocks(report, sections):
    """Checks every basic block's bytes against the synthesized sections.

    sections: iterable of (va_start, content) with content covering [va_start, va_start+len).
    Returns list of block offsets that could not be verified.
    """
    failures = []
    for _function_offset, smda_function in report.xcfg.items():
        for block_offset in sorted(smda_function.blocks.keys()):
            chunk = b"".join(bytes.fromhex(instruction.bytes) for instruction in smda_function.blocks[block_offset])
            for va_start, content in sections:
                if va_start <= block_offset and block_offset + len(chunk) <= va_start + len(content):
                    start = block_offset - va_start
                    if content[start : start + len(chunk)] == chunk:
                        break
            else:
                failures.append(block_offset)
    return failures


class SmdaSynthesisTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        string_config = SmdaConfig()
        string_config.WITH_STRINGS = True
        disasm = Disassembler(string_config, backend="intel")
        cls.pe_report = disasm.disassembleUnmappedBuffer(_load_xored_fixture("cutwail_xored"))
        cls.elf_report = disasm.disassembleUnmappedBuffer(_load_xored_fixture("mirai_x64_xored"))
        aarch64_disasm = Disassembler(string_config, backend="aarch64")
        cls.macho_report = aarch64_disasm.disassembleUnmappedBuffer(_load_macho_fixture("malpedia/osx.hloader"))

    def testSniffBinaryFormat(self):
        assert sniffBinaryFormat(self.pe_report.xheader) == FORMAT_PE
        assert sniffBinaryFormat(self.elf_report.xheader) == FORMAT_ELF
        assert sniffBinaryFormat(self.macho_report.xheader) == FORMAT_MACHO
        assert sniffBinaryFormat(None) is None
        assert sniffBinaryFormat(b"\x00" * 16) is None

    def testUnsupportedArchitectureRaises(self):
        report = SmdaReport(None)
        report.architecture = "cil"
        with self.assertRaises(NotImplementedError):
            report.synthesizeBinary(output_format=FORMAT_PE)

    def testHeaderlessReportRequiresExplicitFormat(self):
        report = SmdaReport.fromDict(self.pe_report.toDict())
        report.xheader = None
        with self.assertRaises(ValueError):
            report.synthesizeBinary()

    def testPeSynthesisFromHeader(self):
        report = self.pe_report
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        assert parsed is not None
        assert int(parsed.header.machine) == 0x14C
        sections = [(report.base_addr + s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []
        report_imports = {int(k): tuple(v) for k, v in report.xmetadata["imported_functions"].items()}
        synthesized_dlls = {imported.name for imported in parsed.imports}
        expected_dlls = {dll for dll, _ in report_imports.values()}
        assert synthesized_dlls == expected_dlls
        synthesized_names = {entry.name for imported in parsed.imports for entry in imported.entries if entry.name}
        expected_names = {name for _, name in report_imports.values() if not name.startswith("#")}
        assert expected_names <= synthesized_names

    def testPeSynthesisMinimalWithImports(self):
        report = SmdaReport.fromDict(self.pe_report.toDict())
        report.xheader = None
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE)
        parsed = lief.parse(synthesized)
        assert parsed is not None
        assert int(parsed.header.machine) == 0x14C
        sections = [(report.base_addr + s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []
        report_imports = {int(k): tuple(v) for k, v in report.xmetadata["imported_functions"].items()}
        synthesized_dlls = {imported.name for imported in parsed.imports}
        expected_dlls = {dll for dll, _ in report_imports.values()}
        assert synthesized_dlls == expected_dlls

    def testPeSynthesisDeterministic(self):
        assert self.pe_report.synthesizeBinary() == self.pe_report.synthesizeBinary()

    def testElfSynthesisFromSections(self):
        report = self.elf_report
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        assert parsed is not None
        loads = [segment for segment in parsed.segments if segment.type == lief.ELF.Segment.TYPE.LOAD]
        assert loads
        for index, first in enumerate(loads):
            for second in loads[index + 1 :]:
                assert not (
                    first.virtual_address < second.virtual_address + second.physical_size
                    and second.virtual_address < first.virtual_address + first.physical_size
                )
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections if s.name]
        assert _verify_planted_blocks(report, sections) == []

    def testElfSynthesisImportTables(self):
        data_va, data_end = next((start, end) for name, start, end in self.elf_report.code_sections if name == ".data")
        slot_a = data_va + 0x8
        slot_b = data_va + 0x10
        report = SmdaReport.fromDict(self.elf_report.toDict())
        report.xmetadata["imported_functions"] = {
            slot_a: ("libc.so.6", "system"),
            slot_b: (None, "strdup"),
        }
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        assert "libc.so.6" in list(parsed.libraries)
        dynsym_names = {symbol.name for symbol in parsed.dynamic_symbols}
        assert {"system", "strdup"} <= dynsym_names
        relocations = {relocation.address: relocation for relocation in parsed.dynamic_relocations}
        assert slot_a in relocations
        assert slot_b in relocations
        assert relocations[slot_a].symbol.name == "system"
        assert relocations[slot_b].symbol.name == "strdup"

    def testElfSynthesisMinimal(self):
        report = SmdaReport.fromDict(self.elf_report.toDict())
        report.code_sections = []
        report.xheader = None
        synthesized = report.synthesizeBinary(output_format=FORMAT_ELF)
        parsed = lief.parse(synthesized)
        assert parsed is not None
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections if s.name]
        assert _verify_planted_blocks(report, sections) == []

    def testMachoSynthesisFromHeader(self):
        report = self.macho_report
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        assert parsed is not None
        segment_names = [segment.name for segment in parsed.segments]
        assert "__TEXT" in segment_names
        assert "__DATA" in segment_names
        loads = list(parsed.segments)
        for index, first in enumerate(loads):
            for second in loads[index + 1 :]:
                assert not (
                    first.virtual_address < second.virtual_address + second.virtual_size
                    and second.virtual_address < first.virtual_address + first.virtual_size
                )
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []
        report_imports = {int(k): tuple(v) for k, v in report.xmetadata["imported_functions"].items()}
        symbol_names = {symbol.name for symbol in parsed.symbols}
        expected_names = {name for _, name in report_imports.values()}
        assert expected_names <= symbol_names
        expected_libs = {lib for lib, _ in report_imports.values() if lib}
        assert {library.name for library in parsed.libraries} == expected_libs

    def testMachoSynthesisDeterministic(self):
        assert self.macho_report.synthesizeBinary() == self.macho_report.synthesizeBinary()

    def testMachoSynthesisMinimal(self):
        report = SmdaReport.fromDict(self.macho_report.toDict())
        report.code_sections = []
        report.xheader = None
        synthesized = report.synthesizeBinary(output_format=FORMAT_MACHO)
        parsed = lief.parse(synthesized)
        assert parsed is not None
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []


if __name__ == "__main__":
    unittest.main()
