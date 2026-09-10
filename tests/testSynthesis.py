#!/usr/bin/python
"""Tests for experimental binary synthesis (SmdaReport.synthesizeBinary).

One fixture per format to keep runtime bounded: cutwail (PE), mirai x64 (ELF),
osx.hloader from the aarch64 Mach-O corpus. Structural assertions are made by
re-parsing the synthesized bytes with LIEF; planted bytes are verified per basic
block because blocks of a function are not necessarily contiguous.
"""

import copy
import json
import logging
import os
import struct
import types
import unittest
from pathlib import Path

import lief

from smda.common.SmdaReport import MAX_ADDRESS_VALUE, SmdaReport
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
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))
    fixture = next(entry for entry in manifest["fixtures"] if entry["id"] == fixture_id)
    raw = (CORPUS_DIR / fixture["path"]).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def _build_empty_segment_macho():
    """A 64-bit Mach-O header whose only LC_SEGMENT_64 has nsects == 0."""
    magic = 0xFEEDFACF
    header = struct.pack("<IIIIIIII", magic, 0x01000007, 0, 2, 1, 72, 0, 0)
    lc = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72,
        b"\x00" * 16,
        0x1000,
        0x1000,
        0,
        0,
        7,
        7,
        0,
        0,
    )
    return header + lc


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

    def testReportWithoutLayoutRaisesInsteadOfFailingInArithmetic(self):
        report = SmdaReport.fromDict(self.pe_report.toDict())
        report.base_addr = None
        with self.assertRaises(ValueError) as ctx:
            report.synthesizeBinary(output_format=FORMAT_PE)
        assert "base_addr" in str(ctx.exception)

    def testNegativeFunctionAddressIsRejectedOnImport(self):
        # the xcfg key becomes the function offset and the synthesizers pack it unsigned;
        # a negative one survived the image-span bound because max - min still measured sane
        report_dict = json.loads(json.dumps(self.pe_report.toDict()))
        offsets = sorted(int(offset) for offset in report_dict["xcfg"])
        report_dict["xcfg"][str(-0xD8A680)] = report_dict["xcfg"].pop(str(offsets[0]))

        with self.assertRaises(ValueError) as ctx:
            SmdaReport.fromDict(report_dict)
        assert "64-bit space" in str(ctx.exception)

    def testNegativeBlockAddressIsRejectedOnImport(self):
        report_dict = json.loads(json.dumps(self.pe_report.toDict()))
        offsets = sorted(int(offset) for offset in report_dict["xcfg"])
        function = report_dict["xcfg"][str(offsets[0])]
        block_address = next(iter(function["blocks"]))
        function["blocks"][str(-0x1000)] = function["blocks"].pop(block_address)

        with self.assertRaises(ValueError) as ctx:
            SmdaReport.fromDict(report_dict)
        assert "64-bit space" in str(ctx.exception)

    def testDerivedEntryPointOverflowIsRejected(self):
        # base_addr and oep are each inside the address space, but their sum is not, so the
        # deserialization bound cannot catch this - only the synthesizer that derives it can
        report_dict = json.loads(json.dumps(self.elf_report.toDict()))
        report_dict["base_addr"] = MAX_ADDRESS_VALUE - 1
        report_dict["oep"] = 1

        with self.assertRaises(ValueError) as ctx:
            SmdaReport.fromDict(report_dict).synthesizeBinary(output_format=FORMAT_ELF)
        assert "entry point" in str(ctx.exception)

    def testOversizedImageSpanIsRejected(self):
        report_dict = json.loads(json.dumps(self.pe_report.toDict()))
        offsets = sorted(int(offset) for offset in report_dict["xcfg"])
        template = report_dict["xcfg"][str(offsets[0])]
        far_offset = offsets[0] + SmdaConfig.MAX_IMAGE_SIZE * 4

        moved = copy.deepcopy(template)
        moved["offset"] = far_offset
        moved["blocks"] = {str(far_offset): next(iter(template["blocks"].values()))}
        report_dict["xcfg"][str(far_offset)] = moved

        for output_format in (FORMAT_PE, FORMAT_ELF, FORMAT_MACHO):
            with self.subTest(output_format=output_format):
                report = SmdaReport.fromDict(copy.deepcopy(report_dict))
                with self.assertRaises(ValueError) as ctx:
                    report.synthesizeBinary(output_format=output_format)
                assert "MAX_IMAGE_SIZE" in str(ctx.exception)

    def testAddressFieldsBeyond64BitsAreRejectedOnImport(self):
        for field in ("base_addr", "binary_size", "bitness", "identified_alignment", "oep"):
            for value in (-1, 2**64, 2**96):
                with self.subTest(field=field, value=value):
                    report_dict = copy.deepcopy(self.pe_report.toDict())
                    report_dict[field] = value
                    with self.assertRaises(ValueError):
                        SmdaReport.fromDict(report_dict)

    def testNonNumericScalarsAreRejectedOnImport(self):
        for field in ("base_addr", "binary_size", "bitness", "oep", "execution_time"):
            for value in ("x", [], {}, True):
                with self.subTest(field=field, value=value):
                    report_dict = copy.deepcopy(self.pe_report.toDict())
                    report_dict[field] = value
                    with self.assertRaises(ValueError):
                        SmdaReport.fromDict(report_dict)

    def testFractionalAddressFieldsAreRejectedOnImport(self):
        for field in ("base_addr", "binary_size", "bitness", "identified_alignment", "oep"):
            with self.subTest(field=field):
                report_dict = copy.deepcopy(self.pe_report.toDict())
                report_dict[field] = 1.5
                with self.assertRaises(ValueError):
                    SmdaReport.fromDict(report_dict)

        for field in ("execution_time", "confidence_threshold"):
            with self.subTest(field=field):
                report_dict = copy.deepcopy(self.pe_report.toDict())
                report_dict[field] = 1.5
                assert SmdaReport.fromDict(report_dict) is not None

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

    def testPeSynthesisNonContiguousImports(self):
        report = SmdaReport.fromDict(self.pe_report.toDict())
        imports = report.xmetadata["imported_functions"]
        sample_dll = next(dll for dll, _ in imports.values() if dll)
        base_slot = next(int(k) for k, v in imports.items() if v[0] == sample_dll)
        report.xmetadata["imported_functions"] = {
            str(base_slot): (sample_dll, "AAASynthFuncA"),
            str(base_slot + 0x10): (sample_dll, "AAASynthFuncB"),
        }
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        synthesized_names = {entry.name for imported in parsed.imports for entry in imported.entries if entry.name}
        assert {"AAASynthFuncA", "AAASynthFuncB"} <= synthesized_names

    def testAnImportNamedLikeAnOrdinalIsNotRewrittenIntoOne(self):
        """A PE imports by name or by ordinal; the report keeps only the string."""
        report = SmdaReport.fromDict(self.pe_report.toDict())
        imports = report.xmetadata["imported_functions"]
        base_slot = next(int(k) for k in imports)
        # "#1" cannot have come from the import parsers for this DLL: they write "#N"
        # only when no table resolves it, and ws2_32.dll ordinal 1 resolves to accept.
        # "#99999" is past a WORD, so it never came from an import table either. Only
        # "#4000" is a real ordinal - in range, and resolving nowhere.
        report.xmetadata["imported_functions"] = {
            str(base_slot): ("ws2_32.dll", "#1"),
            str(base_slot + 0x10): ("ws2_32.dll", "#4000"),
            str(base_slot + 0x20): ("ws2_32.dll", "#99999"),
        }
        parsed = lief.parse(report.synthesizeBinary(output_format=FORMAT_PE))
        entries = [entry for imported in parsed.imports for entry in imported.entries]
        by_name = {entry.name for entry in entries if entry.name}
        by_ordinal = {entry.ordinal for entry in entries if not entry.name}
        self.assertIn("#1", by_name)
        self.assertIn("#99999", by_name)
        self.assertNotIn(1, by_ordinal)
        self.assertIn(4000, by_ordinal)

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

    def testDecoratedImportNamesReachTheImportTableVerbatim(self):
        pe_report = SmdaReport.fromDict(self.pe_report.toDict())
        pe_slot = min(int(key) for key in pe_report.xmetadata["imported_functions"])
        pe_report.xmetadata["imported_functions"] = {pe_slot: ("solver.dll", "?compute@Solver@@QEAAHH@Z")}
        parsed = lief.parse(pe_report.synthesizeBinary())
        pe_names = {entry.name for imported in parsed.imports for entry in imported.entries if entry.name}
        assert "?compute@Solver@@QEAAHH@Z" in pe_names

        elf_report = SmdaReport.fromDict(self.elf_report.toDict())
        data_va = next(start for name, start, _ in self.elf_report.code_sections if name == ".data")
        elf_report.xmetadata["imported_functions"] = {data_va + 0x8: ("libstdc++.so.6", "_Znwm")}
        parsed = lief.parse(elf_report.synthesizeBinary())
        assert "_Znwm" in {symbol.name for symbol in parsed.dynamic_symbols}

        macho_report = SmdaReport.fromDict(self.macho_report.toDict())
        macho_slot = min(int(key) for key in macho_report.xmetadata["imported_functions"])
        macho_report.xmetadata["imported_functions"] = {macho_slot: ("/usr/lib/libc++.1.dylib", "__Znwm")}
        parsed = lief.parse(macho_report.synthesizeBinary())
        assert "__Znwm" in {symbol.name for symbol in parsed.symbols}

    def testFunctionsOutsideEverySectionGetASyntheticSection(self):
        # keeps the header (so the full path runs, not the minimal one) but moves every
        # section clear of the functions, which is the branch that builds the synthetic
        # span - the one that used to invert and reach struct.pack with a negative size
        for output_format, report in ((FORMAT_ELF, self.elf_report), (FORMAT_MACHO, self.macho_report)):
            with self.subTest(output_format=output_format):
                rebuilt = SmdaReport.fromDict(report.toDict())
                rebuilt.code_sections = [(name, 0x10, 0x20) for name, _, _ in rebuilt.code_sections]

                synthesized = rebuilt.synthesizeBinary(output_format=output_format)

                parsed = lief.parse(synthesized)
                assert parsed is not None
                assert parsed.sections

    def testASectionSpanningMoreThanTheImageLimitIsDropped(self):
        # the extents come from the report and the span is what gets allocated, so a section
        # claiming tens of gigabytes has to be dropped rather than laid out: a 611-byte
        # report reached 10GB through this before the bound
        for output_format, report in ((FORMAT_ELF, self.elf_report), (FORMAT_MACHO, self.macho_report)):
            with self.subTest(output_format=output_format):
                rebuilt = SmdaReport.fromDict(report.toDict())
                first = rebuilt.code_sections[0]
                rebuilt.code_sections = [(first[0], first[1], first[1] + 0x13DAF6E5B0), *rebuilt.code_sections[1:]]

                synthesized = rebuilt.synthesizeBinary(output_format=output_format)

                assert len(synthesized) <= SmdaConfig.MAX_IMAGE_SIZE
                assert lief.parse(synthesized) is not None

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

    def testMachoSynthesisNsectsZero(self):
        report = copy.deepcopy(self.macho_report)
        report.xheader = _build_empty_segment_macho()
        synthesized = report.synthesizeBinary()
        assert isinstance(synthesized, bytes)
        assert len(synthesized) > 0

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


class SynthesisRobustnessTestSuite(unittest.TestCase):
    def test_a_function_with_no_blocks_is_skipped_instead_of_raising(self):
        from smda.synthesis.BinarySynthesizer import BinarySynthesizer

        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("cutwail_xored"))
        offsets = sorted(report.xcfg)
        blockless = report.xcfg[offsets[0]]
        blockless.blocks = {}

        synthesizer = BinarySynthesizer.__new__(BinarySynthesizer)
        synthesizer.report = report
        synthesizer.warnings = []

        resolved = synthesizer._resolveFunctionOffsets(None)

        self.assertNotIn(offsets[0], resolved)
        self.assertEqual(len(resolved), len(offsets) - 1)

    def test_scattered_import_slots_do_not_pad_the_whole_gap(self):
        from smda.synthesis.PeSynthesizer import MAX_IAT_PADDING_SPAN, PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.warnings = []
        written = []

        def _record(regions, rva, thunk_value, ptr_size, data_only=False):
            written.append(rva)
            return True

        synthesizer._writeThunkAt = _record
        synthesizer._parseOrdinal = lambda dll, func: 1
        # two slots of one DLL a megabyte apart: only the real slots may be written
        far = 0x1000 + 0x100000
        synthesizer._writeThunks(
            [],
            {0x1000: ("kernel32.dll", "a"), far: ("kernel32.dll", "b")},
            [("kernel32.dll", [(0x1000, "a"), (far, "b")])],
            0,
            0,
            {},
            4,
        )

        self.assertEqual(sorted(written), [0x1000, far])
        self.assertGreater(far - 0x1000, MAX_IAT_PADDING_SPAN)

    def test_adjacent_import_slots_still_pad_their_gap(self):
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.warnings = []
        written = []

        def _record(regions, rva, thunk_value, ptr_size, data_only=False):
            written.append(rva)
            return True

        synthesizer._writeThunkAt = _record
        synthesizer._parseOrdinal = lambda dll, func: 1
        synthesizer._writeThunks(
            [],
            {0x1000: ("kernel32.dll", "a"), 0x100C: ("kernel32.dll", "b")},
            [("kernel32.dll", [(0x1000, "a"), (0x100C, "b")])],
            0,
            0,
            {},
            4,
        )

        self.assertIn(0x1004, written)
        self.assertIn(0x1008, written)

    def test_an_executable_section_is_mapped_executable_wherever_it_lands(self):
        from smda.synthesis.MachoSynthesizer import VM_PROT_EXECUTE, VM_PROT_WRITE, MachoSynthesizer

        synthesizer = MachoSynthesizer.__new__(MachoSynthesizer)
        synthesizer.warnings = []
        sections = [
            {
                "name": "__text",
                "segment": "__SOMETHINGELSE",
                "executable": True,
                "va_start": 0x1000,
                "va_end": 0x2000,
            },
            {
                "name": "__data",
                "segment": "__DATA",
                "executable": False,
                "va_start": 0x4000,
                "va_end": 0x5000,
            },
        ]

        segments = synthesizer._buildSegmentsHeuristic(sections)

        by_name = {segment["sections"][0]["name"]: segment for segment in segments}
        self.assertTrue(by_name["__text"]["perms"] & VM_PROT_EXECUTE)
        self.assertFalse(by_name["__text"]["perms"] & VM_PROT_WRITE)
        self.assertTrue(by_name["__data"]["perms"] & VM_PROT_WRITE)
        self.assertFalse(by_name["__data"]["perms"] & VM_PROT_EXECUTE)


class SynthesisLayoutTestSuite(unittest.TestCase):
    """Layout properties a re-loading disassembler depends on."""

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

    def test_import_slots_inside_code_are_relocated_instead_of_overwriting_it(self):
        report = copy.deepcopy(self.pe_report)
        base = report.base_addr
        report.xmetadata["imported_functions"] = {
            base + 0x1000: ("kernel32.dll", "CreateFileA"),
            base + 0x2000: ("kernel32.dll", "ExitProcess"),
        }
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_strings=False)
        parsed = lief.parse(synthesized)
        sections = [(base + s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []
        names = {entry.name for imported in parsed.imports for entry in imported.entries if entry.name}
        assert {"CreateFileA", "ExitProcess"} <= names
        bspack = next(s for s in parsed.sections if s.name.startswith(".bspack"))
        assert parsed.data_directory(lief.PE.DataDirectory.TYPES.IMPORT_TABLE).rva > bspack.virtual_address

    def test_recorded_import_slots_in_data_keep_their_address(self):
        report = self.pe_report
        slots = sorted(int(key) for key in report.xmetadata["imported_functions"])
        synthesized = report.synthesizeBinary()
        parsed = lief.parse(synthesized)
        thunk_rvas = {entry.iat_address for imported in parsed.imports for entry in imported.entries}
        assert {slot - report.base_addr for slot in slots} <= thunk_rvas

    def test_non_dict_imported_functions_do_not_crash_synthesis(self):
        report = copy.deepcopy(self.pe_report)
        report.xmetadata["imported_functions"] = "not-a-map"
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_strings=False)
        self.assertTrue(synthesized)
        self.assertIsNotNone(lief.parse(synthesized))

        report.xmetadata["imported_functions"] = {
            0x401000: "ExitProcess",
            "not-an-address": ("kernel32.dll", "CreateFileA"),
        }
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_strings=False)
        self.assertTrue(synthesized)
        self.assertIsNotNone(lief.parse(synthesized))

    def test_an_import_slot_below_the_image_base_places_no_negative_section(self):
        report = copy.deepcopy(self.pe_report)
        report.xheader = None
        report.xmetadata["imported_functions"] = {report.base_addr - 0x1000: ("kernel32.dll", "ExitProcess")}
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE, with_strings=False)
        parsed = lief.parse(synthesized)
        assert parsed is not None
        assert all(section.virtual_address > 0 for section in parsed.sections)
        assert ".smdaIAT" not in [section.name for section in parsed.sections]

    def test_a_low_string_ref_does_not_produce_a_section_at_rva_zero(self):
        report = copy.deepcopy(self.pe_report)
        report.xheader = None
        base = report.base_addr
        function = next(iter(report.xcfg.values()))
        function.stringrefs = [
            {"data_addr": base + 0x200, "string": "low"},
            {"data_addr": base + 0x50000, "string": "high"},
        ]
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE)
        parsed = lief.parse(synthesized)
        assert all(section.virtual_address >= parsed.optional_header.sizeof_headers for section in parsed.sections)
        for index, first in enumerate(parsed.sections):
            for second in list(parsed.sections)[index + 1 :]:
                assert not (
                    first.virtual_address < second.virtual_address + second.virtual_size
                    and second.virtual_address < first.virtual_address + first.virtual_size
                )

    def test_a_string_section_is_still_added_when_it_fits(self):
        report = copy.deepcopy(self.pe_report)
        report.xheader = None
        base = report.base_addr
        function = next(iter(report.xcfg.values()))
        function.stringrefs = [{"data_addr": base + 0x80000, "string": "far away"}]
        synthesized = report.synthesizeBinary(output_format=FORMAT_PE)
        parsed = lief.parse(synthesized)
        covering = [s for s in parsed.sections if s.virtual_address <= 0x80000 < s.virtual_address + s.virtual_size]
        assert covering
        assert bytes(covering[0].content).find(b"far away\x00") >= 0

    def test_unnamed_sections_still_reach_the_elf_section_header_table(self):
        report = copy.deepcopy(self.elf_report)
        report.code_sections = [("", start, end) for _, start, end in report.code_sections]
        synthesized = report.synthesizeBinary(output_format=FORMAT_ELF, with_strings=False)
        parsed = lief.parse(synthesized)
        named = [section for section in parsed.sections if section.virtual_address]
        assert len(named) == len([entry for entry in report.code_sections if entry[1] and entry[1] < entry[2]])
        assert all(section.name.startswith(".smda") for section in named)
        assert min(section.virtual_address - section.file_offset for section in named) == report.base_addr

    def test_a_fabricated_section_name_does_not_collide_with_a_real_one(self):
        report = copy.deepcopy(self.elf_report)
        report.code_sections = [
            (".smda0" if index == 0 else "", start, end) for index, (_, start, end) in enumerate(report.code_sections)
        ]
        synthesized = report.synthesizeBinary(output_format=FORMAT_ELF, with_strings=False)
        parsed = lief.parse(synthesized)
        names = [section.name for section in parsed.sections if section.virtual_address]
        assert len(names) == len(set(names))
        assert ".smda1" in names

    def test_elf_sections_stay_congruent_with_the_image_base(self):
        report = self.elf_report
        synthesized = report.synthesizeBinary(with_strings=False)
        parsed = lief.parse(synthesized)
        mapped = [section for section in parsed.sections if section.virtual_address and section.file_offset]
        assert min(section.virtual_address - section.file_offset for section in mapped) == report.base_addr
        loads = [segment for segment in parsed.segments if segment.type == lief.ELF.Segment.TYPE.LOAD]
        assert min(segment.virtual_address - segment.file_offset for segment in loads) == report.base_addr
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []

    def test_a_32bit_elf_with_imports_stays_congruent(self):
        data_va = next(start for name, start, _ in self.elf_report.code_sections if name == ".data")
        report = copy.deepcopy(self.elf_report)
        report.bitness = 32
        report.xheader = None
        report.xmetadata["imported_functions"] = {data_va + 0x8: ("libc.so.6", "system")}
        synthesized = report.synthesizeBinary(output_format=FORMAT_ELF, with_strings=False)
        parsed = lief.parse(synthesized)
        assert parsed.header.identity_class == lief.ELF.Header.CLASS.ELF32
        assert any(segment.type == lief.ELF.Segment.TYPE.DYNAMIC for segment in parsed.segments)
        mapped = [section for section in parsed.sections if section.virtual_address and section.file_offset]
        assert min(section.virtual_address - section.file_offset for section in mapped) == report.base_addr

    def test_macho_text_maps_from_file_offset_zero(self):
        report = self.macho_report
        synthesized = report.synthesizeBinary(with_strings=False)
        parsed = lief.parse(synthesized)
        text = next(segment for segment in parsed.segments if segment.name == "__TEXT")
        assert text.file_offset == 0
        assert min(segment.virtual_address - segment.file_offset for segment in parsed.segments) == report.base_addr
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []

    def test_macho_minimal_keeps_the_header_off_the_planted_bytes(self):
        report = SmdaReport.fromDict(self.macho_report.toDict())
        report.code_sections = []
        report.xheader = None
        synthesized = report.synthesizeBinary(output_format=FORMAT_MACHO)
        parsed = lief.parse(synthesized)
        text = next(segment for segment in parsed.segments if segment.sections)
        assert text.file_offset > 0
        sections = [(s.virtual_address, bytes(s.content)) for s in parsed.sections]
        assert _verify_planted_blocks(report, sections) == []


if __name__ == "__main__":
    unittest.main()


class SynthesisSectionOverflowTestSuite(unittest.TestCase):
    """Recovered code can run past the end of the section it starts in — a call at the tail of
    __text whose fall-through lands in the padding before __stubs. Planting must not drop the
    whole block over the byte that overflows."""

    def _sections(self, va_start, va_end, next_start=None):
        sections = [
            {
                "name": ".text",
                "va_start": va_start,
                "va_end": va_end,
                "executable": True,
                "raw": bytearray(b"\x90" * (va_end - va_start)),
            }
        ]
        if next_start is not None:
            sections.append(
                {
                    "name": ".next",
                    "va_start": next_start,
                    "va_end": next_start + 0x10,
                    "executable": True,
                    "raw": bytearray(b"\x90" * 0x10),
                }
            )
        return sections

    def _synthesizer(self, chunks):
        from smda.synthesis.BinarySynthesizer import BinarySynthesizer

        synthesizer = BinarySynthesizer.__new__(BinarySynthesizer)
        synthesizer.report = types.SimpleNamespace(architecture="intel", xcfg={0x1000: object()})
        synthesizer.warnings = []
        synthesizer._iterFunctionChunks = staticmethod(lambda _function: iter(chunks))
        return synthesizer

    def test_a_block_overflowing_its_section_grows_it_into_unclaimed_space(self):
        # the block needs one byte past .text, and nothing else claims it
        sections = self._sections(0x1000, 0x1005)
        synthesizer = self._synthesizer([(0x1000, b"\xe8\x01\x02\x03\x04\x90")])

        synthesizer._plantFunctionChunks(sections, [0x1000])

        self.assertEqual(sections[0]["va_end"], 0x1006)
        self.assertEqual(bytes(sections[0]["raw"]), b"\xe8\x01\x02\x03\x04\x90")
        self.assertEqual(synthesizer.warnings, [])

    def test_growth_stops_at_the_next_section_and_the_fitting_bytes_are_still_planted(self):
        # .next starts immediately, so the overflowing byte has nowhere to go; the five bytes
        # that do fit must still be planted rather than dropped with the block
        sections = self._sections(0x1000, 0x1005, next_start=0x1005)
        synthesizer = self._synthesizer([(0x1000, b"\xe8\x01\x02\x03\x04\xcc")])

        synthesizer._plantFunctionChunks(sections, [0x1000])

        self.assertEqual(sections[0]["va_end"], 0x1005)
        self.assertEqual(bytes(sections[0]["raw"]), b"\xe8\x01\x02\x03\x04")
        # the tail lands in the neighbouring executable section, which does cover it
        self.assertEqual(bytes(sections[1]["raw"][:1]), b"\xcc")
        self.assertEqual(synthesizer.warnings, [])

    def test_growth_takes_only_the_overflow_not_the_whole_gap(self):
        sections = self._sections(0x1000, 0x1005, next_start=0x2000)
        synthesizer = self._synthesizer([(0x1000, b"\xe8\x01\x02\x03\x04\x90")])

        synthesizer._plantFunctionChunks(sections, [0x1000])

        self.assertEqual(sections[0]["va_end"], 0x1006)
        self.assertEqual(synthesizer.warnings, [])

    def test_a_block_in_a_gap_between_sections_is_reported(self):
        # nothing to grow: the block starts inside no section at all
        sections = self._sections(0x1000, 0x1005, next_start=0x2000)
        synthesizer = self._synthesizer([(0x1500, b"\xe8\x01\x02\x03\x04")])

        synthesizer._plantFunctionChunks(sections, [0x1000])

        self.assertEqual(sections[0]["va_end"], 0x1005)
        self.assertEqual(len(synthesizer.warnings), 1)
        self.assertIn("fit no executable section", synthesizer.warnings[0])

    def test_a_block_below_its_section_is_clipped_not_wrapped(self):
        sections = self._sections(0x1000, 0x1010)
        synthesizer = self._synthesizer([(0x0FFE, b"\xaa\xbb\xcc")])

        synthesizer._plantFunctionChunks(sections, [0x1000])

        self.assertEqual(bytes(sections[0]["raw"][:1]), b"\xcc")
        self.assertEqual(bytes(sections[0]["raw"][1:2]), b"\x90")
        self.assertEqual(len(synthesizer.warnings), 1)

    def test_komplex_round_trips_every_instruction_in_all_three_formats(self):
        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("komplex_xored"))
        for output_format in (FORMAT_PE, FORMAT_ELF, FORMAT_MACHO):
            parsed = lief.parse(list(bytes(report.synthesizeBinary(output_format=output_format))))
            corrupt = []
            for function in report.getFunctions():
                for block in function.getBlocks():
                    for instruction in block.getInstructions():
                        expected = bytes.fromhex(instruction.bytes)
                        try:
                            got = bytes(parsed.get_content_from_virtual_address(instruction.offset, len(expected)))
                        except Exception:
                            got = b""
                        if got != expected:
                            corrupt.append(hex(instruction.offset))
            self.assertEqual(corrupt, [], f"{output_format} lost {len(corrupt)} instructions")


class SynthesisForeignHeaderTestSuite(unittest.TestCase):
    """A report keeps the header of the binary it came from. A synthesizer must only read its
    own format's fields out of it, or it decodes whatever those bytes happen to hold."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # a PE-origin report based above 4 GiB: a 32-bit Mach-O cannot express its addresses
        cls.pe_origin = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("rust_pe_gnu_xored"))

    def test_a_pe_header_does_not_make_a_64_bit_report_a_32_bit_macho(self):
        blob = bytes(self.pe_origin.synthesizeBinary(output_format=FORMAT_MACHO))

        self.assertEqual(struct.unpack("<I", blob[:4])[0], 0xFEEDFACF)

    def test_a_pe_header_does_not_supply_the_macho_cpu_type(self):
        blob = bytes(self.pe_origin.synthesizeBinary(output_format=FORMAT_MACHO))

        # CPU_TYPE_X86_64, derived from the report, not bytes 4:8 of an MZ header
        self.assertEqual(struct.unpack("<I", blob[4:8])[0], 0x01000007)

    def test_addresses_above_four_gib_survive_the_macho_round_trip(self):
        parsed = lief.parse(list(bytes(self.pe_origin.synthesizeBinary(output_format=FORMAT_MACHO))))

        lost = 0
        for function in self.pe_origin.getFunctions():
            for block in function.getBlocks():
                for instruction in block.getInstructions():
                    expected = bytes.fromhex(instruction.bytes)
                    try:
                        got = bytes(parsed.get_content_from_virtual_address(instruction.offset, len(expected)))
                    except Exception:
                        got = b""
                    lost += got != expected
        self.assertEqual(lost, 0)

    def test_a_real_macho_header_still_selects_the_word_size(self):
        from smda.synthesis.MachoSynthesizer import MachoSynthesizer

        synthesizer = MachoSynthesizer.__new__(MachoSynthesizer)
        # a 32-bit Mach-O header must still win over a report claiming 64-bit
        synthesizer.report = types.SimpleNamespace(
            xheader=struct.pack("<I", 0xFEEDFACE) + b"\x00" * 0x40, bitness=64, architecture="intel"
        )
        self.assertFalse(synthesizer._is64())

        synthesizer.report.xheader = struct.pack("<I", 0xFEEDFACF) + b"\x00" * 0x40
        self.assertTrue(synthesizer._is64())

    def test_a_foreign_header_falls_back_to_the_report_bitness(self):
        from smda.synthesis.MachoSynthesizer import MachoSynthesizer

        synthesizer = MachoSynthesizer.__new__(MachoSynthesizer)
        synthesizer.report = types.SimpleNamespace(xheader=b"MZ" + b"\x90" * 0x40, bitness=64, architecture="intel")
        self.assertTrue(synthesizer._is64())

        synthesizer.report.bitness = 32
        self.assertFalse(synthesizer._is64())

    def test_a_pe_header_does_not_reach_the_synthesized_elf_identity(self):
        blob = bytes(self.pe_origin.synthesizeBinary(output_format=FORMAT_ELF))
        e_type = struct.unpack("<H", blob[16:18])[0]

        self.assertEqual(blob[7:16], b"\x00" * 9)  # EI_PAD must be zero
        self.assertEqual(e_type, 2)  # ET_EXEC, not whatever bytes 16:18 of an MZ header hold

    def test_a_real_elf_header_still_supplies_the_identity(self):
        from smda.synthesis.ElfSynthesizer import ElfSynthesizer

        synthesizer = ElfSynthesizer.__new__(ElfSynthesizer)
        synthesizer.report = types.SimpleNamespace(
            xheader=b"\x7fELF" + bytes(range(4, 0x14)) + b"\x00" * 0x20, bitness=64, architecture="intel"
        )
        self.assertTrue(synthesizer._hasElfHeader(0x14))
        self.assertEqual(synthesizer._getMachine(), struct.unpack("<H", bytes(range(4, 0x14))[0x0E:0x10])[0])


class SynthesisLowRvaTestSuite(unittest.TestCase):
    """ELF binaries put their entry stub immediately after the program headers, so a report of
    one has functions below the RVA where a PE section can start. The image base is what has to
    move for those to be representable."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("bashlite_xored"))

    def test_functions_below_the_first_section_rva_are_planted(self):
        parsed = lief.parse(list(bytes(self.report.synthesizeBinary(output_format=FORMAT_PE))))

        lost = 0
        for function in self.report.getFunctions():
            for block in function.getBlocks():
                for instruction in block.getInstructions():
                    expected = bytes.fromhex(instruction.bytes)
                    try:
                        got = bytes(parsed.get_content_from_virtual_address(instruction.offset, len(expected)))
                    except Exception:
                        got = b""
                    lost += got != expected
        self.assertEqual(lost, 0)

    def test_the_lowered_image_base_stays_64k_aligned(self):
        parsed = lief.parse(list(bytes(self.report.synthesizeBinary(output_format=FORMAT_PE))))

        self.assertLess(parsed.optional_header.imagebase, self.report.base_addr)
        self.assertEqual(parsed.optional_header.imagebase % 0x10000, 0)

    def test_the_entry_point_keeps_its_absolute_address(self):
        parsed = lief.parse(list(bytes(self.report.synthesizeBinary(output_format=FORMAT_PE))))
        absolute = parsed.optional_header.imagebase + parsed.optional_header.addressof_entrypoint

        self.assertEqual(absolute, self.report.base_addr + self.report.oep)

    def test_the_xheader_path_keeps_the_reported_base(self):
        # cutwail carries a real PE header, so it synthesizes from that layout rather than from
        # function extents; the lowering must not reach it
        report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("cutwail_xored"))
        parsed = lief.parse(list(bytes(report.synthesizeBinary(output_format=FORMAT_PE))))

        self.assertEqual(parsed.optional_header.imagebase, report.base_addr)

    def test_a_base_is_not_lowered_when_the_lowest_function_already_clears_the_headers(self):
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.report = types.SimpleNamespace(base_addr=0x400000)

        self.assertEqual(synthesizer._imageBaseFor([0x401000, 0x402000], 0x1000), 0x400000)

    def test_the_base_is_never_lowered_below_zero(self):
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.report = types.SimpleNamespace(base_addr=0)

        self.assertEqual(synthesizer._imageBaseFor([0x40], 0x1000), 0)


def _lowestExecutableSectionVa(synthesized_elf):
    """Where an ELF with no usable entry point of its own has to aim instead."""
    parsed = lief.parse(list(synthesized_elf))
    return min(
        section.virtual_address for section in parsed.sections if lief.ELF.Section.FLAGS.EXECINSTR in section.flags_list
    )


class SynthesisEntryPointTestSuite(unittest.TestCase):
    """``oep`` is the one image field no span check bounds.

    _resolveFunctionOffsets caps how far apart the *functions* may sit, which keeps every RVA
    derived from them inside the format's header fields. The entry point is not a function
    offset, so a report may name one arbitrarily far from the image being rebuilt, and it
    reaches the header packers unchecked.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_load_xored_fixture("mirai_x64_xored"))

    def _reportWithEntryPoint(self, oep, bitness=None):
        report_dict = json.loads(json.dumps(self.report.toDict()))
        report_dict["oep"] = oep
        if bitness is not None:
            report_dict["bitness"] = bitness
        return SmdaReport.fromDict(report_dict)

    def test_a_pe_entry_point_beyond_the_rva_space_falls_back_to_text(self):
        # AddressOfEntryPoint is a 32-bit RVA; an oep more than 4 GiB above the image base
        # used to reach struct.pack_into and abort the whole synthesis
        report = self._reportWithEntryPoint(self.report.base_addr + (1 << 32))

        parsed = lief.parse(list(bytes(report.synthesizeBinary(output_format=FORMAT_PE))))
        text = next(section for section in parsed.sections if section.name == ".text")

        self.assertEqual(parsed.optional_header.addressof_entrypoint, text.virtual_address)

    def test_a_pe_entry_point_inside_the_rva_space_is_still_kept(self):
        report = self._reportWithEntryPoint(self.report.base_addr + 0x40)

        parsed = lief.parse(list(bytes(report.synthesizeBinary(output_format=FORMAT_PE))))
        absolute = parsed.optional_header.imagebase + parsed.optional_header.addressof_entrypoint

        self.assertEqual(absolute, report.base_addr + 0x40)

    def test_an_elf32_entry_point_beyond_the_32_bit_field_falls_back_to_text(self):
        # e_entry is half as wide in an ELF32 image, and struct truncates the high half rather
        # than refusing it, which silently aimed the entry at an unrelated address
        report = self._reportWithEntryPoint(self.report.base_addr + (1 << 32), bitness=32)

        synthesized = bytes(report.synthesizeBinary(output_format=FORMAT_ELF))
        entry = struct.unpack_from("<I", synthesized, 24)[0]

        self.assertNotEqual(entry, (report.base_addr + (1 << 32)) & 0xFFFFFFFF)
        self.assertEqual(entry, _lowestExecutableSectionVa(synthesized))

    def test_an_elf64_entry_point_beyond_the_32_bit_field_is_kept(self):
        oep = self.report.base_addr + (1 << 32)
        report = self._reportWithEntryPoint(oep)

        synthesized = bytes(report.synthesizeBinary(output_format=FORMAT_ELF))

        self.assertEqual(struct.unpack_from("<Q", synthesized, 24)[0], oep)

    def test_a_report_without_an_entry_point_uses_the_first_executable_section(self):
        report = self._reportWithEntryPoint(0)

        synthesized = bytes(report.synthesizeBinary(output_format=FORMAT_ELF))

        self.assertEqual(struct.unpack_from("<Q", synthesized, 24)[0], _lowestExecutableSectionVa(synthesized))

    def test_an_oep_below_the_base_is_read_as_an_offset_from_it(self):
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.report = types.SimpleNamespace(base_addr=0x400000, oep=0x1000)

        self.assertEqual(synthesizer._resolveEntryPoint(), 0x401000)

    def test_an_oep_at_or_above_the_base_is_read_as_absolute(self):
        from smda.synthesis.PeSynthesizer import PeSynthesizer

        synthesizer = PeSynthesizer.__new__(PeSynthesizer)
        synthesizer.report = types.SimpleNamespace(base_addr=0x400000, oep=0x401000)

        self.assertEqual(synthesizer._resolveEntryPoint(), 0x401000)
