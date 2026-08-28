import copy
import hashlib
import json
import logging
import struct
import tempfile
import unittest
from pathlib import Path

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import INTEL_PIC_HASH_ESCAPE_VERSION, LazyIntKeyDict, SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import REQUIRED_REPORT_FIELDS, SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

INTEL_BASE = 0x401000


def _disassemble_intel_bytes(code):
    config = SmdaConfig()
    config.WITH_STRINGS = False
    return Disassembler(config).disassembleBuffer(
        code,
        base_addr=INTEL_BASE,
        bitness=64,
        code_areas=[[INTEL_BASE, INTEL_BASE + len(code)]],
        oep=0,
    )


class TestCommonModels(unittest.TestCase):
    def test_lazy_int_key_dict_materializes_for_comparison_and_repr(self):
        # LazyIntKeyDict converts eagerly on construction (see finding 1): the data
        # is materialized into the real storage so JSON serialization sees it.
        expected = {1: "one", 2: "two"}

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertTrue(lazy._is_converted)
        self.assertEqual(lazy, expected)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(expected, lazy)

        left = LazyIntKeyDict({"1": "one", "2": "two"})
        right = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(left, right)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertFalse(lazy != expected)

        lazy = LazyIntKeyDict({"1": "one", "2": "two"})
        self.assertEqual(repr(lazy), "{1: 'one', 2: 'two'}")

        # int-key access/pop works after eager conversion
        lazy = LazyIntKeyDict({"16": "foo"})
        self.assertEqual(lazy.pop(16, "MISSING"), "foo")

    def test_empty_basic_block_string_is_safe(self):
        self.assertEqual(str(SmdaBasicBlock([])), "0x????????: (   0)")

    def test_report_without_disassembly_has_empty_cfg(self):
        # reports built without a disassembly (e.g. controlled error reports
        # for unsupported architectures) must expose an empty CFG, not crash
        report = SmdaReport()
        self.assertEqual(report.num_functions, 0)
        self.assertIsNone(report.getFunction(0x1000))
        self.assertEqual(list(report.getFunctions()), [])

    def test_report_without_disassembly_serializes(self):
        # such a report must also survive toDict() (no xmetadata/timestamp crash)
        report_dict = SmdaReport().toDict()
        self.assertEqual(report_dict["xcfg"], {})
        self.assertEqual(report_dict["xmetadata"], {})
        self.assertEqual(report_dict["timestamp"], "")
        # and round-trip back through fromDict without a strptime("") crash
        restored = SmdaReport.fromDict(report_dict)
        self.assertIsNone(restored.timestamp)
        self.assertEqual(restored.num_functions, 0)

    def test_report_round_trips_through_a_utf8_file(self):
        report = SmdaReport()
        report.filename = "café_módulo.exe"

        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path = Path(tmp_dir) / "report.smda"
            report.toFile(str(report_path))
            self.assertEqual(SmdaReport.fromFile(str(report_path)).filename, "café_módulo.exe")

            raw_path = Path(tmp_dir) / "raw.smda"
            raw_path.write_text(json.dumps(report.toDict(), ensure_ascii=False), encoding="utf-8")
            self.assertIn("café_módulo.exe", raw_path.read_bytes().decode("utf-8"))
            self.assertEqual(SmdaReport.fromFile(str(raw_path)).filename, "café_módulo.exe")

            with self.assertRaises(FileNotFoundError):
                SmdaReport.fromFile(str(Path(tmp_dir) / "absent.smda"))

    def test_report_rejects_non_mapping_function_payloads(self):
        report_dict = SmdaReport().toDict()

        for payload in (None, {"xcfg": []}, {"xcfg": {"0": []}}):
            with self.subTest(payload=payload):
                candidate = copy.deepcopy(report_dict)
                if payload is None:
                    candidate = payload
                else:
                    candidate.update(payload)
                with self.assertRaises(ValueError):
                    SmdaReport.fromDict(candidate)

    def test_report_rejects_missing_required_fields(self):
        report_dict = SmdaReport().toDict()

        for field in sorted(REQUIRED_REPORT_FIELDS):
            with self.subTest(field=field):
                candidate = copy.deepcopy(report_dict)
                candidate.pop(field)
                with self.assertRaises(ValueError):
                    SmdaReport.fromDict(candidate)

    def test_report_rejects_malformed_container_fields(self):
        report_dict = SmdaReport().toDict()
        malformed_fields = [
            ("metadata", []),
            ("code_sections", [1]),
            ("xdata_refs_from", []),
            ("xdata_refs_to", []),
            ("statistics", {"num_functions": 1}),
            ("xdata_refs_from", {"0": [0, "1"]}),
        ]

        for field, value in malformed_fields:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(report_dict)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    SmdaReport.fromDict(candidate)

    @staticmethod
    def _report_with_one_function(smda_version, metadata_extra=None):
        report_dict = SmdaReport().toDict()
        report_dict["architecture"] = "intel"
        report_dict["smda_version"] = smda_version
        report_dict["xcfg"] = {
            "0": {
                "offset": 0,
                "blocks": {},
                "apirefs": {},
                "blockrefs": {},
                "inrefs": [],
                "outrefs": {},
                "metadata": {
                    "binweight": 0,
                    "characteristics": [],
                    "confidence": 0,
                    "function_name": "",
                    "strongly_connected_components": [],
                    "tfidf": {},
                    **(metadata_extra or {}),
                },
            }
        }
        return report_dict

    def test_legacy_report_recalculates_missing_nesting_depth(self):
        restored = SmdaReport.fromDict(self._report_with_one_function("1.0.0"))

        self.assertEqual(restored.getFunction(0).nesting_depth, 0)

    def test_current_report_uses_the_cached_nesting_depth(self):
        restored = SmdaReport.fromDict(self._report_with_one_function("4.4.0", {"nesting_depth": 3}))
        self.assertEqual(restored.getFunction(0).nesting_depth, 3)

        restored = SmdaReport.fromDict(self._report_with_one_function("4.4.0"))
        self.assertEqual(restored.getFunction(0).nesting_depth, 0)

    def test_report_rejects_non_string_instruction_fields(self):
        report_dict = SmdaReport().toDict()
        report_dict["architecture"] = "intel"
        report_dict["xcfg"] = {
            "0": {
                "offset": 0,
                "blocks": {"0": [[0, [], "nop", ""]]},
                "apirefs": {},
                "blockrefs": {},
                "inrefs": [],
                "outrefs": {},
                "metadata": {
                    "binweight": 0,
                    "characteristics": [],
                    "confidence": 0,
                    "function_name": "",
                    "nesting_depth": 0,
                    "strongly_connected_components": [],
                    "tfidf": {},
                },
            }
        }

        with self.assertRaises(ValueError):
            SmdaReport.fromDict(report_dict)

    def test_report_rejects_invalid_scalar_fields(self):
        report_dict = SmdaReport().toDict()
        malformed_fields = {
            "statistics": ["invalid"],
            "timestamp": 1,
            "xheader": 1,
            "xmetadata": 1,
            "smda_version": 1,
        }

        for field, value in malformed_fields.items():
            with self.subTest(field=field):
                candidate = copy.deepcopy(report_dict)
                candidate[field] = value
                with self.assertRaises(ValueError):
                    SmdaReport.fromDict(candidate)

    def test_function_rejects_malformed_container_fields(self):
        function_dict = SmdaFunction().toDict()
        malformed_fields = {
            "incomplete": {},
            "blocks_type": {"blocks": []},
            "block_type": {"blocks": {"0": {}}},
            "apirefs_type": {"apirefs": []},
            "blockrefs_type": {"blockrefs": []},
            "outrefs_type": {"outrefs": []},
            "blockrefs_targets": {"blockrefs": {"0": [0, "1"]}},
            "inrefs_type": {"inrefs": {}},
            "metadata_type": {"metadata": []},
            "metadata_fields": {"metadata": {}},
            "architecture_metadata_type": {"architecture_metadata": []},
        }

        for name, updates in malformed_fields.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(function_dict)
                if name == "incomplete":
                    candidate.pop("metadata")
                candidate.update(updates)
                with self.assertRaises(ValueError):
                    SmdaFunction.fromDict(candidate)

    def test_block_refs_are_resorted_when_a_handler_target_is_not_a_block_start(self):
        from smda.DisassemblyResult import DisassemblyResult

        disassembly = DisassemblyResult()
        # one block at 0x200; the handler target at 0x100 belongs to no block, so it is
        # appended as a new key and the sorted order has to be restored
        disassembly.functions[0x200] = [[(0x200, 2, "nop", "", b"\x00\x00")]]
        disassembly.function_metadata[0x200] = {
            "try_ranges": [{"start_addr": 0x200, "end_addr": 0x202, "handlers": [{"target_addr": 0x100}]}]
        }

        block_refs = disassembly.getBlockRefs(0x200)

        self.assertEqual([0x100, 0x200], list(block_refs))
        self.assertEqual([], block_refs[0x100])
        self.assertEqual([0x100], block_refs[0x200])

    def test_block_refs_keep_seeded_order_when_no_handler_target_is_added(self):
        from smda.DisassemblyResult import DisassemblyResult

        disassembly = DisassemblyResult()
        disassembly.functions[0x100] = [[(0x100, 2, "jmp", "0x200", b"\x00\x00")], [(0x200, 2, "ret", "", b"\x00\x00")]]
        disassembly.code_refs_from[0x100] = {0x200}

        block_refs = disassembly.getBlockRefs(0x100)

        self.assertEqual([0x100, 0x200], list(block_refs))
        self.assertEqual([0x200], block_refs[0x100])

    def test_hash_sequences_fall_back_to_raw_bytes_without_an_escaper(self):
        # an unsupported architecture leaves _escaper None; both sequences must still be emitted
        function = SmdaFunction()
        function.blocks = {
            0x100: [SmdaInstruction([0x100, "5589e5", "push", "ebp"])],
            0x200: [SmdaInstruction([0x200, "c3", "ret", ""])],
        }
        function._sorted_block_keys = [0x100, 0x200]

        self.assertIsNone(function._escaper)
        self.assertEqual(b"5589e5c3", function.getPicHashSequence(None))
        self.assertEqual(b"5589e5c3", function.getOpcHashSequence())

    def test_function_hash_helpers_use_little_endian(self):
        function = SmdaFunction()
        function.pic_hash = 0x0102030405060708
        function.getPicHashSequence = lambda binary_info: b"pic-sequence"
        function.getOpcHashSequence = lambda: b"opc-sequence"

        self.assertEqual(function.getPicHashAsHex(), struct.pack("<Q", function.pic_hash).hex())
        self.assertEqual(
            function.getPicHash(None),
            struct.unpack("<Q", hashlib.sha256(b"pic-sequence").digest()[:8])[0],
        )
        self.assertEqual(
            function.getOpcHash(),
            struct.unpack("<Q", hashlib.sha256(b"opc-sequence").digest()[:8])[0],
        )

    def test_report_exports_language_metadata(self):
        # SmdaReport previously had no `language` attribute at all and dropped the whole
        # feature from toDict(); it must now be exported and round-trip through fromDict.
        config = SmdaConfig()
        config.WITH_STRINGS = False
        func = b"\x55\x48\x89\xe5\x5d\xc3"  # push rbp; mov rbp, rsp; pop rbp; ret
        code = func * 10
        thiscall_tail = b"\x8b\x4d\x04\xe8\x01\x02\x03\x00"
        buf = code + thiscall_tail
        base = 0x401000
        report = Disassembler(config).disassembleBuffer(
            buf, base_addr=base, bitness=64, code_areas=[[base, base + len(code)]]
        )

        self.assertIsInstance(report.language, dict)
        self.assertEqual(
            set(report.language),
            {"c/asm", "delphi", ".net", "visualbasic", "go", "rust", "c++"},
        )
        self.assertTrue(all(isinstance(score, float) for score in report.language.values()))

        report_dict = report.toDict()
        self.assertEqual(report_dict["metadata"]["language"], report.language)

        restored = SmdaReport.fromDict(report_dict)
        self.assertEqual(restored.language, report.language)

        legacy_native = copy.deepcopy(report_dict)
        legacy_native["metadata"]["language"] = {
            "_guess": "delphi",
            "_count_delphi_objects": 5,
            "_count_thiscalls": 2,
            "c/asm": 0.1,
            "delphi": 0.2,
            "delphi_kb_file": 1.0,
        }
        restored_native = SmdaReport.fromDict(legacy_native)
        self.assertEqual(restored_native.language, {"c/asm": 0.1, "delphi": 1.0})

        legacy_cil = copy.deepcopy(report_dict)
        legacy_cil["metadata"]["language"] = "cil"
        restored_cil = SmdaReport.fromDict(legacy_cil)
        self.assertEqual(restored_cil.language, {".net": 1.0})

        legacy_dalvik = copy.deepcopy(report_dict)
        legacy_dalvik["metadata"]["language"] = "dalvik"
        restored_dalvik = SmdaReport.fromDict(legacy_dalvik)
        self.assertEqual(restored_dalvik.language, {"dalvik": 1.0})

    def test_imported_intel_report_recalculates_pic_hash_before_escape_version(self):
        report = _disassemble_intel_bytes(b"\xc3")  # ret
        function = report.getFunction(INTEL_BASE)
        expected_pic_hash = function.pic_hash
        function_dict = function.toDict()
        function_dict["metadata"]["pic_hash"] = 0x0123456789ABCDEF

        imported = SmdaFunction.fromDict(function_dict, version="4.2.17", smda_report=report)

        self.assertEqual(imported.pic_hash, expected_pic_hash)
        self.assertLess([4, 2, 17], INTEL_PIC_HASH_ESCAPE_VERSION)

    def test_imported_intel_report_keeps_pic_hash_at_escape_version(self):
        report = _disassemble_intel_bytes(b"\xc3")  # ret
        function_dict = report.getFunction(INTEL_BASE).toDict()
        stored_pic_hash = 0x0123456789ABCDEF
        function_dict["metadata"]["pic_hash"] = stored_pic_hash
        gate_version = ".".join(str(v) for v in INTEL_PIC_HASH_ESCAPE_VERSION)

        imported = SmdaFunction.fromDict(function_dict, version=gate_version, smda_report=report)

        self.assertEqual(imported.pic_hash, stored_pic_hash)

    def test_imported_report_with_a_suffixed_version_recalculates_instead_of_raising(self):
        report = _disassemble_intel_bytes(b"\xc3")  # ret
        function = report.getFunction(INTEL_BASE)
        expected_pic_hash = function.pic_hash
        function_dict = function.toDict()
        function_dict["metadata"]["pic_hash"] = 0x0123456789ABCDEF

        imported = SmdaFunction.fromDict(function_dict, version="4.4.4-dev", smda_report=report)

        self.assertEqual(imported.pic_hash, expected_pic_hash)

    def test_imported_report_skips_hashing_against_an_unlocated_binary_info(self):
        report = _disassemble_intel_bytes(b"\xc3")  # ret
        function_dict = report.getFunction(INTEL_BASE).toDict()
        stored_pic_hash = 0x0123456789ABCDEF
        function_dict["metadata"]["pic_hash"] = stored_pic_hash
        unlocated = BinaryInfo(b"\xc3")
        unlocated.architecture = "intel"
        unlocated.base_addr = None
        unlocated.binary_size = None

        imported = SmdaFunction.fromDict(function_dict, binary_info=unlocated, version="1.0.0")

        self.assertEqual(imported.pic_hash, stored_pic_hash)

    def test_num_calls_and_returns_count_prefixed_mnemonics(self):
        # capstone prepends mandatory prefixes (bnd/rep/lock/...) to the mnemonic string;
        # a bnd-prefixed call/ret must still be counted as such.
        function = SmdaFunction()
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "f2e80b100000", "bnd call", "0x1010")),
                SmdaInstruction((0x1006, "f2c3", "bnd ret", "")),
            ]
        }

        self.assertEqual(function.num_calls, 1)
        self.assertEqual(function.num_returns, 1)

    def test_is_api_thunk_recognizes_prefixed_jump(self):
        # a single bnd-prefixed jmp/call through an API reference is still a thunk.
        function = SmdaFunction()
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "f2ff25", "bnd jmp", "dword ptr [0x2000]"))]}
        function.apirefs = {0x1000: ("kernel32.dll", "ExitProcess")}

        self.assertTrue(function.isApiThunk())

    def test_aarch64_num_calls_and_returns(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "94000001", "bl", "#0x1004")),
                SmdaInstruction((0x1004, "d63f0000", "blr", "x0")),
                SmdaInstruction((0x1008, "d65f0bff", "retaa", "")),
            ]
        }

        self.assertEqual(function.num_calls, 2)
        self.assertEqual(function.num_returns, 1)

    def test_aarch64_num_returns_counts_pac_and_exception_returns(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "d65f0fff", "retab", "")),
            ],
            0x1004: [
                SmdaInstruction((0x1004, "d69f0bff", "eretaa", "")),
            ],
        }

        self.assertEqual(function.num_returns, 2)

    def test_aarch64_is_api_thunk_recognizes_branch(self):
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "d61f0200", "br", "x16"))]}
        function.apirefs = {0x1000: ("libc.so", "printf")}

        self.assertTrue(function.isApiThunk())

        function.blocks = {0x1000: [SmdaInstruction((0x1000, "14000000", "b", "#0x1000"))]}
        self.assertTrue(function.isApiThunk())

    def test_aarch64_is_api_thunk_recognizes_multi_insn_plt(self):
        # ELF/Mach-O import stubs are adrp+ldr(+add)+br, optionally prefixed with bti/nop.
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x402000
        function.blocks = {
            0x402000: [
                SmdaInstruction((0x402000, "d503245f", "bti", "c")),
                SmdaInstruction((0x402004, "b0000010", "adrp", "x16, #0x403000")),
                SmdaInstruction((0x402008, "f9400e11", "ldr", "x17, [x16, #0x18]")),
                SmdaInstruction((0x40200C, "91006210", "add", "x16, x16, #0x18")),
                SmdaInstruction((0x402010, "d61f0220", "br", "x17")),
            ]
        }
        function.apirefs = {0x402010: ("libc.so", "puts")}

        self.assertTrue(function.isApiThunk())

        # A real function body (stp frame + bl) with an API ref is not a thunk.
        function.blocks = {
            0x402000: [
                SmdaInstruction((0x402000, "a9bf7bfd", "stp", "x29, x30, [sp, #-0x10]!")),
                SmdaInstruction((0x402004, "94000001", "bl", "#0x402008")),
                SmdaInstruction((0x402008, "d65f03c0", "ret", "")),
            ]
        }
        function.apirefs = {0x402004: ("libc.so", "puts")}
        self.assertFalse(function.isApiThunk())

    def test_aarch64_is_api_thunk_rejects_argument_setting_wrapper(self):
        # A wrapper that sets up an argument before tail-branching to an import
        # is a real function, not an import stub - mov/movz/movk/movn/ldp never
        # appear in a genuine ELF/Mach-O import-stub body.
        report = SmdaReport()
        report.architecture = "aarch64"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "52800020", "mov", "w0, #1")),
                SmdaInstruction((0x1004, "14000000", "b", "#0x1004")),
            ]
        }
        function.apirefs = {0x1004: ("libc.so", "exit")}

        self.assertFalse(function.isApiThunk())

    def test_cil_num_calls_counts_callvirt_and_calli(self):
        report = SmdaReport()
        report.architecture = "cil"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {
            0x1000: [
                SmdaInstruction((0x1000, "28", "call", "0x06000001")),
                SmdaInstruction((0x1005, "6f", "callvirt", "0x0a000002")),
                SmdaInstruction((0x100A, "29", "calli", "0x11000003")),
                SmdaInstruction((0x100F, "2a", "ret", "")),
            ]
        }

        self.assertEqual(function.num_calls, 3)
        self.assertEqual(function.num_returns, 1)

    def test_cil_is_api_thunk_recognizes_callvirt(self):
        report = SmdaReport()
        report.architecture = "cil"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "6f", "callvirt", "0x0a000002"))]}
        function.apirefs = {0x1000: ("mscorlib.dll", "WriteLine")}

        self.assertTrue(function.isApiThunk())

    def test_dalvik_is_api_thunk_recognizes_invoke(self):
        report = SmdaReport()
        report.architecture = "dalvik"
        function = SmdaFunction(smda_report=report)
        function.offset = 0x1000
        function.blocks = {0x1000: [SmdaInstruction((0x1000, "6e10", "invoke-virtual", "{v0}, Ljava/io/PrintStream;"))]}
        function.apirefs = {0x1000: ("Ljava/io/PrintStream;", "println")}

        self.assertTrue(function.isApiThunk())

    def test_instruction_from_tuple_matches_list_constructor(self):
        raw = (0x401000, 2, "mov", "eax, ebx", b"\x89\xc3")
        from_list = SmdaInstruction([raw[0], raw[4].hex(), str(raw[2]), str(raw[3])])
        from_tuple = SmdaInstruction.from_tuple(raw)
        self.assertEqual(from_tuple.offset, from_list.offset)
        self.assertEqual(from_tuple.bytes, from_list.bytes)
        self.assertEqual(from_tuple.mnemonic, from_list.mnemonic)
        self.assertEqual(from_tuple.operands, from_list.operands)

    def test_instruction_from_tuple_stringifies_non_str_fields(self):
        instruction = SmdaInstruction.from_tuple((0x10, 1, b"ret", None, b"\xc3"))
        self.assertEqual(instruction.mnemonic, "b'ret'")
        self.assertEqual(instruction.operands, "None")
        self.assertEqual(instruction.bytes, "c3")


class TestBinaryInfoCodeAreas(unittest.TestCase):
    def test_address_one_past_the_image_is_not_inside(self):
        binary_info = BinaryInfo(b"\x90" * 0x100)
        binary_info.base_addr = 0x400000
        binary_info.binary_size = 0x100

        self.assertTrue(binary_info.isInCodeAreas(0x400000))
        self.assertTrue(binary_info.isInCodeAreas(0x4000FF))
        self.assertFalse(binary_info.isInCodeAreas(0x400100))

    def test_overlapping_code_areas_are_merged_for_membership(self):
        binary_info = BinaryInfo(b"\x90" * 0x200)
        binary_info.base_addr = 0
        binary_info.binary_size = 0x200
        binary_info.code_areas = [[0, 100], [50, 60], [150, 180]]

        self.assertTrue(binary_info.isInCodeAreas(70))
        self.assertTrue(binary_info.isInCodeAreas(55))
        self.assertFalse(binary_info.isInCodeAreas(120))
        self.assertTrue(binary_info.isInCodeAreas(160))
        self.assertFalse(binary_info.isInCodeAreas(180))

    def test_overlapping_code_areas_extend_the_merged_end(self):
        binary_info = BinaryInfo(b"\x90" * 0x200)
        binary_info.base_addr = 0
        binary_info.binary_size = 0x200
        binary_info.code_areas = [[0, 100], [90, 150]]

        self.assertTrue(binary_info.isInCodeAreas(120))
        self.assertFalse(binary_info.isInCodeAreas(150))


class TestBinaryInfoBinaryData(unittest.TestCase):
    def test_an_unreadable_binary_path_is_reported_at_warning(self):
        # getBinaryData feeds getLiefBinary and every lief-backed provider through it, so a
        # read failure here silently unnames the whole run
        binary_info = BinaryInfo(b"")
        binary_info.file_path = str(Path(__file__).resolve().parent / "does_not_exist.bin")
        # another test module's import-time logging.disable() would hide these records
        previous_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous_disable)

        with self.assertLogs("smda.common.BinaryInfo", level="WARNING") as logged:
            self.assertIsNone(binary_info.getBinaryData())

        self.assertIn("Failed to read binary", logged.output[0])


class TestSmdaFunctionRobustness(unittest.TestCase):
    def test_escaper_is_declared_for_instances_built_without_a_disassembly(self):
        self.assertIsNone(SmdaFunction()._escaper)
        self.assertIsNone(SmdaFunction.__new__(SmdaFunction)._escaper)

    def test_try_range_without_bounds_is_skipped(self):
        function = SmdaFunction()
        function.offset = 0x100
        function.blocks = {0x100: []}
        function.blockrefs = {}
        function.architecture_metadata = {"try_ranges": [{"handlers": [{"target_addr": 0x200}]}]}

        self.assertEqual(function.getNormalizedBlockRefs(), {0x100: []})

    def test_blockrefs_without_try_ranges_are_deduplicated_and_sorted(self):
        function = SmdaFunction()
        function.offset = 0x100
        function.blocks = {0x200: [], 0x100: []}
        function.blockrefs = {0x100: [0x200, 0x200, 0x080]}
        function.architecture_metadata = {}

        self.assertEqual(function.getNormalizedBlockRefs(), {0x100: [0x080, 0x200], 0x200: []})

    def test_code_xrefs_skip_a_function_whose_offset_is_not_an_instruction(self):
        report = SmdaReport(None)
        report._offset2ins = {0x2000: object()}
        report._has_codexrefs = True
        function = SmdaFunction()
        function.smda_report = report
        function.offset = 0x1000
        function.inrefs = [0x2000]
        function.outrefs = {0x1000: [0x2000]}

        self.assertEqual(list(function.getCodeInrefs()), [])
        self.assertEqual(list(function.getCodeOutrefs()), [])


if __name__ == "__main__":
    unittest.main()
