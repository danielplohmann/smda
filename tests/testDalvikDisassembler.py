#!/usr/bin/python

import logging
import os
import struct
import subprocess
import sys
import tempfile
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.dalvik.DalvikOpcodeDecoder import decode_instruction, parse_code_item_header, read_sleb128, read_uleb128
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.utility.DexFileLoader import DexFileLoader

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


def build_dex_header(version=b"039", file_size=0x70, data_off=0x70, data_size=0):
    header = bytearray(0x70)
    header[:8] = b"dex\n" + version + b"\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x34, 0)
    struct.pack_into("<I", header, 0x68, data_size)
    struct.pack_into("<I", header, 0x6C, data_off)
    return bytes(header)


class DummyResolver:
    def __call__(self, ref_kind, ref_index):
        return f"{ref_kind}@{ref_index}"


class SyntheticDalvikMethod:
    def __init__(self, code_offset=0x10):
        self.code_offset = code_offset
        self.code_info = object()


class SyntheticDalvikResolver:
    def format_ref(self, ref_kind, ref_index):
        return f"{ref_kind}@{ref_index}"

    def format_type_by_index(self, index):
        return f"type@{index}"

    def get_string_value(self, string_index):
        return None

    def get_method_target(self, method_index):
        return None, f"method@{method_index}"

    def format_method(self, method):
        return "LSynthetic;->method()V"

    def get_method_metadata(self, method):
        return {
            "method_name": self.format_method(method),
            "class_name": "LSynthetic;",
            "prototype": "()V",
            "access_flags": 0,
            "access_flags_decoded": [],
        }


def build_code_item(insns, tries=None, handlers_blob=b"", registers_size=1, ins_size=0, outs_size=0, debug_info_off=0):
    tries = tries or []
    insns_size_units = len(insns) // 2
    header = struct.pack("<HHHHII", registers_size, ins_size, outs_size, len(tries), debug_info_off, insns_size_units)
    padding = b"\x00\x00" if tries and insns_size_units % 2 else b""
    try_items = b"".join(
        struct.pack("<IHH", start_addr, insn_count, handler_off) for start_addr, insn_count, handler_off in tries
    )
    return header + insns + padding + try_items + handlers_blob


class DalvikDisassemblerTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(os.path.join(config.PROJECT_ROOT, "tests", "blockblast_classes_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_dex = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_dex.append(byte ^ (index % 256))
        cls.dex_binary = bytes(decrypted_dex)

        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tmp:
            tmp.write(cls.dex_binary)
            cls._temp_file_name = tmp.name

        cls.disasm = Disassembler(config, backend="dalvik")
        cls.file_disassembly = cls.disasm.disassembleFile(cls._temp_file_name)
        cls.buffer_disassembly = Disassembler(config, backend="dalvik").disassembleUnmappedBuffer(cls.dex_binary)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        os.unlink(cls._temp_file_name)

    def _analyzeSyntheticMethod(self, code_item_bytes):
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        disassembler = DalvikDisassembler(config)
        disassembler.disassembly = DisassemblyResult()
        binary_info = BinaryInfo(code_item_bytes)
        binary_info.raw_data = code_item_bytes
        binary_info.architecture = "dalvik"
        disassembler.disassembly.binary_info = binary_info
        method = SyntheticDalvikMethod()
        resolver = SyntheticDalvikResolver()
        disassembler.analyzeFunction(None, resolver, method)
        return disassembler.disassembly, method.code_offset

    def testDexFormatDetection(self):
        self.assertTrue(DexFileLoader.isCompatible(self.dex_binary))
        self.assertEqual(DexFileLoader.getBaseAddress(self.dex_binary), 0)
        self.assertEqual(DexFileLoader.getBitness(self.dex_binary), 32)
        self.assertEqual(DexFileLoader.getArchitecture(self.dex_binary), "dalvik")
        self.assertEqual(DexFileLoader.getAbi(self.dex_binary), "")
        self.assertTrue(DexFileLoader.isCompatible(build_dex_header(version=b"035")))
        self.assertTrue(DexFileLoader.isCompatible(build_dex_header(version=b"037")))
        self.assertTrue(DexFileLoader.isCompatible(build_dex_header(version=b"038")))
        self.assertTrue(DexFileLoader.isCompatible(build_dex_header(version=b"039")))
        self.assertFalse(DexFileLoader.isCompatible(build_dex_header(version=b"041")))
        self.assertFalse(DexFileLoader.isCompatible(b"MZ\x90\x00"))
        self.assertFalse(DexFileLoader.isCompatible(b""))
        self.assertFalse(DexFileLoader.isCompatible(build_dex_header(file_size=0x100)))

    def testMalformedDexFailsExplicitly(self):
        malformed = bytearray(build_dex_header(file_size=0x70, data_off=0x70, data_size=0))
        malformed[0x34:0x38] = struct.pack("<I", 0x60)
        report = Disassembler(config, backend="dalvik").disassembleUnmappedBuffer(bytes(malformed))
        self.assertEqual(report.status, "error")

    def testFileDisassemblyStatus(self):
        self.assertEqual(self.file_disassembly.status, "ok")
        self.assertEqual(self.file_disassembly.message, "Analysis finished regularly.")

    def testFileDisassemblyArchitecture(self):
        self.assertEqual(self.file_disassembly.architecture, "dalvik")
        self.assertEqual(self.file_disassembly.bitness, 32)
        self.assertEqual(self.file_disassembly.base_addr, 0)
        self.assertEqual(len(self.file_disassembly.xheader), 0x70)

    def testHashesAndBinarySize(self):
        self.assertEqual(self.file_disassembly.binary_size, 247668)
        self.assertEqual(
            self.file_disassembly.sha256,
            "70f65a5dc2d9eea731effe48acbbfdd2f1a7efe151b647f30e4a124691fcdc30",
        )
        self.assertEqual(
            self.file_disassembly.sha1,
            "8241e12361e920e09e7cf1c6f2a95dc30a4609c3",
        )
        self.assertEqual(
            self.file_disassembly.md5,
            "92bdf8fc9165fd128d6b4de076530a0d",
        )
        self.assertIsNone(self.file_disassembly.oep)

    def testSemanticRecovery(self):
        self.assertGreater(self.file_disassembly.num_functions, 2000)
        self.assertGreater(self.file_disassembly.num_instructions, 9000)
        self.assertGreater(self.file_disassembly.num_blocks, self.file_disassembly.num_functions)

        stats = self.file_disassembly.statistics
        self.assertGreater(stats.num_function_calls, 0)
        self.assertLess(stats.num_leaf_functions, stats.num_functions)
        self.assertGreaterEqual(stats.num_failed_functions, 0)

        functions = list(self.file_disassembly.getFunctions())
        self.assertTrue(any("->" in function.function_name for function in functions))
        self.assertTrue(any(function.architecture_metadata for function in functions))
        self.assertTrue(any(function.num_outrefs > 0 for function in functions))

        any_invoke = False
        any_string_ref = False
        for function in functions[:250]:
            for instruction in function.getInstructions():
                if instruction.mnemonic.startswith("invoke-"):
                    any_invoke = "->" in instruction.operands or "call_site@" in instruction.operands
                    if any_invoke:
                        break
            if function.stringrefs:
                any_string_ref = True
            if any_invoke and any_string_ref:
                break
        self.assertTrue(any_invoke)
        self.assertTrue(any_string_ref)
        normalized_invokes = [
            instruction.operands
            for function in functions[:250]
            for instruction in function.getInstructions()
            if instruction.mnemonic.startswith("invoke-") and "->" in instruction.operands
        ]
        self.assertTrue(normalized_invokes)
        self.assertTrue(all(" - " not in operand for operand in normalized_invokes[:50]))

    def testNormalizedBlockRefsPreserveLeafBlocksAndExceptionEdges(self):
        func_addr = 0x1000
        disassembly = DisassemblyResult()
        disassembly.functions[func_addr] = [
            [
                (0x1000, 2, "invoke-static", "", b"\x6e\x00"),
                (0x1002, 2, "move-result-object", "", b"\x0c\x00"),
                (0x1004, 2, "return-object", "", b"\x11\x00"),
            ],
            [
                (0x1010, 2, "move-exception", "", b"\x0d\x00"),
                (0x1012, 2, "return-object", "", b"\x11\x00"),
            ],
            [
                (0x1020, 2, "move-exception", "", b"\x0d\x00"),
                (0x1022, 2, "return-object", "", b"\x11\x00"),
            ],
            [(0x1030, 2, "return-void", "", b"\x0e\x00")],
        ]
        disassembly.function_metadata[func_addr] = {
            "try_ranges": [
                {
                    "start_addr": 0x1000,
                    "end_addr": 0x1004,
                    "handlers": [{"type_idx": 1, "type_name": "Ljava/lang/Exception;", "target_addr": 0x1010}],
                    "catch_all_addr": 0x1020,
                }
            ]
        }
        blockrefs = disassembly.getBlockRefs(func_addr)
        self.assertEqual(blockrefs[0x1000], [0x1010, 0x1020])
        self.assertEqual(blockrefs[0x1010], [])
        self.assertEqual(blockrefs[0x1020], [])
        self.assertEqual(blockrefs[0x1030], [])

    def testSmdaFunctionNormalizesSerializedDalvikCfg(self):
        function_dict = {
            "offset": 0x1000,
            "blocks": {
                0x1000: [
                    [0x1000, "6e00", "invoke-static", ""],
                    [0x1002, "0c00", "move-result-object", ""],
                    [0x1004, "1100", "return-object", ""],
                ],
                0x1010: [[0x1010, "0d00", "move-exception", ""], [0x1012, "1100", "return-object", ""]],
                0x1020: [[0x1020, "0d00", "move-exception", ""], [0x1022, "1100", "return-object", ""]],
            },
            "apirefs": {},
            "stringrefs": {},
            "blockrefs": {},
            "inrefs": [],
            "outrefs": {},
            "is_exported": False,
            "architecture_metadata": {
                "debug_info_off": 0,
                "try_ranges": [
                    {
                        "start_addr": 0x1000,
                        "end_addr": 0x1004,
                        "handlers": [{"type_idx": 1, "type_name": "Ljava/lang/Exception;", "target_addr": 0x1010}],
                        "catch_all_addr": 0x1020,
                    }
                ],
                "exception_handlers": [
                    {
                        "type_idx": 1,
                        "type_name": "Ljava/lang/Exception;",
                        "target_addr": 0x1010,
                        "protected_range_start": 0x1000,
                        "protected_range_end": 0x1004,
                    }
                ],
            },
            "metadata": {
                "binweight": 0,
                "characteristics": "",
                "confidence": 0.0,
                "function_name": "LFoo;->bar()Ljava/lang/Object;",
                "pic_hash": None,
                "nesting_depth": 0,
                "strongly_connected_components": [],
                "tfidf": None,
            },
        }
        smda_function = SmdaFunction.fromDict(function_dict)
        self.assertIn(0x1000, smda_function.blockrefs)
        self.assertEqual(smda_function.blockrefs[0x1000], [0x1010, 0x1020])
        self.assertGreater(smda_function.nesting_depth, 0)

    def testDalvikExceptionMetadataAndNormalizedCfg(self):
        functions_with_tries = [
            function
            for function in self.file_disassembly.getFunctions()
            if function.architecture_metadata.get("try_ranges")
        ]
        self.assertTrue(functions_with_tries)
        function = functions_with_tries[0]
        self.assertIn("debug_info_off", function.architecture_metadata)
        self.assertIsInstance(function.architecture_metadata["exception_handlers"], list)
        self.assertGreaterEqual(function.architecture_metadata["exception_handler_count"], 1)
        self.assertIn(function.offset, function.blockrefs)

    def testReportRoundTrip(self):
        report_dict = self.file_disassembly.toDict()
        self.assertEqual(report_dict["status"], "ok")
        self.assertEqual(report_dict["architecture"], "dalvik")
        self.assertEqual(report_dict["base_addr"], 0)
        self.assertEqual(report_dict["binary_size"], 247668)
        self.assertEqual(report_dict["bitness"], 32)
        self.assertTrue(report_dict["data_refs_from"] is not None)
        self.assertGreater(len(report_dict["xcfg"]), 2000)

        reconstructed = SmdaReport.fromDict(report_dict)
        self.assertEqual(reconstructed.status, "ok")
        self.assertEqual(reconstructed.architecture, "dalvik")
        self.assertEqual(reconstructed.base_addr, 0)
        self.assertEqual(reconstructed.binary_size, 247668)
        self.assertEqual(reconstructed.sha256, self.file_disassembly.sha256)
        self.assertEqual(len(reconstructed.xcfg), len(self.file_disassembly.xcfg))

    def testBufferDisassembly(self):
        self.assertEqual(self.buffer_disassembly.status, "ok")
        self.assertEqual(self.buffer_disassembly.architecture, "dalvik")
        self.assertEqual(self.buffer_disassembly.bitness, 32)
        self.assertEqual(self.buffer_disassembly.base_addr, 0)
        self.assertEqual(self.buffer_disassembly.num_functions, self.file_disassembly.num_functions)
        self.assertEqual(self.buffer_disassembly.num_instructions, self.file_disassembly.num_instructions)

    def testAnalyzeScriptVerboseOutputAvoidsCfgNoise(self):
        result = subprocess.run(
            [sys.executable, os.path.join(config.PROJECT_ROOT, "analyze.py"), "-p", "-v", self._temp_file_name],
            cwd=config.PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        combined_output = result.stdout + result.stderr
        self.assertIn("architecture: dalvik.32bit", combined_output)
        self.assertIn("DEX summary:", combined_output)
        self.assertIn("Analyzed Dalvik method", combined_output)
        self.assertIn("Dalvik analysis summary:", combined_output)
        self.assertNotIn("Current analysis callback time", combined_output)
        self.assertNotIn("r not in G", combined_output)

    def testCodeItemHeaderParser(self):
        header = struct.pack("<HHHHII", 6, 2, 3, 1, 0x11223344, 0x40)
        parsed = parse_code_item_header(header, 0)
        self.assertEqual(parsed["registers_size"], 6)
        self.assertEqual(parsed["ins_size"], 2)
        self.assertEqual(parsed["outs_size"], 3)
        self.assertEqual(parsed["tries_size"], 1)
        self.assertEqual(parsed["debug_info_off"], 0x11223344)
        self.assertEqual(parsed["insns_size"], 0x40)

    def testLeb128Readers(self):
        self.assertEqual(read_uleb128(b"\x81\x01", 0), (129, 2))
        self.assertEqual(read_sleb128(b"\x7f", 0), (-1, 1))

    def testDecoderHandlesInvokePolymorphic(self):
        raw = bytes.fromhex("fa21230145006789")
        decoded = decode_instruction(raw, 0, DummyResolver())
        self.assertEqual(decoded.mnemonic, "invoke-polymorphic")
        self.assertEqual(decoded.ref_index, 0x0123)
        self.assertEqual(decoded.ref_index_aux, 0x8967)
        self.assertTrue(decoded.is_invoke)
        self.assertIn("proto@", decoded.operands)

    def testDecoderHandlesSwitchAndFillArrayPayloadRefs(self):
        packed_switch = bytes.fromhex("2b0004000000")
        decoded_switch = decode_instruction(packed_switch, 0, DummyResolver())
        self.assertEqual(decoded_switch.mnemonic, "packed-switch")
        self.assertEqual(decoded_switch.payload_idx, 8)

        fill_array = bytes.fromhex("260002000000")
        decoded_array = decode_instruction(fill_array, 0, DummyResolver())
        self.assertEqual(decoded_array.mnemonic, "fill-array-data")
        self.assertEqual(decoded_array.payload_idx, 4)

    # ── New tests for consolidated enhancement plan ──────────────────────────

    def testDisassembleBufferDexAutodetect(self):
        generic_disasm = Disassembler(config)
        report = generic_disasm.disassembleBuffer(self.dex_binary, base_addr=0)
        self.assertEqual(report.architecture, "dalvik")
        self.assertEqual(report.bitness, 32)
        self.assertGreater(report.num_functions, 2000)

    def testAnalyzeScriptRawDexAvoidsBaseAddrAndOepWarnings(self):
        result = subprocess.run(
            [
                sys.executable,
                os.path.join(config.PROJECT_ROOT, "analyze.py"),
                self._temp_file_name,
                "-o",
                tempfile.gettempdir(),
            ],
            cwd=config.PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        combined_output = result.stdout + result.stderr
        self.assertIn("architecture: dalvik.32bit", combined_output)
        self.assertNotIn("No base address recognized, using 0.", combined_output)
        self.assertNotIn("No OEP recognized, skipping.", combined_output)

    def testGetDetailedRaisesOnDalvik(self):
        functions = list(self.file_disassembly.getFunctions())
        instruction = next(iter(functions[0].getInstructions()))
        with self.assertRaises(NotImplementedError):
            instruction.getDetailed()

    def testOdexCdexFormatDetection(self):
        # Build a minimal valid ODEX header (same structure as DEX, different magic)
        odex_header = bytearray(build_dex_header(version=b"039"))
        odex_header[:4] = b"dey\n"
        self.assertTrue(DexFileLoader.isCompatible(bytes(odex_header)))

        # CDEX: only magic-byte check, no strict structure validation
        cdex_header = b"cdex001\x00" + b"\x00" * 0x70
        self.assertTrue(DexFileLoader.isCompatible(cdex_header))

        # Sanity: non-DEX/ODEX/CDEX magic still rejected
        self.assertFalse(DexFileLoader.isCompatible(b"MZ\x90\x00" + b"\x00" * 0x70))
        self.assertFalse(DexFileLoader.isCompatible(b"\x7fELF" + b"\x00" * 0x70))

    def testConstHigh16SignedDisplay(self):
        # 15 00 FF FF  →  const/high16 v0, #0xFFFF0000  (= -65536 as int32)
        raw = bytes([0x15, 0x00, 0xFF, 0xFF])
        decoded = decode_instruction(raw, 0, DummyResolver())
        self.assertEqual(decoded.mnemonic, "const/high16")
        self.assertIsNotNone(decoded.literal)
        self.assertLess(decoded.literal, 0, "literal should be negative for BBBB=0xFFFF")
        self.assertIn("-", decoded.operands)

    def testStringEscaping(self):
        from smda.dalvik.DalvikDisassembler import DexReferenceResolver

        self.assertEqual(DexReferenceResolver._escapeDexString("hello\nworld"), "hello\\nworld")
        self.assertEqual(DexReferenceResolver._escapeDexString("\0"), "\\0")
        self.assertEqual(DexReferenceResolver._escapeDexString("\t"), "\\t")
        self.assertEqual(DexReferenceResolver._escapeDexString("\r"), "\\r")
        self.assertEqual(DexReferenceResolver._escapeDexString('"quoted"'), '\\"quoted\\"')
        self.assertEqual(DexReferenceResolver._escapeDexString("\\back"), "\\\\back")
        # Non-printable non-mapped character uses \uXXXX
        self.assertIn("\\u0001", DexReferenceResolver._escapeDexString("\x01"))

    def testPartialDisassemblyFlagPropagation(self):
        from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState

        disassembly = DisassemblyResult()

        # Populate BinaryInfo stub so setBinaryInfo won't be called but addCodeRefs works
        class FakeBinaryInfo:
            base_addr = 0
            raw_data = b""
            binary = b""
            binary_size = 0

        disassembly.binary_info = FakeBinaryInfo()
        start_addr = 0x1000
        state = DalvikFunctionAnalysisState(start_addr, disassembly)
        # Simulate one decoded instruction and then a decode error
        state.instructions = [(start_addr, 2, "nop", "", b"\x00\x00")]
        state.instruction_start_bytes = {start_addr}
        state.processed_bytes = {start_addr, start_addr + 1}
        state.metadata = {"heuristics": [], "reference_counts": {}}
        state.num_blocks_analyzed = 1
        state.decode_error_count = 2
        state.is_partial = True
        state._finalizeRegularAnalysis()
        meta = disassembly.function_metadata.get(start_addr, {})
        self.assertTrue(meta.get("partial_disassembly"), "partial_disassembly should be True")
        self.assertEqual(meta.get("decode_error_count"), 2)

    def testForgedPayloadBoundsCheck(self):
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        disasm = DalvikDisassembler(config)
        bytecode = bytearray(100)

        # Packed-switch payload with huge size field
        struct.pack_into("<H", bytecode, 0, 0x0100)  # ident: packed-switch
        struct.pack_into("<H", bytecode, 2, 0xFFFF)  # size: 65535 entries
        struct.pack_into("<I", bytecode, 4, 0)  # first_key
        size = disasm._getPayloadSize(bytecode, 0)
        self.assertLessEqual(size, len(bytecode), "packed-switch payload size must be capped")

        # Sparse-switch payload with huge size field
        struct.pack_into("<H", bytecode, 0, 0x0200)
        struct.pack_into("<H", bytecode, 2, 0xFFFF)
        size = disasm._getPayloadSize(bytecode, 0)
        self.assertLessEqual(size, len(bytecode), "sparse-switch payload size must be capped")

        # fill-array-data payload with huge element count
        struct.pack_into("<H", bytecode, 0, 0x0300)  # ident
        struct.pack_into("<H", bytecode, 2, 4)  # element_width = 4
        struct.pack_into("<I", bytecode, 4, 0xFFFFFF)  # size: huge
        size = disasm._getPayloadSize(bytecode, 0)
        self.assertLessEqual(size, len(bytecode), "fill-array-data payload size must be capped")

        # fill-array-data with element_width=0 must return 0 (avoid divide-by-zero)
        struct.pack_into("<H", bytecode, 2, 0)
        size = disasm._getPayloadSize(bytecode, 0)
        self.assertEqual(size, 0, "element_width=0 must return 0")

    def testZeroOffsetGotoRecordsStructuralViolation(self):
        code_item = build_code_item(bytes.fromhex("2800"))
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]
        blockrefs = disassembly.getBlockRefs(func_addr)

        self.assertIn(func_addr, blockrefs)
        self.assertEqual(blockrefs[func_addr], [])
        self.assertTrue(
            any(violation["type"] == "zero_branch_offset" for violation in metadata.get("structural_violations", []))
        )

    def testZeroOffsetConditionalFallsThroughAndRecordsViolation(self):
        code_item = build_code_item(bytes.fromhex("320000000e00"))
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]
        blockrefs = disassembly.getBlockRefs(func_addr)

        self.assertEqual(blockrefs[func_addr], [func_addr + 4])
        self.assertIn(func_addr + 4, blockrefs)
        self.assertTrue(
            any(violation["type"] == "zero_branch_offset" for violation in metadata.get("structural_violations", []))
        )

    def testProtectedFallthroughBecomesSeparateBlock(self):
        code_item = build_code_item(
            bytes.fromhex("1d000e000d010e00"),
            tries=[(0, 2, 1)],
            handlers_blob=b"\x01\x00\x02",
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        blockrefs = disassembly.getBlockRefs(func_addr)
        block_starts = {block[0][0] for block in disassembly.functions[func_addr]}

        self.assertEqual(blockrefs[func_addr], [func_addr + 2, func_addr + 4])
        self.assertIn(func_addr + 2, block_starts)
        self.assertIn(func_addr + 4, block_starts)

    def testInvalidHandlerOffsetRecordsStructuralViolation(self):
        code_item = build_code_item(
            bytes.fromhex("1d000e00"),
            tries=[(0, 1, 5)],
            handlers_blob=b"\x00",
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]

        self.assertEqual(metadata["exception_handler_count"], 0)
        self.assertTrue(
            any(
                violation["type"] == "invalid_handler_offset" for violation in metadata.get("structural_violations", [])
            )
        )

    def testDalvikStringRefsSerializeAsStableList(self):
        function = next(function for function in self.file_disassembly.getFunctions() if function.stringrefs)
        self.assertIsInstance(function.stringrefs, list)
        self.assertIsNone(function.stringrefs[0]["data_addr"])

        report_dict = self.file_disassembly.toDict()
        function_dict = next(function for function in report_dict["xcfg"].values() if function["stringrefs"])
        self.assertIsInstance(function_dict["stringrefs"], list)
        self.assertIsNone(function_dict["stringrefs"][0]["data_addr"])

        reconstructed = SmdaReport.fromDict(report_dict)
        reconstructed_function = next(function for function in reconstructed.getFunctions() if function.stringrefs)
        self.assertIsInstance(reconstructed_function.stringrefs, list)
        self.assertIsNone(reconstructed_function.stringrefs[0]["data_addr"])


if __name__ == "__main__":
    unittest.main()
