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
from smda.dalvik.DalvikOpcodeDecoder import (
    OPCODES,
    decode_instruction,
    parse_code_item_header,
    read_sleb128,
    read_uleb128,
)
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
    def formatRef(self, ref_kind, ref_index):
        return f"{ref_kind}@{ref_index}"

    def formatTypeByIndex(self, index):
        return f"type@{index}"

    def getStringValue(self, string_index):
        return None

    def getMethodTarget(self, method_index):
        return None, f"method@{method_index}"

    def formatMethod(self, method):
        return "LSynthetic;->method()V"

    def getMethodMetadata(self, method):
        return {
            "method_name": self.formatMethod(method),
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
            if function.architecture_metadata.get("exception_handler_count", 0) >= 1
        ]
        self.assertTrue(functions_with_tries)
        function = functions_with_tries[0]
        self.assertIn("debug_info_off", function.architecture_metadata)
        self.assertIsInstance(function.architecture_metadata["exception_handlers"], list)
        self.assertGreaterEqual(function.architecture_metadata["exception_handler_count"], 1)
        self.assertTrue(function.architecture_metadata.get("try_ranges"))
        self.assertIn(function.offset, function.blockrefs)

    def testReportRoundTrip(self):
        report_dict = self.file_disassembly.toDict()
        self.assertEqual(report_dict["status"], "ok")
        self.assertEqual(report_dict["architecture"], "dalvik")
        self.assertEqual(report_dict["base_addr"], 0)
        self.assertEqual(report_dict["binary_size"], 247668)
        self.assertEqual(report_dict["bitness"], 32)
        self.assertTrue(report_dict["xdata_refs_from"] is not None)
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
        self.assertIn("dalvik.32bit", combined_output)
        self.assertIn("DEX v", combined_output)
        self.assertIn("heuristics=[", combined_output)
        self.assertIn("api_refs=", combined_output)
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

    def testThrowableOpcodeMetadataFeedsExceptionEdges(self):
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        disassembler = DalvikDisassembler(config)
        by_mnemonic = {spec.mnemonic: opcode for opcode, spec in OPCODES.items()}

        # Subset of AOSP continue|throw flags (bytecode.txt reconciled with ART
        # dex_instruction_list.h kThrow, e.g. fill-array-data).
        throwable_mnemonics = [
            "fill-array-data",
            "const-string",
            "const-string/jumbo",
            "const-class",
            "instance-of",
            "const-method-handle",
            "const-method-type",
            "sget",
            "sget-wide",
            "sget-object",
            "sget-boolean",
            "sget-byte",
            "sget-char",
            "sget-short",
            "sput",
            "sput-wide",
            "sput-object",
            "sput-boolean",
            "sput-byte",
            "sput-char",
            "sput-short",
            "div-int",
            "rem-int",
            "div-long",
            "rem-long",
            "div-int/2addr",
            "rem-int/2addr",
            "div-long/2addr",
            "rem-long/2addr",
            "div-int/lit16",
            "rem-int/lit16",
            "div-int/lit8",
            "rem-int/lit8",
        ]
        for mnemonic in throwable_mnemonics:
            with self.subTest(mnemonic=mnemonic):
                opcode = by_mnemonic[mnemonic]
                decoded = decode_instruction(
                    bytes([opcode]) + b"\x00" * (OPCODES[opcode].size_units * 2 - 1), 0, DummyResolver()
                )
                self.assertTrue(decoded.can_throw)
                self.assertTrue(disassembler._instructionCanThrow(decoded))

        non_throwing_mnemonics = [
            "add-int",
            "mul-int",
            "add-long",
            "div-float",
            "rem-double",
            "shl-int/lit8",
            "nop",
            "move",
        ]
        for mnemonic in non_throwing_mnemonics:
            with self.subTest(mnemonic=mnemonic):
                opcode = by_mnemonic[mnemonic]
                decoded = decode_instruction(
                    bytes([opcode]) + b"\x00" * (OPCODES[opcode].size_units * 2 - 1), 0, DummyResolver()
                )
                self.assertFalse(decoded.can_throw)
                self.assertFalse(disassembler._instructionCanThrow(decoded))

    def testThrowableFieldAndIntegerDivideOpcodesAddExceptionEdges(self):
        cases = [
            ("sget", bytes.fromhex("60000000")),
            ("div-int", bytes.fromhex("93000102")),
            ("div-int/2addr", bytes.fromhex("b300")),
            ("div-int/lit8", bytes.fromhex("db000001")),
            ("instance-of", bytes.fromhex("20000000")),
            ("const-string", bytes.fromhex("1a000000")),
        ]
        for mnemonic, protected_instruction in cases:
            with self.subTest(mnemonic=mnemonic):
                handler_addr_units = len(protected_instruction) // 2 + 1
                code_item = build_code_item(
                    protected_instruction + bytes.fromhex("0e000d010e00"),
                    tries=[(0, len(protected_instruction) // 2, 1)],
                    handlers_blob=bytes([1, 0, handler_addr_units]),
                )
                disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
                handler_addr = func_addr + handler_addr_units * 2

                self.assertIn(handler_addr, disassembly.code_refs_from[func_addr])
                edges = disassembly.function_metadata[func_addr].get("exception_edges", [])
                self.assertTrue(edges, f"expected typed exception edges for {mnemonic}")
                self.assertTrue(all(edge["kind"] == "exception" for edge in edges))
                self.assertTrue(any(edge["to_addr"] == handler_addr for edge in edges))
                self.assertTrue(any(edge["mnemonic"] == mnemonic for edge in edges))

    def testFillArrayDataEmitsExceptionEdgesPerArt(self):
        """ART dex_instruction_list.h: fill-array-data is kContinue|kThrow (NPE on null array)."""
        # 0: fill-array-data v0, +3 units (payload at byte 6, inside the try range)
        # 6: fill-array-data-payload, width 1, size 0 (8 bytes)
        # 14: return-void
        fill_insn = bytes.fromhex("260003000000")
        payload = struct.pack("<HHI", 0x0300, 1, 0)
        insns = fill_insn + payload + bytes.fromhex("0e00")
        handler_units = len(fill_insn) // 2
        code_item = build_code_item(
            insns,
            tries=[(0, handler_units, 1)],
            handlers_blob=bytes([1, 0, (len(fill_insn) + len(payload)) // 2]),
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        edges = disassembly.function_metadata[func_addr].get("exception_edges", [])
        self.assertTrue(
            any(edge.get("mnemonic") == "fill-array-data" for edge in edges),
            "fill-array-data must produce exception edges (ART kContinue|kThrow)",
        )

    def testDisassembleBufferDexAutodetect(self):
        generic_disasm = Disassembler(config)
        report = generic_disasm.disassembleBuffer(self.dex_binary, base_addr=0)
        self.assertEqual(report.architecture, "dalvik")
        self.assertEqual(report.bitness, 32)
        self.assertEqual(report.language, {"dalvik": 1.0})
        self.assertGreater(report.num_functions, 2000)

    def testDisassembleBufferExplicitIntelBackendPreservedForDexBytes(self):
        intel_disasm = Disassembler(config, backend="intel")
        report = intel_disasm.disassembleBuffer(self.dex_binary, base_addr=0, architecture="intel")
        self.assertEqual(report.architecture, "intel")
        self.assertEqual(report.bitness, 32)

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
        self.assertIn("dalvik.32bit", combined_output)
        self.assertNotIn("No base address recognized, using 0.", combined_output)
        self.assertNotIn("No OEP recognized, skipping.", combined_output)

    def testGetDetailedRaisesOnDalvik(self):
        functions = list(self.file_disassembly.getFunctions())
        instruction = next(iter(functions[0].getInstructions()))
        with self.assertRaises(NotImplementedError):
            instruction.getDetailed()

    def testOdexCdexFormatDetection(self):
        # ODEX/CDEX are recognized as unsupported runtime artifacts, not analysis-compatible.
        odex_header = bytearray(build_dex_header(version=b"039"))
        odex_header[:4] = b"dey\n"
        self.assertFalse(DexFileLoader.isCompatible(bytes(odex_header)))
        self.assertTrue(DexFileLoader.isRecognizedUnsupported(bytes(odex_header)))
        self.assertIn("ODEX", DexFileLoader.unsupportedReason(bytes(odex_header)))

        cdex_header = b"cdex001\x00" + b"\x00" * 0x70
        self.assertFalse(DexFileLoader.isCompatible(cdex_header))
        self.assertTrue(DexFileLoader.isRecognizedUnsupported(cdex_header))
        self.assertIn("CDEX", DexFileLoader.unsupportedReason(cdex_header))

        # Sanity: non-DEX magic still rejected
        self.assertFalse(DexFileLoader.isCompatible(b"MZ\x90\x00" + b"\x00" * 0x70))
        self.assertFalse(DexFileLoader.isCompatible(b"\x7fELF" + b"\x00" * 0x70))

        report = Disassembler(config, backend="dalvik").disassembleUnmappedBuffer(bytes(odex_header))
        self.assertEqual(report.status, "error")
        self.assertIn("ODEX", report.message or "")

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

    def testBackwardPayloadFixedPointExcludesPayloadFromValidStarts(self):
        """A backward 31t payload offset must not leave payload bytes as valid starts."""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        # packed-switch-payload at offset 0 (12 bytes), packed-switch insn at 12 pointing backward.
        payload = struct.pack("<HHii", 0x0100, 1, 0, 1)  # size=1, first_key=0, target=+1 unit
        # signed unit offset: (0 - 12) / 2 = -6
        switch = bytes([0x2B, 0x00]) + struct.pack("<i", -6)
        bytecode = payload + switch
        self.assertEqual(len(payload), 12)

        disassembler = DalvikDisassembler(config)
        single_valid, _, _ = disassembler._sweepInstructionStarts(bytecode, seed_payload_ranges=None)
        # Naive single pass mis-decodes payload head as nop (opcode 0x00).
        self.assertIn(0, single_valid)

        valid, ranges = disassembler._buildValidInstructionStarts(bytecode)
        self.assertIn((0, 12), ranges)
        for offset in range(0, 12, 2):
            self.assertNotIn(offset, valid, f"payload offset {offset} must not be a valid start")
        self.assertIn(12, valid)

    def testBackwardPayloadNotDecodedAsInstructionsInCfgPass(self):
        # Method layout (realistic entry + adversarial backward 31t):
        #   0: goto/16 -> switch
        #   4: packed-switch-payload (12 bytes)
        #  16: packed-switch pointing backward to payload at 4
        #  22: return-void
        payload = struct.pack("<HHii", 0x0100, 1, 0, 1)
        switch = bytes([0x2B, 0x00]) + struct.pack("<i", -6)  # payload at 16-12=4
        # goto/16 from 0 to switch at 16: +8 code units
        goto = bytes([0x29, 0x00]) + struct.pack("<h", 8)
        ret = bytes.fromhex("0e00")
        insns = goto + payload + switch + ret
        self.assertEqual(len(goto), 4)
        self.assertEqual(len(payload), 12)

        disassembly, func_addr = self._analyzeSyntheticMethod(build_code_item(insns))
        payload_start = func_addr + 4
        payload_end = func_addr + 16
        for ins_addr in disassembly.instructions:
            if payload_start <= ins_addr < payload_end:
                self.fail(f"instruction wrongly recovered inside payload at 0x{ins_addr:x}")
        self.assertIn(func_addr, disassembly.instructions)
        self.assertEqual(disassembly.instructions[func_addr][0], "goto/16")
        self.assertIn(func_addr + 16, disassembly.instructions)
        self.assertEqual(disassembly.instructions[func_addr + 16][0], "packed-switch")

    def testMethodHandleAndCallSiteResolutionFromMap(self):
        """Parse AOSP method_handle_item + call_site_id_item via map_list."""
        from smda.dalvik.DalvikDisassembler import DexReferenceResolver

        class _FakeMethod:
            def __init__(self, index):
                self.index = index
                self.name = "run"
                self.cls = "LBootstrap;"
                self.prototype = None
                self.code_offset = 0
                self.code_info = None

        class _FakeField:
            def __init__(self, index):
                self.index = index
                self.name = "VALUE"
                self.cls = "LConst;"
                self.type = "I"

        class _FakeProto:
            def __init__(self, index):
                self.index = index
                self.parameters_type = []
                self.return_type = "V"

        class _FakeDex:
            strings = ["run", "bootstrapName"]
            methods = [_FakeMethod(0)]
            fields = [_FakeField(0)]
            types = []
            prototypes = [_FakeProto(0)]
            classes = []

        # Layout: header(0x70) | method_handles(8) | call_site_ids(4) | call_site_item | map
        header = bytearray(0x70)
        header[:8] = b"dex\n039\x00"
        struct.pack_into("<I", header, 0x24, 0x70)
        struct.pack_into("<I", header, 0x28, 0x12345678)

        mh_off = 0x70
        # invoke-static (0x04) -> method_id 0
        method_handle = struct.pack("<HHHH", 0x04, 0, 0, 0)
        cs_id_off = mh_off + 8
        call_site_item_off = cs_id_off + 4
        # encoded_array size=3: method_handle@0, string@0, proto@0
        call_site_item = bytes(
            [
                0x03,  # size uleb128 = 3
                0x16,
                0x00,  # VALUE_METHOD_HANDLE, 1-byte index 0
                0x17,
                0x00,  # VALUE_STRING, index 0 ("run")
                0x15,
                0x00,  # VALUE_METHOD_TYPE / proto index 0
            ]
        )
        call_site_id = struct.pack("<I", call_site_item_off)
        map_off = call_site_item_off + len(call_site_item)
        # align map to 4 bytes
        pad = (4 - (map_off % 4)) % 4
        map_off += pad
        map_list = struct.pack("<I", 2)
        map_list += struct.pack("<HHII", 0x0008, 0, 1, mh_off)  # METHOD_HANDLE
        map_list += struct.pack("<HHII", 0x0007, 0, 1, cs_id_off)  # CALL_SITE_ID

        raw = bytearray(header)
        raw += method_handle
        raw += call_site_id
        raw += call_site_item
        raw += b"\x00" * pad
        raw += map_list
        struct.pack_into("<I", raw, 0x20, len(raw))
        struct.pack_into("<I", raw, 0x34, map_off)

        resolver = DexReferenceResolver(_FakeDex(), raw_data=bytes(raw))
        self.assertEqual(len(resolver.method_handles), 1)
        self.assertEqual(resolver.method_handles[0]["type_name"], "invoke-static")
        mh_display = resolver.formatMethodHandle(0)
        self.assertIn("invoke-static", mh_display)
        self.assertIn("run", mh_display)

        self.assertEqual(len(resolver.call_sites), 1)
        cs_display = resolver.formatCallSite(0)
        self.assertIn("call_site@0:", cs_display)
        self.assertIn("invoke-static", cs_display)
        self.assertIn("run", cs_display)
        # invoke-custom operand pretty-print path
        self.assertEqual(resolver.formatRef("call_site", 0), cs_display)
        self.assertEqual(resolver.formatRef("method_handle", 0), mh_display)

    def testEncodedValueExtensionRulesPerAosp(self):
        """encoded_value: byte/short/int/long sign-extend, char zero-extends, float/double right-zero-extend."""
        from smda.dalvik.DalvikDisassembler import DexReferenceResolver

        class _EmptyDex:
            strings = []
            methods = []
            fields = []
            types = []
            prototypes = []
            classes = []

        resolver = DexReferenceResolver(_EmptyDex(), raw_data=b"")
        cases = [
            (bytes([0x00, 0xFF]), -1),  # VALUE_BYTE 0xff -> -1
            (bytes([0x02 | (1 << 5), 0x00, 0x80]), -32768),  # VALUE_SHORT 2 bytes
            (bytes([0x03 | (1 << 5), 0xFF, 0xFF]), 0xFFFF),  # VALUE_CHAR zero-extends
            (bytes([0x04, 0xFF]), -1),  # VALUE_INT, 1-byte encoding sign-extends
            (bytes([0x06, 0x80]), -128),  # VALUE_LONG, 1-byte encoding
            (bytes([0x10 | (1 << 5), 0x80, 0x3F]), 1.0),  # VALUE_FLOAT 0x3F800000, low zeros dropped
            (bytes([0x11 | (1 << 5), 0xF0, 0x3F]), 1.0),  # VALUE_DOUBLE 0x3FF0000000000000
        ]
        for blob, expected in cases:
            with self.subTest(blob=blob.hex()):
                value, end = resolver._readEncodedValue(blob, 0)
                self.assertEqual(value, expected)
                self.assertEqual(end, len(blob))
        # Bootstrap-arg rendering: negative int and float must not show as raw bit patterns.
        self.assertEqual(resolver._formatBootstrapArg(-1), "-0x1")
        self.assertEqual(resolver._formatBootstrapArg(1.0), "1.0")

    def testTypedExceptionEdgesSurfaceOnSmdaFunction(self):
        """Typed exception_edges metadata surfaces via getExceptionBlockRefs()."""
        # monitor-enter (can_throw) then return-void; handler with move-exception+return
        code_item = build_code_item(
            bytes.fromhex("1d000e000d010e00"),
            tries=[(0, 1, 1)],
            handlers_blob=b"\x01\x00\x02",
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]
        self.assertGreaterEqual(len(metadata.get("exception_edges", [])), 1)
        edge = metadata["exception_edges"][0]
        self.assertEqual(edge["kind"], "exception")
        self.assertEqual(edge["from_addr"], func_addr)
        self.assertIn("type_name", edge)
        self.assertIn("mnemonic", edge)

        smda_fn = SmdaFunction(disassembly, func_addr, config=config)
        typed = smda_fn.getExceptionEdges()
        self.assertTrue(typed)
        blockrefs = smda_fn.getExceptionBlockRefs()
        self.assertTrue(blockrefs)
        # Source block at function entry should list the handler block
        self.assertIn(func_addr, blockrefs)
        handler_addr = edge["to_addr"]
        self.assertIn(handler_addr, blockrefs[func_addr])

        # Round-trip: exception_edges live in architecture_metadata
        as_dict = smda_fn.toDict()
        self.assertIn("exception_edges", as_dict.get("architecture_metadata", {}))
        restored = SmdaFunction.fromDict(as_dict)
        self.assertTrue(restored.getExceptionEdges())
        self.assertEqual(restored.getExceptionBlockRefs()[func_addr], blockrefs[func_addr])

    def testArtThrowFlagsMatchBytecodeTxtSubset(self):
        """Guard: can_throw flags follow AOSP bytecode.txt reconciled with ART kThrow."""
        # Spot-check flags where the legacy dalvik table and ART differ or lag.
        self.assertTrue(OPCODES[0x1A].can_throw)  # const-string
        self.assertTrue(OPCODES[0x1B].can_throw)  # const-string/jumbo
        self.assertTrue(OPCODES[0x20].can_throw)  # instance-of
        self.assertTrue(OPCODES[0x26].can_throw)  # fill-array-data (ART kContinue|kThrow)
        self.assertTrue(OPCODES[0xFE].can_throw)  # const-method-handle
        self.assertTrue(OPCODES[0xFF].can_throw)  # const-method-type

    def testDalvikInstructionEscaperMasksPoolIndices(self):
        """Pool indices/immediates/branch offsets are wild-carded for PIC hashing."""
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        # const-string v0, string@0x1234  → 1a 00 34 12
        ins = SmdaInstruction([0, "1a003412", "const-string", 'v0, "x"'])
        escaped = DalvikInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)
        self.assertEqual(escaped[:2], "1a")
        self.assertIn("?", escaped)
        self.assertEqual(escaped[4:], "????")

        # invoke-static {} method@0xABCD  → 71 00 cd ab 00 00 (35c, 0 args)
        ins = SmdaInstruction([0, "7100cdab0000", "invoke-static", "{}, method@?"])
        escaped = DalvikInstructionEscaper.escapeBinary(ins, escape_intraprocedural_jumps=True)
        self.assertEqual(escaped[:2], "71")
        self.assertEqual(escaped[4:8], "????")

        # opc-only keeps first opcode byte
        opc = DalvikInstructionEscaper.escapeToOpcodeOnly(ins)
        self.assertEqual(opc[:2], "71")
        self.assertTrue(all(c == "?" for c in opc[2:]))

        self.assertEqual(DalvikInstructionEscaper.escapeMnemonic("invoke-static"), "C")
        self.assertEqual(DalvikInstructionEscaper.escapeMnemonic("add-int"), "A")
        self.assertIs(SmdaFunction.getInstructionEscaper("dalvik"), DalvikInstructionEscaper)

    def testDalvikEscaperPreservesRegisterOnLit8(self):
        """22b: byte 2 is reg_b (kept), only byte 3 (lit8) is masked.

        add-int/lit8 v0, v1, #5  →  d8 01 05 00  (last byte reg_b, literal 5)
        add-int/lit8 v0, v2, #9  →  d8 02 09 00  (different reg_b, same opcode)
        Only the literal byte (index 3) must differ between the two escapes.
        """
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        ins_a = SmdaInstruction([0, "d8010500", "add-int/lit8", "v0, v1, #5"])
        ins_b = SmdaInstruction([0, "d8020900", "add-int/lit8", "v0, v2, #9"])
        esc_a = DalvikInstructionEscaper.escapeBinary(ins_a, escape_intraprocedural_jumps=True)
        esc_b = DalvikInstructionEscaper.escapeBinary(ins_b, escape_intraprocedural_jumps=True)
        # opcode + reg_a/reg_b kept; literal byte (index 3 → chars 6:8) masked
        self.assertEqual(esc_a[:6], "d80105")
        self.assertEqual(esc_b[:6], "d80209")
        self.assertEqual(esc_a[6:], "??")
        self.assertEqual(esc_b[6:], "??")
        # reg_b distinguishes the two even though only the literal differs
        self.assertNotEqual(esc_a, esc_b)

    def testDalvikEscaperPICMasksBranchOffsets(self):
        """PIC hash must be position-independent, so branch offsets are masked.

        escape_intraprocedural_jumps used to CLEAR the mask for branch-only formats,
        which inverted the flag relative to the Intel and CIL escapers - there the flag
        *wildcards* an intra-procedural branch displacement. Retaining the raw signed
        offset made pic_hash position-DEPENDENT: two structurally identical methods whose
        branch deltas differed only because an earlier instruction had a different width
        (const/4 vs const/16) hashed differently. Changed in 4.4.2; see
        DALVIK_PIC_HASH_ESCAPE_VERSION.
        """
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        # goto +2 units  → 28 01 ; goto +4 units → 28 02
        ins_short = SmdaInstruction([0, "2801", "goto", "2"])
        ins_far = SmdaInstruction([0, "2802", "goto", "4"])
        pic_short = DalvikInstructionEscaper.escapeBinary(ins_short, escape_intraprocedural_jumps=True)
        pic_far = DalvikInstructionEscaper.escapeBinary(ins_far, escape_intraprocedural_jumps=True)
        self.assertEqual(pic_short, "28??")
        self.assertEqual(pic_far, "28??")
        # the same two instructions must now be indistinguishable on the PIC path
        self.assertEqual(pic_short, pic_far)
        # Cross-binary compare (False) masks the branch offset as before.
        cmp_short = DalvikInstructionEscaper.escapeBinary(ins_short, escape_intraprocedural_jumps=False)
        cmp_far = DalvikInstructionEscaper.escapeBinary(ins_far, escape_intraprocedural_jumps=False)
        self.assertEqual(cmp_short, "28??")
        self.assertEqual(cmp_far, "28??")

    def testDalvikPicEscapingStableAcrossBranchDeltaShift(self):
        """A conditional branch whose delta shifted must escape identically on the PIC path.

        This is the real-world shape: an earlier const/4 becoming a const/16 shifts every
        later branch delta by one code unit without changing the method's structure.
        """
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        escaped = [
            DalvikInstructionEscaper.escapeBinary(
                SmdaInstruction([0x1000, "3800" + delta, "if-eqz", "v0, +x"]),
                escape_intraprocedural_jumps=True,
            )
            for delta in ("0800", "0900")
        ]

        self.assertEqual(escaped[0], escaped[1])

    def testDalvikPicHashStableAcrossStringIndexShift(self):
        """Same method body with different string indices → same PicHash."""
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        # Two const-string with different indices then return-void
        blocks_a = {
            0x1000: [
                SmdaInstruction([0x1000, "1a000100", "const-string", 'v0, "a"']),
                SmdaInstruction([0x1004, "0e00", "return-void", ""]),
            ]
        }
        blocks_b = {
            0x1000: [
                SmdaInstruction([0x1000, "1a00ff0f", "const-string", 'v0, "b"']),
                SmdaInstruction([0x1004, "0e00", "return-void", ""]),
            ]
        }

        def _pic_seq(blocks):
            fn = SmdaFunction(None)
            fn.blocks = blocks
            fn._sorted_block_keys = sorted(blocks)
            fn._escaper = DalvikInstructionEscaper
            return fn.getPicHashSequence(type("BI", (), {"base_addr": 0, "binary_size": 0x10000})())

        self.assertEqual(_pic_seq(blocks_a), _pic_seq(blocks_b))
        self.assertIn(b"?", _pic_seq(blocks_a))

    def testGoto32SelfBranchIsLegal(self):
        """AOSP allows goto/32 offset 0 as an infinite-loop idiom."""
        # goto/32 +0 (self): 2a 00 00 00 00 00
        insns = bytes.fromhex("2a0000000000")
        code_item = build_code_item(insns)
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]
        self.assertFalse(
            any(v["type"] == "zero_branch_offset" for v in metadata.get("structural_violations", [])),
            "goto/32 self-branch must not be recorded as zero_branch_offset",
        )
        self.assertIn(func_addr, disassembly.code_refs_from.get(func_addr, set()))

    def testUnreachedValidStartsRecordedInMetadata(self):
        """Dead code after an unconditional goto is flagged, not attached to the CFG."""
        # 0: goto/16 to +3 units (byte 6)
        # 4: const/4 v0, #0   (dead: valid start, never reached)
        # 6: return-void
        insns = bytes([0x29, 0x00]) + struct.pack("<h", 3) + bytes.fromhex("12000e00")
        code_item = build_code_item(insns)
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        metadata = disassembly.function_metadata[func_addr]
        unreached = metadata.get("unreached_instruction_starts", [])
        self.assertTrue(unreached, "expected unreached valid starts after goto")
        self.assertIn("unreachable-code-surface", metadata.get("heuristics", []))
        # Dead const/4 at func_addr+4 must not be a recovered instruction
        self.assertNotIn(func_addr + 4, disassembly.instructions)

    def testOrphanCodeItemDiscovery(self):
        """A plausible unlisted code_item is recovered as orphan_code_item@…"""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        # Minimal orphan: registers=1, ins=0, outs=0, tries=0, debug=0, insns=1 → return-void
        code_item = build_code_item(bytes.fromhex("0e00"))
        # Place it at a known offset inside a fake data region of a minimal DEX header.
        header = bytearray(build_dex_header(version=b"039", file_size=0x200, data_off=0x100, data_size=0x100))
        raw = bytearray(0x200)
        raw[:0x70] = header[:0x70]
        orphan_header_off = 0x100
        raw[orphan_header_off : orphan_header_off + len(code_item)] = code_item
        # Fix file_size / data fields
        struct.pack_into("<I", raw, 0x20, len(raw))
        struct.pack_into("<I", raw, 0x68, 0x100)
        struct.pack_into("<I", raw, 0x6C, 0x100)

        disassembler = DalvikDisassembler(config)
        found = disassembler._discoverOrphanCodeItems(bytes(raw), known_code_offsets=set())
        self.assertIn(orphan_header_off + 16, found)

    def testSecondOrphanFoundAfterTheFirstClaimsItsRange(self):
        """Accepting an orphan re-sorts the claimed intervals; the scan must keep finding later ones."""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        code_item = build_code_item(bytes.fromhex("0e00"))
        header = bytearray(build_dex_header(version=b"039", file_size=0x300, data_off=0x100, data_size=0x200))
        raw = bytearray(0x300)
        raw[:0x70] = header[:0x70]
        first_off, second_off = 0x100, 0x120
        raw[first_off : first_off + len(code_item)] = code_item
        raw[second_off : second_off + len(code_item)] = code_item
        struct.pack_into("<I", raw, 0x20, len(raw))
        struct.pack_into("<I", raw, 0x68, 0x200)
        struct.pack_into("<I", raw, 0x6C, 0x100)

        disassembler = DalvikDisassembler(config)
        found = disassembler._discoverOrphanCodeItems(bytes(raw), known_code_offsets=set())

        self.assertIn(first_off + 16, found)
        self.assertIn(second_off + 16, found)

    def testOrphanWithSwitchPayloadAccepted(self):
        """An orphan body with packed-switch + payload must not be rejected."""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        # 0: packed-switch v0, +4 units (payload at byte 8)
        # 6: return-void (default fallthrough)
        # 8: packed-switch-payload, size=1
        switch = bytes([0x2B, 0x00]) + struct.pack("<i", 4)
        ret = bytes.fromhex("0e00")
        payload = struct.pack("<HHii", 0x0100, 1, 0, 1)
        insns = switch + ret + payload
        code_item = build_code_item(insns)
        header = bytearray(build_dex_header(version=b"039", file_size=0x300, data_off=0x100, data_size=0x200))
        raw = bytearray(0x300)
        raw[:0x70] = header[:0x70]
        orphan_header_off = 0x100
        raw[orphan_header_off : orphan_header_off + len(code_item)] = code_item
        struct.pack_into("<I", raw, 0x20, len(raw))
        struct.pack_into("<I", raw, 0x68, 0x200)
        struct.pack_into("<I", raw, 0x6C, 0x100)

        disassembler = DalvikDisassembler(config)
        found = disassembler._discoverOrphanCodeItems(bytes(raw), known_code_offsets=set())
        self.assertIn(orphan_header_off + 16, found)

    def testOrphanScanScopedToMapCodeItemSection(self):
        """Orphan scan honors the map's TYPE_CODE_ITEM bounds; data-section junk is skipped."""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        code_item = build_code_item(bytes.fromhex("0e00"))
        raw = bytearray(0x300)
        raw[:0x70] = build_dex_header(version=b"039", file_size=0x300, data_off=0x100, data_size=0x200)
        # Orphan inside the declared code_item section at 0x100.
        raw[0x100 : 0x100 + len(code_item)] = code_item
        # Identical bytes OUTSIDE the code section (string-data territory) at 0x200.
        raw[0x200 : 0x200 + len(code_item)] = code_item
        # map_list at 0x2C0: code_items @0x100, string_data @0x200 (next section bounds the scan).
        map_off = 0x2C0
        map_list = struct.pack("<I", 2)
        map_list += struct.pack("<HHII", 0x2001, 0, 1, 0x100)  # TYPE_CODE_ITEM
        map_list += struct.pack("<HHII", 0x2002, 0, 1, 0x200)  # TYPE_STRING_DATA_ITEM
        raw[map_off : map_off + len(map_list)] = map_list
        struct.pack_into("<I", raw, 0x20, len(raw))
        struct.pack_into("<I", raw, 0x34, map_off)
        struct.pack_into("<I", raw, 0x68, 0x200)
        struct.pack_into("<I", raw, 0x6C, 0x100)

        disassembler = DalvikDisassembler(config)
        found = disassembler._discoverOrphanCodeItems(bytes(raw), known_code_offsets=set())
        self.assertIn(0x100 + 16, found)
        self.assertNotIn(0x200 + 16, found)

    def testOrphanRejectsJunkThatDoesNotDecodeCleanly(self):
        """Strict acceptance: chain must decode error-free to insns end with a terminator."""
        from smda.dalvik.DalvikDisassembler import DalvikDisassembler

        disassembler = DalvikDisassembler(config)
        # return-void then a trailing undefined opcode unit (0x3e is unused per AOSP).
        self.assertFalse(disassembler._walksCleanlyToEnd(bytes.fromhex("0e003e00"), []))
        # No terminator at all.
        self.assertFalse(disassembler._walksCleanlyToEnd(bytes.fromhex("01000100"), []))
        # Clean: move + return-void.
        self.assertTrue(disassembler._walksCleanlyToEnd(bytes.fromhex("01000e00"), []))

    def testThrowTerminatorRecordsExceptionEdge(self):
        # throw v0; handler at unit 1: move-exception + return-object
        code_item = build_code_item(
            bytes.fromhex("27000d010e00"),
            tries=[(0, 1, 1)],
            handlers_blob=b"\x01\x00\x01",
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        edges = disassembly.function_metadata[func_addr]["exception_edges"]
        self.assertTrue(any(e["mnemonic"] == "throw" for e in edges))
        # handler is reached only via exception edge (throw is a terminator)
        self.assertTrue(any(e["to_addr"] == func_addr + 2 for e in edges))
        self.assertEqual(disassembly.code_refs_from.get(func_addr, set()), {func_addr + 2})

    def testTypedCatchHandlerExceptionEdge(self):
        # encoded_size = +1 typed handler (type_idx=0, addr=2), no catch-all
        # sleb128 +1 = 0x01; type 0 uleb; addr 2 uleb
        handlers = bytes([0x01, 0x01, 0x00, 0x02])
        code_item = build_code_item(
            bytes.fromhex("1d000e000d010e00"),
            tries=[(0, 1, 1)],
            handlers_blob=handlers,
        )
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        edges = disassembly.function_metadata[func_addr]["exception_edges"]
        self.assertTrue(edges)
        self.assertFalse(edges[0]["catch_all"])
        self.assertEqual(edges[0]["type_idx"], 0)

    def testSwitchFallthroughDoesNotRefPayload(self):
        # packed-switch immediately followed by its payload (no default insn between)
        payload = struct.pack("<HHii", 0x0100, 1, 0, 1)
        switch = bytes([0x2B, 0x00]) + struct.pack("<i", 3)  # payload at +6 bytes
        # After switch (6 bytes) is payload — no fallthrough code
        insns = switch + payload + bytes.fromhex("0e00")
        code_item = build_code_item(insns)
        disassembly, func_addr = self._analyzeSyntheticMethod(code_item)
        # Must not have a code_ref from switch into payload start (func_addr+6)
        refs = disassembly.code_refs_from.get(func_addr, set())
        self.assertNotIn(func_addr + 6, refs)

    def testEscapeOperandsInvokeRegisterList(self):
        from smda.common.SmdaInstruction import SmdaInstruction
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        ins = SmdaInstruction([0, "6e10abcd1020", "invoke-virtual", "{v0, v1}, LFoo;->bar()V"])
        escaped = DalvikInstructionEscaper.escapeOperands(ins)
        self.assertIn("{REG, REG}", escaped)
        self.assertIn("PTR", escaped)

    def testCdexAnalyzeErrorMessage(self):
        cdex = b"cdex001\x00" + b"\x00" * 0x70
        report = Disassembler(config, backend="dalvik").disassembleUnmappedBuffer(cdex)
        self.assertEqual(report.status, "error")
        self.assertIn("CDEX", report.message or "")


class DalvikAuditRegressionTestSuite(unittest.TestCase):
    def test_five_byte_sleb128_sign_extends(self):
        from smda.dalvik.DalvikOpcodeDecoder import read_sleb128

        self.assertEqual(read_sleb128(b"\xff\xff\xff\xff\x7f", 0), (-1, 5))
        self.assertEqual(read_sleb128(b"\xff\xff\xff\xff\x07", 0), (0x7FFFFFFF, 5))
        self.assertEqual(read_sleb128(b"\x7f", 0), (-1, 1))
        self.assertEqual(read_sleb128(b"\x01", 0), (1, 1))

    def test_a_brace_inside_a_string_constant_does_not_join_operands(self):
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        class _Instruction:
            def __init__(self, mnemonic, operands):
                self.mnemonic = mnemonic
                self.operands = operands

        self.assertEqual(DalvikInstructionEscaper.escapeOperands(_Instruction("const-string", 'v0, "}"')), "REG, PTR")
        self.assertEqual(
            DalvikInstructionEscaper.escapeOperands(_Instruction("invoke-virtual", "{v0, v1}, Lfoo;->m()V")),
            "{REG, REG}, PTR",
        )

    def test_an_array_type_descriptor_is_escaped(self):
        from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

        self.assertEqual(DalvikInstructionEscaper.escapeField("[B"), "PTR")
        self.assertEqual(DalvikInstructionEscaper.escapeField("[[Ljava/lang/String;"), "PTR")

    def test_an_unrenderable_type_yields_a_deterministic_marker(self):
        from smda.dalvik.DalvikDisassembler import DexReferenceResolver

        resolver = DexReferenceResolver.__new__(DexReferenceResolver)

        class _Opaque:
            name = None

            def __str__(self):
                return "<lief._lief.DEX.Type object at 0x10bb30cb0>"

        rendered = resolver._formatTypeUncached(_Opaque())

        self.assertEqual(rendered, "<_Opaque>")
        self.assertNotIn("0x", rendered)

    def test_a_call_site_that_cannot_be_decoded_degrades(self):
        from smda.dalvik.DalvikDisassembler import DexReferenceResolver

        disassembler = DexReferenceResolver.__new__(DexReferenceResolver)
        disassembler.raw_data = b"\x00" * 0x20

        def _explode(raw, offset):
            raise RecursionError("maximum recursion depth exceeded")

        disassembler._readEncodedArray = _explode

        self.assertEqual(
            disassembler._parseCallSiteItem(0x10),
            {"offset": 0x10, "values": [], "display": "call_site@off=16"},
        )
        self.assertEqual(
            disassembler._parseCallSiteItem(-1),
            {"offset": -1, "values": [], "display": "call_site@off=-1"},
        )


if __name__ == "__main__":
    unittest.main()
