#!/usr/bin/python

import logging
import os
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.DisassemblyStatistics import DisassemblyStatistics
from smda.utility.FileLoader import FileLoader

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class SmdaIntegrationTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        config.WITH_STRINGS = True
        disasm = Disassembler(config)
        # load encrypted Asprox
        with open(os.path.join(config.PROJECT_ROOT, "tests", "asprox_0x008D0000_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_asprox = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_asprox.append(byte ^ (index % 256))
        cls.asprox_binary = decrypted_asprox
        cls.asprox_disassembly = disasm.disassembleBuffer(bytes(decrypted_asprox), 0x8D0000)
        # load encrypted Cutwail
        with open(os.path.join(config.PROJECT_ROOT, "tests", "cutwail_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_cutwail = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_cutwail.append(byte ^ (index % 256))
        cls.cutwail_binary = bytes(decrypted_cutwail)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(cls.cutwail_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        cls.cutwail_binary_info = binary_info
        cls.cutwail_disassembly = disasm._disassemble(binary_info)
        cls.cutwail_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cls.cutwail_binary)

    def testAsproxDisassemblyCoverage(self):
        # 105: scanning the tail of the mapped image recovered one extra gap-candidate
        # function (105 -> 106), and booking the slot an indirect call reads through as data
        # dropped 0x8de000 again (106 -> 105). That address is not a function: its only inbound
        # reference is `call dword ptr [0x8de000]` at 0x8d31f4, so it is the pointer slot
        # itself, decoded as `lodsb ; wait ; fidiv word ptr [edi + 0x51]`.
        assert len(list(self.asprox_disassembly.getFunctions())) == 105

    def testOep(self):
        # PE header from buffers are not parsed, so we don't get header infos
        assert self.asprox_disassembly.oep is None
        # PE headers are parsed for regularly processed files (PE+ELF)
        assert self.cutwail_unmapped_disassembly.oep == 0x1730

    def testCodeXrefCreation(self):
        example_function = self.asprox_disassembly.getFunction(0x008D8292)
        # should be initialized on demand only
        assert example_function.code_inrefs is None
        # example function has inrefs and outrefs
        inrefs = list(example_function.getCodeInrefs())
        assert len(inrefs) == 1
        for xref in example_function.getCodeInrefs():
            print(
                xref.from_function,
                xref.from_instruction,
                xref.to_function,
                xref.to_instruction,
            )
        outrefs = list(example_function.getCodeOutrefs())
        assert len(outrefs) == 10

    def testAsproxStringRefs(self):
        function_with_strings = self.asprox_disassembly.getFunction(0x008D2850)
        assert len(function_with_strings.stringrefs) == 6
        assert function_with_strings.stringrefs[0]["string"] == "Software"
        marshalled = function_with_strings.toDict()
        unmarshalled = SmdaFunction.fromDict(marshalled)
        assert unmarshalled.stringrefs[0]["string"] == "Software"

    def testAsproxApiCoverage(self):
        num_api_ref_srcs = 0
        api_ref_dsts = set()
        for fn in self.asprox_disassembly.getFunctions():
            num_api_ref_srcs += len(fn.apirefs)
            api_ref_dsts.update(fn.apirefs.values())
        assert num_api_ref_srcs == 546
        assert len(api_ref_dsts) == 95

    def testAsproxMarshalling(self):
        report_as_dict = self.asprox_disassembly.toDict()
        assert report_as_dict["status"] == "ok"
        assert report_as_dict["base_addr"] == 0x8D0000
        # 15706: the eight instructions decoded out of the 0x8de000 pointer slot are gone
        assert report_as_dict["statistics"]["num_instructions"] == 15706
        assert report_as_dict["sha256"] == "db8a133fed1b706608a4492079b702ded6b70369a980d2b5ae355a6adc78ef00"
        SmdaReport.fromDict(report_as_dict)

    def testCutwailMarshalling(self):
        report_as_dict = self.cutwail_disassembly.toDict()
        assert report_as_dict["status"] == "ok"
        assert report_as_dict["base_addr"] == 0x4000000
        assert report_as_dict["statistics"]["num_instructions"] == 1611
        assert report_as_dict["sha256"] == "46686681e2be012ce26219eec1e765f8f2db9fc7a33ca802482050cef189334f"
        # compare our manual file loading with unmapped buffer
        assert self.cutwail_disassembly.num_instructions == self.cutwail_unmapped_disassembly.num_instructions
        SmdaReport.fromDict(report_as_dict)

    def testUnmappedBufferStringRefsMatchMappedImage(self):
        # disassembleUnmappedBuffer used to feed the raw file bytes (not the
        # mapped image) into string extraction and STORE_BUFFER. StringExtractor
        # resolves referencing addresses against base_addr + len(buffer), so the
        # raw file produced different (wrong) data offsets than the mapped path.
        import tempfile

        def string_refs(report):
            refs = set()
            for smda_function in report.getFunctions():
                for entry in smda_function.stringrefs:
                    refs.add((entry["string"], entry["ins_addr"], entry["data_addr"]))
            return refs

        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(self.cutwail_binary)
            file_report = Disassembler(config).disassembleFile(path)
        finally:
            os.unlink(path)
        mapped_refs = string_refs(file_report)
        unmapped_refs = string_refs(self.cutwail_unmapped_disassembly)
        assert mapped_refs
        assert mapped_refs == unmapped_refs

    def testStoreBufferPersistsMappedImage(self):
        config.STORE_BUFFER = True
        try:
            report = Disassembler(config).disassembleUnmappedBuffer(self.cutwail_binary)
        finally:
            config.STORE_BUFFER = False
        assert len(report.buffer) > len(self.cutwail_binary)
        assert report.buffer[:0x40] == self.cutwail_binary[:0x40]

    def testStoreBufferOnRawBufferPathKeepsTheSuppliedBytes(self):
        # disassembleBuffer is handed an already-mapped buffer, so binary_info.binary
        # is the caller's own bytes - storing it must be an identity, not a re-read.
        config.STORE_BUFFER = True
        try:
            report = Disassembler(config).disassembleBuffer(self.cutwail_binary, 0x400000)
        finally:
            config.STORE_BUFFER = False
        assert report.buffer == self.cutwail_binary

    def testBlockLocator(self):
        # test with a function start
        found_function = self.asprox_disassembly.findFunctionByContainedAddress(0x008D8292)
        found_block = self.asprox_disassembly.findBlockByContainedAddress(0x008D8292)
        assert found_function.offset == 0x008D8292
        assert found_block.offset == 0x008D8292
        # test with an instruction in a block a bit deeper in the function
        found_function = self.asprox_disassembly.findFunctionByContainedAddress(0x008D82A6)
        found_block = self.asprox_disassembly.findBlockByContainedAddress(0x008D82A6)
        assert found_function.offset == 0x008D8292
        assert found_block.offset == 0x008D82A4
        # test with an offset that is not start of an instruction
        found_function = self.asprox_disassembly.findFunctionByContainedAddress(0x008D82A7)
        found_block = self.asprox_disassembly.findBlockByContainedAddress(0x008D82A7)
        assert found_function.offset == 0x008D8292
        assert found_block.offset == 0x008D82A4
        # test with offsets beyond image base and binary size
        found_function = self.asprox_disassembly.findFunctionByContainedAddress(0x100)
        found_block = self.asprox_disassembly.findBlockByContainedAddress(0x100)
        assert found_function is None
        assert found_block is None
        found_function = self.asprox_disassembly.findFunctionByContainedAddress(0xFFFFFF00)
        found_block = self.asprox_disassembly.findBlockByContainedAddress(0xFFFFFF00)
        assert found_function is None
        assert found_block is None

    def test_smda_basic_block_from_dict_initializes_fields(self):
        block = SmdaBasicBlock.fromDict([[0x401000, "90", "nop", ""]])

        self.assertEqual(block.offset, 0x401000)
        self.assertEqual(block.length, 1)
        self.assertEqual(block.toDict(), [[0x401000, "90", "nop", ""]])
        self.assertEqual(list(SmdaBasicBlock([]).getInstructions()), [])

    def test_statistics_add_is_pure_and_iadd_mutates(self):
        left = DisassemblyStatistics.fromDict(
            {
                "num_functions": 1,
                "num_recursive_functions": 2,
                "num_leaf_functions": 3,
                "num_basic_blocks": 4,
                "num_instructions": 5,
                "num_api_calls": 6,
                "num_function_calls": 7,
                "num_failed_functions": 8,
                "num_failed_instructions": 9,
            }
        )
        right = DisassemblyStatistics.fromDict(
            {
                "num_functions": 10,
                "num_recursive_functions": 20,
                "num_leaf_functions": 30,
                "num_basic_blocks": 40,
                "num_instructions": 50,
                "num_api_calls": 60,
                "num_function_calls": 70,
                "num_failed_functions": 80,
                "num_failed_instructions": 90,
            }
        )

        total = left + right
        self.assertEqual(left.num_functions, 1)
        self.assertEqual(total.num_functions, 11)
        left += right
        self.assertEqual(left.num_failed_instructions, 99)

    def test_statistics_num_thunk_functions_roundtrip(self):
        result = DisassemblyResult()
        result.thunk_functions.add(0x401000)
        result.thunk_functions.add(0x402000)

        stats = DisassemblyStatistics(result)
        self.assertEqual(stats.num_thunk_functions, 2)

        restored = DisassemblyStatistics.fromDict(stats.toDict())
        self.assertEqual(restored.num_thunk_functions, 2)
        self.assertEqual((restored + stats).num_thunk_functions, 4)

    def test_statistics_from_dict_tolerates_missing_num_thunk_functions(self):
        stats = DisassemblyStatistics.fromDict(
            {
                "num_functions": 1,
                "num_recursive_functions": 0,
                "num_leaf_functions": 1,
                "num_basic_blocks": 1,
                "num_instructions": 2,
                "num_api_calls": 0,
                "num_function_calls": 1,
                "num_failed_functions": 0,
                "num_failed_instructions": 0,
            }
        )
        self.assertIsNone(stats.num_thunk_functions)
        self.assertIsNone(stats.toDict()["num_thunk_functions"])


if __name__ == "__main__":
    unittest.main()
