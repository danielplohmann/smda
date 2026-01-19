#!/usr/bin/python

import logging
import os
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
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
        assert report_as_dict["statistics"]["num_instructions"] == 15706
        assert report_as_dict["sha256"] == "db8a133fed1b706608a4492079b702ded6b70369a980d2b5ae355a6adc78ef00"
        SmdaReport.fromDict(report_as_dict)

    def testCutwailMarshalling(self):
        report_as_dict = self.cutwail_disassembly.toDict()
        assert report_as_dict["status"] == "ok"
        assert report_as_dict["base_addr"] == 0x4000000
        assert report_as_dict["statistics"]["num_instructions"] == 1611
        assert report_as_dict["sha256"] == "a348a0ddfab135d152b684d561a3215ab6c472570facd3d75aa2c7ee845a8e2b"
        # compare our manual file loading with unmapped buffer
        assert self.cutwail_disassembly.num_instructions == self.cutwail_unmapped_disassembly.num_instructions
        SmdaReport.fromDict(report_as_dict)

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


if __name__ == "__main__":
    unittest.main()
