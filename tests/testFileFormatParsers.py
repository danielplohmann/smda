#!/usr/bin/python

import logging
import os
import unittest

import lief

from smda.common.BinaryInfo import BinaryInfo
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

    def _load_xored_fixture(self, fixture_name):
        with open(os.path.join(config.PROJECT_ROOT, "tests", fixture_name), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_binary = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_binary.append(byte ^ (index % 256))
        return bytes(decrypted_binary)

    def _create_binary_info(self, binary):
        loader = FileLoader("/", map_file=True)
        loader._loadFile(binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.abi = loader.getAbi()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        return binary_info

    def testPeParsingWithCutwail(self):
        disasm = Disassembler(config, backend="intel")
        cutwail_binary = self._load_xored_fixture("cutwail_xored")
        # run FileLoader and disassemble as file
        binary_info = self._create_binary_info(cutwail_binary)
        # parse bytes of 0x400 truncated PE header
        pe_header = lief.parse(binary_info.getHeaderBytes())
        assert pe_header.dos_header.magic == 0x5A4D
        assert pe_header.header.machine == 0x14C
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 33
        cutwail_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cutwail_binary)
        assert cutwail_unmapped_disassembly.num_functions == 33
        assert cutwail_unmapped_disassembly.getFunction(0x4001730).function_name == "original_entry_point"

    def testPeExportLabelExtraction(self):
        disasm = Disassembler(config, backend="intel")
        pe_export_binary = self._load_xored_fixture("pe_export_label_test_xored")
        binary_info = self._create_binary_info(pe_export_binary)

        assert binary_info.getExportedFunctions() == {0x401000: "exported_test_function"}

        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 1
        assert controlled_disassembly.getFunction(0x401000).function_name == "exported_test_function"

        unmapped_disassembly = disasm.disassembleUnmappedBuffer(pe_export_binary)
        assert unmapped_disassembly.num_functions == 1
        assert unmapped_disassembly.getFunction(0x401000).function_name == "exported_test_function"

    def testElfParsingWithBashlite(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted benign /bin/cat
        bashlite_binary = self._load_xored_fixture("bashlite_xored")
        # run FileLoader and disassemble as file
        binary_info = self._create_binary_info(bashlite_binary)
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 177
        bashlite_unmapped_disassembly = disasm.disassembleUnmappedBuffer(bashlite_binary)
        assert bashlite_unmapped_disassembly.num_functions == 177
        assert len([f.function_name for f in bashlite_unmapped_disassembly.getFunctions() if f.function_name]) == 174
        assert binary_info.abi == "SYSTEMV"
        # test section extraction
        sections = {name: (start, end) for name, start, end in binary_info.getSections()}
        assert len(sections) > 0
        assert ".text" in sections

    def testDotnetParsingWithNjRAT(self):
        disasm = Disassembler(config, backend="cil")
        # load encrypted malicious win.cutwail
        with open(os.path.join(config.PROJECT_ROOT, "tests", "njrat_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_njrat = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_njrat.append(byte ^ (index % 256))
        njrat_binary = bytes(decrypted_njrat)
        # run FileLoader and disassemble as file
        njrat_unmapped_disassembly = disasm.disassembleUnmappedBuffer(njrat_binary)
        assert njrat_unmapped_disassembly.num_functions == 64
        assert len([f.function_name for f in njrat_unmapped_disassembly.getFunctions() if f.function_name]) == 64

    def testMacOsParsingWithKomplex(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted malicious osx.komplex
        with open(os.path.join(config.PROJECT_ROOT, "tests", "komplex_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_komplex = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_komplex.append(byte ^ (index % 256))
        komplex_binary = bytes(decrypted_komplex)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(komplex_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        disasm._disassemble(binary_info)
        komplex_unmapped_disassembly = disasm.disassembleUnmappedBuffer(komplex_binary)
        self.assertEqual(komplex_unmapped_disassembly.num_functions, 211)


if __name__ == "__main__":
    unittest.main()
