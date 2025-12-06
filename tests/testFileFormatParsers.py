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

    def testPeParsingWithCutwail(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted malicious win.cutwail
        with open(os.path.join(config.PROJECT_ROOT, "tests", "cutwail_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_cutwail = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_cutwail.append(byte ^ (index % 256))
        cutwail_binary = bytes(decrypted_cutwail)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(cutwail_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        # parse bytes of 0x400 truncated PE header
        pe_header = lief.parse(binary_info.getHeaderBytes())
        assert pe_header.dos_header.magic == 0x5A4D
        assert pe_header.header.machine == 0x14C
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 33
        cutwail_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cutwail_binary)
        assert cutwail_unmapped_disassembly.num_functions == 33
        # TODO test label extraction for PE, add another binary for testing

    def testElfParsingWithBashlite(self):
        disasm = Disassembler(config, backend="intel")
        # load encrypted benign /bin/cat
        with open(os.path.join(config.PROJECT_ROOT, "tests", "bashlite_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_bashlite = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_bashlite.append(byte ^ (index % 256))
        bashlite_binary = bytes(decrypted_bashlite)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(bashlite_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        controlled_disassembly = disasm._disassemble(binary_info)
        assert controlled_disassembly.num_functions == 177
        bashlite_unmapped_disassembly = disasm.disassembleUnmappedBuffer(bashlite_binary)
        assert bashlite_unmapped_disassembly.num_functions == 177
        assert len([f.function_name for f in bashlite_unmapped_disassembly.getFunctions() if f.function_name]) == 174

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
