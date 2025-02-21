#!/usr/bin/python

import logging
import os
import unittest

from smda.utility.FileLoader import FileLoader
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.common.SmdaReport import SmdaReport
from smda.common.SmdaFunction import SmdaFunction
from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class SmdaIntegrationTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    @classmethod
    def setUpClass(cls):
        super(SmdaIntegrationTestSuite, cls).setUpClass()

    def testPeParsingWithCutwail(self):
        disasm = Disassembler(config)
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
        cutwail_binary_info = binary_info
        cutwail_disassembly = disasm._disassemble(binary_info)
        cutwail_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cutwail_binary)
        assert cutwail_unmapped_disassembly.num_functions == 33

    def testElfParsingWithBase64(self):
        disasm = Disassembler(config)
        # load encrypted benign /bin/cat
        with open(os.path.join(config.PROJECT_ROOT, "tests", "cat_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_cat = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_cat.append(byte ^ (index % 256))
        cat_binary = bytes(decrypted_cat)
        # run FileLoader and disassemble as file
        loader = FileLoader("/", map_file=True)
        loader._loadFile(cat_binary)
        file_content = loader.getData()
        binary_info = BinaryInfo(file_content)
        binary_info.raw_data = loader.getRawData()
        binary_info.file_path = ""
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        cat_binary_info = binary_info
        cat_disassembly = disasm._disassemble(binary_info)
        cat_unmapped_disassembly = disasm.disassembleUnmappedBuffer(cat_binary)
        assert cat_unmapped_disassembly.num_functions == 150

    def testMacOsParsingWithKomplex(self):
        disasm = Disassembler(config)
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
        komplex_binary_info = binary_info
        komplex_disassembly = disasm._disassemble(binary_info)
        komplex_unmapped_disassembly = disasm.disassembleUnmappedBuffer(komplex_binary)
        komplex_unmapped_disassembly.num_functions == 208


if __name__ == '__main__':
    unittest.main()
