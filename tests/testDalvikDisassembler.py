#!/usr/bin/python

import logging
import os
import tempfile
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.utility.DexFileLoader import DexFileLoader

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class DalvikDisassemblerTestSuite(unittest.TestCase):
    """Test suite for Dalvik/DEX disassembly using a real DEX file (blockblast classes.dex)"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Load and decrypt the XOR'd DEX fixture
        with open(os.path.join(config.PROJECT_ROOT, "tests", "blockblast_classes_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted_dex = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted_dex.append(byte ^ (index % 256))
        cls.dex_binary = bytes(decrypted_dex)

        # Write decrypted DEX to temp file for file-based disassembly
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tmp:
            tmp.write(cls.dex_binary)
            cls._temp_file_name = tmp.name

        # File-based disassembly (primary working path, matches CLI: python analyze.py -p -r dalvik <file>)
        disasm = Disassembler(config, backend="dalvik")
        cls.file_disassembly = disasm.disassembleFile(cls._temp_file_name)

        # Buffer-based disassembly
        disasm_buf = Disassembler(config, backend="dalvik")
        cls.buffer_disassembly = disasm_buf.disassembleUnmappedBuffer(cls.dex_binary)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        os.unlink(cls._temp_file_name)

    def testDexFormatDetection(self):
        """DexFileLoader.isCompatible() correctly identifies DEX files"""
        assert DexFileLoader.isCompatible(self.dex_binary) is True
        assert DexFileLoader.getBaseAddress(self.dex_binary) == 0
        assert DexFileLoader.getBitness(self.dex_binary) == 32
        assert DexFileLoader.getArchitecture(self.dex_binary) == "dalvik"
        assert DexFileLoader.getAbi(self.dex_binary) == ""
        # Non-DEX data should be rejected
        assert DexFileLoader.isCompatible(b"MZ\x90\x00") is False
        assert DexFileLoader.isCompatible(b"") is False
        assert DexFileLoader.isCompatible(b"\x7fELF") is False

    def testFileDisassemblyStatus(self):
        """File-based disassembly completes successfully"""
        self.assertEqual(self.file_disassembly.status, "ok")
        self.assertEqual(self.file_disassembly.message, "Analysis finished regularly.")

    def testFileDisassemblyArchitecture(self):
        """Architecture is 'dalvik', bitness 32, base_addr 0"""
        self.assertEqual(self.file_disassembly.architecture, "dalvik")
        self.assertEqual(self.file_disassembly.bitness, 32)
        self.assertEqual(self.file_disassembly.base_addr, 0)

    def testFileDisassemblyHashes(self):
        """SHA256/SHA1/MD5 match expected values for the DEX file"""
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

    def testFileDisassemblyFunctionRecovery(self):
        """Correct number of functions recovered from DEX"""
        self.assertEqual(self.file_disassembly.num_functions, 2219)
        functions = list(self.file_disassembly.getFunctions())
        self.assertEqual(len(functions), 2219)

    def testFileDisassemblyInstructionCount(self):
        """Total instruction count matches expected"""
        self.assertEqual(self.file_disassembly.num_instructions, 9593)

    def testFileDisassemblyBlockCount(self):
        """Total block count matches expected"""
        self.assertEqual(self.file_disassembly.num_blocks, 2219)

    def testDalvikFunctionNames(self):
        """All functions have Dalvik-style names (Lclass;->method)"""
        functions = list(self.file_disassembly.getFunctions())
        named_functions = [f for f in functions if f.function_name]
        self.assertEqual(len(named_functions), 2219)
        # All function names should contain '->' (class->method separator)
        arrow_functions = [f for f in functions if "->" in f.function_name]
        self.assertEqual(len(arrow_functions), 2219)
        # All function names should start with 'L' (Dalvik class descriptor)
        l_prefix_functions = [f for f in functions if f.function_name.startswith("L")]
        self.assertEqual(len(l_prefix_functions), 2219)

    def testFileDisassemblyStatistics(self):
        """DisassemblyStatistics fields are correct"""
        stats = self.file_disassembly.statistics
        self.assertEqual(stats.num_functions, 2219)
        self.assertEqual(stats.num_recursive_functions, 0)
        self.assertEqual(stats.num_leaf_functions, 2219)
        self.assertEqual(stats.num_basic_blocks, 2219)
        self.assertEqual(stats.num_instructions, 9593)
        self.assertEqual(stats.num_api_calls, 0)
        self.assertEqual(stats.num_function_calls, 0)
        self.assertEqual(stats.num_failed_functions, 0)
        self.assertEqual(stats.num_failed_instructions, 0)

    def testMarshallingRoundTrip(self):
        """toDict() -> fromDict() produces equivalent report"""
        report_dict = self.file_disassembly.toDict()
        # Validate key fields in dict
        self.assertEqual(report_dict["status"], "ok")
        self.assertEqual(report_dict["architecture"], "dalvik")
        self.assertEqual(report_dict["base_addr"], 0)
        self.assertEqual(report_dict["binary_size"], 247668)
        self.assertEqual(report_dict["bitness"], 32)
        self.assertEqual(
            report_dict["sha256"],
            "70f65a5dc2d9eea731effe48acbbfdd2f1a7efe151b647f30e4a124691fcdc30",
        )
        self.assertEqual(report_dict["statistics"]["num_instructions"], 9593)
        self.assertEqual(report_dict["statistics"]["num_functions"], 2219)
        self.assertEqual(len(report_dict["xcfg"]), 2219)
        # Reconstruct from dict
        reconstructed = SmdaReport.fromDict(report_dict)
        self.assertEqual(reconstructed.status, "ok")
        self.assertEqual(reconstructed.architecture, "dalvik")
        self.assertEqual(reconstructed.num_functions, 2219)
        self.assertEqual(reconstructed.num_instructions, 9593)
        self.assertEqual(reconstructed.num_blocks, 2219)
        self.assertEqual(
            reconstructed.sha256,
            "70f65a5dc2d9eea731effe48acbbfdd2f1a7efe151b647f30e4a124691fcdc30",
        )

    def testBufferDisassembly(self):
        """Buffer-based disassembly via disassembleUnmappedBuffer"""
        self.assertEqual(self.buffer_disassembly.status, "ok")
        self.assertEqual(self.buffer_disassembly.architecture, "dalvik")
        self.assertEqual(self.buffer_disassembly.bitness, 32)
        self.assertEqual(self.buffer_disassembly.base_addr, 0)

    def testFunctionProperties(self):
        """Individual function properties are well-formed"""
        functions = list(self.file_disassembly.getFunctions())
        for fn in functions[:10]:
            self.assertIsInstance(fn.offset, int)
            self.assertGreater(fn.offset, 0)
            self.assertGreaterEqual(fn.num_blocks, 1)
            self.assertGreaterEqual(fn.num_instructions, 1)
            self.assertIsInstance(fn.apirefs, dict)
            self.assertIsInstance(fn.blockrefs, dict)
            self.assertIsInstance(fn.inrefs, list)
            self.assertIsInstance(fn.outrefs, dict)

    def testBinarySize(self):
        """binary_size matches the actual DEX file size"""
        self.assertEqual(self.file_disassembly.binary_size, 247668)
        self.assertIsNone(self.file_disassembly.oep)


if __name__ == "__main__":
    unittest.main()
