#!/usr/bin/python

import logging
import os
import unittest

from smda.Disassembler import Disassembler
from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class SmdaIntegrationTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    @classmethod
    def setUpClass(cls):
        super(SmdaIntegrationTestSuite, cls).setUpClass()
        disasm = Disassembler(config)
        with open(os.path.join(config.PROJECT_ROOT, "tests", "asprox_0x008D0000_xored"), "rb") as f_binary:
            binary = f_binary.read()
        decrypted = bytearray()
        for index, byte in enumerate(binary):
            if isinstance(byte, str):
                byte = ord(byte)
            decrypted.append(byte ^ (index % 256))
        cls.asprox_disassembly = disasm.disassemble(bytes(decrypted), 0x8D0000)

    def testAsproxDisassemblyCoverage(self):
        assert len(self.asprox_disassembly.functions.keys()) == 105

    def testApiCoverage(self):
        assert len(self.asprox_disassembly.apis.keys()) == 95

    def testReport(self):
        disasm = Disassembler(config)
        report = disasm.getDisassemblyReport(self.asprox_disassembly)
        assert report["status"] == "ok"
        assert report["base_addr"] == 0x8D0000
        assert report["summary"]["num_instructions"] == 15706
        assert report["sha256"] == "db8a133fed1b706608a4492079b702ded6b70369a980d2b5ae355a6adc78ef00"


if __name__ == '__main__':
    unittest.main()
