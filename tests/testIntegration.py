#!/usr/bin/python

import logging
import os
import unittest

from smda.Disassembler import Disassembler
from smda.common.SmdaReport import SmdaReport
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
        cls.asprox_disassembly = disasm.disassembleBuffer(bytes(decrypted), 0x8D0000)

    def testAsproxDisassemblyCoverage(self):
        assert len([fn for fn in self.asprox_disassembly.getFunctions()]) == 105

    def testApiCoverage(self):
        num_api_ref_srcs = 0
        api_ref_dsts = set()
        for fn in self.asprox_disassembly.getFunctions():
            num_api_ref_srcs += len(fn.apirefs)
            api_ref_dsts.update(fn.apirefs.values())
        assert num_api_ref_srcs == 546
        assert len(api_ref_dsts) == 95

    def testMarshalling(self):
        report_as_dict = self.asprox_disassembly.toDict()
        assert report_as_dict["status"] == "ok"
        assert report_as_dict["base_addr"] == 0x8D0000
        assert report_as_dict["statistics"]["num_instructions"] == 15706
        assert report_as_dict["sha256"] == "db8a133fed1b706608a4492079b702ded6b70369a980d2b5ae355a6adc78ef00"
        reimported_report = SmdaReport.fromDict(report_as_dict)


if __name__ == '__main__':
    unittest.main()
