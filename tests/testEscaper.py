#!/usr/bin/python

import logging
import os
import unittest

from smda.common.SmdaReport import SmdaReport
from smda.common.SmdaInstruction import SmdaInstruction
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class DisassemblyTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testInstructionEscaping(self):
        test_data = [
            {"ins": (0, "55", "push", "ebp"), "mnemonic_group": "S", "escaped_operands": "REG"},
            {"ins": (1, "8365fc00", "and", "dword ptr [ebp - 4], 0"), "mnemonic_group": "A", "escaped_operands": "PTR, CONST"},
        ]
        for data in test_data:
            smda_ins = SmdaInstruction(data["ins"])
            self.assertEqual(smda_ins.getMnemonicGroup(IntelInstructionEscaper), data["mnemonic_group"])
            self.assertEqual(smda_ins.getEscapedOperands(IntelInstructionEscaper), data["escaped_operands"])


if __name__ == '__main__':
    unittest.main()
