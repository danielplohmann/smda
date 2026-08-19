#!/usr/bin/python
"""DEX string references have to survive WITH_STRINGS being enabled.

Dalvik string references are recovered from the parsed DEX structure rather than
from buffer bytes, so they are populated whether or not WITH_STRINGS is set. That
made enabling the option - whose entire purpose is more string data - the one way
to lose all of it.
"""

import unittest
from pathlib import Path

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

DEX_FIXTURE = Path(__file__).resolve().parent / "blockblast_classes_xored"


def _load_dex():
    raw = DEX_FIXTURE.read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def _disassemble(with_strings):
    config = SmdaConfig()
    config.WITH_STRINGS = with_strings
    return Disassembler(config).disassembleUnmappedBuffer(_load_dex())


class DalvikStringRefsWithStringsTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.without = _disassemble(False)
        cls.with_strings = _disassemble(True)

    def _refs(self, report):
        return {function.offset: function.stringrefs for function in report.getFunctions() if function.stringrefs}

    def testStringRefsSurviveWithStringsEnabled(self):
        without = self._refs(self.without)
        self.assertGreater(len(without), 2000)
        self.assertEqual(self._refs(self.with_strings), without)

    def testEnablingWithStringsNeverReducesTheReferenceCount(self):
        def total(report):
            return sum(len(function.stringrefs) for function in report.getFunctions())

        self.assertGreater(total(self.without), 2000)
        self.assertGreaterEqual(total(self.with_strings), total(self.without))

    def testReferencesKeepTheirNormalizedShapeUnderWithStrings(self):
        function = next(f for f in self.with_strings.getFunctions() if f.stringrefs)
        self.assertIsInstance(function.stringrefs, list)
        entry = function.stringrefs[0]
        self.assertEqual(set(entry), {"string", "ins_addr", "data_addr", "type"})
        self.assertEqual(entry["type"], "dex")


if __name__ == "__main__":
    unittest.main()
