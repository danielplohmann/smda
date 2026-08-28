import os
import unittest

import dnfile

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


def _decode(name):
    config = SmdaConfig()
    with open(os.path.join(config.PROJECT_ROOT, "tests", name), "rb") as fixture:
        raw = fixture.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


class CilOffsetsAreFileOffsetsTest(unittest.TestCase):
    """The managed backend addresses a method by where its body sits in the file, where every
    other backend reports a virtual address. Pinned rather than fixed: the offsets are a public
    compatibility surface, so which space they are in is a deliberate decision. What a test can
    do is stop it changing by accident and stop the README describing it wrongly."""

    @classmethod
    def setUpClass(cls):
        cls.binary = _decode("njrat_xored")
        cls.report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(cls.binary)
        cls.recovered = {function.offset for function in cls.report.getFunctions()}

    def testEveryRecoveredMethodIsAtItsBodysFileOffset(self):
        parsed = dnfile.dnPE(data=self.binary)
        declared = set()
        for row in parsed.net.mdtables.MethodDef.rows:
            if row.Rva:
                declared.add(parsed.get_offset_from_rva(row.Rva))
        self.assertTrue(declared)
        self.assertTrue(self.recovered)
        self.assertEqual(self.recovered - declared, set())

    def testNoneOfThemIsTheVirtualAddressOfTheSameMethod(self):
        """The control that makes the assertion above mean something. On this image the two
        spaces are far enough apart that a report in either one satisfies the first test alone
        only if it is in the file's."""
        parsed = dnfile.dnPE(data=self.binary)
        image_base = parsed.OPTIONAL_HEADER.ImageBase
        virtual = {image_base + row.Rva for row in parsed.net.mdtables.MethodDef.rows if row.Rva}
        self.assertTrue(virtual)
        self.assertEqual(self.recovered & virtual, set())

    def testTheReportSaysWhichBackendProducedIt(self):
        """A consumer can only apply the rule if the report identifies itself. Two fields do:
        the architecture, and the language score map."""
        self.assertEqual(self.report.architecture, "cil")
        self.assertIn(".net", self.report.toDict()["metadata"]["language"])


if __name__ == "__main__":
    unittest.main()
