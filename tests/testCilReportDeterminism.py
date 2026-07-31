import hashlib
import json
import os
import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


def _canonicalize(report):
    as_dict = report.toDict()
    as_dict.pop("timestamp", None)
    as_dict.pop("execution_time", None)
    return json.dumps(as_dict, sort_keys=True, separators=(",", ":"))


class TestCilReportDeterminism(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = SmdaConfig()
        fixture_path = os.path.join(config.PROJECT_ROOT, "tests", "njrat_xored")
        with open(fixture_path, "rb") as f_binary:
            binary = f_binary.read()
        decrypted = bytearray()
        for index, byte in enumerate(binary):
            decrypted.append(byte ^ (index % 256))
        cls.njrat_binary = bytes(decrypted)
        cls.blobs = []
        for _ in range(2):
            report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(cls.njrat_binary)
            cls.blobs.append(_canonicalize(report))

    def test_repeated_disassembly_yields_identical_reports(self):
        # unhandled dnfile row types fell through to str(operand), serializing the default object
        # repr - including a memory address - so every run produced a different report
        first, second = (hashlib.sha256(blob.encode()).hexdigest() for blob in self.blobs)
        self.assertEqual(first, second)

    def test_no_object_repr_leaks_into_operands(self):
        for blob in self.blobs:
            self.assertNotIn("object at 0x", blob)

    def test_typespec_and_typedef_operands_are_named(self):
        report = Disassembler(SmdaConfig(), backend="cil").disassembleUnmappedBuffer(self.njrat_binary)
        operands = [ins.operands for fn in report.getFunctions() for ins in fn.getInstructions()]
        self.assertTrue(any(op.startswith("TypeSpec(") for op in operands))
        self.assertFalse(any("dnfile.mdtable" in op for op in operands))


if __name__ == "__main__":
    unittest.main()
