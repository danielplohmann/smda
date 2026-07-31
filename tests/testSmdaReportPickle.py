import json
import os
import pickle
import unittest

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


def _decrypt(name):
    config = SmdaConfig()
    with open(os.path.join(config.PROJECT_ROOT, "tests", name), "rb") as f_binary:
        binary = f_binary.read()
    decrypted = bytearray()
    for index, byte in enumerate(binary):
        decrypted.append(byte ^ (index % 256))
    return bytes(decrypted)


def _canonicalize(report):
    as_dict = report.toDict()
    as_dict.pop("timestamp", None)
    as_dict.pop("execution_time", None)
    return json.dumps(as_dict, sort_keys=True, separators=(",", ":"))


class TestSmdaReportPickle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = Disassembler(SmdaConfig()).disassembleUnmappedBuffer(_decrypt("cutwail_xored"))

    def test_intel_report_is_picklable(self):
        # SmdaReport.capstone and SmdaInstruction.detailed hold capstone objects backed by ctypes
        # pointers, which raised "ctypes objects containing pointers cannot be pickled"
        restored = pickle.loads(pickle.dumps(self.report))
        self.assertEqual(_canonicalize(self.report), _canonicalize(restored))

    def test_report_is_picklable_after_full_traversal(self):
        for function in self.report.getFunctions():
            for instruction in function.getInstructions():
                instruction.getDetailed()
        restored = pickle.loads(pickle.dumps(self.report))
        self.assertEqual(_canonicalize(self.report), _canonicalize(restored))

    def test_lazy_capstone_paths_work_after_unpickling(self):
        restored = pickle.loads(pickle.dumps(self.report))
        self.assertIsNone(restored.capstone)
        self.assertIsNotNone(restored.getCapstone())
        functions = list(restored.getFunctions())
        instruction = list(functions[0].getInstructions())[0]
        self.assertIsNone(instruction.detailed)
        self.assertIsNotNone(instruction.getDetailed())

    def test_object_graph_survives_unpickling(self):
        restored = pickle.loads(pickle.dumps(self.report))
        function = list(restored.getFunctions())[0]
        self.assertIs(function.smda_report, restored)
        self.assertIsNotNone(function._escaper)


if __name__ == "__main__":
    unittest.main()
