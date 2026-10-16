import copy
import json
import os
import pickle
import unittest

from smda.common.SmdaBasicBlock import _UNSET, SmdaBasicBlock
from smda.common.SmdaInstruction import SmdaInstruction
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

    def _copyWithUnhashedBlocks(self):
        report = pickle.loads(pickle.dumps(self.report))
        for function in report.getFunctions():
            function.getBlocks()
        return report

    @staticmethod
    def _blockHashes(report):
        return {
            (function.offset, block.offset): (block.getPicBlockHash(), block.getOpcBlockHash())
            for function in report.getFunctions()
            for block in function.getBlocks()
        }

    def test_uncomputed_block_hashes_survive_pickle_and_deepcopy(self):
        # the "not computed yet" sentinel used to come back as a bare object(), which
        # getPicBlockHash() and getOpcBlockHash() then returned as the hash
        expected = self._blockHashes(self._copyWithUnhashedBlocks())
        report = self._copyWithUnhashedBlocks()
        copies = [pickle.loads(pickle.dumps(report, protocol)) for protocol in (0, 2, pickle.HIGHEST_PROTOCOL)]
        copies.append(copy.deepcopy(report))
        for restored in copies:
            self.assertEqual(expected, self._blockHashes(restored))

    def test_state_pickled_before_slots_still_loads(self):
        # such a state holds only the attributes set on the instance, and a block's uncomputed
        # hashes as copies of the sentinel
        instruction = SmdaInstruction.__new__(SmdaInstruction)
        instruction.__setstate__(
            {"smda_function": None, "offset": 0x1000, "bytes": "c3", "mnemonic": "ret", "operands": ""}
        )
        self.assertIsNone(instruction.detailed)
        self.assertIsNone(instruction._data_refs)
        block = SmdaBasicBlock.__new__(SmdaBasicBlock)
        block.__setstate__(
            {
                "smda_function": None,
                "instructions": [instruction],
                "offset": 0x1000,
                "length": 1,
                "_picblockhash": object(),
                "_opcblockhash": object(),
            }
        )
        self.assertIs(block._picblockhash, _UNSET)
        self.assertIs(block._opcblockhash, _UNSET)


if __name__ == "__main__":
    unittest.main()
