"""Function boundaries in the MSVC /O2 reproducer for #384, against the linker map."""

import json
import os
import tempfile
import unittest

from smda.Disassembler import Disassembler

CORPUS = os.path.join(os.path.dirname(__file__), "msvc_smda384_corpus")


def _unxor(path):
    with open(path, "rb") as handle:
        return bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))


class MsvcSmda384CorpusTest(unittest.TestCase):
    """Each function of cases.obj is one SMDA function, with no other function starting inside it."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(CORPUS, "manifest.json")) as handle:
            cls.fixtures = json.load(handle)["fixtures"]

    def _report(self, fixture, with_pdb):
        with tempfile.TemporaryDirectory() as workdir:
            dll_path = os.path.join(workdir, "repro.dll")
            with open(dll_path, "wb") as handle:
                handle.write(_unxor(os.path.join(CORPUS, fixture["path"])))
            pdb_path = None
            if with_pdb:
                pdb_path = os.path.join(workdir, "repro.pdb")
                with open(pdb_path, "wb") as handle:
                    handle.write(_unxor(os.path.join(CORPUS, fixture["pdb_path"])))
            report = Disassembler().disassembleFile(dll_path, pdb_path=pdb_path)
        self.assertEqual(report.status, "ok")
        return report

    def _starts(self, fixture, with_pdb):
        return {function.offset for function in self._report(fixture, with_pdb).getFunctions()}

    def testEveryFunctionIsIntact(self):
        for fixture in self.fixtures:
            expected = sorted(fixture["expected_functions"], key=lambda function: function["va"])
            for with_pdb in (False, True):
                starts = self._starts(fixture, with_pdb)
                for index, function in enumerate(expected[:-1]):
                    with self.subTest(fixture=fixture["id"], pdb=with_pdb, function=function["name"]):
                        self.assertIn(function["va"], starts)
                        following = expected[index + 1]["va"]
                        self.assertEqual({start for start in starts if function["va"] < start < following}, set())
                with self.subTest(fixture=fixture["id"], pdb=with_pdb, function=expected[-1]["name"]):
                    self.assertIn(expected[-1]["va"], starts)

    def testArm64GsFailureIsPartOfTheCookieCheckWithoutAPdb(self):
        # a known trade-off: without a PDB, __gsfailure behind __security_check_cookie's
        # `ret` reads as that function's early-return body, which changes its hashes
        fixture = next(fixture for fixture in self.fixtures if fixture["id"] == "msvc/smda384/arm64-O2")
        named = {function.function_name: function.offset for function in self._report(fixture, True).getFunctions()}
        functions = {function.offset: function for function in self._report(fixture, False).getFunctions()}
        self.assertNotIn(named["__gsfailure"], functions)
        cookie_check = functions[named["__security_check_cookie"]]
        self.assertIn(named["__gsfailure"], {instruction.offset for instruction in cookie_check.getInstructions()})


if __name__ == "__main__":
    unittest.main()
