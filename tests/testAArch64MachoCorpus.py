#!/usr/bin/python
"""AArch64 Mach-O corpus fixtures for loader and disassembly regression tests.

Fixtures are committed only in the repository's XOR-obfuscated test-fixture
format. Tests de-XOR bytes in memory, never write raw samples, and exercise the
Mach-O loader plus the AArch64 disassembly path.
"""

import hashlib
import json
import logging
import unittest
from pathlib import Path

from smda.aarch64.definitions import BTI_PROLOGUES, INSTRUCTION_SIZE, PAC_PROLOGUES
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader

logging.disable(logging.CRITICAL)

CORPUS_DIR = Path(__file__).resolve().parent / "aarch64_macho_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
MAX_XORED_FIXTURE_BYTES = 10 * 1024 * 1024
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
THIN_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}


def _xor_fixture(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _count_code_words(loader, expected_words):
    mapped = loader.getData()
    base_addr = loader.getBaseAddress()
    count = 0
    for start, end in loader.getCodeAreas():
        start_offset = max(0, start - base_addr)
        end_offset = min(len(mapped), end - base_addr)
        for offset in range(start_offset, max(start_offset, end_offset - INSTRUCTION_SIZE + 1), INSTRUCTION_SIZE):
            word = int.from_bytes(mapped[offset : offset + INSTRUCTION_SIZE], "little")
            if word in expected_words:
                count += 1
    return count


def _stringref_count(report):
    return sum(len(function.stringrefs or []) for function in report.getFunctions())


def _dataref_count(report):
    return sum(len(targets) for targets in (report.data_refs_from or {}).values())


def _fixtures_for_source(fixtures, source_id):
    return [fixture for fixture in fixtures if fixture["source"] == source_id]


class TestAArch64MachoCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text())
        cls.fixtures = cls.manifest["fixtures"]
        cls.sources = cls.manifest["sources"]
        cls._cases = {}

    @classmethod
    def _get_case(cls, fixture):
        fixture_id = fixture["id"]
        if fixture_id not in cls._cases:
            fixture_path = CORPUS_DIR / fixture["path"]
            xored = fixture_path.read_bytes()
            raw = _xor_fixture(xored)
            loader = MemoryFileLoader(raw, map_file=True)

            config = SmdaConfig()
            config.TIMEOUT = 20
            config.WITH_STRINGS = True
            config.STORE_BUFFER = False
            report = Disassembler(config).disassembleUnmappedBuffer(raw)

            cls._cases[fixture_id] = {
                "path": fixture_path,
                "xored": xored,
                "raw": raw,
                "loader": loader,
                "report": report,
            }
        return cls._cases[fixture_id]

    def test_manifest_schema(self):
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(self.manifest["xor_scheme"], "byte ^ (index % 256)")
        self.assertEqual(set(self.sources), {"objective-see", "malpedia"})
        self.assertEqual(len(self.fixtures), 12)
        self.assertLessEqual(sum(fixture["size"] for fixture in self.fixtures), MAX_XORED_FIXTURE_BYTES)
        for fixture in self.fixtures:
            with self.subTest(fixture=fixture["id"]):
                self.assertIn(fixture["source"], self.sources)
                self.assertTrue((CORPUS_DIR / fixture["path"]).exists())
                self.assertEqual(fixture["architecture"], "aarch64")
                self.assertEqual(fixture["bitness"], 64)
                self.assertGreaterEqual(fixture["expected_min_functions"], 1)

    def test_source_provenance(self):
        objective_see = _fixtures_for_source(self.fixtures, "objective-see")
        malpedia = _fixtures_for_source(self.fixtures, "malpedia")

        self.assertEqual(self.sources["objective-see"]["label"], "Objective-See/Malware")
        self.assertEqual(self.sources["malpedia"]["label"], "Malpedia")
        self.assertEqual(len(objective_see), 6)
        self.assertEqual(len(malpedia), 6)
        self.assertEqual(len({fixture["provenance"]["zip_name"] for fixture in objective_see}), len(objective_see))
        self.assertEqual(len({fixture["provenance"]["family"] for fixture in malpedia}), len(malpedia))

        for fixture in malpedia:
            with self.subTest(fixture=fixture["id"]):
                self.assertTrue(fixture["provenance"]["inner_path"].endswith("_unpacked"))

    def test_fixtures_are_xored_and_hash_to_manifest(self):
        for fixture in self.fixtures:
            with self.subTest(source=fixture["source"], fixture=fixture["id"]):
                case = self._get_case(fixture)
                self.assertNotIn(case["xored"][:4], MACHO_MAGICS)
                self.assertEqual(hashlib.sha256(case["xored"]).hexdigest(), fixture["xor_sha256"])
                self.assertEqual(len(case["raw"]), fixture["size"])
                self.assertIn(case["raw"][:4], THIN_MACHO_MAGICS)
                self.assertEqual(hashlib.sha256(case["raw"]).hexdigest(), fixture["raw_sha256"])

    def test_macho_loader_reports_aarch64_metadata(self):
        for fixture in self.fixtures:
            with self.subTest(source=fixture["source"], fixture=fixture["id"]):
                case = self._get_case(fixture)
                parsed = MachoFileLoader.parseBinary(case["raw"])
                self.assertTrue(MachoFileLoader.isCompatible(case["raw"]))
                self.assertEqual(MachoFileLoader.getArchitecture(case["raw"], parsed=parsed), "aarch64")
                self.assertEqual(MachoFileLoader.getBitness(case["raw"], parsed=parsed), 64)
                self.assertTrue(MachoFileLoader.getCodeAreas(case["raw"], parsed=parsed))
                self.assertEqual(case["loader"].getArchitecture(), "aarch64")
                self.assertEqual(case["loader"].getBitness(), 64)
                self.assertTrue(case["loader"].getCodeAreas())

    def test_selected_fixtures_disassemble(self):
        for fixture in self.fixtures:
            with self.subTest(source=fixture["source"], fixture=fixture["id"]):
                report = self._get_case(fixture)["report"]
                self.assertEqual(report.status, "ok")
                self.assertEqual(report.architecture, "aarch64")
                self.assertEqual(report.bitness, 64)
                self.assertGreaterEqual(report.num_functions, fixture["expected_min_functions"])
                self.assertTrue(report.code_areas)

    def test_reports_roundtrip(self):
        for fixture in self.fixtures:
            with self.subTest(source=fixture["source"], fixture=fixture["id"]):
                report = self._get_case(fixture)["report"]
                roundtrip = SmdaReport.fromDict(report.toDict())
                self.assertEqual(roundtrip.status, "ok")
                self.assertEqual(roundtrip.architecture, "aarch64")
                self.assertEqual(roundtrip.bitness, 64)
                self.assertEqual(roundtrip.num_functions, report.num_functions)

    def test_feature_tagged_expectations(self):
        for fixture in self.fixtures:
            stats = fixture["stats"]
            with self.subTest(source=fixture["source"], fixture=fixture["id"], tags=fixture["feature_tags"]):
                case = self._get_case(fixture)
                report = case["report"]
                if "stringrefs" in fixture["feature_tags"]:
                    self.assertGreater(_stringref_count(report), 0)
                if "datarefs" in fixture["feature_tags"]:
                    self.assertGreater(_dataref_count(report), 0)
                if "pac" in fixture["feature_tags"] or stats["pac_count"]:
                    self.assertGreater(_count_code_words(case["loader"], PAC_PROLOGUES), 0)
                if "bti" in fixture["feature_tags"] or stats["bti_count"]:
                    self.assertGreater(_count_code_words(case["loader"], BTI_PROLOGUES), 0)


if __name__ == "__main__":
    unittest.main()
