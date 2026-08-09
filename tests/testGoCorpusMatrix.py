import collections
import json
import os
import unittest

import pytest

pytestmark = pytest.mark.slow

MATRIX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "go_corpus", "matrix.json")
SCHEMA_VERSION = 1
# what the recorded run achieved; go tool nm and the pclntab agree on every cell but a
# handful of compiler-generated wrappers, so this is a real floor and not a token one
MIN_RECALL = 0.99
# a cgo build links in C functions that clang compiled; go tool nm reports them but the
# pclntab only ever describes Go functions, so they are a fixed floor rather than a miss
MIN_CGO_RECALL = 0.98


def _load():
    with open(MATRIX_PATH) as handle:
        return json.load(handle)


def _isChainedFixupPointerTable(cell):
    """A 1.12/1.16 table in an externally linked Mach-O, whose entries are packed fixups.

    Apple's linker writes pointer-wide fields as dyld chained-fixup entries rather than plain
    addresses, so the pointer-wide entry a pre-1.18 functab stores is not an address at all.
    Go's own linker does not do this, which is why only the cgo cells are affected. Resolving
    those needs the Mach-O rebase map, not a change to the pclntab parser.
    """
    return cell["mode"] == "cgo" and cell["goos"] == "darwin" and cell.get("pclntab_version") in ("1.12", "1.16")


class GoCorpusMatrixTestSuite(unittest.TestCase):
    """The committed record of what SMDA recovered from real Go toolchain output.

    tests/go_corpus/build_matrix.py regenerates it; these assertions are what a
    regression in the pclntab parser would have to get past in review.
    """

    @classmethod
    def setUpClass(cls):
        cls.matrix = _load()
        cls.cells = cls.matrix["cells"]

    def test_the_matrix_matches_the_schema_the_harness_writes(self):
        self.assertEqual(self.matrix["schema_version"], SCHEMA_VERSION)
        self.assertIn("reference", self.matrix)
        for cell in self.cells:
            with self.subTest(cell=cell.get("go_version")):
                self.assertIn("status", cell)
                self.assertIn("go_version", cell)

    def test_every_measured_cell_recovers_what_go_reports(self):
        measured = [cell for cell in self.cells if "recall" in cell]
        self.assertGreater(len(measured), 200)
        for cell in measured:
            with self.subTest(
                version=cell["go_version"], platform=f"{cell['goos']}/{cell['goarch']}", mode=cell["mode"]
            ):
                if _isChainedFixupPointerTable(cell):
                    continue
                self.assertGreaterEqual(cell["recall"], MIN_CGO_RECALL if cell["mode"] == "cgo" else MIN_RECALL)
                self.assertEqual(cell["reference"], "go tool nm")

    def test_the_only_cells_below_threshold_are_the_known_chained_fixup_case(self):
        """Nothing may fall short except the one limitation the README documents."""
        short = [
            cell
            for cell in self.cells
            if "recall" in cell
            and cell["recall"] < (MIN_CGO_RECALL if cell["mode"] == "cgo" else MIN_RECALL)
            and not _isChainedFixupPointerTable(cell)
        ]

        self.assertEqual(short, [])

    def test_an_externally_linked_build_resolves_against_the_container_text_start(self):
        # cgo forces external linking, where the header's text start reads 0 and every
        # recovered address would otherwise be short by the real text base
        cgo = [cell for cell in self.cells if cell["mode"] == "cgo" and cell["status"] == "parsed"]

        self.assertTrue(cgo)
        for cell in cgo:
            with self.subTest(version=cell["go_version"], platform=f"{cell['goos']}/{cell['goarch']}"):
                self.assertTrue(cell["text_start"])

    def test_every_pclntab_layout_the_parser_knows_was_exercised(self):
        seen = {cell["pclntab_version"] for cell in self.cells if cell.get("pclntab_version")}

        self.assertEqual(seen, {"1.12", "1.16", "1.18", "1.20"})

    def test_both_byte_orders_and_both_pointer_sizes_were_exercised(self):
        parsed = [cell for cell in self.cells if cell["status"] == "parsed"]
        # s390x is the big-endian target; 386 is the 32-bit one
        self.assertTrue(any(cell["goarch"] == "s390x" for cell in parsed))
        self.assertTrue(any(cell.get("pclntab_bitness") == 32 for cell in parsed))
        self.assertTrue(any(cell.get("pclntab_bitness") == 64 for cell in parsed))

    def test_every_container_format_and_link_mode_was_exercised(self):
        parsed = [cell for cell in self.cells if cell["status"] == "parsed"]
        by_os = collections.Counter(cell["goos"] for cell in parsed)
        by_mode = collections.Counter(cell["mode"] for cell in parsed)

        self.assertEqual(set(by_os), {"linux", "windows", "darwin"})
        self.assertEqual(set(by_mode), {"default", "stripped", "pie", "cgo", "distribution"})

    def test_a_stripped_build_still_finds_its_table(self):
        stripped = [cell for cell in self.cells if cell["mode"] == "stripped"]

        self.assertTrue(stripped)
        for cell in stripped:
            with self.subTest(version=cell["go_version"], platform=f"{cell['goos']}/{cell['goarch']}"):
                self.assertEqual(cell["status"], "parsed")

    def test_no_cell_failed_to_parse_a_table_it_located(self):
        broken = [cell for cell in self.cells if cell["status"] in ("parse_error", "offset_error", "no_pclntab_found")]

        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
