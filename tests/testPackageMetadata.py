"""Guards on packaging metadata that is duplicated by hand.

The version lives in two places and is load-bearing: it is written into every report
as `smda_version`, and report import uses it to decide whether cached pic-hashes and
nesting depths have to be recalculated. A silent disagreement between the two makes
those decisions depend on which one a given code path happened to read.
"""

import logging
import re
import unittest
from pathlib import Path

logging.disable(logging.CRITICAL)

import smda  # noqa: E402
from smda.SmdaConfig import SmdaConfig  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPackageMetadata(unittest.TestCase):
    def test_the_two_version_strings_agree(self):
        self.assertEqual(smda.__version__, SmdaConfig.VERSION)

    def test_the_version_is_a_three_part_release(self):
        self.assertRegex(smda.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_changelog_documents_the_current_version(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = re.findall(r"^ \* \d{4}-\d{2}-\d{2}: v([\d.]+) ", changelog, re.MULTILINE)
        self.assertIn(smda.__version__, versions)
        self.assertEqual(smda.__version__, versions[0])

    def test_config_instances_do_not_share_mutable_defaults(self):
        first, second = SmdaConfig(), SmdaConfig()
        first.API_COLLECTION_FILES["win_7"] = "/nonexistent/apiscout.json"
        self.assertNotIn("win_7", second.API_COLLECTION_FILES)
        self.assertNotIn("win_7", SmdaConfig.API_COLLECTION_FILES)

    def test_library_import_installs_a_null_handler(self):
        handlers = logging.getLogger("smda").handlers
        self.assertTrue(any(isinstance(handler, logging.NullHandler) for handler in handlers))


if __name__ == "__main__":
    unittest.main()
