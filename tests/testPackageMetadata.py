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


def _version_tuple(version):
    return tuple(int(part) for part in version.split("."))


class TestPackageMetadata(unittest.TestCase):
    def test_the_two_version_strings_agree(self):
        self.assertEqual(smda.__version__, SmdaConfig.VERSION)

    def test_the_version_is_a_three_part_release(self):
        self.assertRegex(smda.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_escaper_compatibility_marker_is_a_three_part_release(self):
        self.assertRegex(SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY, r"^\d+\.\d+\.\d+$")

    def test_the_escaper_compatibility_marker_is_not_newer_than_the_package(self):
        self.assertLessEqual(
            _version_tuple(SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY),
            _version_tuple(SmdaConfig.VERSION),
        )

    def test_the_escaper_compatibility_marker_covers_the_4_4_5_output_change(self):
        # 4.4.5 changed Intel escaped operands (segment-qualified memory, AVX-512)
        # and six mnemonic groups. MCRIT selects samples whose recorded
        # smda_version is strictly below this marker, so the marker must be at
        # least 4.4.5 or those reports stay invisible to the repair path.
        marker = _version_tuple(SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY)
        self.assertLessEqual(_version_tuple("4.4.5"), marker)
        self.assertLess(_version_tuple("4.4.4"), marker)
        # The previous marker, 1.13.16, compared less than every 2.x/4.x report
        # and so selected nothing after 1.13.16 — including the 4.4.4 reports
        # whose escaped output 4.4.5 invalidated.
        self.assertFalse(_version_tuple("4.4.4") < _version_tuple("1.13.16"))

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


class TestStructEndianness(unittest.TestCase):
    """Every binary field SMDA decodes belongs to a little-endian format.

    A native-endian format string decodes correctly on x86 hosts and silently wrongly
    everywhere else, so it cannot be caught by running the suite. Assert the convention
    on the source instead.
    """

    IMPLICIT_FORMAT = re.compile(r"struct\.(?:pack|unpack|unpack_from|pack_into)\(\s*[\"']([^<>!=@\"'])")

    def test_no_struct_call_uses_an_implicit_byte_order(self):
        offenders = []
        for path in sorted((REPO_ROOT / "src" / "smda").rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if self.IMPLICIT_FORMAT.search(line):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")

        self.assertEqual(offenders, [], "struct format strings must start with '<'")


if __name__ == "__main__":
    unittest.main()
