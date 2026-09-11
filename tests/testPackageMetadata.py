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

    def _documentedVersions(self):
        """Every release the changelog documents, newest first.

        Releases cut from keep-a-changelog onward head their section `## [vX.Y.Z] - date`;
        the ones before it keep the one-line ` * date: vX.Y.Z - ` shape under Older releases.
        Both are read, so this keeps working across the release that introduces the first of
        the new form rather than failing on it.
        """
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        headings = re.findall(r"^## \[v([\d.]+)\] - \d{4}-\d{2}-\d{2}", changelog, re.MULTILINE)
        legacy = re.findall(r"^ \* \d{4}-\d{2}-\d{2}: v([\d.]+)\s*-", changelog, re.MULTILINE)
        return headings + legacy

    def test_the_changelog_documents_the_current_version(self):
        documented = self._documentedVersions()
        self.assertIn(smda.__version__, documented)
        self.assertEqual(smda.__version__, documented[0])

    def test_the_changelog_is_ordered_newest_version_first(self):
        """Entries are ordered by version, which is a rule a reader cannot enforce by eye.

        Date order and version order disagree legitimately -- a patch on an older line can be
        released after a newer minor -- so an entry filed in the wrong place looks exactly like
        one of those. The v1.9.16-v1.9.11 block had been appended below v1.0.0 instead of filed
        above v1.9.9 and went unnoticed across 186 entries.
        """
        documented = self._documentedVersions()
        out_of_order = [
            (earlier, later)
            for earlier, later in zip(documented, documented[1:], strict=False)
            if _version_tuple(earlier) < _version_tuple(later)
        ]
        self.assertEqual(out_of_order, [], "a later entry names a higher version than the one above it")

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
