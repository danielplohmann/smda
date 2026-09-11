#!/usr/bin/python
"""Tests for the release gate (`.github/workflows/scripts/release_guard.py`).

Its checks run once per release, minutes before the artifact becomes permanent, so here is the
only place they can be exercised before they matter.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_ROOT = _TESTS.parent
_SCRIPT = _ROOT / ".github" / "workflows" / "scripts" / "release_guard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("release_guard", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_module()

CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- **(intel)** something not yet released. (#1)

## [v4.7.0] - 2026-09-20

### Changed

- **(common)** the thing this release did. (#2)

### Compatibility

- recovery output moves. (#2)

## [v4.6.0] - 2026-09-10

### Fixed

- an older release. (#3)

## Older releases

 * 2026-09-10: v4.6.0 - the one-line shape.
"""


class ChangelogSectionTest(unittest.TestCase):
    def testTheSectionForAVersionIsReturned(self):
        notes = guard.changelogSection(CHANGELOG, "4.7.0")
        self.assertIn("the thing this release did", notes)
        self.assertIn("### Compatibility", notes)

    def testTheSectionStopsAtTheNextRelease(self):
        # without the stop it would swallow every older entry and the whole Older releases block
        notes = guard.changelogSection(CHANGELOG, "4.7.0")
        self.assertNotIn("an older release", notes)
        self.assertNotIn("Older releases", notes)

    def testAnUnreleasedSectionIsNotAVersion(self):
        # `## [Unreleased]` carries no date, so it cannot be mistaken for the release being cut
        self.assertNotIn("not yet released", guard.changelogSection(CHANGELOG, "4.7.0"))
        with self.assertRaises(SystemExit):
            guard.changelogSection(CHANGELOG, "Unreleased")

    def testAMissingSectionFailsAndSaysWhatToDo(self):
        with self.assertRaises(SystemExit) as raised:
            guard.changelogSection(CHANGELOG, "4.8.0")
        self.assertIn("Unreleased", str(raised.exception))

    def testAHeadingWithNothingUnderItFails(self):
        # renaming Unreleased without writing anything into it is the shape this catches
        empty = "# Changelog\n\n## [v9.0.0] - 2026-01-01\n\n## Older releases\n"
        with self.assertRaises(SystemExit):
            guard.changelogSection(empty, "9.0.0")

    def testAnUndatedHeadingIsNotASection(self):
        undated = "# Changelog\n\n## [v9.0.0]\n\n- something. (#1)\n"
        with self.assertRaises(SystemExit):
            guard.changelogSection(undated, "9.0.0")


class DeclaredVersionTest(unittest.TestCase):
    def testBothVersionsAreReadFromTheRealTree(self):
        versions = guard.declaredVersions(_ROOT)
        self.assertEqual(set(versions), {"smda.__version__", "SmdaConfig.VERSION"})
        self.assertTrue(all(value for value in versions.values()))

    def testTheTwoAgreeInThisTree(self):
        versions = guard.declaredVersions(_ROOT)
        self.assertEqual(versions["smda.__version__"], versions["SmdaConfig.VERSION"])


class MainTest(unittest.TestCase):
    """The gate as the workflow calls it."""

    def _tree(self, version, changelog):
        root = Path(tempfile.mkdtemp())
        package = root / "src" / "smda"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
        (package / "SmdaConfig.py").write_text(f'class SmdaConfig:\n    VERSION = "{version}"\n', encoding="utf-8")
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        return root

    def testAMatchingTagPassesAndWritesTheNotes(self):
        root = self._tree("4.7.0", CHANGELOG)
        notes = root / "notes.md"
        self.assertEqual(guard.main(["--tag", "v4.7.0", "--root", str(root), "--notes", str(notes)]), 0)
        self.assertIn("the thing this release did", notes.read_text(encoding="utf-8"))

    def testATagThatDisagreesWithThePackagedVersionFails(self):
        # nothing else in the release notices that the tag names a different version
        root = self._tree("4.6.0", CHANGELOG)
        with self.assertRaises(SystemExit) as raised:
            guard.main(["--tag", "v4.7.0", "--root", str(root)])
        self.assertIn("4.6.0", str(raised.exception))

    def testATagWithoutTheVPrefixFails(self):
        root = self._tree("4.7.0", CHANGELOG)
        with self.assertRaises(SystemExit):
            guard.main(["--tag", "4.7.0", "--root", str(root)])

    def testOneVersionStringLaggingFails(self):
        # the three-place bump with one place missed
        root = self._tree("4.7.0", CHANGELOG)
        (root / "src" / "smda" / "SmdaConfig.py").write_text(
            'class SmdaConfig:\n    VERSION = "4.6.0"\n', encoding="utf-8"
        )
        with self.assertRaises(SystemExit) as raised:
            guard.main(["--tag", "v4.7.0", "--root", str(root)])
        self.assertIn("SmdaConfig.VERSION = 4.6.0", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
