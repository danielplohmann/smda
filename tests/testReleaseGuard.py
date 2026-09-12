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

## [4.7.0rc1] - 2026-09-15

### Added

- the candidate. (#2)

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
        self.assertNotIn("the candidate", notes)
        self.assertNotIn("an older release", notes)
        self.assertNotIn("Older releases", notes)

    def testAHeadingWithOrWithoutTheVPrefixIsASection(self):
        self.assertIn("the candidate", guard.changelogSection(CHANGELOG, "4.7.0rc1"))
        self.assertIn("an older release", guard.changelogSection(CHANGELOG, "4.6.0"))

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
    def testTheVersionIsReadFromTheRealTree(self):
        versions = guard.declaredVersions(_ROOT)
        self.assertEqual(set(versions), {"smda.__version__"})
        self.assertRegex(versions["smda.__version__"], r"^\d+\.\d+\.\d+")


class MainTest(unittest.TestCase):
    """The gate as the workflow calls it."""

    def _tree(self, version, changelog):
        root = Path(tempfile.mkdtemp())
        package = root / "src" / "smda"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        return root

    def testAMatchingTagPassesAndWritesTheNotesAndOutputs(self):
        root = self._tree("4.7.0", CHANGELOG)
        notes = root / "notes.md"
        output = root / "output.txt"
        argv = ["--tag", "v4.7.0", "--root", str(root), "--notes", str(notes), "--github-output", str(output)]
        self.assertEqual(guard.main(argv), 0)
        self.assertIn("the thing this release did", notes.read_text(encoding="utf-8"))
        self.assertEqual(output.read_text(encoding="utf-8"), "version=4.7.0\nprerelease=false\n")

    def testAPreReleaseTagIsFlagged(self):
        root = self._tree("4.7.0rc1", CHANGELOG)
        output = root / "output.txt"
        self.assertEqual(guard.main(["--tag", "v4.7.0rc1", "--root", str(root), "--github-output", str(output)]), 0)
        self.assertIn("prerelease=true", output.read_text(encoding="utf-8"))

    def testATagThatDisagreesWithThePackagedVersionFails(self):
        # nothing else in the release notices that the tag names a different version
        root = self._tree("4.6.0", CHANGELOG)
        with self.assertRaises(SystemExit) as raised:
            guard.main(["--tag", "v4.7.0", "--root", str(root)])
        self.assertIn("4.6.0", str(raised.exception))

    def testAMalformedTagFails(self):
        root = self._tree("4.7.0", CHANGELOG)
        for tag in ("4.7.0", "v4.7", "v4.7.0-rc1", "v4.7.0.dev1", "vlatest"):
            with self.subTest(tag=tag), self.assertRaises(SystemExit):
                guard.main(["--tag", tag, "--root", str(root)])


if __name__ == "__main__":
    unittest.main()
