"""Checks that decide whether a tag may be released, and the notes that go with it.

A script rather than inline workflow steps so the parsing has tests: the changelog format it
reads is a convention, and a release is the one action here that cannot be undone.
"""

import argparse
import re
import sys
from pathlib import Path

#: `## [v4.7.0] - 2026-09-20`, the heading a release section opens with.
SECTION = re.compile(r"^## \[v(?P<version>[\d.]+)\] - (?P<date>\d{4}-\d{2}-\d{2})\s*$")
#: any second-level heading, which is where a section ends
NEXT_HEADING = re.compile(r"^## ")


def declaredVersions(root: Path) -> dict:
    """The version as each of the two places that carry it states it."""
    found = {}
    for label, path, pattern in (
        ("smda.__version__", root / "src" / "smda" / "__init__.py", r'^__version__ = "([\d.]+)"'),
        ("SmdaConfig.VERSION", root / "src" / "smda" / "SmdaConfig.py", r'^\s+VERSION = "([\d.]+)"'),
    ):
        match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
        if match is None:
            raise SystemExit(f"could not read a version from {path}")
        found[label] = match.group(1)
    return found


def changelogSection(changelog: str, version: str) -> str:
    """The release notes for `version`, or a failure naming what is missing."""
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        match = SECTION.match(line)
        if match is None or match.group("version") != version:
            continue
        body = []
        for following in lines[index + 1 :]:
            if NEXT_HEADING.match(following):
                break
            body.append(following)
        text = "\n".join(body).strip()
        if not text:
            raise SystemExit(f"CHANGELOG.md has a heading for v{version} but nothing under it")
        return text
    raise SystemExit(
        f"CHANGELOG.md has no `## [v{version}] - <date>` section. "
        "Rename `## [Unreleased]` to the release being cut before tagging."
    )


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="the tag being released, e.g. v4.7.0")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--notes", help="write the release notes to this file")
    args = parser.parse_args(argv)

    if not args.tag.startswith("v"):
        raise SystemExit(f"tag {args.tag!r} does not start with 'v'")
    version = args.tag[1:]

    versions = declaredVersions(Path(args.root))
    disagreeing = {label: value for label, value in versions.items() if value != version}
    if disagreeing:
        stated = ", ".join(f"{label} = {value}" for label, value in versions.items())
        raise SystemExit(f"tag {args.tag} does not match the packaged version ({stated})")

    notes = changelogSection((Path(args.root) / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    if args.notes:
        Path(args.notes).write_text(notes + "\n", encoding="utf-8")
    print(f"{args.tag} matches {versions['smda.__version__']} and has a changelog section")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
