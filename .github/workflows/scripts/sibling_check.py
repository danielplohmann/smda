#!/usr/bin/env python3
"""Sibling-pair detection for SMDA CI.

When a PR modifies one file in a known sibling group (e.g. PeFileLoader but not
ElfFileLoader or MachoFileLoader), warn that the sibling may need the same change.

The five real sibling-pair bugs this aims to catch:
  1. Negative-index guard present in _map_segments but absent in _map_sections (ELF)
  2. Same guard absent in Mach-O section mapping
  3. Base-address filter present in ELF _calculate_base_address but absent in Mach-O
  4. Content-mismatch degrade handled in ELF but raised in Mach-O
  5. Import metadata parity across PE and ELF label providers

False positives are expected and acceptable (this only warns, does not fail).
The maintainer reviews the warning and dismisses it when the change is intentional.
"""

import os
import subprocess
import sys

# Sibling groups: files that should typically be changed together.
# Group name -> list of relative paths (from repo root).
SIBLING_GROUPS = {
    "loaders": [
        "src/smda/utility/PeFileLoader.py",
        "src/smda/utility/ElfFileLoader.py",
        "src/smda/utility/MachoFileLoader.py",
        "src/smda/utility/DexFileLoader.py",
    ],
    "escapers": [
        "src/smda/intel/IntelInstructionEscaper.py",
        "src/smda/aarch64/AArch64InstructionEscaper.py",
        "src/smda/cil/CilInstructionEscaper.py",
        "src/smda/dalvik/DalvikInstructionEscaper.py",
    ],
    "label_providers": [
        "src/smda/common/labelprovider/PeSymbolProvider.py",
        "src/smda/common/labelprovider/ElfSymbolProvider.py",
        "src/smda/common/labelprovider/MachoSymbolProvider.py",
    ],
    "backends": [
        "src/smda/intel/X86Backend.py",
        "src/smda/aarch64/AArch64Backend.py",
    ],
    "function_candidate_managers": [
        "src/smda/intel/FunctionCandidateManager.py",
        "src/smda/aarch64/FunctionCandidateManager.py",
    ],
    "synthesizers": [
        "src/smda/synthesis/PeSynthesizer.py",
        "src/smda/synthesis/ElfSynthesizer.py",
        "src/smda/synthesis/MachoSynthesizer.py",
    ],
    "binary_info_loaders": [
        "src/smda/utility/PeFileLoader.py",
        "src/smda/utility/ElfFileLoader.py",
        "src/smda/utility/MachoFileLoader.py",
    ],
}


def get_modified_files(repo_root="."):
    """Return a set of modified file paths (relative to repo_root).

    Works in CI (Github Actions: GITHUB_BASE_REF is set) and locally.
    """
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        # We're in a PR context on GitHub Actions. actions/checkout may have made a
        # shallow clone with no base branch, so fetch it explicitly first.
        fetch = subprocess.run(
            [
                "git",
                "fetch",
                "--no-tags",
                "--depth=200",
                "origin",
                f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if fetch.returncode != 0:
            print(f"Could not fetch base ref '{base_ref}': {fetch.stderr.strip()}")
            return set()
        diff_target = f"origin/{base_ref}..."
    else:
        # Local check: diff against master
        diff_target = "master..."
    result = subprocess.run(
        ["git", "diff", "--name-only", diff_target],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Could not diff against '{diff_target}': {result.stderr.strip()}")
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def check_siblings(modified):
    """Check if only one file in a sibling group was modified.

    Returns a list of warning messages.
    """
    warnings = []
    for group_name, members in SIBLING_GROUPS.items():
        matched = [p for p in members if p in modified]
        if 1 <= len(matched) < len(members):
            unmatched = [p for p in members if p not in modified]
            warnings.append(
                f"[{group_name}] Only {len(matched)}/{len(members)} "
                f"files in this sibling group were modified.\n"
                f"  Modified: {', '.join(matched)}\n"
                f"  Unmodified: {', '.join(unmatched)}\n"
                f"  Review: does the same change apply to the unmodified sibling(s)?"
            )
    return warnings


def main():
    # this file lives at <repo>/.github/workflows/scripts/sibling_check.py
    repo_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
    os.chdir(repo_root)

    modified = get_modified_files(repo_root)
    if not modified:
        print("No modified files detected.")
        return 0

    smda_files = {f for f in modified if f.startswith("src/smda/")}
    if not smda_files:
        print("No SMDA source files modified.")
        return 0

    warnings = check_siblings(smda_files)

    if warnings:
        print("::warning title=Sibling-pair check::")
        print(f"Found {len(warnings)} sibling group(s) with partial modification:")
        print()
        for w in warnings:
            print(w)
            print()
        print(
            "This is a WARNING, not a failure. Review the unmodified sibling(s) "
            "to confirm the change does not apply there, or suppress this warning "
            "by acknowledging the sibling was intentionally left unchanged."
        )
        print()

    # Advisory only: a partial sibling group is a prompt to review, never a build failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
