"""Bound a cached corpus directory by file count and total size.

libFuzzer's own ``-merge=1`` cannot be used here: the merge driver re-executes
argv[0] to run its inner passes, which under atheris is the bare Python
interpreter without the harness script, so the merge processes nothing and
reports zero new files. Pruning by size instead is deterministic, needs no
instrumentation, and keeps the cache from growing without limit across weekly
runs.

Smaller inputs are kept first: they reach the same code faster, and libFuzzer
already prefers short inputs when it reduces the corpus in-process.
"""

import argparse
import sys
from pathlib import Path

DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


def prune(corpus_dir, max_files, max_bytes):
    entries = sorted(
        ((path.stat().st_size, path.name, path) for path in corpus_dir.iterdir() if path.is_file()),
    )
    kept_bytes = 0
    kept = 0
    removed = 0
    for size, _name, path in entries:
        if kept < max_files and kept_bytes + size <= max_bytes:
            kept += 1
            kept_bytes += size
            continue
        path.unlink()
        removed += 1
    return kept, kept_bytes, removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_dir", type=Path)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args()
    if not args.corpus_dir.is_dir():
        print(f"no corpus at {args.corpus_dir}, nothing to prune")
        return 0
    kept, kept_bytes, removed = prune(args.corpus_dir, args.max_files, args.max_bytes)
    print(f"kept {kept} files ({kept_bytes} bytes), removed {removed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
