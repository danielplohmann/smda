"""Restore the in-repo corpus floor into a working corpus directory.

The accumulating corpus lives in the Actions cache, which evicts after 7 days without
a hit, so a quiet fortnight would reset coverage progress to whatever generate_seeds.py
produces. `tests/fuzz_corpus/<target>/` is a small pruned floor committed to the repo so
every run starts from a known state regardless of cache state.

Entries are stored XOR-obfuscated with the same `byte ^ (index % 256)` scheme as the
malware fixtures under `tests/`: corpus entries are derived from those samples and must
be inert at rest.
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "fuzz_corpus"


def deobfuscate(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def restore(target, corpus_dir):
    source = CORPUS_ROOT / target
    if not source.is_dir():
        return 0
    corpus_dir.mkdir(parents=True, exist_ok=True)
    restored = 0
    for entry in sorted(source.iterdir()):
        if entry.is_file() and entry.name != "README.md":
            (corpus_dir / f"floor_{entry.name}").write_bytes(deobfuscate(entry.read_bytes()))
            restored += 1
    return restored


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="target name, e.g. 'report' (not the fuzz_ entry point)")
    parser.add_argument("corpus_dir", nargs="?", default="corpus", type=Path)
    args = parser.parse_args(argv)

    restored = restore(args.target, args.corpus_dir)
    print(f"restored {restored} floor entries for '{args.target}' into {args.corpus_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
