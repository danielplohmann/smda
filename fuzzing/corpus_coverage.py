"""Measure which SMDA code a fuzz corpus reaches.

libFuzzer only reports an edge count, which says whether a run made progress but not
where. This runs a target body over every file of a corpus under coverage.py, without
atheris, and writes the coverage data plus a text report, so code that no input ever
reaches can be found and given seeds or a better target:

    python fuzzing/corpus_coverage.py loaders corpus --data-file .coverage.loaders

The data files of several targets combine with ``coverage combine``. Inputs that raise
are counted, not fatal: the fuzzer is what judges a crash, this only measures.
"""

import argparse
import logging
import sys
import warnings
from pathlib import Path

import coverage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="target name, e.g. 'loaders'")
    parser.add_argument("corpus_dir", type=Path)
    parser.add_argument("--data-file", type=Path, default=Path(".coverage"))
    parser.add_argument("--report", type=Path, help="write the per-file report here instead of stdout")
    args = parser.parse_args(argv)
    if not args.corpus_dir.is_dir():
        parser.error(f"no corpus at {args.corpus_dir}")

    logging.disable(logging.CRITICAL)
    # lief warns on every unknown enum value, which malformed inputs are full of
    warnings.simplefilter("ignore")
    # config_file=False: the project config enables multiprocessing concurrency, which
    # only works under `coverage run`, and a fail_under meant for the test suite
    cov = coverage.Coverage(data_file=str(args.data_file), branch=True, source=["smda"], config_file=False)
    cov.start()
    try:
        # imported under measurement so module-level lines count as reached
        from replay import decode
        from targets import TARGETS

        if args.target not in TARGETS:
            parser.error(f"unknown target '{args.target}', choose from {', '.join(sorted(TARGETS))}")
        target = TARGETS[args.target]
        ran = raised = 0
        for path in sorted(p for p in args.corpus_dir.iterdir() if p.is_file()):
            ran += 1
            try:
                target(decode(path))
            except Exception:
                raised += 1
    finally:
        cov.stop()
        cov.save()

    print(f"{args.target}: replayed {ran} inputs, {raised} raised")
    if args.report:
        with args.report.open("w") as f:
            total = cov.report(file=f)
    else:
        total = cov.report(file=sys.stdout)
    print(f"{args.target}: {total:.1f}% of smda reached")
    return 0


if __name__ == "__main__":
    sys.exit(main())
