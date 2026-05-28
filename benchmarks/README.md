# SMDA Performance Gate

This directory contains the GitHub Actions benchmark harness for comparing a
pull request against its base commit on the same runner.

## Corpus setup

The workflow expects an encrypted ZIP archive at `benchmarks/corpus/smda-samples.zip`. For forks that cannot upload Git LFS objects, store the same encrypted ZIP as split files named `benchmarks/corpus/smda-samples.zip.part-00`, `benchmarks/corpus/smda-samples.zip.part-01`, and so on; the workflow reassembles them before unzipping.

Store the ZIP password in the repository
secret `SMDA_SAMPLE_ARCHIVE_PASSWORD`. The workflow decrypts the archive inside
the runner temp directory and statically disassembles the extracted samples; it
does not execute sample binaries.

Fork pull requests do not receive repository secrets, so the benchmark will skip
the corpus-backed gate there instead of using `pull_request_target`.

The workflow prefers benchmark helper scripts from the base checkout when they
exist. That keeps ordinary PRs from modifying the benchmark parser or comment
logic to hide a regression. The head checkout is only used as a bootstrap
fallback before this directory exists on the default branch.

The pass/fail decision uses `pyperf` because it is the most stable timing
primitive for CI. If the gate fails, the workflow also records the CI-safe
subset of the deeper SMDA profiling research harness: cProfile/pstats,
Pyinstrument, Memray native allocation profiling, and a tracemalloc/psutil
memory baseline. Those artifacts are uploaded for investigation without making
the PR comment noisy.

## Optional manifest

Set the workflow input `corpus-manifest` to a JSONL file if the archive contains
more files than should be benchmarked. Each JSON line may contain:

```json
{"relative_path": "family/version/sample_dump7_0x0000000000400000", "mode": "dump"}
```

When no manifest is supplied, the runner discovers Daniel-style memory dumps and
unpacked files by filename.
