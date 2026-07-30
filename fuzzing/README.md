# Fuzzing

Coverage-guided fuzzing of SMDA's untrusted-input surfaces with
[atheris](https://github.com/google/atheris) / libFuzzer. atheris publishes no
arm64 or macOS wheels, so the fuzzers run on Linux CI only
(`.github/workflows/fuzzing.yml`); everything needed to *reproduce* a finding
works anywhere without atheris.

## Layout

| File | Role |
| --- | --- |
| `targets.py` | the actual target bodies — plain Python, no atheris import |
| `harness.py` | atheris/libFuzzer plumbing, instruments `targets.py` |
| `fuzz_<target>.py` | one entry point per target, for libFuzzer to run |
| `generate_seeds.py` | builds a per-target seed corpus from the test fixtures |
| `smda.dict` | libFuzzer dictionary of magics, section names, report keys |
| `replay.py` | runs a target over files on disk, no atheris needed |

## Targets

| Target | Surface |
| --- | --- |
| `loaders` | `MemoryFileLoader(..., map_file=True)` and every accessor |
| `formats` | one format loader per input with `isCompatible()` bypassed |
| `disassembler` | `disassembleUnmappedBuffer()`, the full pipeline |
| `buffer` | `disassembleBuffer()` with fuzzer-chosen architecture/bitness/base |
| `report` | `SmdaReport.fromDict()` over fuzzer-generated JSON, plus round-trip |

## What counts as a finding

SMDA's public contract is that malformed input yields an error *report*, not an
exception: `disassembleUnmappedBuffer()` catches broadly and the loaders funnel
through `reraise_non_operational_exception`. The harnesses mirror that, so
ordinary parse failures are not findings. What fails a run:

- a segfault, abort, or uncaught native error in capstone/lief
- a hang (libFuzzer `-timeout`) or memory blow-up (`-rss_limit_mb`,
  `-malloc_limit_mb`)
- an exception the contract classes as non-operational (`AssertionError`,
  `MemoryError`, `ImportError`, `NameError`, `ReferenceError`, `SyntaxError`)
- `RecursionError` — operational by type, but a latent stack overflow in
  practice, so the harnesses promote it (`FATAL_EXCEPTION_TYPES`)
- a report that is `None` or carries a status outside `{ok, timeout, error}`

## Reproducing a CI finding

Download the `fuzz-artifacts-<target>` artifact from the failed run, then:

```
python fuzzing/replay.py <target> artifacts/crash-*
```

Once confirmed, minimize it and pin it as a regression test — see
`tests/fuzz_regressions/README.md`.

## Running locally (Linux x86_64 only)

```
pip install -e . && pip install atheris
python fuzzing/generate_seeds.py corpus_loaders --profile binary
python fuzzing/fuzz_loaders.py corpus_loaders -max_total_time=120 -dict=fuzzing/smda.dict
```

Use `--profile formats` / `--profile buffer` / `--profile report` for the
corresponding targets: those targets consume selector bytes from the front of
the input, and the profile prepends them.

The corpus is cached per target in CI, so coverage accumulates across runs
instead of restarting from the seeds every time.
