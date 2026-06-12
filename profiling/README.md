# SMDA Profiling Toolkit

CPU and memory **profiling** for the SMDA disassembly pipeline. This is the
profiling layer only — benchmarking and base-vs-PR regression comparison already
live in [`.github/workflows/scripts/`](../.github/workflows/scripts/)
(`run_perf_check.py`, `compare_perf.py`) and the
[`perf_benchmark.yml`](../.github/workflows/perf_benchmark.yml) workflow. Use
those for "is this PR slower?"; use this for "*where* is the time/memory going?".

## Install

```bash
pip install -e ".[dev,profile]"
```

This pulls in `py-spy`, `memray`, `line_profiler`, `snakeviz`, and `psutil`. The
base SMDA install stays lean without the `profile` extra.

## The workload

Every profiler wraps the **same** unit of work — one disassembly of one target —
so results are comparable. A target is either:

- a **fixture name**: `asprox`, `cutwail`, `bashlite`, `blockblast`, `komplex`,
  `njrat`, `pe_export` (the same XOR-encrypted fixtures the benchmark gate uses), or
- a **path** to any binary on disk.

> Fixtures are XOR-decrypted into an in-memory buffer and handed to the analyzer.
> They are never executed as programs.

## Commands

```bash
# CPU: cProfile + (optional) line-by-line over SMDA's hot functions
python -m profiling.profile_smda cpu  --target asprox --line
make profile-cpu TARGET=asprox

# Memory: memray capture + tracemalloc top allocators + USS delta
python -m profiling.profile_smda mem  --target asprox
make profile-mem TARGET=asprox

# Raw workload (no profiling) — the unit external samplers wrap
python -m profiling.profile_smda run  --target asprox
```

Outputs land in `profiling/output/` (git-ignored): `*.cpu.prof`, `*.mem.bin`,
`*.mem.html`, `*.cpu.svg`.

### Viewing results

| Output | View with |
|--------|-----------|
| `<t>.cpu.prof` (cProfile) | `snakeviz profiling/output/<t>.cpu.prof` (interactive icicle chart) |
| `<t>.mem.bin` (memray) | `memray flamegraph profiling/output/<t>.mem.bin` → HTML, or `memray table ...` |
| `<t>.cpu.svg` (py-spy) | open in a browser |

## Native flamegraphs (py-spy / memray `--native`)

To see **into** the Capstone / LIEF C frames you need native sampling:

```bash
# CPU native flamegraph (Linux)
py-spy record --native -o profiling/output/asprox.cpu.svg -- \
    python -m profiling.profile_smda run --target asprox
make profile-flame TARGET=asprox

# Memory native frames
python -m profiling.profile_smda mem --target asprox --native
```

### Platform caveats

| Tool | Linux | macOS |
|------|-------|-------|
| `cProfile`, `line_profiler`, `tracemalloc` | ✅ | ✅ |
| `memray` (Python allocations) | ✅ | ✅ (macOS 11+) |
| `memray --native` | ✅ best | ⚠️ limited |
| `py-spy` | ✅ (may need `sysctl kernel.yama.ptrace_scope=0`) | ⚠️ needs `sudo` |
| `py-spy --native` | ✅ | ❌ **not supported on macOS** |

So **local macOS** development gets the full Python-level view (cProfile +
line_profiler + memray); for native C-frame flamegraphs, use the CI workflow,
which runs on Linux. Note that pip wheels for `capstone`/`lief` may be partially
stripped, so native frames can be coarse — the Python-level view is the primary
signal.

## CI

[`.github/workflows/profile.yml`](../.github/workflows/profile.yml) runs this
toolkit on Linux, **on demand only**:

- **Manual:** Actions → *On-Demand Profiling* → *Run workflow* (pick target /
  profiler / iterations).
- **PR label:** add the `profile` label to a PR.

It uploads the flamegraphs / `.prof` / `.bin` as run artifacts, and on the
label path posts a PR comment linking to them.
