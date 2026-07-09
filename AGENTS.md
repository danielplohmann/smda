# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. Follow this before making changes.

## Project Overview

SMDA is a minimalist recursive disassembler optimized for accurate Control Flow Graph (CFG) recovery from memory dumps and raw files. It is built on [Capstone](https://www.capstone-engine.org/) and supports:

- **intel** — x86 / x64
- **aarch64** — ARM64
- **cil** — .NET / CIL (via `dncil` / `dnfile`)
- **dalvik** — Android DEX bytecode

**Backend maturity:** `intel` is production-ready and rivals other disassemblers in accuracy. `aarch64` (ARM64) is a newer but consistent addition — on test data it matched IDA's output closely, so treat it as more mature than the rest. `cil` (.NET) and `dalvik` are recent additions that produce solid results but have **not yet been benchmarked against non-uniform / obfuscated code**, so expect caveats.

Inputs are arbitrary memory dumps (ideally with a known base address), raw DEX files, or binary files parsed via LIEF.
Output is a tree of functions → basic blocks → instructions with inter-block / inter-function edges. On top of the recovered CFG, SMDA performs a variety of optional recovery passes: symbol extraction and reconstruction (e.g. Windows API references via the ApiScout method, exports, imports, ELF/PE symbols, Rust/Delphi VMT parsing), and referenced string parsing. A function may only contain instructions that belong to a single function, and instructions may not overlap (IDA-style model).

Key entry point: `smda.Disassembler.Disassembler`.

## Disassembly Pipeline

SMDA is a **recursive (descent) disassembler** organized into phases, designed to recover code robustly from memory dumps with minimal assumptions about context. The guiding principle is aggressive, completeness-over-accuracy **function entry point (FEP)** detection.

> **Scope:** Phases 1–2 below describe the **intel (x86/x64)** pipeline in detail and are the reference model. Other backends implement the same `ArchBackend` contract but may differ substantially — e.g. `cil` (.NET) typically performs **no gap search at all** because the rich metadata already yields accurate FEPs, while `aarch64`/`dalvik` follow their own candidate and traversal logic. Do not assume the intel heuristics (opcode patterns, prologues, NOP lists) apply verbatim to other architectures.

### Phase 1 — Function Entry Point discovery & disassembly (intel)

A single scan over the input buffer locates two kinds of FEP candidates:

- **Code references:** scan for call/jump opcode byte patterns (e.g. `E8` relative call on x86, `FF 15`/`FF 25` RIP-relative on x64) and compute their targets. Any target landing inside the buffer becomes a candidate.
- **Common prologues:** match a small, deliberately conservative set of stack-frame / hotpatch prologues (e.g. `55 8B EC`, `8B FF 55 8B EC`).

When an unmapped PE/ELF is given (not a bare dump), LIEF provides additional candidates from the entry point and exports; candidates outside executable sections are discarded. Candidates are scored by reference count and prologue match, sorted, then disassembled one function at a time via recursive descent (DFS over basic-block starts):

- **Call:** does not end the block; used to update the FEP queue. Register-indirect calls are resolved via local dataflow backtracking.
- **Unconditional jump:** ends the block; target added to the work stack. Jump tables (switch) are resolved via a dedicated heuristic; jumps into a known FEP are treated as tailcalls.
- **Conditional jump / loop:** ends the block; fall-through added first, then the branch/loop target.
- **Terminating (`ret`/`int3`):** ends the function/block. A `push`-`ret` obfuscation construct is recognized and its target resolved.

FEP candidates outside executable regions are skipped; the FEP queue is continuously updated as indirect calls are resolved.

### Phase 2 — Gap analysis (intel)

After Phase 1, the spaces between recovered function bodies are scanned linearly for **gap functions** (unreferenced or unresolved functions, important for completeness). Within gaps:

- **Effective NOPs** (including padding `int3`/`CC` for alignment) are skipped.
- A non-NOP instruction is tested against a short list of common function-start bytes; on match, a recursive-disassembly attempt is made. Success extends the gap past the new function; failure moves to the next gap.

When an unmapped PE/ELF is given, gap search is limited to executable sections. Because FEP detection + gap analysis is intentionally aggressive, it can produce false positives — accepted because completeness is prioritized over precision.

### Phase 3 — Report finalization, escaping & hashing

Once functions/blocks/instructions are recovered, `SmdaReport` is built and enriched. A key enrichment is **instruction escaping and hashing** (e.g. `PicHash`, `OpcHash`): instructions are normalized ("escaped") to make them comparable across binaries despite differing immediates/addresses, then hashed to produce robust function-identifying fingerprints. These are accessed through and applied over interaction with the report, and the per-architecture escaping rules live in each backend's `InstructionEscaper` (e.g. `smda.intel.IntelInstructionEscaper`, `smda.aarch64.AArch64InstructionEscaper`).

## Environment Setup

A virtualenv lives at `.venv/` in the repo root. Always activate it before running anything:

```bash
source .venv/bin/activate
```

If the venv is missing or stale, bootstrap it with:

```bash
make init   # upgrades pip/setuptools/wheel, installs -e ".[dev]", installs pre-commit
```

`make init` installs the `dev` extra (pytest, ruff, pre-commit, build, twine, tqdm). For CPU/memory profiling tooling, install `.[dev,profile]` instead.

## Commands

All commands assume the venv is activated. Prefer the `Makefile` targets:

| Task | Command |
| ---- | ------- |
| Lint (ruff check) | `make lint`  (or `ruff check .`) |
| Format (ruff format) | `make format`  (or `ruff format .`) |
| Auto-fix lint | `make ruff-fix` |
| Run tests | `make test`  (or `pytest tests/test*`) |
| Tests + coverage | `make test-coverage` |
| Build package | `make package` |
| Publish to PyPI | `make publish` |

`pyproject.toml` configures pytest with `pythonpath = ["src"]` and `testpaths = ["tests"]`, so tests import the package from `src/` without install gymnastics. Run tests with `pytest` (not `python -m pytest` against an installed copy) to exercise the working tree.

Pre-commit hooks (ruff + standard hygiene checks) run on commit via `.pre-commit-config.yaml`. Install them with `make init`; they will auto-format/fix on commit.

## Code Conventions

- **Formatter / linter:** Ruff. Line length **120**, target **Python 3.10+** (`py310`).
- **Style:** Ruff `select` set is `E4, E7, E9, F, W, I, UP, B, C4, PIE, SIM`. `E501` is ignored (formatter handles length). `UP006`/`UP007` are intentionally ignored to avoid sweeping typing modernization churn.
- **No comments in code** unless explicitly requested. Keep code self-documenting via clear names and structure.
- **Imports:** `src`-layout package. Import as `from smda....` (the installed/editable package), never relative path hacks. Ruff's `I` rule enforces import ordering.
- **Typing:** Keep existing `Optional`/`Union` annotation style where already present (do not broadly convert to `X | None` unless touching that code).
- **Dependencies:** runtime deps are `capstone`, `dncil`, `dnfile`, `lief>=0.16.0`. Add new runtime deps to `pyproject.toml` `[project].dependencies`, not scattered imports.

## Repo Layout

```
src/smda/        # the package (Disassembler, SmdaConfig, common/, intel/, aarch64/, cil/, dalvik/, ida/, utility/)
tests/           # pytest suite (test*.py)
data/            # generated ApiScout / reference JSON data (do not hand-edit; see Gotchas)
profiling/       # CPU/memory profiling toolkit (make profile-cpu / profile-mem / profile-flame)
analyze.py       # demo: disassemble a file/dump, optionally store JSON
export.py        # example export usage
ida_analyze.py   # IDA-side analysis/export helper
```

## Versioning & Releases

When a change warrants a version bump, update **all three** in one commit:

1. `src/smda/__init__.py` → `__version__`
2. `src/smda/SmdaConfig.py` → `SmdaConfig.VERSION`
3. Add a dated entry at the top of the **Version History** section in `README.md` (format: ` * YYYY-MM-DD: vX.Y.Z - <summary>`).

Keep the two version strings in sync. Do not bump versions unless the change is a release-worthy change (and see Git Workflow re: explicit ask).

## Git Workflow

- Work on a **feature branch**, then open a **PR** against `master`. Do not commit directly to `master`.
- Commit messages: concise, lowercase, imperative ("add aarch64 tailcall handling"). Version-bump commits in this repo have historically used `bump X.Y.Z`.
- **PR titles** must be **semantic/conventional** (e.g. `feat:`, `fix:`, `refactor:`) — enforced by CI (`semantic-pr-title.yml`), distinct from the commit-message style above.
- Never commit secrets/keys. Do not force-push shared branches.
- Only create commits/PRs when explicitly asked.

## Testing

- Add or update tests under `tests/` for behavioral changes; match the existing `test*.py` naming and pytest style.
- Run `make test` and `make lint` before considering work complete.
- Architecture-specific behavior (intel / aarch64 / cil / dalvik) should be covered with representative fixtures where feasible.
- The xored `tests/*_xored` corpora and the malpedia **benchmark matrix (`.github/workflows/perf_benchmark.yml`) are PR/CI-only** — they require a password-gated malpedia corpus and are not expected to run locally. For local recovery-quality validation, the maintainer works against separate groundtruth datasets rather than the full public matrix. Do not assume you can reproduce the benchmark suite locally.

## Gotchas

Constraints an agent must respect to avoid breaking SMDA or its downstream consumers.

### `data/` is read-only generated input
- `data/apiscout_win7_prof-n_sp1.json` and `data/apiscout_winxp_prof_sp3.json` are large **generated** ApiScout WinAPI databases consumed by `WinApiResolver` for symbol reconstruction. Never hand-edit them.
- Pre-commit excludes these from trailing-whitespace / end-of-file-fixer and only `check-json`s `^data/.*\.json$`; the `check-added-large-files` hook caps at 85 MB. Do not commit new/larger generated data without adjusting the hook limit.

### IDA Pro interface compatibility
- `smda.ida.IdaInterface` / `IdaExporter` convert IDA Pro's disassembly into an `SmdaReport`. Downstream projects that build on SMDA depend on this interface, so **do not change the `SmdaReport` format or version in ways that break it** without an explicit, deliberate decision.
- `IdaInterface` is version-branched on `IDA_SDK_VERSION` (`< 740`, `< 850`, ...). Changes here must stay compatible across those SDK generations.

### Resource safeguards are configurable — preserve them
`SmdaConfig` carries bounds that stop pathological / junk samples from exploding time or memory (cf. `tests/testCandidateSafeguards.py`):
- `TIMEOUT`, `MAX_IMAGE_SIZE`, `MAX_INDIRECT_CALLS_PER_BASIC_BLOCK`, `MAX_FUNCTION_CANDIDATES`, `MAX_CALL_REFS_PER_CANDIDATE`.
- These are defaults meant to stay bounded. Do not remove them or flip them to unlimited (`0`) by default. Tune via config, not by deleting the guard.

### Golden test fixtures are frozen baselines
- `tests/` holds an xored corpus (`mirai_*`, `asprox_*`, `komplex_*`, ...) plus escaper-verification suites. They encode expected CFG recovery.
- Changing recovery heuristics (FEP discovery, gap search, tailcall/jump-table resolution, escaper) must **not silently change these baselines**. If a heuristic change is intentional, update the fixtures deliberately and explain why in the PR.

### Architecture code is isolated by the `ArchBackend` interface
- `smda.common.RecursiveDisassembler` is the **architecture-agnostic** engine (traversal, candidate orchestration, gap/tailcall passes, label/symbol resolution). It delegates all arch-specific work to an injected `ArchBackend` (`smda.common.arch.ArchBackend`).
- Per-arch backends live under `smda.intel`, `smda.aarch64`, `smda.cil`, `smda.dalvik`. Symbol/label logic lives under `smda.common.labelprovider`.
- There is **no hard boundary** as of now: in practice, most changes land in the areas around `RecursiveDisassembler` (the engine), the arch backends, the label providers, or the `FunctionCandidateManager`. To add or change an architecture, implement/extend `ArchBackend` and keep arch-specific logic within its own module; share only through the common base class rather than baking arch behavior into the engine.

### Version strings stay in sync — and are load-bearing
- `SmdaConfig.VERSION` and `smda.__version__` must match (see Versioning). The value is written into every `SmdaReport` (`disassembly.smda_version`) and feeds IDA-compatibility decisions, so an inconsistent or careless bump has downstream effects.

### CFG model is strict (IDA-style)
- A function may contain only instructions belonging to that function, and instructions may not overlap. Do not relax this model — recovery passes and downstream tooling depend on it.

### Reality check — common traps for agents
- **The pipeline description is intel-centric.** The `E8`/`FF 15`/`55 8B EC` heuristics and the gap-search/NOP-list logic belong to the intel backend. Other backends follow their own candidate/traversal logic (e.g. `cil` does essentially no gap search thanks to rich metadata). Do not apply intel assumptions to other architectures.
- **Symbol/API resolution is feature-gated and context-sensitive.** `SmdaConfig` defaults have `API_COLLECTION_FILES = {}` and `WITH_STRINGS = False`. Windows-API resolution via ApiScout needs **profiles for the target machine** and works well mainly on memory dumps; import-table parsing handles the rest. Do not assume API/symbol resolution "just works" out of the box — wire config (see `tests/context.py` for the pattern).
- **The Escaper / hashing subsystem is SMDA's differentiator and is per-architecture.** `PicHash`/`OpcHash` escaping lives in each backend's `InstructionEscaper`. Changes to recovery or escaping affect these fingerprints — keep them consistent with the golden fixtures.
- **CI enforces more than `make lint`.** Beyond `ruff check`, the pipeline runs `ruff format --check` (formatting is **mandatory**, not optional) and a **semantic PR-title** lint (`semantic-pr-title.yml`). Run `make format` and use a conventional PR title (e.g. `feat:`, `fix:`, `refactor:`) before opening a PR.
- **False positives are a feature.** Completeness is prioritized over precision by design; fixing a perceived false positive can silently degrade recall on the frozen golden corpus. Treat such "fixes" with suspicion and validate against fixtures.
