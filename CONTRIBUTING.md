# Contributing to SMDA

Thanks for taking the time. This file is the short version; the long version already exists
and is not repeated here.

- **[`AGENTS.md`](AGENTS.md)** — the working document for this repository: how the disassembly
  pipeline is organized, the code conventions Ruff enforces, the commands, and the gotchas that
  will bite a change to recovery heuristics. Read it before your first change, whether you are a
  human or an agent.
- **[`RELEASING.md`](RELEASING.md)** — versioning, the changelog contract, and how a release is cut.
- **[`SECURITY.md`](SECURITY.md)** — **do not open a public issue for a vulnerability.** Use
  GitHub's private "Report a vulnerability" form.

## Getting set up

```bash
make init          # venv deps, editable install, pre-commit hooks
make test          # fast tier
make lint          # ruff check
```

SMDA requires Python 3.11+ and is tested on 3.11 through 3.14.

## Before you open a pull request

1. `make format` — `ruff format --check` is a CI gate, not a suggestion.
2. `make lint` and `make typecheck`.
3. `make test-all` — `make test` deselects the `slow` tier, which is where the fixture corpora
   live. CI runs everything, so a slow-tier failure surfaces either way, just later.
4. Add a `CHANGELOG.md` bullet under `## [Unreleased]` if you touched `src/smda/` or
   `pyproject.toml`. The *Changelog* check fails the PR otherwise; apply the `no-changelog`
   label, and say why, for a change that genuinely needs no entry. `CHANGELOG.md` itself
   documents how a bullet is written — a measured claim names its corpus and its cost.
5. Give the PR a **conventional title** (`feat(intel): …`, `fix(loaders): …`). The allowed types
   and scopes are the list in `.github/workflows/semantic-pr-title.yml`, and it is enforced.

## What reviewers look for

- **Changing recovery heuristics changes the golden fixtures.** If a baseline moves, that is a
  deliberate decision to be explained in the PR, not a test to be updated quietly.
- **Over-detection is by design.** Completeness is prioritized over precision; a "fix" for a false
  positive can cost recall on the corpus. Measure it.
- Architecture-specific logic belongs in its backend (`smda.intel`, `smda.aarch64`, `smda.cil`,
  `smda.dalvik`), not in the shared engine.
- New tests match the existing `tests/test*.py` naming, and anything that disassembles a real
  fixture corpus is marked `slow`.

## Reporting things

Open an issue with one of the [forms](https://github.com/danielplohmann/smda/issues/new/choose). Malware fixtures and crash inputs
are shared XOR-obfuscated (`byte ^ (index % 256)`) or archived — never as a runnable file.
