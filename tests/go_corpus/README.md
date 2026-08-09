# Go pclntab validation corpus

`matrix.json` records what SMDA's `GoSymbolProvider` recovered from Go binaries built by real
toolchains, across go version x GOOS/GOARCH x link mode. `tests/testGoCorpusMatrix.py` reads it.

## Supported pclntab range

Go has shipped four table layouts, each with its own magic. A layout stays in use until the
next replaces it, so the four markers cover every Go release to date:

| Magic        | Introduced by | Covers          |
| ------------ | ------------- | --------------- |
| `0xFFFFFFFB` | Go 1.2        | Go 1.2 - 1.15   |
| `0xFFFFFFFA` | Go 1.16       | Go 1.16 - 1.17  |
| `0xFFFFFFF0` | Go 1.18       | Go 1.18 - 1.19  |
| `0xFFFFFFF1` | Go 1.20       | Go 1.20 onwards |

`0xFFFFFFF1` is still current, so a release after 1.20 needs no new marker. The
`_PCLNTAB_VERSIONS` keys name the release that introduced a layout, not the only one using
it - a binary reported as `1.12` may have been built by anything up to 1.15. Both byte orders
are read (Go targets big-endian s390x, ppc64 and mips) and both pointer sizes.

The recorded run covers every layout, all three container formats, both byte orders, both
pointer sizes, and default/stripped/PIE linking, at 0.9985 symbol recall or better per cell.

Known limits:

- Names come back as the table stores them, with `U+00B7` rendered as `.` to match
  `debug/gosym`. Nothing else is demangled, so generic instantiations keep `go.shape...`.
- Offset discovery prefers the container's own section (`.gopclntab`, `__gopclntab`, or the
  `runtime.pclntab` symbol on PE) and otherwise scans for the header, accepting only an
  unambiguous single hit rather than guessing between several.
- Addresses are the ones the table records, so a position-independent binary loaded at a base
  other than its link-time one reports link-time addresses.

No Go binaries are committed. A hello-world Go binary is 1.5-2 MB and the sweep builds a few
hundred of them, so `build_matrix.py` builds each sample, measures it, and deletes it; only the
measurements are kept.

## Re-running the sweep

Install the toolchains (one release per minor), then run the harness:

```bash
go install golang.org/dl/go1.21.13@latest && go1.21.13 download
python tests/go_corpus/build_matrix.py --out tests/go_corpus/matrix.json
```

`--sdk-dir` points at where `goX.Y.Z download` unpacked (default `~/sdk`), and `--versions`
overrides the version list. Anything missing is recorded as `toolchain_unavailable` rather than
skipped quietly.

A host can only run a toolchain built for it: darwin/arm64 machines cannot run Go below 1.16,
which is the first release with a darwin/arm64 distribution. Those versions need an amd64 host
or Rosetta 2. Cross-*compiling* to every GOOS/GOARCH works from any host, so a single machine
still covers the whole platform axis for the versions it can run.

## Reference baseline

`go tool nm` on the same binary, restricted to text symbols (`T`/`t`). Go's own `cmd/nm` reads
the pclntab through `debug/gosym`, so this compares SMDA's parse against Go's parse of the same
bytes. Three differences are presentation, not disagreement, and are normalized away:

- nm appends `.abi0`/`.abiinternal` to assembly routines; the pclntab name has no suffix.
- nm reports section boundary markers (`runtime.text`, `runtime.etext`, ...) that are not functions.
- On Mach-O, nm reports assembly symbols under the C convention with a leading underscore.

A `-ldflags="-s -w"` build keeps its pclntab but loses the symbol table nm needs. Stripping does
not move any address, so those cells are scored against the unstripped twin of the same cell.

## Adding an axis

Extend `PLATFORMS` or `MODES` in `build_matrix.py` and re-run. The platform list is chosen for
what changes how a pclntab is located and read - container format, pointer size, byte order -
rather than for architecture coverage: `linux/s390x` is there because it is the only big-endian
target Go still ships, and `windows/386` because a 32-bit PE exercises both the 32-bit table
layout and the PE offset-discovery path.
