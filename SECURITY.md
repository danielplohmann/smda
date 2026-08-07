# Security Policy

## Scope

SMDA is a disassembler. It parses untrusted, frequently malicious binaries by design,
and it is consumed as a library (notably by MCRIT). The security-relevant surface is
therefore everything reachable from a crafted input file:

- the format loaders (`src/smda/utility/`: PE, ELF, Mach-O, DEX, Delphi KB, raw memory)
- the disassembly backends (`src/smda/intel/`, `aarch64/`, `cil/`, `dalvik/`)
- report deserialization (`SmdaReport.fromDict` / `fromFile`), since reports are
  exchanged between tools
- `src/smda/synthesis/`, which is explicitly experimental and **not** hardened against
  adversarial input

SMDA links LIEF and capstone, both large C++ codebases reached with untrusted bytes.
A crash originating inside those libraries is still in scope for a report here, and
will be forwarded upstream where appropriate.

## What counts as a vulnerability

In scope:

- memory-unsafety, a native crash, or unbounded allocation reachable from a crafted input
- an unhandled exception that escapes the public API instead of producing an error report
  (the library contract is to degrade into `status="error"`, not to raise)
- unbounded recursion, or a hang that defeats the analysis timeout
- path traversal or arbitrary write from report or binary content

Not in scope:

- an incorrect or incomplete control-flow graph. Over-detection is intentional;
  recovery accuracy is a correctness concern, not a security one.
- resource use proportionate to a genuinely large input.
- anything requiring the operator to supply a malicious configuration or API database,
  which are trusted inputs.

## Reporting

Please report privately via GitHub's ["Report a vulnerability"][advisories] form on this
repository rather than opening a public issue.

Useful in a report: the input that triggers it (XOR-obfuscated or archived if it is
live malware), the SMDA version, the LIEF and capstone versions, and the traceback or
crash output. A `fuzzing/replay.py` invocation that reproduces it is ideal.

Expect an initial response within 14 days. Fixes land on `master` with a regression
test; artifacts from a report are pinned under `tests/fuzz_regressions/` where the
input can be redistributed.

[advisories]: https://github.com/danielplohmann/smda/security/advisories/new

## Handling malware samples

The fixtures under `tests/` are live malware, stored XOR-obfuscated (`byte ^ (index % 256)`)
specifically so they are inert at rest. Never execute them. Report artifacts are handled
the same way.
