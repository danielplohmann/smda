# Delphi recovery fixtures

The two TObject JSON fixtures are **modified, sparse metadata excerpts**, not runnable copies of Inno Setup.
They retain original RVAs and pointer values from the official Inno Setup 7.1.0 installers, including
TObject's VMT, method entries, class RTTI, indirect type references, parameter records and short code
excerpts. The third JSON fixture is a short, unmodified finally-dispatch code excerpt. Unrecorded bytes
reconstruct as zero. Each fixture records its source URL and SHA-256.
Expected names are checked against the metadata layout in Lukas Wenz's thesis, tables 2–8.

Inno Setup's tagged README identifies its build compiler as Delphi 12.3 Athens with the May Patch:
https://github.com/jrsoftware/issrc/blob/is-7_1_0/README.md

Original software: Copyright (C) 1997–2026 Jordan Russell; portions Copyright (C) 2000–2026
Martijn Laan. https://jrsoftware.org/ . See [INNO-LICENSE.txt](INNO-LICENSE.txt).
The SMDA project did not write the original software. The excerpts are modified for parser testing.
The TObject VMT, the System unit RTTI and the `_HandleFinally` sequence are Delphi run-time library code
compiled into Inno Setup rather than Inno Setup's own: Copyright (C) Embarcadero Technologies, Inc.

`testDelphiReSymProvider.py` reconstructs these images and verifies the entire recovered symbol map.
Additional generated layouts cover published entries preceding extended RTTI, metadata outside code,
unaligned VMTs, multiple code regions, external ancestors, corrupt lengths/counts/pointers, invalid
names and bounded alias expansion. Pythia tests cover shared-table caching, record-bounded names,
external parents and x86 gating. These layouts are format tests, not evidence of compiler-version or
optimization-level coverage.

The full audit corpus is described in `profiling/delphi_audit/manifest.json`; full installers and the
third-party upstream issue attachment are deliberately not bundled. Never execute those binaries.
