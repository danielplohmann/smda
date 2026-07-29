
# SMDA

SMDA is a minimalist recursive disassembler library that is optimized for accurate Control Flow Graph (CFG) recovery from memory dumps.
It is based on [Capstone](http://www.capstone-engine.org/) and currently provides native backends for x86/x64 Intel and AArch64 (ARM64) machine code, experimental CIL (.NET) disassembly, and Dalvik bytecode from raw DEX files.
As input, PE, ELF, and Mach-O files (including fat/universal binaries), arbitrary memory dumps (ideally with known base address), and raw DEX files can be processed.
The output is a collection of functions, basic blocks, and instructions with their respective edges between blocks and functions (in/out).
Optionally, references to the Windows API can be inferred by using the ApiScout method.

## Installation

With version 1.2.0, we have finally simplified things by moving to [PyPI](https://pypi.org/project/smda/)!
So installation now is as easy as:

```
$ pip install smda
```

## Usage

A typical workflow using SMDA could like this:

```
>>> from smda.Disassembler import Disassembler
>>> disassembler = Disassembler()
>>> report = disassembler.disassembleFile("/bin/cat")
>>> print(report)
 0.777s -> (architecture: intel.64bit, base_addr: 0x00000000): 143 functions
>>> for fn in report.getFunctions():
...     print(fn)
...     for ins in fn.getInstructions():
...         print(ins)
...
0x00001720: (->   1,    1->)   3 blocks,    7 instructions.
0x00001720: (      4883ec08) - sub rsp, 8
0x00001724: (488b05bd682000) - mov rax, qword ptr [rip + 0x2068bd]
0x0000172b: (        4885c0) - test rax, rax
0x0000172e: (          7402) - je 0x1732
0x00001730: (          ffd0) - call rax
0x00001732: (      4883c408) - add rsp, 8
0x00001736: (            c3) - ret
0x00001ad0: (->   1,    4->)   1 blocks,   12 instructions.
[...]
>>> json_report = report.toDict()
```

There is also a demo script:

* analyze.py -- example usage: perform disassembly on a file or memory dump and optionally store results in JSON to a given output path.

### IDA Pro integration

SMDA can also turn an IDA-analyzed database into a SMDA report instead of running its own disassembly. Inside the IDA GUI, SMDA supports IDA Pro 8.4 and newer via the existing IDAPython integrations; older SDK generations are rejected. On IDA 9.1 or newer, it prefers the higher-level [IDA Domain API](https://ida-domain.docs.hex-rays.com/) when the optional package is installed and otherwise falls back to IDAPython.

Inside the IDA GUI, run `export.py` to export IDA's existing analysis to a `.smda` file next to the database. Run `ida_analyze.py` to have SMDA independently recover functions from the loaded bytes and add missing function starts and names back to IDA. This augmentation workflow is useful when IDA analyzes a raw or mapped buffer conservatively. Both scripts can be launched via *File -> Script file...*.

For headless export of IDA's analysis (no GUI), use `ida_domain_export.py`:

```
python -m pip install "smda[ida]"
python ida_domain_export.py /path/to/sample.i64 -o sample.smda
```

Headless export requires IDA 9.1+ and the optional `ida-domain>=0.5.0` dependency. Make sure `IDADIR` points at the IDA installation when it cannot be discovered automatically (see the [getting started guide](https://ida-domain.docs.hex-rays.com/getting_started/)). Standard SMDA installations do not include `ida-domain`.

For Dalvik, the current scope is raw single-DEX inputs (`dex\n`). APK and multi-dex containers are not first-class workflows. ODEX (`dey\n`) and CDEX (`cdex`) are not analysis-compatible (quickened ops / compact `code_item`): with `backend="dalvik"` they raise an explicit error; auto-detect will not select the Dalvik backend for those magics.

The code requires Python 3.11+.
`SmdaReport.metadata.language` is always a score map (`language name -> float`). Internal guesses and evidence
counters are not serialized; loading an older report normalizes its legacy string/private-key form to this contract.
To pick a single language from the map, take the highest score, except that `go` and `rust` win outright when their
score exceeds 0.5 — a build ID, pclntab header, or demangled Rust symbol is conclusive, while the other scores are
graded evidence.
For ELF files, `xmetadata.exported_symbols` contains all defined dynamic exports (functions and data) keyed by
virtual address, while the legacy `exported_functions` and `symbols` maps remain function-only. C++ names are
demangled in these label maps; API references (`SmdaFunction.apirefs`) keep the undecorated import name so they
stay comparable across PE, ELF, and Mach-O.

### Experimental: Binary Synthesis

SMDA can rebuild fictive PE, ELF, and Mach-O files from a recovered CFG via `SmdaReport.synthesizeBinary()`. The output plants function bytes per basic block at their original VAs and fuses import metadata, producing binaries that parse cleanly with LIEF and can be loaded into analysis tools (e.g. IDA, Ghidra Binary Ninja). This feature is experimental and works on well-formed reports but has not been hardened against pathological or adversarial inputs. Synthesis is deterministic from report content only and does not require the stored buffer.


## Development

### Code Quality

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and code formatting. To set up the development environment:

```bash
# Install development dependencies
python3 -m pip install --upgrade pip "setuptools>=64.0.0,<82.1.0" "wheel>=0.47.0"
python3 -m pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
make init

# Run linting
make lint
# or
ruff check .

# Run formatting
make format
# or
ruff format .

# Fix auto-fixable issues
make ruff-fix
# or
ruff check . --fix
```

### Pre-commit Hooks

Pre-commit hooks are configured to run ruff automatically on commit. Install them with:

```bash
pre-commit install
```

### Testing

Run tests with:

```bash
make test
```
´
## Version History
 * 2026-07-29: v4.4.2 - Dalvik PIC hashing is now position-independent: `escape_intraprocedural_jumps` was inverted relative to the Intel and CIL escapers, retaining the raw signed branch offset on the `pic_hash` path so two structurally identical methods whose branch deltas differed only by an earlier instruction's width produced different hashes. Branch-only formats (10t/20t/21t/22t/30t) are now masked on both paths. **This invalidates previously computed Dalvik `pic_hash` values**; reports below 4.4.2 recalculate on import.
 * 2026-07-29: v4.4.1 - Experimental binary synthesis: `SmdaReport.synthesizeBinary()` rebuilds fictive PE/ELF/Mach-O files from a recovered CFG, planting bytes per basic block at their original VAs and fusing import metadata (new `smda/synthesis/` package with `BinarySynthesizer`, `PeSynthesizer`, `ElfSynthesizer`, `MachoSynthesizer`). Includes review-hardening fixes: graceful fallbacks for malformed/headerless inputs, non-contiguous IAT gap handling, and removal of dead base-class helpers. (No new runtime deps.)
 * 2026-07-26: v4.4.0 - Labels/reporting: recover and demangle ELF function/data exports and relocation imports, add `xmetadata.exported_symbols`, normalize `metadata.language` to score-only maps (including legacy report loading), replace host C++ demangler tools with the bundled `pycxxfilt` LLVM demangler, and require Python 3.11+. (THX: @r0ny123)
 * 2026-07-28: v4.3.11 - Labels: tier-1 symbol recovery — apply `DelphiPythiaProvider` names via the engine (register it as a symbol provider so recovered VMT/method-table names land on functions), format Go pclntab marker error messages as hex, and expand `OrdinalHelper` with stable Winsock (`ws2_32`/`wsock32`) and `oleaut32` ordinals for more accurate API name resolution. (THX: @r0ny123)
 * 2026-07-24: v4.3.10 - Dalvik: format-aware DalvikInstructionEscaper for PIC/OPC hashing (pool-index/immediate/branch masking), typed exception edges surfaced via SmdaFunction.getExceptionBlockRefs(), method_handle/call_site resolution (DEX 038+), orphan code_item discovery, unreachable-code flagging, backward-payload fixed-point sweep, ART-reconciled can_throw flags (incl. fill-array-data), goto/32 self-branch accepted, and explicit ODEX/CDEX rejection. (THX: @r0ny123)
 * 2026-07-24: v4.3.9 - Common: surface Rust detection in the language-guess heuristic (wire RustSymbolProvider.is_rust_binary() into LanguageAnalyzer so Rust binaries guess "rust" instead of "c++", and harden _get_binary_data() against missing raw_data/file_path). (THX: @r0ny123)
 * 2026-07-24: v4.3.8 - CIL: complete opcode coverage in the CIL instruction escaper by deriving mnemonic grouping and binary token/branch escaping directly from dncil's opcode table (instead of a hand-maintained list), and add a CIL pic_hash recalculation gate for older reports. (THX: @r0ny123)
 * 2026-07-24: v4.3.7 - Performance: cross-backend hot-path pass hoisting repeated lookups and avoiding redundant allocations (setdefault->get+conditional-set, zero-copy memoryview word scans in Aarch64 candidate discovery, skipped capstone re-decode in _recordDataRefs, debug-f-string gating, frozenset mnemonic membership in the intel backend). (THX: @r0ny123)
 * 2026-07-24: v4.3.6 - Cross-backend correctness sweep: intel prefix normalization and xadd clobber fixes, Aarch64 LSL shift propagation, CIL/Dalvik exception-flow and throwable-opcode handling plus DEX payload hardening, and label-provider/type-surface fixes. (THX: @r0ny123)
 * 2026-07-22: v4.3.5 - Widened Intel PIC-hash escaping to cover 64-bit immediates (`mov r64, imm64` constants were previously truncated to their first 8 hex digits and never escaped, so PicHash was not relocation-invariant on 64-bit binaries). (THX: @r0ny123)
 * 2026-07-22: v4.3.4 - Added a default-off x64 PE pass (`USE_PE_X64_PDATA_ENDS`) that splits already-recovered functions at exact `.pdata` RUNTIME_FUNCTION boundaries when an interior boundary has an external non-fall-through inbound reference. (THX: @r0ny123)
 * 2026-07-22: v4.3.3 - Detect x86/x64 import-jmp thunks (a single `jmp` through a resolved IAT/GOT slot) and populate `num_thunk_functions` in reports. (THX: @r0ny123)
 * 2026-07-22: v4.3.2 - Fixed language identification to prefer exact Go build-ID evidence over the structurally noisy C++ score and now export the computed `language` guess in `SmdaReport`. (THX: @r0ny123)
 * 2026-07-22: v4.3.1 - Restored the dropped reachable-collision cleanup in `FunctionAnalysisState.getBlocks()` so a fall-through colliding with another function removes the stale cross-function code reference and ends the block. (THX: @r0ny123)

 * 2026-07-17: v4.3.0 - Format-aware `xheader` capture: `getHeaderBytes()` now stores computed, trailing-zero-trimmed, capped header regions for PE (section table), ELF (program headers), and Mach-O (active-slice load commands) instead of fixed truncations, enabling metadata recovery and binary re-synthesis. Added a normalized PE header hash (`SmdaReport.pe_header_hash`, volatile TimeDateStamp/CheckSum/SizeOfImage zeroed) for hash-busting-resistant clustering.
 * 2026-07-17: v4.2.17 - Improved function-boundary accuracy on ARM64 PE binaries (trap-data gap rejection, prologue-gated call-fallthrough alignment cuts, .pdata-authoritative conditional-tailcall boundaries) with the matching x86 gap-scan/alignment-cut fixes. (THX: @r0ny123)
 * 2026-07-15: v4.2.16 - Aarch64: add platform-specific function-candidate sources (PE ARM64 exception directory, ELF .eh_frame FDEs, Mach-O function-pointer metadata), wire the analysis-timeout callback into candidate identification, and extend README platform support wording. (THX: @r0ny123)
 * 2026-07-15: v4.2.15 - Improved interoperability with IDA Pro: Now using `ida_domain` if available, supporting headless IDB->SMDA report conversion. (THX: @r0ny123)
 * 2026-07-15: v4.2.14 - Improved consistency for capstone instance retrieval from SmdaReport. (THX: @r0ny123)
 * 2026-07-14: v4.2.13 - Adressed an issue where a lazy data structure caused issues after (un)marshalling.
 * 2026-07-14: v4.2.12 - Better exposure of getInstructionEscaper(), which no returns the correct instance based on the respective architecture.
 * 2026-07-14: v4.2.11 - Performance: skip redundant Aarch64 report-time data-ref re-derivation and complete the set.update([x]) -> set.add(x) sweep (both behavior-preserving). (THX: @r0ny123)
 * 2026-07-14: v4.2.10 - Aarch64: deduplicate shared raw-word GOT/reference decode constants and register-field helpers into definitions.py. (THX: @r0ny123)
 * 2026-07-14: v4.2.9 - Aarch64: shared constant-propagation dataflow module enabling cross-block indirect-call resolution and deeper jump-table recovery (predecessor-resolved bases/sizes, ldr+extend chains). (THX: @r0ny123)
 * 2026-07-14: v4.2.8 - Aarch64: architecture-aware report metrics (num_calls/num_returns/isApiThunk), indirect-jump PLT/GOT API attribution, and candidate-scan timeout guards. (THX: @r0ny123)
 * 2026-07-14: v4.2.7 - Intel x64: extended AMD64 prologue family (endbr64, callee-saved pushes, masked mov/sub openers) and exit_group / int 0x80 syscall-exit detection. (THX: @r0ny123)
 * 2026-07-13: v4.2.6 - Aarch64: FEAT_HBC bc.<cond>/drps classification, adrp+ldr+br API/GOT thunk detection, and stack-built string recovery. (THX: @r0ny123)
 * 2026-07-13: v4.2.5 - Core: hoist shared import-stub range helpers into ArchBackend and report the unsupported architecture in no-backend error reports. (THX: @r0ny123)
 * 2026-07-11: v4.2.4 - Cross-format loader parity: Mach-O fat-binary slice handling, Intel/AArch64 import stub resolution, and Mach-O Rust symbol demangling. (THX: @r0ny123)
 * 2026-07-10: v4.2.3 - Fix: function promotion bug caused by missing symbol type evaluation (THX: @r0ny123).
 * 2026-07-09: v4.2.2 - Now also parsing delay import tables from Windows PEs.
 * 2026-07-09: v4.2.1 - Better detection of CFG instructions with prefixes, improved accuracy of gap search. (THX: @r0ny123) IDA ARM64 export.
 * 2026-06-24: v4.2.0 - Further improvements for inter-procedural operand escaping (closer to x86_x64 and traditional PIC hashing).
 * 2026-06-23: v4.1.0 - Significantly extended Aarch64 mnemonic escapes and improved PIC/OPC hashing. (THX: @r0ny123)
 * 2026-06-23: v4.0.2 - Improvements to Aarch64 function recovery, adressing tailcalls and gap function cornercases.
 * 2026-06-23: v4.0.1 - Refactoring: improved and streamlined symbol parsing and metadata handling. (THX: @r0ny123)
 * 2026-06-12: v4.0.0 - Support for Aarch64! (THX: @r0ny123)
 * 2026-06-12: v3.4.2 - Minor bugfixes regarding corner case offset extraction and calculations. (THX: @r0ny123)
 * 2026-06-12: v3.4.1 - Added test payloads for various additional architectures. (THX: @r0ny123)
 * 2026-06-12: v3.4.0 - Now properly inferring architecture and bitness based on ELF headers. Information sources like symbols etc. are properly handled. (THX: @r0ny123)
 * 2026-06-12: v3.3.2 - Added ability to store binary input file/buffer using MCRIT's deflate+base85 method. (THX: @r0ny123)
 * 2026-06-12: v3.3.1 - Added safeguards intended to limit processing time and heap consumption explosions. (THX: @r0ny123)
 * 2026-06-12: v3.3.0 - Introdcued a performance benchmarking suite with profilers for execution and memory to verify and guide improvements. (THX: @r0ny123)
 * 2026-06-10: v3.2.1 - minor fixes, dependency bumps.
 * 2026-05-26: v3.2.0 - Several performance optimizations to reduce processing time. (THX: @r0ny123)
 * 2026-05-26: v3.1.0 - Repository structure changed to src-style, modernized overall package and CI procedures. (THX: @r0ny123)
 * 2026-05-20: v3.0.1 - Improved performance for string extraction by reducing type casts. (THX: @r0ny123)
 * 2026-05-20: v3.0.0 - Support for Android Dalvik disassembly. (THX: @r0ny123)
 * 2026-05-20: v2.6.0 - Use Pythia as drop-in replacement for current Delphi VMT parser. (THX: @r0ny123)
 * 2026-05-20: v2.5.4 - Improve performance by precompiling regexes, doing additional prefix extraction and covering more GAP sequence NOPs. (THX: @r0ny123)
 * 2026-03-23: v2.5.3 - Added ELF ABI to SmdaReport info, upgraded DelphiReSym to handle Delphi 13, slight performance improvements by removing redundant label extraction. (THX: @r0ny123)
 * 2026-01-16: v2.5.2 - Fixed bug in IdaInterface where binary data was unproperly extracted.
 * 2026-01-16: v2.5.1 - Reducing calls to lief by caching the object. (THX: @r0ny123)
 * 2026-01-16: v2.5.0 - Introduced Rust symbol extraction and demangling. (THX: @r0ny123)
 * 2026-01-16: v2.4.7 - Improved reliability of exception handler candidate extraction. (THX: @r0ny123)
 * 2026-01-07: v2.4.6 - Fixed version check for IDA compatibility decision
 * 2025-12-17: v2.4.5 - Improved security and reliability in various spots. (THX: @r0ny123)
 * 2025-12-15: v2.4.4 - Extended set of default prologues for additional 64bit GCC-style byte combinations. Added exit syscall check to improve function end recognition. (THX: @N0fix)
 * 2025-12-10: v2.4.3 - Compatibility issue for IDA export, API changes happened already in 8.5, so adjusted the version check.
 * 2025-11-28: v2.4.2 - Fix for a bug when extracting and merging code areas from section tables. (THX: @r0ny123)
 * 2025-11-28: v2.4.1 - Modernized packaging by also building a wheel. (THX: @dimbleby)
 * 2025-11-21: v2.4.0 - Integration of DelphiReSym by @WenzWenzWenz for Delphi VMT parsing, thanks to @r0ny123 for adapting it!!
 * 2025-10-21: v2.3.1 - Fixed lief error for section/segment flags in ELF files crashing file loading. Now properly parsing and providing symbol info for PEs in their own xmetadata section.
 * 2025-10-21: v2.3.0 - Major code refactor and cleanup, with many thanks to the contribution @r0ny123!!
 * 2025-07-25: v2.2.3 - Minor bugfixes.
 * 2025-07-23: v2.2.1 - Added xmetadata field to SmdaReport, with information about imports and exports. Improved string extraction from Go binaries.
 * 2025-06-13: v2.1.0 - Support for export from IDA 9.0+ (THX to @jershmagersh for the update!).
 * 2025-02-26: v2.0.2 - Adjusting relative import, adding init file.
 * 2025-02-25: v2.0.0 - Initial experimental support for CIL (.NET) disassembly.
 * 2025-01-29: v1.14.0 - Bump to LIEF 0.16.0+ (THX to @huettenhain for the ping!). Migrated tests to `pytest`, UTC datetime handling fixes.
 * 2023-11-21: v1.13.0  - BREAKING adjustments to PicHashing (now wildcarding intraprocedural jumps in functions, additionally more immediates if within address space). Introduction of OpcodeHash (OpcHash), which wildcards all but prefixes and opcode bytes.
 * 2023-03-24: v1.12.0  - SMDA now parses PE export directories for symbols, as well as MinGW DWARF information if available.
 * 2023-02-06: v1.11.0  - SmdaReport now has functionality to find a function/block by a given offset contained within in (THX to @cccs-ay!).
 * 2023-02-06: v1.10.0  - Adjusted to LIEF 0.12.3 API for binary parsing (THX to @lainswork!).
 * 2022-08-12: v1.9.1   - Added support for parsing intel MachO files, including Go parsing.
 * 2022-08-01: v1.8.0   - Added support for parsing Go function information (THX to @danielenders1!).
 * 2022-01-27: v1.7.0   - SmdaReports now contains a field `oep`; SmdaFunctions now indicate `is_exported` and can provide CodeXrefs via `getCodeInrefs()` and `getCodeOutrefs()`. (THX for the ideas: @mr-tz)
 * 2021-08-20: v1.6.0   - Bugfix for alignment calculation of binary mappings. (THX: @williballenthin)
 * 2021-08-19: v1.6.0   - Bugfix for truncation during ELF segment/section loading. API usage in ELF files is now resolved as well! (THX: @williballenthin)
 * 2020-10-30: v1.5.0   - PE section table now contained in SmdaReport and added `SmdaReport.getSection(offset)`.
 * 2020-10-26: v1.4.0   - Adding SmdaBasicBlock. Some convenience code to ease intgration with capa. (GeekWeek edition!)
 * 2020-06-22: v1.3.0   - Added DominatorTree (Implementation by Armin Rigo) to calculate function nesting depth, shortened PIC hash to 8 byte, added some missing instructions for the InstructionEscaper, IdaInterface now demangles names.
 * 2020-04-29: v1.2.0   - Restructured config.py into smda/SmdaConfig.py to similfy usage and now available via PyPI! The smda/Disassembler.py now emits a report object (smda.common.SmdaReport) that allows direct (pythonic) interaction with the results - a JSON can still be easily generated by using toDict() on the report.
 * 2020-04-28: v1.1.0   - Several improvements, including: x64 jump table handling, better data flow handling for calls using registers and tailcalls, extended list of common prologues based on much more groundtruth data, extended padding instruction list for gap function discovery, adjusted weights in candidate priority score, filtering code areas based on section tables, using exported symbols as candidates, new function output metadata: confidence score based on instruction mnemonic histogram, PIC hash based on escaped binary instruction sequence
 * 2018-07-01: v1.0.0   - Initial Release.

For full earlier history, check `version_history.md`.

## Credits

Thanks to Steffen Enders for his extensive contributions to this project!
Thanks to Paul Hordiienko for adding symbol parsing support (ELF+PDB)!
Thanks to Jonathan Crussell for helping me to beef up SMDA enough to make it a disassembler backend in capa!
Thanks to Willi Ballenthin for improving the handling of ELF files, including properly handling API usage!
Thanks to Daniel Enders for his contributions to the parsing of the Golang function registry and label information!
The project uses the implementation of Tarjan's Algorithm by Bas Westerbaan and the implementation of Lengauer-Tarjan's Algorithm for the DominatorTree by Armin Rigo.
Thanks to r0ny123 for his major code quality improvements via ruff and various contributions for several aspects of this project!

Pull requests welcome! :)
