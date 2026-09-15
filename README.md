# SMDA

[![PyPI version](https://img.shields.io/pypi/v/smda.svg)](https://pypi.org/project/smda/)
[![CI](https://github.com/danielplohmann/smda/actions/workflows/ci.yml/badge.svg)](https://github.com/danielplohmann/smda/actions/workflows/ci.yml)
[![Python versions](https://img.shields.io/pypi/pyversions/smda.svg)](https://pypi.org/project/smda/)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/danielplohmann/smda)

SMDA is a minimalist recursive disassembler library optimized for accurate Control Flow Graph (CFG)
recovery from memory dumps. It is based on [Capstone](https://www.capstone-engine.org/) and analyzes
PE, ELF and Mach-O files, .NET assemblies, raw DEX files, and arbitrary memory dumps (ideally with a
known base address).

The output is a tree of functions, basic blocks and instructions, with the edges between blocks and
between functions (in/out). On top of the recovered CFG, SMDA runs optional passes: symbol and label
recovery (imports, exports, PE/ELF symbols, PDB, Go and Rust metadata, Delphi VMTs), string
extraction, and inference of Windows API references via the
[ApiScout](https://github.com/danielplohmann/apiscout) method.

Two design decisions shape the results and are deliberate:

* **Completeness over precision.** Function entry point discovery is aggressive and followed by a
  linear gap scan, so false positives are accepted in exchange for recall.
* **A strict, IDA-style CFG model.** A function contains only instructions belonging to it, and
  instructions may not overlap.

SMDA is the disassembler backend used by [capa](https://github.com/mandiant/capa) and the code
analysis layer of [MCRIT](https://github.com/danielplohmann/mcrit), which is where the report format
and the escaping/hashing guarantees below matter.

## Installation

```
$ pip install smda
```

SMDA requires Python 3.11+. Runtime dependencies (`capstone<6`, `dncil`, `dnfile`, `lief`,
`pycxxfilt`, `purepdb`) are installed with it. Capstone is pinned below 6 because capstone 6 renames
the ARM64 modules and constants, and its compatibility shim does not cover all of them.

Extras: `smda[ida]` for headless IDA export (`ida-domain>=0.5.0`, IDA 9.1+), `smda[dev]` for the
test/lint toolchain, `smda[dev,profile]` for that plus the profiling toolkit in
[`profiling/`](profiling/README.md).

The command line scripts (`analyze.py`, `batch_analyze.py`, `export.py`, `ida_analyze.py`,
`ida_domain_export.py`) are not installed as console entry points -- they ship in the repository, so
clone it if you want them.

## Quick start

### Library

```
>>> from smda.Disassembler import Disassembler
>>> disassembler = Disassembler()
>>> report = disassembler.disassembleFile("/bin/cat")
>>> print(report)
 0.068s -> (architecture: intel.64bit, base_addr: 0x00000000): 140 functions
>>> for fn in report.getFunctions():
...     print(fn)
...     for ins in fn.getInstructions():
...         print(ins)
...
0x00002000: (->   0,    0->)   3 blocks,    8 instructions.
0x00002000: (      f30f1efa) - endbr64
0x00002004: (      4883ec08) - sub rsp, 8
0x00002008: (488b05b97f0000) - mov rax, qword ptr [rip + 0x7fb9]
0x0000200f: (        4885c0) - test rax, rax
[...]
>>> json_report = report.toDict()
```

The three entry points on `Disassembler`:

* `disassembleFile(file_path, pdb_path="")` -- parse the container, map it, analyze it.
* `disassembleUnmappedBuffer(file_content)` -- same, for a container already held in memory.
* `disassembleBuffer(file_content, base_addr, bitness=None, code_areas=None, oep=None, architecture="")`
  -- analyze a raw dump at a known base address.

`SmdaReport.toFile(path)` / `SmdaReport.fromFile(path)` write and read the JSON report,
`SmdaReport.toDict()` / `fromDict()` the same thing in memory.

### Raw buffers and the instruction set

`disassembleFile` reads the instruction set from the container header. `disassembleBuffer` has no
header to read, so it guesses: a mapped image still begins with its own headers and those are read
first, DEX and AArch64 are recognized from the bytes, and anything else is analyzed as x86. A buffer
holding ARM32, MIPS, PowerPC, SPARC, SH4, m68k, Xtensa, NIOS2 or OpenRISC code is recognized as well
and comes back as `status == "error"` naming the instruction set, rather than as a report whose
every block is wrong.

The guess is evidence, not proof: it looks for a run of that architecture's function-return
encoding, aligned, close enough together to be one code region, and not sitting inside text. Across
60939 files of every type on one machine it named nothing that was not that architecture and
recognized all ten bundled foreign samples, but it is biased towards silence, so **pass
`architecture=` whenever you know it** -- an explicitly named architecture is never overruled.

### Command line

```
$ python analyze.py /path/to/sample -o report.smda
```

`analyze.py` disassembles one file or dump and optionally writes the JSON report. Container formats
(PE, ELF, Mach-O, Delphi KB, DEX) are detected from the bytes and mapped automatically; anything
else is treated as a raw buffer. Passing `-a/--base_addr` or `-i/--oep` says the input is a dump
with a known mapping and selects raw buffer mode even for a file that starts with a container
header, while `-p/--parse_header` forces mapping in turn. The flags worth knowing:
`-a/--base_addr` (base address for a dump; also inferred from a `_0x<addr>` filename),
`-b/--bitness`, `-r/--architecture` (`intel`, `aarch64`, `cil`, `dalvik`; default auto),
`-p/--parse_header`, `-d/--pdb_path`, `-i/--oep`, `-s/--strings`, `-v/--verbose`.

### Batch mode

Disassembly is CPU-bound and every input file is independent, so corpora are processed in parallel:

```
$ python batch_analyze.py /path/to/corpus -o /path/to/reports
```

* `-w/--workers` defaults to all usable cores; `-w 1` is the serial reference.
* `-c/--resume` skips inputs whose report already exists in the output directory.
* `-m/--max_tasks_per_child` recycles workers after N files. It defaults to off, and measurement
  says that is usually right (see below).
* `-t/--timeout` sets the per-file analysis timeout; `0` disables it.

Reports are named after the input's path-relative stem, so identically-named samples in different
subdirectories cannot overwrite each other. Batch mode uses `disassembleFile`, so raw memory dumps
that need an explicit base address still belong in `analyze.py -a <base_addr>`.

The same thing is available as a library helper, which yields one summary dict per completed file:

```python
from smda.utility.BatchProcessor import disassembleParallel

if __name__ == "__main__":  # required: workers are spawned, so they re-import your module
    for summary in disassembleParallel(["/path/to/corpus"], output_dir="/path/to/reports"):
        print(summary["path"], summary["status"], summary["num_functions"])
```

Workers use the `spawn` start method, which re-imports the calling module in each child. Calling
`disassembleParallel` at import time therefore fails with a `multiprocessing` traceback -- keep the
call under a `__main__` guard (or inside a function that a guard invokes).

Peak memory is dominated by the single largest binary in flight, not by how many files a worker has
already processed. Measured over 136 real PE binaries in one worker, live Python objects grew by 9
across 105 files, so there is no per-file accumulation to bound; what is large is the per-file peak,
where one 3 MB binary reached roughly 1.8 GB resident on its own. Size the run by
`workers x per-file peak` -- four workers peaked at about 5.3 GB combined on that corpus. Recycling
every file (`--max_tasks_per_child 1`) cost 30% wall clock (86.6s to 112.3s) for 8% off the
single-worker peak, because it reclaims allocator high-water rather than a leak, so leave it off
unless a corpus shows otherwise.

Output does not depend on the number of workers, with one exception: `SmdaConfig.TIMEOUT` is
wall-clock, so under heavy oversubscription a slow sample can time out where a serial run finished.
Pass `--timeout 0` when output must be reproducible regardless of machine load.

## Supported targets

Backends:

| backend | code | maturity |
| --- | --- | --- |
| `intel` | x86 / x64 | production, benchmarked against other disassemblers |
| `aarch64` | ARM64 | consistent; matches IDA closely on the test corpora |
| `cil` | .NET / CIL, via `dnfile` / `dncil` | recent, solid on regular code, not benchmarked against obfuscated code |
| `dalvik` | Android DEX bytecode | recent, same caveat |

Containers:

| input | notes |
| --- | --- |
| PE | x86, x64, ARM64; a CLR header routes to the `cil` backend |
| ELF | x86, x64, AArch64 |
| Mach-O | x86, x64, ARM64, including fat/universal binaries |
| DEX | raw single-DEX files (`dex\n`) only |
| IDR knowledge base | Delphi `IDR Knowledge Base File` dumps |
| raw memory dump | any buffer, via `disassembleBuffer` with a base address |

Other machine types (ARM32, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, Xtensa, NIOS2, OpenRISC) are
*recognized* by the loaders so report metadata stays truthful, but there is no backend for them.

APK and multi-dex containers are not first-class Dalvik workflows, and ODEX (`dey\n`) / CDEX
(`cdex`) are not analysis-compatible at all (quickened ops / compact `code_item`): they raise an
explicit error under `architecture="dalvik"`, and auto-detect never selects the Dalvik backend for
those magics.

## Configuration

`SmdaConfig` is a plain attribute holder; set what you need and pass it to the `Disassembler`:

```python
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

config = SmdaConfig()
config.WITH_STRINGS = True
config.STORE_BUFFER = True
report = Disassembler(config).disassembleFile("/bin/cat")
```

The knobs most callers touch:

| option | default | effect |
| --- | --- | --- |
| `TIMEOUT` | `300` | cooperative analysis budget in seconds; `0` disables it |
| `MAX_IMAGE_SIZE` | `100 MB` | refuse to allocate more than this while loading |
| `STORE_BUFFER` | `False` | keep the raw buffer in the report, so data refs can be carved later |
| `WITH_STRINGS` | `False` | extract referenced strings |
| `API_COLLECTION_FILES` | `{}` | ApiScout WinAPI databases for API resolution in dumps |
| `CALCULATE_HASHING` / `CALCULATE_NESTING` / `CALCULATE_SCC` | `True` | optional per-function metadata (PIC hashes, nesting depth, SCCs) |
| `RESOLVE_TAILCALLS` | `False` | promote tailcall targets to functions of their own |
| `HIGH_ACCURACY`, `USE_*`, `RESOLVE_*`, `RECORD_*`, `CANDIDATE_QUEUE` | see source | candidate discovery; read by the `intel` and `aarch64` backends only |
| `MAX_FUNCTION_CANDIDATES`, `MAX_CALL_REFS_PER_CANDIDATE`, `MAX_INDIRECT_CALLS_PER_BASIC_BLOCK` | see source | safeguards against pathological input; do not disable them by default |

Windows API resolution via ApiScout needs profiles matching the target machine and works mainly on
memory dumps; for regular files, import-table parsing covers it. Every option is documented inline
in [`src/smda/SmdaConfig.py`](src/smda/SmdaConfig.py), several with the measurements behind their
default.

### Tuning analysis cost

The largest built-in performance lever is the optional per-function metadata: measured on the
bundled cutwail fixture, in Python calls per run (a stable metric, unlike wall-clock on a loaded
machine), hashing accounts for 10.0%, nesting 4.6% and SCC 3.2% of all calls, and disabling all
three removes 17.8%. Turn off whatever a downstream consumer does not read.

`RESOLVE_TAILCALLS` runs the other way round: it is off by default and buys recovery for time. Only
the `intel` and `aarch64` disassemblers read it -- `cil` and `dalvik` run their own pipelines and
ignore it. Where it applies, it promotes the target of a jump that leaves a function into a function
of its own, in a pass after gap analysis, so what it is worth depends on how much a binary
tail-calls. On `libstdc++.so.6` it adds 337 functions (8473 to 8810) for 40-130% more analysis time,
the spread being how much the measuring machine had to spare; on Go ELF and Mach-O memory images it
adds 8 functions each, for 20-26%. A jump into an already-recovered function is treated as a tailcall
either way -- only promoting targets that are not yet known needs this pass.

`TIMEOUT` bounds analysis cooperatively, not as a wall-clock guarantee. It is polled between
candidates, between passes, every 256 basic blocks within a function, between tailcall resolutions,
and inside the record walks that carve an exception table out of a headerless image; label providers
are exempt by design, since they parse before analysis begins and each caps its own table reads. The
verdict latches on first trip, so a function the budget cut short stays truncated rather than being
carved into a second one by the gap scan. It bounds how much *new* work is begun, not how long a
call takes to return, so a run overshoots by whatever was already in flight. A run that exceeded the
budget reports `status == "timeout"` and a function set that is a lower bound -- check the status
before comparing counts across samples, and impose your own ceiling if you need a hard one.

## Output format

`report.toDict()` produces the JSON report: file metadata (`sha256`, `binary_size`, `base_addr`,
`bitness`, `architecture`, `abi`, `code_areas`, `code_sections`, `oep`), `status` and `message`,
`smda_version`, `statistics`, `metadata` (including the language score map), `xmetadata` (symbols,
imports, exports), `xdata_refs_from`/`xdata_refs_to`, and `xcfg` -- the functions, keyed by offset.

Each function carries `blocks` (block offset to instruction list), `blockrefs`, `inrefs`, `outrefs`,
`apirefs`, `stringrefs`, `is_exported`, `architecture_metadata` and a `metadata` dict with
`function_name`, `pic_hash`, `confidence`, `binweight`, `nesting_depth`,
`strongly_connected_components` and `tfidf`. An instruction is a compact list of offset, bytes and
mnemonic/operands; `SmdaInstruction` exposes it with accessors.

### What an offset means

`SmdaFunction.offset`, the basic-block keys and `SmdaInstruction.offset` are **virtual addresses**
(`base_addr` plus an RVA) on `intel` and `aarch64`. On the two managed backends they are **file
offsets**: the method body in the assembly for `cil`, the code item in the DEX for `dalvik`.

The two are not the same kind of number, so correlating a managed report with a native one -- or
either with another tool's output -- compares two different address spaces. `report.architecture` is
the field to branch on before treating an offset as an address. Do not read `metadata.language` as
the backend: it is a source-language score map, and while it happens to carry a single decisive entry
on the two managed backends (`{'.net': 1.0}`, `{'dalvik': 1.0}`), on a native one it is a
distribution that includes a `.net` score -- so branching on `.net` appearing in it can read a native
report as managed, which is the exact mistake this section exists to prevent.

The two managed cases differ in why. A CIL method has an RVA, and reporting the file offset instead
is a choice; a DEX carries no load address at all, so the file offset is the only address there is.
Either way, adding `base_addr` to one of them produces a number that means nothing. This is recorded
rather than corrected: the offsets are a public compatibility surface that downstream consumers index
on, so changing which space they are in is a deliberate decision and not a bug fix.

### Labels and language

`metadata.language` is always a score map (`language name -> float`). Internal guesses and evidence
counters are not serialized; loading an older report normalizes its legacy string form to this
contract. To pick a single language, take the highest score, except that `go` and `rust` win outright
when their score exceeds 0.5 -- a build ID, pclntab header, or demangled Rust symbol is conclusive,
while the other scores are graded evidence.

For ELF files, `xmetadata.exported_symbols` contains all defined dynamic exports (functions and data)
keyed by virtual address, while the legacy `exported_functions` and `symbols` maps remain
function-only. C++ names are demangled in these label maps; API references (`SmdaFunction.apirefs`)
keep the undecorated import name so they stay comparable across PE, ELF and Mach-O.

### Escaper output compatibility

Anything that stores escaped-operand signatures -- minhashes and escaped-block shingles, as MCRIT
does -- has to know when SMDA's escaping itself changed, because a hash computed under the older
escaping will not match one computed now. Two kinds of marker carry that, and they move
independently:

* `SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY` (currently `"4.4.5"`) covers mnemonic groups and
  escaped operands, which is what `getMnemonicGroup` and `getEscapedOperands` produce.
* The per-architecture pic-hash markers in `smda.common.SmdaFunction` cover the separate
  `escapeBinary` path: `INTEL_PIC_HASH_ESCAPE_VERSION` (`[4, 3, 5]`),
  `AARCH64_PIC_HASH_ESCAPE_VERSION` (`[4, 2, 0]`), `CIL_PIC_HASH_ESCAPE_VERSION` (`[4, 3, 8]`) and
  `DALVIK_PIC_HASH_ESCAPE_VERSION` (`[4, 4, 2]`).

A report whose `smda_version` is below the relevant marker was produced under different escaping, so
its stored hashes have to be recomputed before they can be compared against current ones. If you
change an `InstructionEscaper`'s output, bump the matching constant in the same commit;
`tests/testEscaperFingerprint.py` hashes a committed corpus of escaped representations and fails when
the output moves, which is the reminder to do it.

## IDA Pro integration

SMDA can turn an IDA-analyzed database into a SMDA report instead of running its own disassembly.
Inside the IDA GUI it supports IDA Pro 8.4 and newer (`IDA_SDK_VERSION >= 840`); older SDK
generations are rejected. On IDA 9.1+ it prefers the higher-level
[IDA Domain API](https://ida-domain.docs.hex-rays.com/) when the optional package is installed, and
otherwise falls back to IDAPython.

Inside the IDA GUI (*File -> Script file...*):

* `export.py` exports IDA's existing analysis to a `.smda` file next to the database.
* `ida_analyze.py` has SMDA independently recover functions from the loaded bytes and adds missing
  function starts and names back to IDA. This is useful where IDA analyzes a raw or mapped buffer
  conservatively.

For headless export (no GUI), use `ida_domain_export.py`:

```
python -m pip install "smda[ida]"
python ida_domain_export.py /path/to/sample.i64 -o sample.smda
```

Headless export requires IDA 9.1+ and the optional `ida-domain>=0.5.0` dependency; standard SMDA
installations do not include it. Make sure `IDADIR` points at the IDA installation when it cannot be
discovered automatically (see the
[getting started guide](https://ida-domain.docs.hex-rays.com/getting_started/)).

## Experimental: binary synthesis

`SmdaReport.synthesizeBinary()` rebuilds a fictive PE, ELF or Mach-O file from a recovered CFG. The
output plants function bytes per basic block at their original VAs and fuses import metadata,
producing binaries that parse cleanly with LIEF and can be loaded into analysis tools (IDA, Ghidra,
Binary Ninja). Synthesis is deterministic from report content only and does not need the stored
buffer; it is not available for `cil` and `dalvik` reports. The feature is experimental: it works on
well-formed reports but has not been hardened against pathological or adversarial inputs.

## Development

```bash
make init          # pins pip/setuptools/wheel, installs -e ".[dev]", installs pre-commit hooks
make test          # fast tier (deselects the `slow` marker)
make test-all      # everything; run this before pushing
make lint format   # ruff check / ruff format
make typecheck     # ty
```

Pull requests welcome; [`CONTRIBUTING.md`](CONTRIBUTING.md) is what a change has to clear before one
is opened, and [`AGENTS.md`](AGENTS.md) the pipeline, conventions and constraints behind that.
[`CHANGELOG.md`](CHANGELOG.md), [`RELEASING.md`](RELEASING.md), [`SECURITY.md`](SECURITY.md),
[`fuzzing/`](fuzzing/README.md) and [`profiling/`](profiling/README.md) cover the rest.

Bugs and feature requests go through the
[issue forms](https://github.com/danielplohmann/smda/issues/new/choose); a crash reachable from a
crafted input is a security report, not an issue.

## Credits

Thanks to Steffen Enders for his extensive contributions to this project!
Thanks to Paul Hordiienko for adding symbol parsing support (ELF+PDB)!
Thanks to Jonathan Crussell for helping me to beef up SMDA enough to make it a disassembler backend in capa!
Thanks to Willi Ballenthin for improving the handling of ELF files, including properly handling API usage!
Thanks to Daniel Enders for his contributions to the parsing of the Golang function registry and label information!
The project uses the implementation of Tarjan's Algorithm by Bas Westerbaan and the implementation of Lengauer-Tarjan's Algorithm for the DominatorTree by Armin Rigo.
Rust symbol demangling is derived from the rust_demangler package by Team bi0s (MIT), with behaviour reimplemented from Ghidra's Rust demanglers (Apache-2.0); see [NOTICE](NOTICE) for the full list of third-party components.
Thanks to r0ny123 for his major code quality improvements via ruff and various contributions for several aspects of this project!

## License

BSD 2-Clause, see [LICENSE](LICENSE). Third-party components and their licenses are listed in
[NOTICE](NOTICE).
