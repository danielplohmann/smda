
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

### Batch mode

Disassembly is CPU-bound and every input file is independent, so corpora are processed in parallel:

```
$ python batch_analyze.py /path/to/corpus -o /path/to/reports
```

* `-w/--workers` defaults to all usable cores; `-w 1` is the serial reference.
* `-c/--resume` skips inputs whose report already exists in the output directory.
* `-m/--max_tasks_per_child` recycles workers after N files. It defaults to off, and measurement says that is usually right (see memory notes below).
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
`disassembleParallel` at import time therefore fails with a `multiprocessing` traceback - keep the
call under a `__main__` guard (or inside a function that a guard invokes).

#### Memory

Peak memory is dominated by the single largest binary in flight, not by how many files a worker has
already processed. Measured over 136 distinct real PE binaries in one worker: live Python objects
grew by 9 across 105 files, and resident memory oscillated inside a stable band instead of trending
up, so there is no per-file accumulation to bound. What is large is the per-file peak - one 3 MB
binary reached roughly 1.8 GB resident on its own.

Size the run by `workers x per-file peak`: on the same corpus, four workers peaked at about 5.3 GB
combined. Reduce `--workers` on a memory-constrained machine. Recycling every file
(`--max_tasks_per_child 1`) cost 30% wall clock (86.6s to 112.3s) while cutting the single-worker
peak by only 8%, because it reclaims allocator high-water rather than a leak - so leave it off
unless a specific corpus shows otherwise.

Output does not depend on the number of workers, with one exception: `SmdaConfig.TIMEOUT` is
wall-clock, so under heavy oversubscription a slow sample can time out where a serial run
finished. Pass `--timeout 0` when output must be reproducible regardless of machine load.

### Tuning analysis cost

The largest built-in performance lever is the optional per-function metadata in `SmdaConfig`:
`CALCULATE_HASHING` (PIC hashes), `CALCULATE_NESTING` (nesting depth) and `CALCULATE_SCC`
(strongly connected components). Measured on the bundled cutwail fixture, in Python calls per
run (a stable metric, unlike wall-clock on a loaded machine): hashing accounts for 10.0%,
nesting 4.6% and SCC 3.2% of all calls, and disabling all three removes 17.8%. Turn off whatever
a downstream consumer does not read.

`RESOLVE_TAILCALLS` runs the other way round: it is **off** by default and buys recovery for time.
It promotes the target of a jump that leaves a function into a function of its own, in a pass after
gap analysis, so what it is worth depends on how much a binary tail-calls. On `libstdc++.so.6` it
adds 337 functions (8473 to 8810) for 40-130% more analysis time, the spread being how much the
measuring machine had to spare; on Go ELF and Mach-O memory images it adds 8 functions each, for
20-26%. A jump into an already-recovered function is treated as a tailcall either way — only
promoting targets that are not yet known needs this pass.

Analysis is also bounded by `TIMEOUT` (300s by default). A run that hits it comes back with
`status == "timeout"`: the function set is a lower bound, not the whole binary. Check the status
before comparing counts across samples, and pass `TIMEOUT = 0` to disable the bound entirely.

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
python3 -m pip install --upgrade pip "setuptools>=64.0.0,<83.1.0" "wheel>=0.47.0"
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

## Version History

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## Credits

Thanks to Steffen Enders for his extensive contributions to this project!
Thanks to Paul Hordiienko for adding symbol parsing support (ELF+PDB)!
Thanks to Jonathan Crussell for helping me to beef up SMDA enough to make it a disassembler backend in capa!
Thanks to Willi Ballenthin for improving the handling of ELF files, including properly handling API usage!
Thanks to Daniel Enders for his contributions to the parsing of the Golang function registry and label information!
The project uses the implementation of Tarjan's Algorithm by Bas Westerbaan and the implementation of Lengauer-Tarjan's Algorithm for the DominatorTree by Armin Rigo.
Thanks to r0ny123 for his major code quality improvements via ruff and various contributions for several aspects of this project!

Pull requests welcome! :)
