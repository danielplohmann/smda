# MSVC Function-Boundary Fixtures (issue #384)

Minimal MSVC-built DLLs, each with its PDB, for function-boundary regression tests. They reproduce three ways SMDA splits or loses functions in MSVC /O2 code (see [#384](https://github.com/danielplohmann/smda/issues/384)):

1. **Shrink-wrapped arm64 prologues (without a PDB):** an early-exit check runs before `stp x19, x20, [sp, #-N]!`, and SMDA starts a function at the `stp`. Cases: `case_a2_unistr`, `case_a3_concat`, both static and reached only through a function-pointer table.
2. **A block after a `ret` reached only by a conditional branch (x86 / x64, with and without a PDB):** SMDA cuts the block out into a separate function. Case: `case_b2_whitespace`.
3. **An x86 jump table in `.text` decoded as code:** the misaligned decoding runs into the next function, so that function is lost, even with an export and a PDB. Case: `case_b3_control`, whose table directly precedes `case_b4_aggregate`.

The code is written for these tests (`src/`). It contains no third-party or malware code.

## Layout

```text
msvc_smda384_corpus/
  manifest.json
  msvc_smda384_{x86,x64,arm64}_O2_xored       the DLLs
  msvc_smda384_{x86,x64,arm64}_O2_pdb_xored   their PDBs
  src/cases.c, src/helpers.c, src/repro.h
```

Both files of a build are XOR-obfuscated with `byte ^ (index % 256)`, like the other fixtures. De-XOR them in memory only.

`manifest.json` records per fixture:
- the raw and xored sha256 of the DLL and the PDB;
- the base address;
- the toolchain and the exact flags;
- `expected_functions`: the functions of `cases.obj` from the linker map, with address, name and static / public;
- `known_failures_smda_4_9_0`: what SMDA 4.9.0 does with and without the PDB.

The expectation: each expected function is one SMDA function starting at its address, with no other SMDA function starting inside it.

## Build

VS 2026 Build Tools (cl 19.51.36260, link 14.51.36260, VCTools 14.51.36231, SDK 10.0.26100), built on GitHub's `windows-2025` runner in a neutral directory:

```text
cl /nologo /c /O2 /MD /Zi /FS /W3 /Brepro src\cases.c  (and src\helpers.c)
link /nologo /DLL /DEBUG:FULL /INCREMENTAL:NO /Brepro /OPT:REF /OPT:NOICF
     /MACHINE:{X86,X64,ARM64} /PDBALTPATH:%_PDB% /MAP cases.obj helpers.obj
```

arm64 is cross-compiled from the x64 host (`amd64_arm64`).
- **/OPT:NOICF** keeps identical functions apart, so every name has its own address.
- **/Brepro** makes the output reproducible.
- **/PDBALTPATH:%_PDB%** records only `repro.pdb` in the DLL.

The helpers live in a separate translation unit and there is no `/GL`, so calls stay calls and the callers keep callee-saved registers live. That is what produces the prologues.
At /O1 all three architectures come out intact with SMDA 4.9.0, so only /O2 is included.
