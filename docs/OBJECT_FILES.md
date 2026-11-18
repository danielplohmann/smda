# Relocatable objects

SMDA accepts ordinary little-endian x86/x64 ELF relocatable objects (`.o` and
uncompressed `.ko`) and conventional COFF objects (`.obj`) through
`Disassembler.disassembleFile()`. No compiler, linker, kernel loader or analyzed
program runs during analysis. Static archives (`.a` and `.lib`) are not supported.

These inputs have no final load addresses. SMDA assigns allocated sections
deterministic analysis addresses in section-table order, beginning at
`0x10000000`, honors their alignment, zero-fills BSS/common storage and applies
supported relocations. Function offsets of zero in different sections remain
distinct. The SHA-256 still identifies the original file, not this derived
analysis image. Addresses and bytes in the mapped view are not those of an
upstream final linked image.

`report.xmetadata["object_image"]` records the input format, layout policy,
section addresses, symbol aliases, known function sizes, the number of applied
relocations and unresolved external symbols. The individual relocation records
stay on `binary_info.object_image.relocations` and are not serialized. Unknown
externals receive analysis-only addresses directly after the mapped image; no
executable stub or implementation is supplied. Aliases share one recovered body. Ordinary C++ decorations use the
same readable-name logic as linked images.

Sized ELF symbols of at most 64 bytes containing only decoded NOP padding and ending at another
declared function entry are preserved as symbol aliases but are not seeded as
function entries. Trap-only bodies remain eligible. This is based on bytes
and extents rather than a `__pfx_` naming rule. For objects, known function
extents prevent a guessed interior prologue from splitting an existing body;
explicit function-symbol starts remain eligible, and calls located inside a
known extent still count as references to their targets. COFF function-definition
auxiliary sizes are used when present. Objects without such sizes still depend
on the normal recovery heuristics and may have fragmented/unnamed code.

## Initial scope

Supported ELF relocations:

* x86: `R_386_32`, `PC32`, `PLT32`, `GOT32`, `GOTOFF`, `GOTPC`, `GOT32X`.
* x64: `R_X86_64_64`, `PC32`, `PLT32`, `GOTPCREL`, `32`, `32S`, `PC64`,
  `GOTPCRELX`, `REX_GOTPCRELX`.

Supported COFF relocations:

* x86: `DIR32`, `DIR32NB`, `REL32`, `SECTION`, `SECREL`.
* x64: `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32` through `REL32_5`, `SECTION`,
  `SECREL`.

Absolute/no-op relocation entries are skipped. COFF weak externals resolve to
their default symbol and are not listed as unresolved. COFF debug symbols such
as `.file` are ignored. Input that starts with a COFF machine value but whose
section or symbol table does not fit the file is not treated as an object. TLS, compressed allocated ELF
sections, ELF extended section numbering, unsupported architectures/relocations,
COFF relocation-overflow tables, and unsupported weak-external modes are
explicit errors. Bigobj and COFF import-object variants are not recognized by
this initial object loader. COMDAT sections are retained within an individual
object; SMDA does not perform link-time selection across separate objects.
There is no archive iteration, decompression, dependency linking or kernel
version emulation. Non-code objects are refused rather than scanning their
data as machine instructions.

Malformed table/section/symbol bounds and relocation overflows fail analysis.
The existing maximum image size bounds section/GOT/common allocations.
`MAX_OBJECT_SYMBOLS` (250,000), `MAX_OBJECT_RELOCATIONS` (1,000,000), and
`MAX_OBJECT_NAME_LENGTH` (4,096 bytes) bound object-table bookkeeping; zero
disables the corresponding limit.
Symbols whose targets are outside allocated sections are not silently mapped
to arbitrary code. The existing linked-image loaders and CIL backend are kept;
there is no new hash-escape version or report-format version.

## Verification

`tests/testObjectFileLoader.py` constructs harmless ELF32/ELF64 and COFF32/COFF64
objects in memory. Tests cover section-relative zero symbols, call and data
relocations, negative addends, weak externals, debug symbols, BSS/common alignment, external references, padding and aliases,
known function extents, readable names, report serialization, malformed input,
allocation bounds and the continued exclusion of archives.

An optional real-file regression uses Ubuntu's `crc32_generic.ko` from
`linux-modules-6.8.0-31-generic`, version `6.8.0-31.31`:

* Package URL: https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-6.8.0-31-generic_6.8.0-31.31_amd64.deb
* Package SHA-256, checked against Ubuntu's noble main package index:
  `3f17f2c279257eb50e40da44390bdf8272c440ca078831c348773d1314b5c2fe`.
* Extracted module SHA-256:
  `8dcf24cc22b706cc3ee8d8c3368b0ba42a45441198af5ba44c5de60be1567982`.

The test requires an already extracted, uncompressed file and performs no
network access or module loading:

```sh
SMDA_TEST_KO_FILE=/path/to/crc32_generic.ko pytest tests/testObjectFileLoader.py
```

It checks all nine distinct CRC32 bodies against the original ELF symbol
addresses, sizes and independent instruction counts, plus the init/cleanup
aliases. Without this exact supplied file the optional regression is skipped;
the synthetic object tests still run. Neither the module nor a package archive
is committed as a fixture. This is evidence for one real module, not a claim
that every kernel version, architecture or object dialect is supported.
