# Delphi integration audit — 2026-10-26

Baseline: SMDA `04652e6` (5.0.1). Upstream: DelphiReSym
`22ad5f7cbe2b5f07487df96a9dfec1566e9a96b5`. Independent reference: the official
Ghidra **12.2** release, with its published ZIP SHA-256 verified. Java 25 and
PyGhidra 3.2.0 were used. None of the input executables were executed.

## Integration and provenance

`e1ca7b1` imported the algorithm in November 2025. `02be949` added the namespace
parser and purported upstream RTTI validation in January 2026. That adaptation
invented a byte between the class name and the first class-RTTI pointer.
`0d7dc3c` subsequently reused that shifted pointer offset to locate the namespace,
turning a pointer-validation error into a namespace-decoding error as well.
The original upstream fix, `45f9cb1`, caught inaccessible RTTI and removed the
associated false-positive VMT; it did not add this byte. `e6b4176` only regrouped
the arithmetic, without correcting the layout.

SMDA maps PE sections into an RVA-indexed buffer before invoking the providers.
Subtracting `base_addr` is correct for this buffer, but it does **not** convert a
VA into an on-disk file offset. The provider now documents this distinction.
`DelphiReSymProvider` supplies names and extended method-table entry points;
`DelphiPythiaProvider` also supplies legacy, fixed, virtual, dynamic and interface
method candidates. The recursive engine and language analyzer previously created
separate instances and repeated both Delphi scans. The analyzer now shares the
engine's updated providers, while retaining standalone operation.

Ghidra classes, namespaces, data types, VMT structures and signature objects are
not SMDA report objects. Porting their mutation code would not preserve those
semantics in SMDA. Qualified names and signatures remain flat symbol labels;
function bodies, block edges and fingerprints remain the recursive engine's job.

## Confirmed problems and fixes

| Problem | Origin and evidence | Resolution |
|---|---|---|
| Class RTTI pointers and unit namespace shifted by one byte | Port regression; thesis table 8, upstream traversal and both real architecture fixtures agree | Use the encoded name's byte length, then the two packed pointers and property-count word |
| Mostly unusable labels despite apparently successful extraction | Shifted namespace decoded binary data into strings; on the uploaded sample only 292 of 7,955 raw entries survived `getSymbol()` | Reject corrupt components before inserting symbols; preserve printable names |
| UTF-8 names corrupt following field offsets | Upstream reads individual bytes as characters; decoded character count differs from encoded byte count | Decode UTF-8, with Windows-1252 fallback; retain byte lengths for all cursor arithmetic |
| Published entries misread as an extended-reference count/table | Upstream and port assume the first method-table count is zero | Traverse length-delimited published entries before reading the extended count |
| Parsing beyond a method's declared length | Both implementations ignore the method-length boundary | Bound names, return metadata and parameters to that record; retain a valid method name if optional signature data is corrupt |
| Non-executable method addresses become symbol candidates | Neither original extractor validates every recovered method target | Validate against all executable ranges; reject data targets, including upstream's `TCustomDecompressor.Reset` entry in both Inno 7.1 stubs |
| First executable region treated as the entire image | Upstream `.text` assumption and port's `code_areas[0]` shortcut | Scan mapped metadata independently of code permissions; use merged code ranges only for function targets |
| MDT must follow its VMT and lie in code | Inherited heuristic, not a format requirement | Accept mapped metadata before or after the VMT; validate VMT class identity and method targets instead |
| Unreadable VMT fields silently omitted from validation | Inherited permissive validation | Require a complete header, class name, fixed method slots and consistent class RTTI when present |
| External ancestor or optional table pointer discards otherwise usable VMT methods | Port-specific ReSym check and inherited Pythia metadata check | Do not dereference external pointers; keep fixed in-image slots and parse only bounded mapped tables |
| Shared legacy tables are reparsed for every class; malformed method names can cross table records | Pythia port; especially costly on aliases and unsafe on damaged metadata | Cache table walks for one provider update and bound each name to its declared record |
| Pythia layout heuristics can run on non-x86 images; interface pointer walks have no bound | Port-specific architecture and hostile-input gaps | Gate to Intel binaries and cap interface walks at 4,096 entries |
| Empty parameter list deletes an entire upstream class | Upstream `if not params: del ...`; observed additional static `TThread` methods | Preserve zero-parameter methods; reject only the defective optional signature |
| Failed non-null return-type lookup represented as `void` | Port fallback loses the distinction between absent and unresolved type information | Use `?` for an unresolved return type |
| Duplicate names/corrupt parameter sets | Upstream issues #6/#8; invalid Delphi signatures | Drop the defective signature, preserve the method and continue the binary |
| Valid named `tkUnknown` types rejected | Official `TTypeKind` includes zero | Preserve their available names without guessing a layout |
| Hostile counts and repeated references can multiply work | Count fields and aliases are attacker-controlled | Bound record traversal and cache repeated type lookups; configurable `MAX_DELPHI_METADATA_ENTRIES`, default 1,000,000; zero disables extraction |
| Partial results lost when the metadata budget expires | Budget enforcement must bound parsing, not discard completed records | Preserve already parsed method names and stop subsequent traversal |
| Shared code acquires a later derived class's name | Multiple metadata names can identify one address | Deterministic first-qualified-name precedence, preferring available signature information; one address still has one report label |
| PDB supplementation clears Delphi and other non-PDB providers | Engine routes the empty PDB-only buffer to every provider | Route PDB updates only to the PDB provider; test Delphi label survival |
| Valid ReSym-only classes do not enable Delphi-specific recovery | Language evidence previously consulted only Pythia | Reuse validated ReSym evidence when the legacy scan finds nothing |
| Missing normal-flow continuation after a Delphi finally block | Independently exposed by Ghidra constructor bodies and checked in machine code | In 32-bit structurally identified Delphi, match the saved continuation, `pop eax; jmp eax`, handler thunk and cleanup back-edge; recover the continuation in its owning function |

The finally resolver deliberately requires a local saved continuation and rejects
explicit stack mutations inside the matched cleanup. It does not invent exception
edges, absorb the separate handler thunk into its caller, or claim to reconstruct
all Delphi EH personalities. Runtime or imported calls with unknown stack effects
remain a limitation of static CFG reconstruction.

## Upstream issues and pull requests

All 12 issue/PR records, including open and closed entries and their available
comments, were reviewed on the audit date. Closed PR patches were also compared
against repository history. Numbers link to the upstream discussion.

| Record | Finding and applicability |
|---|---|
| [#1](https://github.com/WenzWenzWenz/DelphiReSym/pull/1), closed | Cancellation/types. Ghidra monitor integration is not an SMDA API. SMDA's parsing now has its own bounded metadata work. |
| [#2](https://github.com/WenzWenzWenz/DelphiReSym/issues/2), open | Ghidra template display simplification. No SMDA display setting to port; complete generic names are preserved. |
| [#3](https://github.com/WenzWenzWenz/DelphiReSym/pull/3), closed | Type/VT construction collaboration. Ghidra data-type behavior is not represented by SMDA's flat labels. |
| [#4](https://github.com/WenzWenzWenz/DelphiReSym/pull/4), closed | Shifted VT pointer types. SMDA does not create these Ghidra pointer types. |
| [#5](https://github.com/WenzWenzWenz/DelphiReSym/issues/5), closed | Delphi 7 uses `CODE`, not `.text`, and older tables. Its attached binary was included in the audit; SMDA retains legacy recovery through Pythia. |
| [#6](https://github.com/WenzWenzWenz/DelphiReSym/issues/6), closed | Malformed duplicate parameters abort Ghidra signature application. Structural record checks and per-method degradation address the parser side. |
| [#7](https://github.com/WenzWenzWenz/DelphiReSym/issues/7), closed | Per-byte JPype crossings dominate scanning. SMDA has no JPype crossing, but had its own per-byte Python reader overhead. |
| [#8](https://github.com/WenzWenzWenz/DelphiReSym/pull/8), merged | Catch `DuplicateNameException`. No equivalent Ghidra exception is needed in SMDA. |
| [#9](https://github.com/WenzWenzWenz/DelphiReSym/pull/9), merged | Bulk NumPy scan, limited to 32-bit, with bytewise fallback. Replaced in SMDA by a dependency-free exact candidate filter for both widths. |
| [#10](https://github.com/WenzWenzWenz/DelphiReSym/issues/10), open | Non-ASCII/misdecoded names abort renaming. Decode names appropriately and preserve Unicode in SMDA; bound and validate encoded strings. |
| [#11](https://github.com/WenzWenzWenz/DelphiReSym/issues/11), open | Final x64 VT pointer represented as four bytes in Ghidra. This concerns Ghidra structure construction, which SMDA does not port. |
| [#12](https://github.com/WenzWenzWenz/DelphiReSym/pull/12), open | Proposed ASCII-only cleanup removes underscores, generic syntax and non-ASCII characters. Not adopted: it destroys valid names and can cause collisions. |

The upstream Ghidra type table also maps `UInt64` to a four-byte
`UnsignedIntegerDataType`, and maps Delphi `string` to a pointer to `Char` despite
the Unicode string representation. SMDA does not inherit these errors because it
does not construct Ghidra data types; its output records the parsed type name only.

## Papers and technical evidence

Read Wenz's *Towards Ghidra Reverse Engineering Tools for Delphi Executables*
(thesis, November 22, 2025), including format tables 2–10, methodology, tool design,
evaluation and limitations, and the associated August 18, 2025 presentation.
The Git repository contains Git LFS pointers for both PDFs; the actual PDF objects
were retrieved, rather than treating those pointer files as documents.

- [Thesis](https://github.com/WenzWenzWenz/DelphiReSym/blob/main/Academic_work_v2.pdf),
  SHA-256 `9ecb96009a6c136328a38ae94bbb4d53f4a9bcd4983f338ac3126ba4a1f5f080`.
- [Slides](https://github.com/WenzWenzWenz/DelphiReSym/blob/main/Presentation_slides_v1.pdf).
- [Official TTypeKind documentation](https://docwiki.embarcadero.com/Libraries/Athens/en/System.TypInfo.TTypeKind).
- Tagged Inno Setup build READMEs establish Delphi 2009 Update 3, 10.3.3 Rio and
  12.3 Athens compiler provenance; see the manifest's evidence URLs.

The thesis explicitly calls its evaluation **transformation coverage, not semantic
correctness**. Its approximately 31–54% name-recovery figures are not precision or
recall against source-level ground truth. Its claim that all Delphi 2010–12 layouts
are compatible also rests on sampled versions, with missing 2009/2010 binaries.
Neither claim substitutes for validation of this port.

## Empirical results

The eight-binary corpus includes 32/64-bit release executables, real VCL and RTL
metadata, legacy `CODE` images, signed installers with overlays, and the supplied
sample. Public source/download URLs, executable SHA-256 values and archive hashes
are in [manifest.json](manifest.json). The uploaded binary and complete third-party
executables are not redistributed in this repository.

The uploaded sample is SHA-256
`1d4e54529feef53850f97f39029a906d53f3d4b2aea8373e27c413324a55681c`:

- Original raw metadata entries: **7,955**, with only **292 usable labels**.
- Revised metadata entries: **7,969**, all printable and usable; every entry is
  recovered as an SMDA function start.
- Unmodified upstream extractor in Ghidra: **7,911** named entries. All are retained
  by SMDA, with zero namespace disagreements on the common entries. SMDA adds 58.
- Stock Ghidra 12.2: **8,336** functions. Metadata gives independent evidence for
  functions absent from its default recursive analysis.
- Metadata fixes alone preserve all **20,486** original SMDA functions and CFGs.
  The finally-continuation correction subsequently recovers additional reachable
  code, producing **20,950** functions. This is a deliberate CFG/fingerprint change.

The Inno Setup 5.6.1 executable is tagged as Delphi 2009 Update 3, but only 84,992
of its 1,963,136 bytes map into the PE image. Its code section is named `CODE`;
SMDA scans it and rejects three self-pointer lookalikes because their VMT fields
are machine code, recovering no Delphi labels. Upstream stops earlier at its
`.text`-only lookup. This checks the section-name edge case from issue #5; the
small mapped stub does not establish Delphi 2009 method-table coverage.

The Delphi 7 executable attached to upstream issue #5 also has a `CODE` section
and no `.text`; the unmodified extractor exits with `.text segment not found`.
SMDA's legacy Pythia path yields 3,873 method candidates, 224 with usable names,
while ReSym yields none on this older layout. Ghidra 12.2 reports 6,537 functions.
This exercises the legacy recovery path on the actual issue binary.

The upstream comparison invokes its unmodified extraction functions inside Ghidra;
it does **not** count partially successful GUI renaming, overwrite types, or treat
Ghidra's process exit status as proof that a script succeeded. The upstream README
asks users to run its mutating script twice; this audit's extraction comparison
requires no second mutation pass.

The audit CLI writes machine-readable measurements to the directory passed with `--output`.
Function-count differences are **not** automatically false positives or negatives.
For example, the supplied sample's compressed switch tables contain real cases
missing from Ghidra's recovered bodies; conversely, Ghidra exposed the constructor
continuation bug fixed here. The saved-continuation pattern also establishes
normal-flow blocks absent from Ghidra's analysis, so raw agreement can decrease
when SMDA becomes more complete. No source-ground-truth precision percentage is
claimed.

## Performance

The original ReSym scanner read and unpacked every byte position. The optimized scanner
partitions candidate addresses into windows within which the upper pointer bytes
are constant. Native `bytes.find` locates that necessary suffix, after which the
entire pointer and VMT are checked. Carry boundaries, the final readable pointer,
unaligned candidates and pointer-width overflow are covered by bytewise-oracle tests.
There is no NumPy dependency or input-sized temporary vector.

Other measured changes: native `unpack_from` avoids pointer slices; entire VMT
headers are unpacked together; string printability is checked in C; repeated RTTI
lookups are cached only for the current update; temporary records use slots;
redundant namespace validation/parser construction and an unused inheritance graph
are removed; legacy metadata tables are deduplicated; and engine/analyzer scans
share provider results. Long-lived per-method/table caches were tried and removed
after profiling showed a memory regression.

On five-run medians in this environment, the supplied sample's ReSym provider pass
fell from **1.100 s to 0.084 s**, and 64-bit HeidiSQL from **5.467 s to 0.209 s**.
These are provider timings, not whole-disassembler speedups, and include accuracy
fixes. A separate alternating experiment against the previous corrected scanner
asserted identical symbol dictionaries: the new scan reduced that revision's total
provider time by approximately 2.8x on the upload and 6x on 64-bit HeidiSQL.
Pythia's complete provider pass fell from 0.129 s to 0.056 s on the upload,
0.342 s to 0.148 s on 64-bit HeidiSQL, and 0.075 s to 0.027 s on the Delphi 7
binary. All eight maps match the original implementation exactly after the
record-boundary and table-cache changes. Candidate counts include unnamed method
addresses: the upload has 4,840 Pythia candidates, of which 14 carry names; ReSym
recovers 7,969 named methods there.

Tracemalloc/cProfile on the upload measured peak Python allocation of approximately
**2.69 MB**, versus **2.87 MB** in the original provider. Its per-byte reader had
3.11 million calls; the final implementation makes about **51,600** pointer-reader
calls after the native suffix filter. RTTI traversal
calls fell from 22,567 to 2,989. Profiling overhead is excluded from timing medians.
These are measured improvements, not a proof of globally optimal performance.

## Reproduction

Activate SMDA's `.venv`. The harness executes each input in a fresh worker so large
reports and JVM state do not accumulate across the corpus. Profile mode reports
both ReSym and Pythia calls and peak Python allocation. It verifies downloaded
archive and executable digests and never executes an input binary.

```bash
python profiling/delphi_audit/audit.py --download --corpus /tmp/delphi-corpus --output /tmp/delphi-provider --repeat 5
python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/delphi-baseline --source /path/to/baseline/src --repeat 5
python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/delphi-native --mode native
python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/delphi-profile --mode profile
```

Install `pyghidra` separately and provide Java 25 plus the verified Ghidra 12.2
installation for independent analysis. NumPy is optional only for reproducing the
upstream extractor's own 32-bit optimization.

```bash
JAVA_TOOL_OPTIONS=-Xmx4g python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/delphi-ghidra --mode ghidra --ghidra-install /path/to/ghidra_12.2_PUBLIC
JAVA_TOOL_OPTIONS=-Xmx4g python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/delphi-upstream --mode upstream --ghidra-install /path/to/ghidra_12.2_PUBLIC --upstream-script /path/to/DelphiReSym.py
JAVA_TOOL_OPTIONS=-Xmx6g python profiling/delphi_audit/audit.py --corpus /tmp/delphi-corpus --output /tmp/heidi64-ghidra.json --mode ghidra --ghidra-install /path/to/ghidra_12.2_PUBLIC --ghidra-disable-analyzer 'Create Address Tables' --worker /tmp/delphi-corpus/HeidiSQL_12.10_64_Portable.exe
```

Use `--include-private` only after placing the supplied executable under its
manifest filename in the local corpus directory. Ghidra and the full slow test
suite can each use several GB; run those sequentially in an 8 GB environment.
Stock 12.2 analysis of HeidiSQL 64-bit exhausted a 6 GB heap in `Create Address
Tables`. Its completed comparison disables only that analyzer; the result records
the setting and is not presented as stock output. The other seven Ghidra snapshots
use stock analysis. Function data is captured before Ghidra saves or closes its
temporary project, which avoids a separate high-memory database commit.

## Scope and remaining evidence limits

Sparse real metadata fixtures, a real finally-dispatch excerpt, and generated
malformed/partially stripped variants are permanent tests. They cover both pointer
widths, names/signatures, VMT/RTTI consistency, virtual/fixed method survival after
extended metadata removal, duplicate parameters, entry budgets, code-range handling,
Unicode byte lengths, provider reuse and PDB supplementation.

This is not an exhaustive compiler/optimization matrix. Release binaries do not
supply independently verified optimization settings; Delphi 2010, every XE release,
and Delphi 13 were not all rebuilt with licensed compilers. Pythia's conservative
interface-table recovery remains 32-bit only and is capped at 4,096 methods. Fully removed RTTI,
packing, imported runtime-package metadata, all EH personalities, class properties,
and complete unit/type hierarchies cannot be reconstructed from these method tables
alone. Damaged optional metadata degrades to known names or unknown types rather
than fabricated signatures. No claim is made that all possible correctness or
performance issues have been eliminated.
