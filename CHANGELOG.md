# Changelog

All notable changes to this project are documented here, in the format of [keep a
changelog](https://keepachangelog.com/en/1.1.0/).

**The package version is a release counter, not [semantic versioning](https://semver.org/).** Major has meant a new
capability, minor a notable feature group, and patch everything else including small features -- `v4.3.4` added a
new configuration option, `v4.0.0` added an architecture without breaking anything, and `v4.4.3` carried a whole
audit-hardening pass. Reading a version bump as a compatibility signal will mislead you.

The compatibility promise for report consumers is carried by three constants instead, alongside the `toDict()`
report shape:

| constant | what it versions |
|---|---|
| `SmdaConfig.ESCAPER_DOWNWARD_COMPATIBILITY` | the escaped-operand form that escaped-block shingles and minhashes are built from |
| `SmdaFunction.INTEL_PIC_HASH_ESCAPE_VERSION` | the Intel `pic_hash` escaping |
| `SmdaFunction.CIL_PIC_HASH_ESCAPE_VERSION` | the CIL `pic_hash` escaping |

**If a release moves any of the three, that release's `Compatibility` section names which one and from what to
what.** A header pointing at constants the entries do not track would be worse than no promise at all, because it
looks precise.

## How an entry is written

Each PR adds its own bullet under `## [Unreleased]` while the change is fresh, rather than the release being
reconstructed from merge commits afterwards. At release time a missing entry looks exactly like a change that did
not need one, and only the author can tell the difference. A PR touching `src/smda/` therefore has to touch this
file or carry the `no-changelog` label.

Subsections are the keep-a-changelog set -- `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security` --
plus `Compatibility`, which comes last and holds both "recovery output moves on binaries these paths touch" and
"this constant moved, from X to Y". Drop the ones a release did not use when it is cut.

A bullet opens with a bold subsystem prefix, then one summary sentence, then the mechanism, the measurement and the
cost:

```markdown
### Fixed
- **(intel)** Keep the switch index tied across a relative dispatch's base add. `_findJumpTableSize` read the
  base `add` as a redefinition and sized a 27-case table at 2, so 25 unreferenced case bodies reached the gap
  scan and five were booked as functions inside the function they belong to. *Measured on `<sha>`:* 140 built
  C/C++ cells (117,654 truth functions) -- 20 false positives removed, no true positive lost, 135/140 cells
  bit-identical. *Reproduced by reviewer on bundled fixtures.* (#306)
```

**The prefix is the PR title's own scope token**, from the list `.github/workflows/semantic-pr-title.yml` already
enforces: `core`, `intel`, `aarch64`, `dalvik`, `cil`, `common`, `utility`, `loaders`, `labels`, `report`, `ida`,
`cli`, `profiling`, `tests`, `ci`, `build`, `docs`. A PR carrying no scope gets no prefix rather than an invented
one, and a scope added to that workflow is available here the same day -- one vocabulary, enforced in one place.

Four rules for the content:

1. **Any accuracy or performance claim names the corpus it was measured on.** A bare percentage is not an
   entry.
2. **Say whether the figure was reproduced.** A figure resting on a corpus that is not bundled cannot be checked
   by a reader, and saying which ones those are is what keeps the rest worth something.
3. **A measured claim states its cost, or says there was none.** "20 false positives removed" reads as free. What
   makes an entry trustworthy is *no true positive lost*, or *-580 false positives against -53 functions*, or
   *bit-identical on the corpora it does not reach*. An entry reporting only the gain is the one that gets written
   when a trade did happen and nobody wanted to lead with it.
4. **A figure that is marginal against a moving baseline says so** -- in practice "measured on `<tree>`", four more
   words. An exact split is a property of an instruction encoding and does not decay; an absolute count is a
   property of every other rule in the engine on the day it was taken, and one published as 2,941 false positives
   removed measured 745 two releases later against a baseline 6.5 points higher. Neither number was wrong when it
   was taken, and without the tree a reader cannot tell staleness from disagreement.

On length: the summary line is one sentence, the attached block is the mechanism, the measurement and the cost, and
past roughly six lines it belongs in the PR the entry links.

## [Unreleased]

### Added

### Changed

- **(tests)** `make test` now runs the fast tier and `make test-all` runs the whole suite. The `slow`
  marker already existed, was already applied to the eleven fixture-corpus files, and was documented in
  `pyproject.toml` with its own deselect recipe — but no entry point used it, so every local run paid for
  it. *Measured on `857081f`:* the marked tier is 124 of 2110 tests and 116s of the 151s total, so the
  default target drops from about 150s to about 40s. *Not reproduced on other hardware;* the ratio is what
  travels, not the seconds. CI is unchanged and still runs the whole suite on every leg, so the gate does
  not move — `make test-all` before pushing is what keeps a slow-tier failure from reaching the PR. (#340)

- **(common)** Refuse a candidate from any source that the image's `.eh_frame` declares interior to a function,
  not only a gap-scan candidate -- the gap pointer reaches only what the gap scan walks to, so the prologue,
  reference and symbol scans seeded the rest unchecked. A procedure linkage table is exempt, the declared
  range's own start has to be a recovered function, and that owner's recovered extent has to surround the
  address. *Measured on `0a0a4c6` against compiler symbol tables:* 72 AArch64 ELF cells 95.994 -> 97.063 PPV
  (-683 false positives) and 140 built C/C++ ELF cells 98.903 -> 98.969 (-77), both at identical true positives
  and false negatives; the PE, Go, ARM64 Mach-O and 57 malpedia cells are bit-identical, which is the control
  that it reaches only images carrying an `.eh_frame`. *Not reproducible from the bundled fixtures, which
  produce 0 refusals.* (#327)

### Deprecated

### Removed

### Fixed

- **(intel)** Resume the gap scan inside the gap a failed candidate was found in, rather than
  abandoning the rest of it. `getNextGap`'s resume refinement is gated on the candidate being in
  `code_map`, so one that failed to become a function fell through to the next entry of a gap map
  that is snapshotted once when the gap phase opens and never refreshed -- everything between the
  failed candidate and the end of its gap was never offered as a candidate at all. The Intel
  backend now names the first entry past the padding run that ends the failed candidate, and only
  when that entry is already 16-byte aligned; a backend with no reading of its own padding keeps
  the previous behaviour. *Measured on `857081f` against compiler symbol tables:* 120 MinGW PE
  cells +47 true positives against +18 false, 24 Rust cells +0 against +6, 57 malpedia dumps +7
  against +12, and **no true positive lost on any corpus**. The 140 C/C++ ELF cells, 72 AArch64
  ELF cells and 11 ARM64 Mach-O cells are bit-identical. *Not reproducible from the bundled
  fixtures, which do not move.* (#338)
- **(common)** Bound the LSDA reads that lead nowhere, and remember a pointer that reads back empty. The
  call-site table budget is charged only once a table's length field is parsed, so an LSDA failing before that
  point -- an unsupported LPStart mode, a short buffer, a TType offset that will not read -- cost a read of up to
  `MAX_LSDA_BYTES` and charged nothing: a section naming `MAX_RECORDS` such pointers read 12.2 GB over 199,999
  reads. `MAX_LSDA_FAILED_READ_BYTES` holds that to 256 MB over 4,096, leaving 8.6x headroom over the heaviest
  real image measured, which spends 29.75 MB. Separately, an address the reader hands nothing back for returned
  before the memo was written, so a section naming one dead pointer from every record read it once per record;
  remembered by address, that is now one read. *All 447 cells across the six corpora are bit-identical.* (#335)

### Security

### Compatibility

- Recovery output moves on Intel PE and ELF images whose gap scan meets a failed candidate: the
  bytes after it are now scanned instead of skipped. No true positive was lost on the corpora
  this was measured over. (#338)
- Recovery output moves on ELF images carrying an `.eh_frame`: an address a declared FDE range covers is no
  longer reported as a function start unless it is that range's own start. No true positive was lost on the
  corpora this was measured over. (#327)

## Older releases

Entries below predate this format and are kept verbatim, in the one-line shape they were written in. They are
ordered by **version**, not by date, so a patch on an older line can sit below a minor released before it --
`v4.4.0` above `v4.3.11` and `v3.1.0` above `v3.0.2` are both that rather than filing errors. The undated lines at
the very bottom predate versioned releases entirely.

 * 2026-09-10: v4.6.0 - Function-boundary accuracy taken from what the image declares rather than guessed from the
   bytes, plus an analysis hot-path pass that leaves report output unchanged. Each topic below links the PR that
   carries the full mechanism, the measurements and the approaches that were tried and rejected.
   * **Recovery -- believe the binary over the bytes**
     ([#300](https://github.com/danielplohmann/smda/pull/300)): compilers write down a lot the engine was not
     reading. An ELF says in `.eh_frame` which address range belongs to which routine and in `.gcc_except_table`
     which addresses are landing pads; a PE declares where its exception table lives; a COFF header states the
     bitness and the instruction set outright. Each was previously ignored or re-derived from a byte heuristic that
     is wrong on a predictable class of binaries. Nothing here is a new heuristic: every rule refuses a candidate
     because a structure the compiler emitted says the address is inside a function rather than at the start of one.
     * *Read the header when there is one.* `Disassembler.declaredArchitecture()` and
       `BitnessAnalyzer._declaredBitness()` believe a buffer that parses as PE, ELF or Mach-O and names an
       instruction set a backend exists for, instead of scoring REX.W density and running a byte probe. A headerless
       dump or a shellcode blob falls through to the same probes as before, so this narrows where the guessing
       happens rather than replacing it. A managed PE still routes to `intel`, because CLR metadata is addressed by
       file offset and a mapped dump has none. 93 functions recovered and 64 false positives removed on the malpedia
       dump corpus with bitness withheld.
     * *The PE exception table's address is declared, not conventional.* The x64 table is read from the data
       directory through a new `BinaryInfo.getExceptionDirectory()`, falling back to a section named `.pdata` only
       when the image declares no directory entry -- `.pdata` is the name MSVC happens to use, and the .NET
       ReadyToRun compiler puts the table in `.data`. On a ReadyToRun image: 419 to 626 functions, which is every
       start the directory declares and nothing it does not name. The walk now also polls the analysis budget every
       4,096 records, since reading from the directory is what widened the range it covers.
     * *A prologue that begins exactly where an earlier prologue ends is not a function* (intel). clang follows
       `push rbp; mov rbp, rsp` with the callee-saved run `push r15; push r14`, and both are on the seeded prologue
       list, so the scan booked a second "function" four bytes into the same body. Refused when the earlier address
       is already a candidate, which is what keeps it off byte coincidences. Across ten corpora: 912 false positives
       removed, 0 true positives lost.
     * *`endbr64` is an indirect-branch marker, not a function marker.* Under `-fcf-protection` it sits at every
       address an indirect branch can land on, jump-table case labels and landing pads included. An FDE covers
       exactly one routine, so an `endbr64` that is not its own range's start is inside that routine. Applied to
       this one seeded pattern deliberately: it is the only one naming a place a branch can arrive rather than a way
       a function opens.
     * *A call that never returns is a function boundary* (AArch64). With no `ret` after a call to `abort` or a
       panic handler, decoding runs into the next function and the two merge; the existing checks all look for a
       reason to stop and decline when the next function is packed right up against this one.
       `_callFallthroughFunctionStart` now also asks whether the next instruction opens a stack frame -- `sub sp, sp,
       #imm` followed within three instructions by `stp x29, x30, [sp, #imm]`. Neither half is conclusive alone; the
       pair is, because nothing mid-function re-saves the incoming link register into a frame it just created.
     * *The candidate snapshot predates analysis, so it cannot be the whole answer* (AArch64). Checks asking whether
       an address is in `getFunctionStartCandidates()` could not see a function gap analysis had discovered, since
       that set is snapshotted before analysis and never added to; they ask the live function set as well now. On
       the bundled ARM64 Mach-O corpus: 8 recovered, 0 new false positives, and the fixture's primary pass moves
       from 246 to 269 functions.
     * *After a `bl` fall-through the cut recovers the function and the seed makes it worse* (AArch64). The backend
       cut the caller short **and** seeded the boundary as a tailcall candidate, where the seed re-books the address
       with worse extents than the ordinary machinery would. The seed now sits behind `RESOLVE_TAILCALLS` (default
       off); the cut still happens either way. Gate off to on: Go n=47, -408 false positives at identical TP; ARM64
       Mach-O n=11, -27 false positives and +11 functions; built C/C++ AArch64 ELF n=72, **-580 false positives
       against -53 functions**. That last row is a reject by the strict per-change rule and is kept anyway, because
       before this release nothing turned the AArch64 seeding off at all, so the gate is what makes both behaviours
       reachable; with `USE_ELF_EH_FRAME_CANDIDATES` on it costs 13 and gains 24 instead.
   * **New (default on)** ([#300](https://github.com/danielplohmann/smda/pull/300)): two rules refusing a gap
     candidate the image declares interior, each with the guard that makes it safe.
     * `USE_LSDA_LANDING_PADS` -- `.gcc_except_table` tells the unwinder where to resume when an exception escapes a
       call site, which is by definition inside a function. These addresses are the perfect storm for a byte scan:
       they open with the indirect-branch marker (`endbr64`, or `bti` on AArch64) and sit in gaps precisely because
       nothing branches to them. Where the scan resumes is the whole decision -- one instruction past a refused pad
       lands *inside* it, so it resumes at the end of the declaring FDE. Across the three corpora carrying pads, 0
       of 41,215 pads have a declared function start between the pad and that resume point. On AArch64 the rule also
       runs in `locatePrologueCandidates`, because `bti` is a recognised prologue there.
     * `USE_ELF_FDE_INTERIOR_GAPS` -- the same idea with a wider net: any gap candidate strictly inside a declared
       `.eh_frame` range, which catches the jump-table case labels a switch emits under `-fcf-protection`. Two
       guards, both found by measuring what it cost without them: the PLT is exempt, since the whole PLT sits under
       one FDE and without it every stub after the first reads as interior to the first (3,457 real functions); and
       the range's own start must already be a recovered function, since an FDE can begin in the padding ahead of it
       (the remaining 35 losses). Reached only from the gap scan -- widening where it is consulted is #324.
     * Over six representative C/C++ cells, `endbr64` seeded as a function start accounted for **822 false
       positives** before these rules and the prologue refusal, and **zero** after, with true positives on the same
       cells up from 5,695 to 5,718.
   * **Measured** against compiler symbol tables on corpora built from source, both trees run back to back on the
     same machine, arithmetic macro mean, `6240b74` to this release. Full table, per-rule attribution and the five
     proposals that were measured and left out are in
     [#300](https://github.com/danielplohmann/smda/pull/300):

     | corpus | n | PPV | TPR | FP change | TP change |
     |---|---|---|---|---|---|
     | Built C/C++ AArch64 ELF (gcc cross) | 72 | 91.497 to 94.947 | 97.705 to 98.069 | -3,645 | +151 |
     | Built Rust (gnu targets) | 24 | 79.659 to 87.480 | 98.237 to 98.361 | -1,641 | +19 |
     | Built Go (pclntab truth) | 47 | 95.361 to 95.626 | 99.367 to 99.367 | -408 | 0 |
     | ARM64 Mach-O (`LC_FUNCTION_STARTS`) | 11 | 94.281 to 94.499 | 96.402 to 97.207 | -27 | +38 |
     | Malpedia dumps (`.fnmap` truth) | 57 | 92.645 to 92.648 | 98.552 to 98.552 | -1 | 0 |

     The 260-cell C/C++ matrix rebuilt from source (213,706 truth functions): PPV 94.038 to 96.908, TPR 97.001 to
     97.074, FP -12,853, TP +210. **No corpus loses recall.** Three further corpora are bit-identical -- 120 MinGW
     PE cells and both ByteWeight msvc10-64 sets -- and that is the control rather than filler: Go carries no
     landing pads and Mach-O no `.eh_frame`, so movement there would have meant a rule firing where it had no
     business firing. The malpedia row is level because those are packed Windows dumps that carry no ELF unwind
     data; on the three files that do move, the benchmark gate's own artifact reads 143 likely false positives
     removed against 5 addresses that read as a lost function. Figures are the contributor's own except the ARM64
     Mach-O row and the ReadyToRun result, which were reproduced here.
   * **Robustness** ([#300](https://github.com/danielplohmann/smda/pull/300)): both new decoders read structures the
     analysed file controls. A 205 KB `.eh_frame` whose records each named a 64 KB LSDA took 155 seconds to decode;
     each LSDA is memoised once and a per-section budget bounds the call-site bytes decoded, taking the same input
     to 0.047s. A pad falling outside its own FDE is refused, because the format guarantees it cannot: on one
     NativeAOT image, LSDA pointers led into arbitrary data that parsed cleanly and produced 4,826 fabricated pads,
     and across four corpora and three system libraries all 43,881 genuine pads are inside their own FDE while all
     4,828 spurious ones are outside.
   * **Performance** ([#299](https://github.com/danielplohmann/smda/pull/299)): six changes cutting overhead with
     report output unchanged -- per-instruction lookups hoisted to locals in `analyzeFunction`'s loop, PIC-hash
     escaping memoised behind a size-capped cache (real binaries repeat 30-50% of their instructions, a DEX classes
     dump 98%), a `getNormalizedBlockRefs` fast path plus a duplicate `fix_graph()` dropped, AArch64 candidate scans
     prefiltered by top byte via one `bytes.translate` (prologue scan 4.14ms to 0.74ms, BL 1.17ms to 0.59ms),
     `hasUnprocessedBlocks()` trusting the queue instead of allocating a set difference per call, the Dalvik
     resolver closure hoisted, and ApiScout database parsing deferred to the first API lookup. Interleaved median
     wall-clock against master: aarch64_static -9 to -10%, komplex -6 to -7%, blockblast/asprox -2 to -4%,
     cutwail/njrat neutral within noise. Serialized reports hash byte-for-byte equal to master across ten fixtures
     spanning all four backends.
   * **Three defects a report-identity check could not see**
     ([#299](https://github.com/danielplohmann/smda/pull/299)), fixed before merge, each with a regression test that
     fails on the pre-fix source. An explicit `setOsName()` was silently discarded once the os-name inference moved
     into the deferred load. The `getNormalizedBlockRefs()` fast path stopped normalizing on the `fromDict()` path,
     where blockrefs come from a report this code did not write, so duplicates reached the SCC and dominator-tree
     passes. And `updateFunctionGaps()` had been re-keyed from a walk over `code_map` byte keys to a merge of
     `disassembly.functions` intervals, which are not interchangeable -- `code_map` records every decoded byte,
     `functions` only finalized ones -- dropping the decoded-but-unattributed regions out of the gap scan: on a
     32-bit MSVC PE, **6,249 functions to 5,247**, a 16% loss, for a pass that also got slower. Only that hunk is
     reverted. The lesson generalises: a report-identity comparison is evidence about the fixtures, not about the
     change, and the first two live on paths no bundled fixture reaches while the third lives on one they
     under-represent.
   * **Two bundled fixture baselines moved,** both stated in the tests.
     `elf_cet_landing_pads_x64` drops four `endbr64` addresses, all jump-table case labels strictly inside the
     function the symbol table names `dispatch` -- a correction. `aarch64_static` drops `0x400350` and `0x40DF30`,
     both mid-function instructions inside a range the image declares. Separately `0x40DF34` is refused and is a
     Binary Ninja function start, though it was not recovered before this release either: it repeats its FDE's
     opening minus a `prfm` prefetch, i.e. an alternate entry sharing one frame, and these rules follow the unwinder
     where the two disagree. All three are asserted absent rather than deleted from the expected list, so the
     disagreement stays visible in the source.
   * **Compatibility:** no escaper output changed. The only escaping-related edit memoises `escapeBinary` results
     behind a cache keyed on its complete input tuple and no escaper module is touched, so
     `ESCAPER_DOWNWARD_COMPATIBILITY` stays at `4.4.5` and `INTEL_PIC_HASH_ESCAPE_VERSION` at `4.3.5`, and no report
     needs reprocessing. Three intentional nuances, none of which moves a report: an uncached ApiScout database is
     parsed at the first `getApi()` call rather than at resolver construction, an explicit `setOsName()` outranks
     the inference regardless of when the deferred load fires, and `getNormalizedBlockRefs()` still deduplicates and
     sorts on the `fromDict()` path.
   * **New fixtures,** built from source and XORed like the rest: `elf_cxx_landing_pads_x64_xored` (g++ 13.3.0,
     `-O2 -fcf-protection=full`), `elf_cxx_landing_pads_arm64_xored` (aarch64 cross-g++ 13.3.0,
     `-O2 -mbranch-protection=standard`, 5 pads all `bti j`) and `elf_cet_landing_pads_x64_xored`, with seven new
     test files behind the rules above.
   * **Housekeeping:**
     * The perf benchmark workflow was comparing two machines -- base on one runner, PR on another, an hour apart --
       and once reported a branch 13.18% slower at p = 0.0000 when its only source change was AArch64-only code
       measured on an x86 corpus. Both sides are now timed interleaved in one job with the leading side rotated per
       pass ([#300](https://github.com/danielplohmann/smda/pull/300)).
     * The per-rule figures in `SmdaConfig.py` for `USE_LSDA_LANDING_PADS`, `USE_ELF_FDE_INTERIOR_GAPS` and
       `RESOLVE_TAILCALLS` are the re-measured ones; the first two had shipped with attribution measured before
       #304/#307/#309/#310/#311 landed, against a baseline whose AArch64 PPV had since moved from 76.676 to 91.497.
       A PR description records a conversation; a config comment is what the next reader has. Also here:
       `getExceptionDirectory` matches the typed `lief.PE.DataDirectory.TYPES.EXCEPTION_TABLE` rather than a
       substring of the enum's repr, and a comment #312 left dangling is removed
       ([#325](https://github.com/danielplohmann/smda/pull/325)).
   * (THX: @r0ny123)
 * 2026-09-08: v4.5.1 - Function-recovery fixes across intel and AArch64, a fuzz-found synthesis crash, and the
   report's address-space contract written down.
   * **Recovery (intel):**
     * A 64-bit relative switch dispatch ends by adding the table's base to the entry the table read produced, and
       `_findJumpTableSize` treated that `add` as a redefinition -- dropping the index tie one instruction short of
       the table read, falling back to the first register-against-immediate compare in the window, and sizing a
       27-case table at 2. The 25 unreferenced case bodies then reached the gap scan, which booked five of them as
       functions inside the function they belong to, so one defect produced a false positive and a shattered function
       together. The tie is now carried across the base add in both spellings a compiler writes (`add rax, rdi` with a
       register or memory source, and a `lea` whose address reads the register it writes), and only on the instruction
       the branch actually reads: an `add` further back is index arithmetic, and a compare bounding one summand is not
       a bound on the sum. Measured on 140 built C/C++ cells (117,654 truth functions): 20 false positives removed, no
       true positive lost on any cell, 135 of 140 cells bit-identical.
     * The alignment cut also gained its second way in. It had exactly one before -- padding that follows a `call` --
       on the theory that a noreturn call is what leaves padding behind; GCC pads between functions whatever the
       previous one ended with, so a function reached by falling through inter-function padding was decoded as a
       continuation of its predecessor and the two came back as one. Padding is now evidence in its own right, read as
       a whole run: every byte from the current address to the next 16-byte boundary has to be alignment filler and
       the run has to stop at that boundary. Because GCC aligns loop heads with the same encodings it pads between
       functions with, a fall-through cut additionally requires its seed to decode as a function entry on every
       format, where the call path keeps the old exemption. Two CS-prefixed GCC/binutils multi-byte nops (`2e 8d 74 26
       00` and `2e 8d b4 26 00 00 00 00`) join `GAP_SEQUENCES`, which sharpens every padding test that reads it, not
       only the new one. Measured on 296,225 ground-truth functions over 191 samples: pooled recall 97.29% to 98.31%
       and precision 92.83% to 93.70%, +3,009 true starts against -2,676 false ones, all 47 Go cells bit-identical, at
       +3.4% analysis time (reproduced here at +3.84%).
     * The exception directory now also refuses gap candidates it places inside a function. A 64-bit PE carries one
       `RUNTIME_FUNCTION` record per function, each naming the extent the unwinder needs, so an address strictly
       inside one is declared to belong to a routine that starts earlier and cannot itself be an entry; only the gap
       scan ever reaches these addresses, since every one of them sits in a region no reference and no prologue
       claimed. Two conditions keep it from overreaching. A chained record (`UNW_FLAG_CHAININFO`) describes a fragment
       of another function, so its first byte is interior too and suppresses on its own, while a primary record's
       first byte is the entry and stays bookable; and a primary range only suppresses once the analysis has actually
       recovered the function it names, because a record whose function never analysed is not evidence about what
       covers the address. The scan then resumes at the extent's end rather than one byte on, which skips the body the
       record describes instead of re-testing it. Extents are deliberately not merged -- functions are laid out
       end-to-start, and merging adjacent records would collapse the text section into a handful of spans in which
       every address but the first reads as interior. Records carved out of an image with no parseable header seed
       candidates but contribute no extents, which is the distinction that keeps suppression honest: seeding is cheap
       and self-correcting, suppression is expensive and silent. `USE_PE_X64_PDATA_INTERIOR_GAPS`, on by default. The
       `is_pe` guard that came with it also stops *seeding* from a non-PE section merely named `.pdata`, which is a
       candidate-discovery change wider than the title suggests and inert on every bundled image.
   * **Recovery (AArch64):**
     * Candidate discovery seeds a function start at the target of a backward branch or a short no-frame stub, and the
       AArch64 candidate manager recorded the branching instruction as an inbound *call* reference for it. An inbound
       call is one of exactly two things exempt from the inferred alignment floor -- the image's own declaration that
       an address is an entry -- so the seed manufactured the evidence the floor trusts, and mid-function addresses
       went through it. That is worse than a stray false positive: on a routine only the gap scan recovers, the
       smuggled interior address is analysed first, takes the bytes, and the real start is never reported. A branch is
       not a call, so no reference is recorded now; the address is still discovered, queued and analysed, on the
       alignment and prologue it actually has. The shared implementation in `common/` never recorded one. Measured
       across three corpora: 175 false positives removed and 3 functions recovered, with no corpus losing recall; on
       the bundled 11-sample ARM64 Mach-O corpus the totals are flat because `LockBit_3e4bbd21756a` gains a function
       and `RustyPages_e98756472404` loses `0x10000548c`, which is the single recall cost anywhere and is offset
       inside the same corpus.
     * Separately, candidate discovery read all four BTI forms as entry prologues, and two of them mean opposite
       things: `bti j` permits a target reached by `br` and never one reached by `blr`, so a call landing on a J-only
       pad faults and the compiler that wrote J was naming an interior label - a switch case or a computed-goto target
       - rather than an entry. The existing guard reads the word before a pad and refuses one that follows ordinary
       code, which cannot separate these, because a case block is preceded by the previous case's terminating branch
       and that is exactly the boundary shape the guard accepts. `USE_AARCH64_BTI_TARGET_TYPE`, on by default, reads
       the target type instead: over 1,308 prologue-sole bookings on 72 built AArch64 ELF cells the split is exact
       rather than statistical, `bti j` accounting for 803 false positives and no true ones against `bti c`'s 505 true
       and none false. Precision moves 87.596 to 89.186 with recall unchanged to three decimals and 2,941 false
       positives removed, which is more than the 803 bookings because a wrong entry also starts an analysis that
       fragments the routine it sits inside. `bti jc` is deliberately untouched: it permits `blr`, so it can be a real
       entry. Refusing a pad then has to resume past the block the pad labels rather than one instruction on, or the
       false positive simply moves four bytes onto the pad's own first body instruction - and that walk stops at
       `brk`/`hlt`/`udf` as well as at `ret`/`br`/`b`, because `analyzeInstruction` ends a function on all three traps
       and a walk that reads past one skips whatever lies behind it, which is exactly the unreferenced routine the gap
       scan exists to reach.
     * A follow-up pass then took four candidate-quality defects the BTI series exposed. The interior-BTI test read
       the candidate snapshot rather than the live function set, so it judged a landing pad against what discovery had
       proposed instead of against what analysis had recovered. The hoisted-guard heuristic claimed a
       compare-and-branch could not be a function's first instruction, which is simply false -- on
       `aarch64_static_xored` the corrected entry sits at `0x40df30`, four bytes ahead of what was booked, and the
       inter-function `nop` in front of it settles which of the two is the boundary. A metadata-coverage gate now
       skips the address-materialization scan on an image whose own metadata already named its functions, guarded by a
       minimum sample count, because a coverage ratio over four resolved call targets says nothing: across the 13
       bundled AArch64 images it fires exactly once, on `Turtle_5f9cd91d8d1d` at 98.3% coverage, with output
       bit-identical either way, so on bundled data it is a work saving with no accuracy consequence. And the ARM64
       counterpart of the x64 interior-gap refusal above lands with it: an ARM64 `RUNTIME_FUNCTION` carries no
       `EndAddress`, so the extent is reconstructed from bits 2-12 of the packed unwind word or from bits 0-17 of the
       `.xdata` header it points at, both counting instructions. Once an extent is known the rule is identical, which
       is why the lookup moved into `common/` rather than being written twice; the x64 path keeps the same list, the
       same bisect and the same running-maximum walk. `USE_PE_ARM64_PDATA_INTERIOR_GAPS`, on by default. Worth knowing
       that ARM64 PE seeding over-reports on MSVC-built images -- a separated chunk of a routine gets its own record
       and sets up its own frame, so the entry-shape filter reads it as an entry -- and that no exact test for it is
       in reach, since 120 of 145 such chunks continue a record with no `.xdata` handler data to name them.
   * **Synthesis:** a report's entry point is the one image field no span check bounds. `_resolveFunctionOffsets` caps
     how far apart the *functions* may sit, which is what keeps every RVA derived from them inside a header field, but
     `oep` is not a function offset and reached the header packers unchecked. `fuzz_synthesis` found it: a PE whose
     entry sits more than 4 GiB above the image base raised `struct.error` out of `struct.pack_into("<I", ...)` and
     lost the whole image. The quieter half is ELF32, whose bound was checked against the 64-bit space on both
     branches while the 32-bit branch packs `<I`, so an out-of-range entry silently truncated and aimed somewhere
     unrelated. Both now fall back to `.text`, which is what a report carrying no `oep` already got and what the
     Mach-O synthesizer has always done for an entry outside its text segment; an entry past the end of the 64-bit
     space still raises, because that describes no image at all. The relative-or-absolute reading of `oep` moves to
     `BinarySynthesizer._resolveEntryPoint` so the next backend inherits the bound along with the reading, and the
     minimized reproducer is pinned under `tests/fuzz_regressions/`.
   * **Defaults changed:** `USE_MACHO_ADDRESS_REF_CANDIDATES` moves from `False` to `True`. The
     address-materialization scan was off because it was a per-container bet; the coverage gate above now decides per
     image, which is what makes turning it on defensible. It is the only default whose value changes in this release,
     and it changes recovery output on Mach-O input without any configuration change on the caller's side, so it is
     called out here rather than left inside a follow-ups entry.
   * **New (default off):** `USE_READYTORUN_NATIVE_ROUTING` offers a ReadyToRun assembly's precompiled native body
     instead of its CIL. Such an assembly ships both, its CLR header is what routes it, so the native half -- most of
     what the image contains -- was never analysed; on the bundled fixture the native body holds 51 more functions
     than the CIL half. It ships off because there is no way to have both: a CIL report addresses methods by file
     offset and a native report by virtual address, so one report cannot carry both without putting two address spaces
     in one `offset` field. `PeFileLoader.getReadyToRunArchitecture()` answers the instruction set named by the COFF
     machine field of an image whose CLR header points at an `RTR\0` managed-native header, and `""` for everything
     else -- including a ReadyToRun image whose machine field names no instruction set a backend exists for, which the
     bundled fixture is: declining beats guessing, since the optional header's magic is as true of ARM64 as of x86-64.
   * **Docs:** the report's offsets are virtual addresses on `intel` and `aarch64` and **file offsets** on `cil` and
     `dalvik`, and nothing said so, so a consumer correlating a managed report with a native one -- or adding
     `base_addr` to either -- was silently comparing two address spaces. Now stated in the README and in both managed
     disassemblers' docstrings, with the reason they differ: a CIL method has an RVA that `CilDisassembler` declines
     to use, where a DEX carries no load address at all. Recorded rather than corrected, because the offsets are a
     public compatibility surface downstream consumers index on.
   * **Housekeeping:**
     * `ty` 0.0.74's new `unsound-return-statement`/`unsound-assignment` rules were addressed after a Dependabot bump
       landed them unaccompanied and turned `Code Quality` red on master (41 errors across 15 files); `ty` is now
       Dependabot-ignored, since a pre-1.0 checker that ships rules in patch releases has to move in a change that
       handles them.
     * `ruff` gained a pin at `0.16.6` level with the `ruff-pre-commit` rev, which had drifted apart -- the pip side
       floated while the hook was fixed, so CI and `pre-commit run` could disagree about what counts as a lint error.
     * A follow-up pass then took five corrections the reviews above had left behind: the address-space section had
       named `metadata.language` alongside `report.architecture` as a way to tell which backend produced a report,
       which is wrong in the direction that section exists to prevent -- it is a source-language score map, decisive
       on the two managed backends but a distribution carrying a `.net` score on the native ones, so branching on it
       can read a native report as managed, and the file already stated that contract 130 lines below;
       `smda_instruction_matches_capstone` got its `-> bool` back through a `bool()` wrapper rather than keeping the
       annotation deleted; the ruff hook moved to `id: ruff-check`, astral having renamed it and left `ruff` as a
       legacy alias; `GAP_SEQUENCES` gained a note that it is read in seven places outside the alignment cut, which is
       what makes a measurement over a change to that table hard to attribute to one caller; and the queue-rebuild
       test now says it guards against reintroducing scoring into `addTailcallCandidate`, its assertion having become
       trivially true when that scoring was removed. No escaper output changed, so `ESCAPER_DOWNWARD_COMPATIBILITY`
       stays at `4.4.5` and `INTEL_PIC_HASH_ESCAPE_VERSION` at `4.3.5`.
     * One serialized value does change shape, in a way worth knowing about downstream: `binweight`'s class default
       moved from int `0` to float `0.0` while the `ty` errors were being cleared, and `binweight` is written into
       `toDict()`. Every function with at least one block was already a float, since the per-block accumulation adds
       `float(...)`, so this is visible only on a function that has no blocks at all -- a zero-function or error
       report -- where the value now serializes as `0.0` rather than `0`. Nothing reads it as an integer, but a
       consumer diffing stored reports byte-for-byte will see it.
     * The two items that pass had deliberately left open close here as well, both having needed work upstream of the
       annotation rather than the annotation itself. `SmdaFunction.blocks` is now typed as what it holds, which
       restores `getInstructionsForBlock`'s return annotation and forces a decision on the PIC/OPC hash path: it
       refuses an instruction carrying no bytes rather than defaulting it to a blank the way seven formatting and
       length-arithmetic sites nearby do, because a blank there would hash a different instruction sequence and the
       result would still look like a valid hash. And `extract_strings` narrows from `Tuple[str, Any, Any, str]` to
       `Tuple[str, Optional[int], int, str]`, which required typing `read_string`, `read_go_string` and `derefs`
       first, and those in turn required declaring `SmdaReport.base_addr`, `.bitness` and `._derefs_cache` -- the
       reason the item could not be taken as a signature change. Both are behaviour-neutral, and checked as such:
       PIC/OPC hashes and extracted strings are identical on every fixture that produces them, and the corpus
       benchmark reports 0 of 155 files differing over 175,946 functions.
   * **Recovery output moves on binaries these paths touch:** eight of the 21 bundled fixtures these paths reach
     change between v4.5.0 and this release, and the two that carry independent ground truth were scored against it
     rather than against the contributing PRs' own corpora. `rust_pe_gnu_xored`, against the 2,186 `.text` function
     symbols its mingw build retains: 2,355 to 2,201 starts, +26 real against -180 false, recall 92.45% to 93.64% and
     precision 85.82% to 93.00%. The 11-sample ARM64 Mach-O corpus, against `LC_FUNCTION_STARTS` over 2,056 truth
     functions: 1,787 to 1,818 true positives and 1,113 to 1,107 false ones, recall 86.92% to 88.42%, with no sample
     losing recall. `aarch64_static_xored` holds at 278 functions with one start corrected four bytes earlier, and
     `Turtle_5f9cd91d8d1d` drops 12 starts to the inbound-call fix; it carries no `LC_FUNCTION_STARTS`, so those 12
     cannot be scored here, but they are part of that change's measured 175 false positives. The remaining 13 are
     bit-identical. Two headline figures could **not** be reproduced against bundled data and are the contributors'
     own: the `bti j` 803/0 split, since no bundled fixture contains a single `bti j` word, and the ARM64 PE
     interior-gap result, since no bundled fixture is an ARM64 PE at all -- of 104 fixture files, 8 are i386 PEs, 4
     are AMD64, one is the ReadyToRun image, and none is `0xAA64`. (THX: @r0ny123)

 * 2026-08-25: v4.5.0 - Function-recovery accuracy pass, MSVC/PDB symbol recovery, synthesis robustness, and the escaper compatibility marker that downstream indexes read. **Recovery (intel/AArch64):** CET `notrack` switch dispatches are now classified as dispatches instead of far jumps and discarded (a single switch previously produced 43 bogus functions); switch tables whose base is register-held are recovered via a bounded `lea` back-walk; jump-table entry scans are bounded against attacker-controlled counts (1049.7 s to 0.002 s) and the address-0 sentinel class is refused at five call sites; the indirect-call backward walk stops resolving against stale registers (branch predecessors, ABI-preserving calls, memory-writing `mov` forms); a function is cut at the CET landing pad it runs into after padding; `push rbp`-opening prologues seed their real entry instead of one byte in; direct calls outrank the inferred alignment floor (recovered `abort` in static glibc). On AArch64, a jump table whose sign-extension is folded into the merging `add` (`add x8, x8, w9, sxtw #2`) is read as signed instead of losing the whole table at its first backward entry, and the constant tracker now drops the registers capstone reports only as implicit writes, so a value held in x30 no longer survives the `bl`/`blr` that clobbers it. On intel, `popa`/`popad` join the instructions known to overwrite eax without naming it, so the syscall-number backtrack stops reporting a `mov eax, N` the pop had already replaced, which is a wrong answer rather than an unresolved one. PE ARM64 exception records are carved from headerless images (0 to 24 functions on veneer-style images) with packed-fragment rejection. Absolute memory operands book data references, which enables a late candidate pass recovering Delphi method-table entries nothing else names (+3 real functions on the corpus, replacing three recoveries that rested on provably wrong stale-register dataflow). Both Delphi method-table walks stop at the first unreadable entry rather than spending a declared 16-bit entry count as an iteration count. The analysis budget is an actual in-pass bound now (polled within passes, latched between them). **Measured against newly bundled labelled ground truth (50 locally built binaries, 11,384 labelled functions): recall 93.781% to 95.098%, body splits 1095 to 306 (-72%), with documented deliberate moves to the `mirai_x64`, `mirai_i386`, `rust_pe_gnu` and `asprox` fixtures.** Median runtime dropped 34% on the 155-file malpedia corpus alongside. **Symbols/demangling:** new vendored MSVC demangler measured per-name against `llvm-undname` on LLVM's own 609-name stress corpus (100% exact spellings, zero third spellings, hostile-input depth and output bounds, shipped with a fuzz target and an attributed reference corpus); `PdbSymbolProvider` rebuilt on `purepdb>=0.3.0`, a declared BSD-compatible pure-Python dependency replacing the optional GPL `pdbparse` import whose failure was silent (three-source record merge: procedures, publics, thunks; OMAP-aware RVA resolution; parent-relative fragment attribution `<parent>$+0x<delta>`; naming 273/4045 to 3698/4045 functions on sqlite3 x64 and 1/477 to 442/477 on Rust x64); MSVC-decorated PDB public records demangle ahead of the Rust evidence gate; PE symbols demangle Itanium names like their ELF/Mach-O siblings and resolve through `section_idx`; demangled Rust names keep rustc spacing instead of Ghidra-style condensation; punycode identifiers decode non-ASCII text; lief symbol names survive invalid UTF-8 via a shared helper; ELF import names stay binary-encoded for import reconstruction and report merging; Mach-O Swift demangling batches through one toolchain call per image (4.29 s to 0.08 s over the 12-sample corpus, identical output); confirmed-format parse failures across providers and loaders warn instead of vanishing at debug. **Probes/loaders:** bitness decided by REX.W usage statistics over code areas; AArch64 recognized in raw buffers; unrecognized inputs pass through to analysis instead of erroring; opt-in `.eh_frame_hdr`/linker-table candidates on both instruction sets; `WITH_STRINGS` no longer destroys a DEX report's string references; a lief type object's repr can no longer reach a DEX report's type field dressed as a type descriptor, since the `<lief.` guard ran after the normalization that strips the very prefix it tests for, and an orphan code item takes its label from what the object is instead of from matching the generated name back off the text a real method is free to carry; timed-out analyses announce themselves instead of returning quietly; gap scans honour the analysis budget. **Synthesis:** blocks overflowing their section are planted instead of dropped; stored headers are only read when they are the target format's own; the synthetic image base lowers so low-RVA ELF functions fit a PE; sections are bounded by the image limit; imports named like ordinals stay names. **Compatibility:** `ESCAPER_DOWNWARD_COMPATIBILITY` moves from `1.13.16` to `4.4.5`, the release whose Intel escaper changed output: segment-qualified memory operands escape as `PTR` where they had been flattened to `CONST`, AVX-512 mask and high registers as `XREG` instead of leaking their raw names, and six mnemonics move group. The marker had never moved, so a downstream staleness test read `4.4.4 < 1.13.16` as false and passed on precisely the reports that change had invalidated. Anything persisting escaped-operand signatures needs those pre-4.4.5 reports reprocessed, minhashes and escaped-block shingles first among them, and this marker is what makes them selectable; pic-hashes escape through `escapeBinary`, which the classification change never touched, so `INTEL_PIC_HASH_ESCAPE_VERSION` stays at 4.3.5. A committed fingerprint over mnemonic group plus escaped operands now fails the suite when escaper output moves, so the marker and the change that needs it land together. capstone is pinned below 6 until the arm64-to-aarch64 rename is ported: its compatibility shim covers neither the six `ARM64_*` constants used here that it omits nor the three modules importing `CS_ARCH_ARM64` before any `capstone.arm64*` submodule loads it, and capstone 6 has no stable release yet, so nothing installable is excluded today (tracked in #297). **Housekeeping:** NOTICE with vendored-code attribution, Dependabot exempted from the semantic PR title check, the corpus benchmark classifier reports which direction each changed address points, the AArch64 Mach-O corpus budget sits at `SmdaConfig`'s own 300 s default so a contended runner stops reporting as an analysis defect, the bundled MSVC PE fixture finally has provider-level tests behind it, ruff/pre-commit/dependency bumps. (THX: @r0ny123)

 * 2026-08-11: v4.4.7 - Seven defects in x86/x64 function-start recovery, each one a heuristic discarding a start the binary itself identifies. `mov edi, edi` is both alignment filler and a hot-patched function's own first instruction, and the two were never separated: the prologue scan seeded the body two bytes behind the pad, and the gap scan skipped the pad unless the whole five-byte window matched, mislocating the start. The separator is alignment, since filler exists only to reach the next 16-byte boundary. `_findJumpTableSize` reports an unrecovered bound as `0` while `_resolveExplicitTable` tested against `None`, so an unresolved switch table was abandoned and each case body became a one-block pseudo-function. A relative jump table's own bytes were never claimed as data, letting the gap scan seed functions inside them. A headerless x64 dump lost `.pdata` entirely, since locating it needed the section table; `RUNTIME_FUNCTION` records are now carved directly, validated against exact ground truth at 56/56 tables and 103,815/103,815 entries before any accuracy was measured. And the inferred alignment floor no longer outranks an exception record, which is the image's own declaration. **Recovery output moves on binaries these paths touch**: measured on the bundled fixtures, function sets are unchanged everywhere, while `cutwail` gains two failed functions under a mapped-buffer load and `rust_pe_gnu_xored` gains 3,400 data references from the jump-table claim. (THX: @r0ny123)

 * 2026-08-11: v4.4.6 - `PeSymbolProvider.parseSymbols()` recovered no names at all from a PE carrying a COFF symbol table, because it resolved each symbol's section through `Symbol.section`, which lief leaves as `None` for every PE symbol on 0.17 and 1.0 alike. The 1-based `Symbol.section_idx` carries the same information across the supported lief range and is what the provider reads now. Measured on a mingw-linked Rust binary: 1 of 2344 functions named before, 2020 of 2354 after, and 96% of the functions above the 10-instruction threshold; the function count moves with it because recovered symbols also seed candidates. The failure was silent, so a corpus could be built entirely unnamed without anything complaining; a populated symbol table that yields no usable offset now logs a warning. `tests/rust_pe_gnu_xored` is a new fixture for it, our own `x86_64-pc-windows-gnu` build rather than a sample, because none of the bundled PEs carried a COFF symbol table and the mocked tests had been asserting a shape lief never produces. Closes #229.

 * 2026-08-11: v4.4.5 - Correctness sweep across all four backends, plus report-import and CI hardening. `SmdaReport.fromDict` now validates what it reads, so a truncated or crafted report raises `ValueError` at one boundary instead of a `KeyError` from mid-rebuild, and every address it carries has to fit the 64-bit space the synthesizers pack it into. Recovery fixes: a PE section at `PointerToRawData == 0x200` no longer copies the whole raw file to RVA 0, a zero-`VirtualSize` section no longer yields a code area that rejects every address, the `is_jmp` latch and the `jump_targets` purge no longer split blocks that nothing branches into, .NET blocks end at `throw`/`rethrow`/`endfinally`/`endfilter` and methods are no longer all reported as leaves, AArch64 relative jump-table targets are rebased on the `adr` anchor, strings are read from the mapped image and follow pointer chains at the target word size, and sixteen native-endian `struct` reads are pinned little-endian. **This invalidates previously computed CIL `pic_hash` values for methods containing `throw`, `rethrow`, `endfinally` or `endfilter`.** The block structure changed rather than the escaping, so unlike v4.4.2 no recalculation gate can repair it and affected samples have to be analyzed again. Also: `SmdaConfig` no longer leaks `API_COLLECTION_FILES` between instances, `safe_lief_parse` degrades on a native `ValueError` as well as a `MemoryError`, `py.typed` ships so consumers get types, the test suite runs on Windows and macOS, coverage is measured and floored at 75%, and `pip-audit` plus `zizmor` scan dependencies and workflows on a weekly cron. `version_history.md` and `requirements.txt` are gone, folded into this file and into `pyproject.toml`. Binary synthesis closes four defects that made a synthesized file unusable: the synthetic IAT no longer plants gap and terminator thunks over recovered code, unnamed ELF ranges get `.smdaN` names so the file describes its `PT_LOAD`s instead of re-loading at base 0, synthesized ELF and Mach-O images map at the base the report recorded, and the minimal-PE string section no longer straddles the headers. Report metadata gains the APIs resolved during analysis: `xmetadata.imported_functions` merges them with the static import table, so a sample that builds its own import table at runtime is described by what it actually uses rather than by an IAT that does not parse (0 to 95 imports on the bundled `asprox` dump, with recovery unchanged). Two new options control it, `RESOLVE_COMPUTED_IMPORT_SLOTS` on by default for `call/jmp <ptr> [<reg> + <disp>]`, and `RECORD_IMPORT_SLOT_LOADS` off by default for a slot that is only loaded into a register and never called through. Go symbol recovery reads a big-endian pclntab in its own byte order, reads a 1.16 function entry at its real pointer width instead of four bytes, and takes the text start from the container rather than from the header field Go no longer maintains, which moves externally linked (cgo) builds from 0.0 to 0.986 symbol recall against `go tool nm` across Go 1.18 to 1.25; symbol names now render `U+00B7` as `.`, matching `debug/gosym`. Closes #214, #216, #217, #218, #219, #223. A profile-driven pass over the pipeline then cut roughly a third of the primitive calls out of it, measured here as 18% to 21% less wall time across the bundled fixtures with recovered functions, blocks, instructions and report identity hashes unchanged on every one: per-instruction call overhead removed from the CFG and report paths, instruction dispatch by table, precompiled escaper regexes, literal prefixes for the stub-chain and pclntab scans so the regex engine can fast-search instead of entering the matcher at every offset, one shared metadata parse for .NET, a shallow decoder for the Dalvik start sweep, and the removal of eight `lru_cache` decorators keyed on a LIEF object whose `__hash__` cost more than the work they cached. Batch mode additionally runs inputs above 1 MB on a separate pool whose concurrency is capped by a memory budget (`SmdaConfig.LARGE_INPUT_RSS_FACTOR` and `MEMORY_BUDGET_FRACTION`), derived from the cgroup limit where one applies and from physical RAM otherwise, with workers recycled per file: measured 3.39 GiB to 2.55 GiB aggregate peak child RSS on two multi-megabyte inputs. (THX: @r0ny123)
 * 2026-08-04: v4.4.4 - Continuous fuzzing and determinism hardening: an atheris/libFuzzer harness (`fuzzing/`) covers loaders, format parsers, the full disassembly pipeline, and report JSON round-trip, running on a schedule and on relevant PRs. Fixes it surfaced: CIL `TypeDef`/`TypeSpec` operands fell through to `str(operand)` and serialized a raw memory address, making every report of the same input non-deterministic; a negative disassembly-window offset could read from the tail of the mapped image and book unrelated bytes into `code_map`; and `MachoFileLoader.parseBinary` was missing the `safe_lief_parse` guard against a crafted-header `std::bad_alloc`. Also adds `SmdaReport`/`SmdaInstruction` picklability (excludes the ctypes-backed capstone objects from `__getstate__`), parallel batch disassembly (`smda.utility.BatchProcessor`, `batch_analyze.py`, ~4.5x on a 10-core box), and a report-identity-hash correctness channel in the perf-benchmark gate. (THX: @r0ny123)
 * 2026-08-04: v4.4.3 - Audit hardening: `ty` static type checking wired into CI, ~36 Hypothesis fuzz tests over the file loaders/Rust demangler/Go+Delphi label providers, 15 property tests (report round-trip, block coverage, pic-hash relocation stability, escaper determinism, a dominator-tree brute-force oracle), and an advisory sibling-pair CI check that flags when a PR touches one file in a related group (loaders, escapers, backends, ...) but not its siblings. Adds `safe_lief_parse()` so a crafted header that would make lief attempt an unbounded allocation degrades to `None` instead of aborting the process, and fixes mutable class-level defaults shared across `SmdaFunction`/`SmdaReport` instances plus a register-operand `getDataRefs()` false positive on base-0 images. (THX: @r0ny123)
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
 * 2026-06-01: v3.0.2 - Added safeguards against memory usage explosion during candidate identification on pathological/junk samples (issue #85): new SmdaConfig backstops `MAX_FUNCTION_CANDIDATES` (default 200000) and `MAX_CALL_REFS_PER_CANDIDATE` (default 2000), the high-volume reference/prologue locators now honor the existing wall-clock TIMEOUT, and high-value candidate locators run before the cap can be exhausted.
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
 * 2025-02-24: v1.14.3 - PicHashing can now be disabled via SmdaConfig to save some processing time. (THX to @Nalexander-hanel!)
 * 2025-02-24: v1.14.2 - We are Python 3.8+ compatible again (changed UTC usage) and (DWARF) PE symbols for PE files should be extracted again (THX to @N0fix for the update!)
 * 2025-02-21: v1.14.1 - Fixed changed field names in LIEF usage that broke ELF parsing, added tests for ELF+macOS parsing (THX to @N0fix for the update!)
 * 2025-01-29: v1.14.0 - Bump to LIEF 0.16.0+ (THX to @huettenhain for the ping!). Migrated tests to `pytest`, UTC datetime handling fixes.
 * 2025-01-26: v1.13.24 - Added functionality to import and export SMDA reports as JSON. Fixed byte patterns matching special regex chars (THX to @alexander-hanel!).
 * 2024-07-26: v1.13.23 - Now using OEP as symbol function candidate when available (THX to @alexander-hanel for reporting!).
 * 2024-05-10: v1.13.22 - Handled odd case where disassembly with capstone and IDA would return different results (THX to @r0ny123 for reporting!).
 * 2024-04-17: v1.13.21 - Fixed handling of Go binaries for version 1.20+ (THX to @Manny684!).
 * 2024-04-08: v1.13.20 - Fixed handling of bnd prefix in CFG instructions to help with parsing PLT (THX to @Manny684!).
 * 2024-04-02: v1.13.19 - Fixed bug in string parsing, added tests, strings now no longer are hex-encoded as they are always printable anyway.
 * 2024-03-12: v1.13.18 - Added functionality to extract and store all referenced strings along SmdaFunctions (has to be enabled via SmdaConfig).
 * 2024-03-12: v1.13.17 - Extended disassembleBuffer() to now take additional arguments `code_areas` and `oep`.
 * 2024-02-21: v1.13.16 - BREAKING IntelInstructionEscaper.escapeMnemonic: Escaper now handles another 200 instruction names found in other capstone source files (THX for reporting @malwarefrank!).
 * 2024-02-15: v1.13.15 - Fixed issues with version recognition in SmdaFunction which cause issues in MCRIT (THX to @
 * 2024-02-02: v1.13.12 - Versions might be non-numerical, addressed that in SmdaFunction.
 * 2024-01-23: v1.13.11 - Introduced indicator in SmdaConfig for compatibility of instruction escaping.
 * 2024-01-23: v1.13.10 - Parsing of PE files should work again with lief >=0.14.0.
 * 2024-01-23: v1.13.9  - Improved parsing robustness for section/segment tables in ELF files, also now padding with zeroes when finding less content than expected physical size in a segment (THX for reporting @schrodyn!).
 * 2024-01-23: v1.13.8  - BREAKING adjustments to IntelInstructionEscaper.escapeMnemonic: Escaper now is capable of handling all known x86/x64 instructions in capstone (THX for reporting @schrodyn!).
 * 2023-12-01: v1.13.7  - Skip processing of Delphi structs for large files, workaround until this is properly reimplemented.
 * 2023-11-29: v1.13.6  - Made OpcodeHash an attribute with on-demand calculation to save processing time.
 * 2023-11-29: v1.13.3  - Implemented an alternative queue working with reference count based brackets in pursuit of accelerated processing.
 * 2023-11-28: v1.13.2  - IndirectCallAnalyzer will now analyze at most a configurable amount of calls per basic block, default 50.
 * 2023-11-21: v1.13.1  - SmdaBasicBlock now has `getPredecessors()` and `getSuccessors()`.
 * 2023-11-21: v1.13.0  - BREAKING adjustments to PicHashing (now wildcarding intraprocedural jumps in functions, additionally more immediates if within address space). Introduction of OpcodeHash (OpcHash), which wildcards all but prefixes and opcode bytes.
 * 2023-10-12: v1.12.7  - Bugfix for parsing Delphi structs.
 * 2023-09-15: v1.12.6  - Bugfix in BlockLocator (THX to @cccs-ay!).
 * 2023-08-28: v1.12.5  - Bugfix for address dereferencing where buffer sizes were not properly checked (THX to @yankovs!).
 * 2023-08-08: v1.12.4  - SmdaBasicBlock can now do getPicBlockHash().
 * 2023-05-23: v1.12.3  - Fixed bugs in PE parser and Go parser.
 * 2023-05-08: v1.12.1  - Get rid of deprecation warning in IDA 8.0+.
 * 2023-03-24: v1.12.0  - SMDA now parses PE export directories for symbols, as well as MinGW DWARF information if available.
 * 2023-03-14: v1.11.2  - SMDA report now also contains SHA1 and MD5.
 * 2023-03-14: v1.11.1  - rendering dotGraph can now include API references instead of plain calls.
 * 2023-02-06: v1.11.0  - SmdaReport now has functionality to find a function/block by a given offset contained within in (THX to @cccs-ay!).
 * 2023-02-06: v1.10.0  - Adjusted to LIEF 0.12.3 API for binary parsing (THX to @lainswork!).
 * 2022-11-18: v1.9.16- Fixed a bug where handling of inrefs in SmdaReport could lead to crashes (THX to @1337-42!).
 * 2022-09-27: v1.9.15- Fixed a bug where recognition of code areas would not incorporate virtual addressing (infinite loops while Delphi VMT parsing).
 * 2022-09-20: v1.9.13- Fixed a bug for listing unreachable basic block refs pointing outside of function boundaries (exception handling).
 * 2022-09-19: v1.9.12- Fixed a logic binding bug in IntelInstructionEscaper (THX to @1337-42!).
 * 2022-09-08: v1.9.11- Exposed masking of intraprocedural jmps/calls in SmdaInstruction.
 * 2022-08-31: v1.9.9 - Better handling of colliding code due to tailjumps.
 * 2022-08-30: v1.9.8 - Improved accuracy for references around tailcalls.
 * 2022-08-25: v1.9.6 - Fixed bug in delphi knowledge base handling and improved performance.
 * 2022-08-23: v1.9.4 - Fixed bug in section padding for ELF files.
 * 2022-08-22: v1.9.3 - Added parsing for Delphi knowledge base files (THX to @danielenders1!).
 * 2022-08-22: v1.9.2 - Improved structural parsing of Delphi binaries (THX to @danielenders1!).
 * 2022-08-12: v1.9.1   - Added support for parsing intel MachO files, including Go parsing.
 * 2022-08-10: v1.8.5 - Fixed Go 64bit lavel parsing for v1.12 binaries.
 * 2022-08-04: v1.8.4 - Dot export now uses hex formatted addresses in node names.
 * 2022-08-03: v1.8.3 - Added support for producing a Dot export for SmdaFunction.
 * 2022-08-01: v1.8.1 - Added support for parsing 32bit Go binaries as well.
 * 2022-08-01: v1.8.0   - Added support for parsing Go function information (THX to @danielenders1!).
 * 2022-07-22: v1.7.4 - Bugfix for marshalling of reports.
 * 2022-07-08: v1.7.2 - Excluded overly aggressive tailcall recognition heuristics when processing Golang binaries.
 * 2022-01-27: v1.7.0   - SmdaReports now contains a field `oep`; SmdaFunctions now indicate `is_exported` and can provide CodeXrefs via `getCodeInrefs()` and `getCodeOutrefs()`. (THX for the ideas: @mr-tz)
 * 2021-08-20: v1.6.1 - Bugfix for alignment calculation of binary mappings. (THX: @williballenthin)
 * 2021-08-20: v1.6.0   - Bugfix for alignment calculation of binary mappings. (THX: @williballenthin)
 * 2021-07-22: v1.5.19 - Now also parsing plt.sec structures to identify functions.
 * 2021-06-07: v1.5.18 - Bugfix for struct.pack 8byte conversion using L instead Q (works on Linux, not on Windows).
 * 2021-05-21: v1.5.17 - Bugfix for MemoryError when having LIEF try to process section data.
 * 2021-05-20: v1.5.16 - Bugfix for formatting exceptions in report output (THX: @BonusPlay)
 * 2021-05-18: v1.5.15 - Changed SHA256 in SmdaReports for unmapped files (was hash of memory-mapped image, not it's the input file's hash).
 * 2021-04-07: v1.5.14 - Bugfix when processing Exception handler addresses as function entry point candidates (THX: capa team).
 * 2021-01-20: v1.5.13 - Now using LIEF 0.11 and moved some print output to logging.
 * 2021-01-15: v1.5.11 - Disassembler now offers `disassembleUnmappedBuffer(buffer)` to load and process unmapped files directly from memory.
 * 2020-12-11: v1.5.10 - Pinned LIEF to 0.10.1.
 * 2020-12-01: v1.5.9 - Bugfix for section names. again. :)
 * 2020-11-25: v1.5.6 - Now considering segments for content when ELF file has no sections (THX: @jcrussell).
 * 2020-11-10: v1.5.5 - Unmarshalling setting default value for older reports.
 * 2020-11-06: v1.5.4 - Minor fix on PE header parsing.
 * 2020-11-05: v1.5.3 - Adjusted API thunk identification.
 * 2020-10-30: v1.5.2 - One bugfix, also removed one print and reduced logging priority for the message in case the PDB parser module is missing.
 * 2020-10-30: v1.5.1 - PE section table now contained in SmdaReport and added `SmdaReport.getSection(offset)`.
 * 2020-10-30: v1.5.0   - PE section table now contained in SmdaReport and added `SmdaReport.getSection(offset)`.
 * 2020-10-30: v1.4.12 - Bugfix in IndirectCallHandler (THX: @jcrussell).
 * 2020-10-29: v1.4.11 - Populate exception handlers specified in PE64 `.pdata` section as FEPs.
 * 2020-10-29: v1.4.10 - Resolves 64bit API calls of style `call qword ptr [rip + offset]` and more register-based API calls in general (THX: @jcrussell).
 * 2020-10-29: v1.4.8 - Bugfixes. Verbose mode added (THX: @jcrussell).
 * 2020-10-28: v1.4.6 - WinApiResolver now tries to resolve import by ordinal to their name if it is known - can be extended in the database of OrdinalHelper.
 * 2020-10-28: v1.4.5 - Store the (mapped) buffer that was used to do disassembly along inside a SmdaReport - goal: enable to read strings/bytes at offsets at a later time.
 * 2020-10-27: v1.4.4 - SmdaInstructions can now provide potential data references via `SmdaInstruction.getDataRefs()`.
 * 2020-10-27: v1.4.3 - SmdaInstructions can now on demand provide the detailed capstone instruction representation via `SmdaInstruction.getDetailed()`.
 * 2020-10-27: v1.4.1 - 10-20% gain in processing speed by switching to `capstone.disasm_lite()`.
 * 2020-10-26: v1.4.0   - Adding SmdaBasicBlock. Some convenience code to ease intgration with capa. (GeekWeek edition!)
 * 2020-09-07: v1.3.11 - Summarizable DisassemblyStatistics.
 * 2020-09-02: v1.3.10 - Fixed a bug where IDA Pro would crash when failing to demangle a function name while exporting a SMDA report.
 * 2020-08-31: v1.3.9 - Adjusted Logging to avoid interference with other loggers configured outside of SMDA (THX: @BonusPlay).
 * 2020-08-25: v1.3.6 - PicHash no longer stored as list.
 * 2020-08-17: v1.3.5 - Bugfix for import parsing (ELF files).
 * 2020-08-17: v1.3.4 - Recalculate PIC hash and nesting depth for  older (v1.2.x) reports on import for compatibility.
 * 2020-08-17: v1.3.3 - Added binary variation of `push ebp;mov ebp, esp` to list of default prologues and added exception handling for DominatorTrees (THX: @fxb).
 * 2020-07-13: v1.3.2 - Use LIEF to parse Import Table for WinAPI usage data when processing unmapped files.
 * 2020-07-13: v1.3.1 - Fixed `setup.py` to properly specify dependencies (THX: @BonusPlay).
 * 2020-06-22: v1.3.0   - Added DominatorTree (Implementation by Armin Rigo) to calculate function nesting depth, shortened PIC hash to 8 byte, added some missing instructions for the InstructionEscaper, IdaInterface now demangles names.
 * 2020-05-28: v1.2.15 - Bugfixes in IntelInstructionEscaper (handling of negative RIP-relative offsets), SmdaReport (datetime handling), PeFileParser (handling of empty pefile.sections); SCC calculation changed to iterative algorithm (using @bwesterb's implementation) and activated by default again.
 * 2020-05-14: v1.2.10 - Bug in IdaInterface fixed.
 * 2020-05-13: v1.2.9 - Bugfix in code gap identification in FunctionCandidateManager, SCC calculation is now optional.
 * 2020-05-12: v1.2.7 - Added additional default metadata field "component" to SmdaReport.
 * 2020-05-11: v1.2.6 - Export from IDA to SMDA data format is now supported (IDA 7.4).
 * 2020-05-09: v1.2.5 - Fixed off-by-one that affected wildcarding of instructions (THX to Viviane Zwanger).
 * 2020-05-04: v1.2.4 - Various minor fixes.
 * 2020-04-29: v1.2.0   - Restructured config.py into smda/SmdaConfig.py to similfy usage and now available via PyPI! The smda/Disassembler.py now emits a report object (smda.common.SmdaReport) that allows direct (pythonic) interaction with the results - a JSON can still be easily generated by using toDict() on the report.
 * 2020-04-28: v1.1.0   - Several improvements, including: x64 jump table handling, better data flow handling for calls using registers and tailcalls, extended list of common prologues based on much more groundtruth data, extended padding instruction list for gap function discovery, adjusted weights in candidate priority score, filtering code areas based on section tables, using exported symbols as candidates, new function output metadata: confidence score based on instruction mnemonic histogram, PIC hash based on escaped binary instruction sequence
 * 2019-08-05: v1.0.3 - SMDA can now export reports from IDA Pro (requires capstone to be available for idapython).
 * 2019-02-14: v1.0.2 - ELF symbols for functions are now resolved, if present in the file. Also "-m" parameter changed to "-p" to imply parsing instead of just mapping (THX: @VPaulV).
 * 2018-07-09: v1.0.1 - Performance improvements.
 * 2018-07-01: v1.0.0   - Initial Release.
 * 2020-03-10: Various minor fixes and QoL improvements.
 * 2019-08-20: IdaExporter is now handling failed instruction conversion via capstone properly.
 * 2019-08-19: Minor fix for crashes caused by PDB parser.
 * 2019-06-13: PDB symbols for functions are now resolved if given a PDB file using parameter "-d" (THX to @VPaulV).
 * 2019-05-15: Fixed a bug in PE mapper where buffer would be shortened because of misinterpretation of section sizes.
 * 2018-12-12: all gcc jump table styles are now parsed correctly.
 * 2018-11-26: Better handling of multibyte NOPs, ELF loader now provides base addr.
 * 2018-09-28: We now have functional PE/ELF loaders.

[Unreleased]: https://github.com/danielplohmann/smda/compare/v4.6.0...HEAD
