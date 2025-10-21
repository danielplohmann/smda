# Full Version History
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
malwarefrank!)
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
 * 2022-08-22: v1.9.3 - Added parsing for Delphi knowledge base files (THX to @danielenders1!).
 * 2022-08-22: v1.9.2 - Improved structural parsing of Delphi binaries (THX to @danielenders1!).
 * 2022-08-12: v1.9.1 - Added support for parsing intel MachO files, including Go parsing.
 * 2022-08-10: v1.8.5 - Fixed Go 64bit lavel parsing for v1.12 binaries.
 * 2022-08-04: v1.8.4 - Dot export now uses hex formatted addresses in node names.
 * 2022-08-03: v1.8.3 - Added support for producing a Dot export for SmdaFunction.
 * 2022-08-01: v1.8.1 - Added support for parsing 32bit Go binaries as well.
 * 2022-08-01: v1.8.0 - Added support for parsing Go function information (THX to @danielenders1!).
 * 2022-07-22: v1.7.4 - Bugfix for marshalling of reports.
 * 2022-07-08: v1.7.2 - Excluded overly aggressive tailcall recognition heuristics when processing Golang binaries.
 * 2022-01-27: v1.7.0 - SmdaReports now contains a field `oep`; SmdaFunctions now indicate `is_exported` and can provide CodeXrefs via `getCodeInrefs()` and `getCodeOutrefs()`. (THX for the ideas: @mr-tz)
 * 2021-08-20: v1.6.1 - Bugfix for alignment calculation of binary mappings. (THX: @williballenthin)
 * 2021-08-19: v1.6.0 - Bugfix for truncation during ELF segment/section loading. API usage in ELF files is now resolved as well! (THX: @williballenthin)
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
 * 2020-10-30: v1.4.12 - Bugfix in IndirectCallHandler (THX: @jcrussell).
 * 2020-10-29: v1.4.11 - Populate exception handlers specified in PE64 `.pdata` section as FEPs.
 * 2020-10-29: v1.4.10 - Resolves 64bit API calls of style `call qword ptr [rip + offset]` and more register-based API calls in general (THX: @jcrussell).
 * 2020-10-29: v1.4.8 - Bugfixes. Verbose mode added (THX: @jcrussell).
 * 2020-10-28: v1.4.6 - WinApiResolver now tries to resolve import by ordinal to their name if it is known - can be extended in the database of OrdinalHelper.
 * 2020-10-28: v1.4.5 - Store the (mapped) buffer that was used to do disassembly along inside a SmdaReport - goal: enable to read strings/bytes at offsets at a later time.
 * 2020-10-27: v1.4.4 - SmdaInstructions can now provide potential data references via `SmdaInstruction.getDataRefs()`.
 * 2020-10-27: v1.4.3 - SmdaInstructions can now on demand provide the detailed capstone instruction representation via `SmdaInstruction.getDetailed()`.
 * 2020-10-27: v1.4.1 - 10-20% gain in processing speed by switching to `capstone.disasm_lite()`.
 * 2020-10-26: v1.4.0 - Adding SmdaBasicBlock. Some convenience code to ease intgration with capa. (GeekWeek edition!)
 * 2020-09-07: v1.3.11 - Summarizable DisassemblyStatistics.
 * 2020-09-02: v1.3.10 - Fixed a bug where IDA Pro would crash when failing to demangle a function name while exporting a SMDA report.
 * 2020-08-31: v1.3.9 - Adjusted Logging to avoid interference with other loggers configured outside of SMDA (THX: @BonusPlay).
 * 2020-08-25: v1.3.6 - PicHash no longer stored as list.
 * 2020-08-17: v1.3.5 - Bugfix for import parsing (ELF files).
 * 2020-08-17: v1.3.4 - Recalculate PIC hash and nesting depth for  older (v1.2.x) reports on import for compatibility.
 * 2020-08-17: v1.3.3 - Added binary variation of `push ebp;mov ebp, esp` to list of default prologues and added exception handling for DominatorTrees (THX: @fxb).
 * 2020-07-13: v1.3.2 - Use LIEF to parse Import Table for WinAPI usage data when processing unmapped files.
 * 2020-07-13: v1.3.1 - Fixed `setup.py` to properly specify dependencies (THX: @BonusPlay).
 * 2020-06-22: v1.3.0 - Added DominatorTree (Implementation by Armin Rigo) to calculate function nesting depth, shortened PIC hash to 8 byte, added some missing instructions for the InstructionEscaper, IdaInterface now demangles names.
 * 2020-05-28: v1.2.15 - Bugfixes in IntelInstructionEscaper (handling of negative RIP-relative offsets), SmdaReport (datetime handling), PeFileParser (handling of empty pefile.sections); SCC calculation changed to iterative algorithm (using @bwesterb's implementation) and activated by default again.
 * 2020-05-14: v1.2.10 - Bug in IdaInterface fixed.
 * 2020-05-13: v1.2.9 - Bugfix in code gap identification in FunctionCandidateManager, SCC calculation is now optional.
 * 2020-05-12: v1.2.7 - Added additional default metadata field "component" to SmdaReport.
 * 2020-05-11: v1.2.6 - Export from IDA to SMDA data format is now supported (IDA 7.4).
 * 2020-05-09: v1.2.5 - Fixed off-by-one that affected wildcarding of instructions (THX to Viviane Zwanger).
 * 2020-05-04: v1.2.4 - Various minor fixes.
 * 2020-04-29: v1.2.0 - Restructured config.py into smda/SmdaConfig.py to similfy usage and now available via PyPI! The smda/Disassembler.py now emits a report object (smda.common.SmdaReport) that allows direct (pythonic) interaction with the results - a JSON can still be easily generated by using toDict() on the report.
 * 2020-04-28: v1.1.0 - Several improvements, including: x64 jump table handling, better data flow handling for calls using registers and tailcalls, extended list of common prologues based on much more groundtruth data, extended padding instruction list for gap function discovery, adjusted weights in candidate priority score, filtering code areas based on section tables, using exported symbols as candidates, new function output metadata: confidence score based on instruction mnemonic histogram, PIC hash based on escaped binary instruction sequence
 * 2020-03-10: Various minor fixes and QoL improvements.
 * 2019-08-20: IdaExporter is now handling failed instruction conversion via capstone properly.
 * 2019-08-19: Minor fix for crashes caused by PDB parser.
 * 2019-08-05: v1.0.3 - SMDA can now export reports from IDA Pro (requires capstone to be available for idapython).
 * 2019-06-13: PDB symbols for functions are now resolved if given a PDB file using parameter "-d" (THX to @VPaulV).
 * 2019-05-15: Fixed a bug in PE mapper where buffer would be shortened because of misinterpretation of section sizes.
 * 2019-02-14: v1.0.2 - ELF symbols for functions are now resolved, if present in the file. Also "-m" parameter changed to "-p" to imply parsing instead of just mapping (THX: @VPaulV).
 * 2018-12-12: all gcc jump table styles are now parsed correctly.
 * 2018-11-26: Better handling of multibyte NOPs, ELF loader now provides base addr.
 * 2018-09-28: We now have functional PE/ELF loaders.
 * 2018-07-09: v1.0.1 - Performance improvements.
 * 2018-07-01: v1.0.0 - Initial Release.
