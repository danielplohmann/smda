"""The address-materialization scan runs on the images that need it and not on the ones that do not.

It exists to reach entries no call names -- a pointer handed to a callback, a table walked at run
time. An image whose metadata already lists every function has none of those left over, and what
the scan adds there is addresses that are materialized but are not entries.

Instruction encodings below were verified against capstone 5.0.7 (CS_ARCH_ARM64).
"""

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from smda.aarch64.FunctionCandidateManager import _METADATA_MIN_CALL_TARGETS, FunctionCandidateManager
from smda.common.LanguageAnalyzer import LanguageAnalyzer
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig
from smda.utility.FileLoader import FileLoader

BASE = 0x400000
#: call targets the predicate tests divide, chosen above the floor and so that the cutoff
#: ratio is exact rather than a rounding of one
SAMPLE = 800
AT_CUTOFF = 760

#: the reuse test needs a second image whose addresses cannot be confused with the first's
REUSE_BASE = 0x800000
#: the single PT_LOAD maps file offset 0 at the base, so .text is at base + its file offset
TEXT_OFFSET = 0x1000
TEXT_SIZE = 0x9000

NOP = 0xD503201F
RET = 0xD65F03C0
PROLOGUE = 0xA9BF7BFD  # stp x29, x30, [sp, #-16]!
EPILOGUE = 0xA8C17BFD  # ldp x29, x30, [sp], #16
MOV_W0_1 = 0x52800020  # mov w0, #1
MOV_W1_2 = 0x52800041  # mov w1, #2
MOV_W2_3 = 0x52800062  # mov w2, #3
BTI_C = 0xD503245F  # bti c

#: 16-aligned entries each carrying more than one call reference, which does two jobs: it
#: gives the alignment floor a population to infer 16 from, and it puts the image over
#: `_METADATA_MIN_CALL_TARGETS` so the coverage test reads a rate rather than declining for
#: want of a sample
LEAF_COUNT = _METADATA_MIN_CALL_TARGETS + 8
LEAF_BLOCK = 0x2000
LEAF_STRIDE = 0x10
TARGET_BLOCK = 0x6000
SEEDER_BLOCK = 0x7000
#: jump-table entries: small offsets, which occupy the udf encoding space, so the gap scan reads
#: them as data and only the address scan can book the table
TABLE_WORDS = (0x00000008, 0x00000010, 0x00000018, 0x00000020)
#: how far into its page a materialized address sits, so the `add` carries a real offset, not #0
LO12_OFFSET = 0x100


def _bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x03FFFFFF)


def _adr(source, target, rd=0):
    imm = (target - source) & 0x1FFFFF
    return 0x10000000 | ((imm & 0x3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def _adrp(source, target, rd=0):
    # the immediate counts pages between the two addresses' pages, not bytes between the addresses
    imm = ((target >> 12) - (source >> 12)) & 0x1FFFFF
    return 0x90000000 | ((imm & 0x3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def _add(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def _elf(text, base, symbols=()):
    """ELF64/AArch64 image: one R+X PT_LOAD, a .text section, and a symbol table when asked for one.

    An ELF rather than a bare buffer because the address scan reads its executable extents from
    the section table and does nothing at all without one, so a buffer cannot exercise the gate
    either way. The symbol table is the metadata the gate asks about.
    """
    ehsize, phentsize, shentsize, symentsize = 64, 56, 64, 24
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text\x00")
    name_symtab = shstrtab.index(b".symtab\x00")
    name_strtab = shstrtab.index(b".strtab\x00")
    name_shstrtab = shstrtab.index(b".shstrtab\x00")

    strtab = bytearray(b"\x00")
    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))  # the reserved null entry
    for name, value, size in symbols:
        symtab += struct.pack("<IBBHQQ", len(strtab), 0x12, 0, 1, value, size)  # STB_GLOBAL STT_FUNC
        strtab += name.encode() + b"\x00"

    text_va = base + TEXT_OFFSET
    symtab_offset = TEXT_OFFSET + len(text)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    sh_offset = shstrtab_offset + len(shstrtab)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT
        2,  # e_type = ET_EXEC
        183,  # e_machine = EM_AARCH64
        1,  # e_version
        text_va,  # e_entry
        ehsize,  # e_phoff
        sh_offset,  # e_shoff
        0,  # e_flags
        ehsize,
        phentsize,
        1,  # e_phnum
        shentsize,
        5,  # e_shnum
        4,  # e_shstrndx
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, sh_offset, sh_offset, 0x1000)  # PT_LOAD, R+X

    def shdr(name, sh_type, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, offset, size, link, info, align, entsize)

    section_headers = (
        shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  # SHT_NULL
        + shdr(name_text, 1, 0x6, text_va, TEXT_OFFSET, len(text), 0, 0, 4, 0)  # PROGBITS, ALLOC|EXECINSTR
        # LIEF drops the table when sh_link (its string table) and sh_info (its first non-local
        # symbol) disagree with its contents
        + shdr(name_symtab, 2, 0, 0, symtab_offset, len(symtab), 3, 1, 8, symentsize)
        + shdr(name_strtab, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0)
        + shdr(name_shstrtab, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)
    )
    header = bytearray(ehdr + phdr)
    header += b"\x00" * (TEXT_OFFSET - len(header))
    return bytes(header) + text + bytes(symtab) + bytes(strtab) + shstrtab + section_headers


def _leaves(text_va):
    return [text_va + LEAF_BLOCK + index * LEAF_STRIDE for index in range(LEAF_COUNT)]


def _callTargets(text_va):
    """Every address the scaffold's `bl` instructions call, which is the population the coverage
    test divides by."""
    return set(_leaves(text_va)) | {text_va + SEEDER_BLOCK}


def _scaffold(text_va):
    """The leaves and the caller that calls each of them twice and the seeder once: twenty-two
    16-aligned call-referenced entries for the alignment floor to infer 16 from, and the image's
    `bl` population, without which the coverage test has no denominator and answers False."""
    words = {}
    for leaf in _leaves(text_va):
        words.update({leaf: PROLOGUE, leaf + 4: MOV_W0_1, leaf + 8: EPILOGUE, leaf + 12: RET})
    address = text_va
    words[address] = PROLOGUE
    address += 4
    for leaf in _leaves(text_va):
        for _call in range(2):
            words[address] = _bl(address, leaf)
            address += 4
    words[address] = _bl(address, text_va + SEEDER_BLOCK)
    address += 4
    words[address] = EPILOGUE
    words[address + 4] = RET
    return words


def _text(words, text_va):
    text = bytearray(NOP.to_bytes(4, "little") * (TEXT_SIZE // 4))
    for word_address, word in words.items():
        text[word_address - text_va : word_address - text_va + 4] = word.to_bytes(4, "little")
    return bytes(text)


def _callbackImage(base, materialized=True):
    """A stripped image whose two callbacks only a materialized address reaches.

    Nothing calls either one and no stored pointer points at them, and each opens on a `bti c` pad
    that the prologue and gap scans both refuse -- `_isLikelyInteriorBtiCandidate` reads a pad whose
    preceding word is ordinary code, the `mov` in front of each one here, as an indirect-branch
    target rather than an entry. That leaves what the seeder materializes, `adr` for the first and
    the `adrp`/`add` pair for the second. `materialized=False` replaces those three words with nops:
    the control saying the address scan is what recovered them.
    """
    text_va = base + TEXT_OFFSET
    adr_callback = text_va + TARGET_BLOCK
    pair_callback = text_va + TARGET_BLOCK + LO12_OFFSET
    seeder = text_va + SEEDER_BLOCK
    words = _scaffold(text_va)
    for callback in (adr_callback, pair_callback):
        words.update(
            {
                callback - 4: MOV_W2_3,  # the ordinary code that makes the pad behind it read as interior
                callback: BTI_C,
                callback + 4: MOV_W1_2,
                callback + 8: RET,
            }
        )
    words.update(
        {
            seeder: PROLOGUE,
            seeder + 4: _adr(seeder + 4, adr_callback) if materialized else NOP,
            seeder + 8: _adrp(seeder + 8, pair_callback, 8) if materialized else NOP,
            seeder + 12: _add(8, 8, pair_callback & 0xFFF) if materialized else NOP,
            seeder + 16: EPILOGUE,
            seeder + 20: RET,
        }
    )
    return _elf(_text(words, text_va), base), adr_callback, pair_callback


def _tableImage(base, named=True):
    """An image whose one materialized address is a jump table rather than an entry -- the shape
    the scan produces on an image carrying a full function map, where it books the table's base as
    a function. `named=False` leaves the symbol table out: the control saying it is the coverage
    and not the table's own shape that decides."""
    text_va = base + TEXT_OFFSET
    table = text_va + TARGET_BLOCK + LO12_OFFSET
    seeder = text_va + SEEDER_BLOCK
    words = _scaffold(text_va)
    for index, entry in enumerate(TABLE_WORDS):
        words[table + index * 4] = entry
    words.update(
        {
            seeder: PROLOGUE,
            seeder + 4: _adrp(seeder + 4, table, 8),
            seeder + 8: _add(8, 8, table & 0xFFF),
            seeder + 12: EPILOGUE,
            seeder + 16: RET,
        }
    )
    symbols = ()
    if named:
        # a symbol per call target, which is what a full function map amounts to here
        symbols = [(f"leaf_{index}", leaf, 0x10) for index, leaf in enumerate(_leaves(text_va))]
        symbols += [("seeder", seeder, 0x14), ("caller", text_va, 0xC0)]
    return _elf(_text(words, text_va), base, symbols), table


def _functions(blob):
    """Analyse a built image, returning the report as well so a test can say it analysed at all."""
    config = SmdaConfig()
    config.WITH_STRINGS = False
    report = Disassembler(config).disassembleUnmappedBuffer(blob)
    return report, {function.offset for function in report.getFunctions()}


def _disassembly(blob):
    """What a candidate manager is initialized over, built without running an analysis so a test
    can hold the manager afterwards and read what discovery left in it."""
    loader = FileLoader("/", map_file=True)
    loader._loadFile(blob)
    disassembly = DisassemblyResult()
    disassembly.binary_info = Disassembler()._populateBinaryInfo(loader)
    return disassembly


class MetadataCoverageTest(unittest.TestCase):
    """The coverage test itself, over the two sets it reads and nothing else."""

    def _manager(self, target_count, named_count):
        """Only what the coverage test consults, so what survives here is its whole input. The
        counts divide exactly at the cutoff, keeping the boundary case about the comparison
        rather than about where a ratio rounds."""
        manager = FunctionCandidateManager(SmdaConfig())
        targets = [BASE + index * 0x10 for index in range(target_count)]
        manager._call_targets = set(targets)
        manager._metadata_candidates = set(targets[:named_count])
        return manager

    def testCoverageBelowTheCutoffLeavesTheScanRunning(self):
        # 760 of 800 is 0.95; one fewer is not
        self.assertFalse(self._manager(SAMPLE, AT_CUTOFF - 1)._metadataNamedTheCallTargets())

    def testCoverageAtTheCutoffSkipsTheScan(self):
        # 760 of 800 computes to the same double the cutoff is written as, so the comparison
        # decides the boundary and not which way a division rounded
        self.assertTrue(self._manager(SAMPLE, AT_CUTOFF)._metadataNamedTheCallTargets())

    def testCoverageAboveTheCutoffSkipsTheScan(self):
        self.assertTrue(self._manager(SAMPLE, SAMPLE)._metadataNamedTheCallTargets())

    def testEveryCallTargetNamedIsStillNotEnoughFromTooSmallASample(self):
        """A rate needs a sample. One image in the corpus resolves four `bl` targets in total,
        and metadata naming all four says nothing about the functions only a materialized
        address reaches -- so below the floor the scan runs however the few came out."""
        self.assertFalse(
            self._manager(_METADATA_MIN_CALL_TARGETS - 1, _METADATA_MIN_CALL_TARGETS - 1)._metadataNamedTheCallTargets()
        )
        self.assertTrue(
            self._manager(_METADATA_MIN_CALL_TARGETS, _METADATA_MIN_CALL_TARGETS)._metadataNamedTheCallTargets()
        )

    def testAnImageWhoseCallsResolvedToNothingLeavesTheScanRunning(self):
        """No call targets is no evidence either way, and the scan is the last pass that could
        reach an entry, so it runs."""
        self.assertFalse(self._manager(0, 0)._metadataNamedTheCallTargets())

    def testOnlyTheNamedAddressesThatAreCallTargetsCount(self):
        """Control on the denominator: metadata that names addresses nothing calls says nothing
        about the addresses something does call, so it cannot lift an image over the cutoff."""
        manager = self._manager(SAMPLE, AT_CUTOFF - 1)
        manager._metadata_candidates |= {BASE + 0x80000 + index * 0x10 for index in range(SAMPLE)}

        self.assertFalse(manager._metadataNamedTheCallTargets())


class AddressScanRunsWithoutMetadataTest(unittest.TestCase):
    """The recall side: a stripped image is the case the address scan exists for."""

    def setUp(self):
        blob, self.adr_callback, self.pair_callback = _callbackImage(BASE)
        report, self.functions = _functions(blob)
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")

    def testTheCallbackReachedByAnAdrIsRecovered(self):
        self.assertIn(self.adr_callback, self.functions)

    def testTheCallbackReachedByTheAdrpAddPairIsRecovered(self):
        self.assertIn(self.pair_callback, self.functions)

    def testTheRestOfTheImageIsRecovered(self):
        """Control. Both assertions above would also hold on an image that failed to analyse."""
        self.assertIn(BASE + TEXT_OFFSET, self.functions)
        self.assertIn(BASE + TEXT_OFFSET + SEEDER_BLOCK, self.functions)
        self.assertEqual([leaf for leaf in _leaves(BASE + TEXT_OFFSET) if leaf not in self.functions], [])

    def testNeitherCallbackIsRecoveredOnceTheMaterializationIsGone(self):
        """Control on the other side: with the three words that materialize the addresses replaced
        by nops, nothing else in the image reaches either callback, so it is the address scan that
        recovered them above and not a pass that would have reached them regardless."""
        blob, adr_callback, pair_callback = _callbackImage(BASE, materialized=False)
        report, functions = _functions(blob)

        self.assertEqual(report.status, "ok")
        self.assertNotIn(adr_callback, functions)
        self.assertNotIn(pair_callback, functions)
        self.assertIn(BASE + TEXT_OFFSET, functions)


class AddressScanIsSkippedWhenMetadataNamedTheCallsTest(unittest.TestCase):
    """The precision side: on an image that names its own call targets the scan is not run."""

    def setUp(self):
        blob, self.table = _tableImage(BASE)
        report, self.functions = _functions(blob)
        self.assertEqual(report.status, "ok")
        self.assertEqual(report.architecture, "aarch64")

    def testTheMaterializedTableIsNotBookedAsAFunction(self):
        self.assertNotIn(self.table, self.functions)

    def testTheImageItselfIsStillRecovered(self):
        """Control. The assertion above says an address is absent, which an image that analysed
        into nothing would satisfy just as well."""
        self.assertIn(BASE + TEXT_OFFSET, self.functions)
        self.assertIn(BASE + TEXT_OFFSET + SEEDER_BLOCK, self.functions)
        self.assertEqual([leaf for leaf in _leaves(BASE + TEXT_OFFSET) if leaf not in self.functions], [])

    def testTheSameCodeWithoutASymbolTableDoesBookTheTable(self):
        """Control on what decided it: strip the symbol table and nothing else, and the coverage
        falls to zero, the scan runs, and the table becomes the false positive the gate is for."""
        blob, table = _tableImage(BASE, named=False)
        report, functions = _functions(blob)

        self.assertEqual(report.status, "ok")
        self.assertIn(table, functions)


class LanguageMetadataDecidesIndependentlyOfSymbolCandidatesTest(unittest.TestCase):
    """USE_SYMBOLS_AS_CANDIDATES turns off booking symbols as candidates, not the image's own
    language metadata. A Go image's pclntab is read by locateLangSpecCandidates whatever that
    option says, and that pass runs after this test -- so the test has to read the metadata
    rather than the candidate set, or a fully mapped Go image is treated as naming nothing and
    the scan it exists to suppress runs anyway.

    Driven by forcing the Go answer on the real analyzer: what is under test is which pass the
    coverage is read from, not whether a synthetic pclntab parses.
    """

    def _functionsWithGoMetadata(self, blob, go_objects, use_symbols):
        class _GoAnalyzer(LanguageAnalyzer):
            def checkGo(self):
                return True

            def getGoObjects(self):
                return list(go_objects)

        config = SmdaConfig()
        config.WITH_STRINGS = False
        config.USE_SYMBOLS_AS_CANDIDATES = use_symbols
        with patch("smda.common.FunctionCandidateManager.LanguageAnalyzer", _GoAnalyzer):
            report = Disassembler(config).disassembleUnmappedBuffer(blob)
        return report, {function.offset for function in report.getFunctions()}

    def testTheScanIsSkippedWhetherOrNotSymbolsAreBooked(self):
        blob, table = _tableImage(BASE, named=False)
        go_objects = sorted(_callTargets(BASE + TEXT_OFFSET))

        for use_symbols in (True, False):
            with self.subTest(use_symbols=use_symbols):
                report, functions = self._functionsWithGoMetadata(blob, go_objects, use_symbols)

                self.assertEqual(report.status, "ok")
                self.assertNotIn(table, functions)
                self.assertIn(BASE + TEXT_OFFSET, functions)

    def testTheSameImageWithoutTheGoMetadataStillBooksTheTable(self):
        """Control on what decided it: the image is the one the scan books, and it is the
        metadata reading and not the image that keeps the table out above."""
        blob, table = _tableImage(BASE, named=False)
        report, functions = _functions(blob)

        self.assertEqual(report.status, "ok")
        self.assertIn(table, functions)

    def testAnImageOfNoRecognizedLanguageContributesNoMetadata(self):
        manager = FunctionCandidateManager(SmdaConfig())
        manager.lang_analyzer = SimpleNamespace(checkGo=lambda: False)

        self.assertEqual(manager._languageMetadataStarts(), set())


class ManagerReuseTest(unittest.TestCase):
    """Candidate discovery runs inside `init`, so a manager initialized a second time would weigh
    the second image's coverage against the first image's call targets. `_call_targets` is the set
    that carries over without the reset; the candidate snapshot is retaken inside discovery."""

    def testASecondImageIsNotDecidedByTheFirstsCallTargets(self):
        stripped, _adr_callback, _pair_callback = _callbackImage(BASE)
        named, _table = _tableImage(REUSE_BASE)
        manager = FunctionCandidateManager(SmdaConfig())

        manager.init(_disassembly(stripped))
        # control: the first image really did fill the sets
        self.assertEqual(manager._call_targets, _callTargets(BASE + TEXT_OFFSET))
        self.assertFalse(manager._metadataNamedTheCallTargets())

        # the engine hands the manager the image's symbols before init; a full function map is
        # one naming every call target
        manager.symbol_addresses = sorted(_callTargets(REUSE_BASE + TEXT_OFFSET))
        manager.init(_disassembly(named))

        self.assertEqual(manager._call_targets, _callTargets(REUSE_BASE + TEXT_OFFSET))
        self.assertTrue(manager._metadataNamedTheCallTargets())

    def testTwoImagesThroughOneDisassemblerAreDecidedSeparately(self):
        """The same property through the public interface. Every analysis builds its own candidate
        manager today, so this holds on that as much as on the reset; it is here to catch a change
        that carries one manager across analyses without carrying the reset with it."""
        config = SmdaConfig()
        config.WITH_STRINGS = False
        disassembler = Disassembler(config)
        stripped, adr_callback, _pair_callback = _callbackImage(BASE)
        named, table = _tableImage(REUSE_BASE)

        first = disassembler.disassembleUnmappedBuffer(stripped)
        second = disassembler.disassembleUnmappedBuffer(named)

        self.assertEqual(first.status, "ok")
        self.assertEqual(second.status, "ok")
        self.assertIn(adr_callback, {function.offset for function in first.getFunctions()})
        second_functions = {function.offset for function in second.getFunctions()}
        self.assertNotIn(table, second_functions)
        # control: the second image analysed rather than merely producing no table
        self.assertIn(REUSE_BASE + TEXT_OFFSET, second_functions)


if __name__ == "__main__":
    unittest.main()
