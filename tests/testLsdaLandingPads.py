import logging
import os
import tempfile
import unittest

import lief

from smda.common.EhFrameDecoder import (
    MAX_LSDA_TABLE_BYTES,
    _decodeLsdaLandingPads,
    decodeEhFrameFdeRanges,
    decodeEhFrameLandingPads,
)
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)
lief.logging.disable()

ENDBR64 = b"\xf3\x0f\x1e\xfa"
BTI_J = b"\x9f\x24\x03\xd5"
#: g++ 13.3.0 -O2 -fcf-protection=full over nested try/catch, stripped. Its four landing pads
#: all carry a CET pad, which is the shape a byte scan reads as a function entry.
X64_FIXTURE = "elf_cxx_landing_pads_x64_xored"
#: the same source built by aarch64-linux-gnu-g++ 13.3.0 -O2 -mbranch-protection=standard.
#: Its five landing pads each open with `bti j`, which is what makes the shape test in the
#: AArch64 backend accept them: a bti marks real indirect-call entries too.
ARM64_FIXTURE = "elf_cxx_landing_pads_arm64_xored"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), X64_FIXTURE)


def loadFixture(name=X64_FIXTURE):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    with open(path, "rb") as fixture_file:
        raw = fixture_file.read()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(raw))


def declaredPads(data):
    binary = lief.ELF.parse(list(data))
    sections = [(s.virtual_address, bytes(s.content)) for s in binary.sections if s.virtual_address and s.size]

    def readVa(addr, length):
        for start, content in sections:
            if start <= addr < start + len(content):
                return content[addr - start : addr - start + length]
        return b""

    eh_frame = next(section for section in binary.sections if section.name == ".eh_frame")
    return decodeEhFrameLandingPads(bytes(eh_frame.content), eh_frame.virtual_address, readVa), binary


class _LandingPadFixtureCase:
    """A landing pad is where the unwinder resumes, so it is interior by construction and is
    never a function start; on both instruction sets it opens with the same marker a real
    indirect-branch target does, which is why a scan looking for entry shapes accepts it.

    Subclasses name the fixture, the marker its pads carry and how many the image declares.
    """

    FIXTURE_NAME = ""
    PAD_MARKER = b""
    EXPECTED_PADS = 0
    #: recovered functions with the rule off, below which the run has failed rather than
    #: the rule worked
    MIN_FUNCTIONS = 0

    @classmethod
    def setUpClass(cls):
        cls.data = loadFixture(cls.FIXTURE_NAME)
        cls.pads, cls.binary = declaredPads(cls.data)

    def textBytes(self):
        section = next(s for s in self.binary.sections if s.name == ".text")
        return section.virtual_address, bytes(section.content)

    def testTheFixtureCarriesTheFeatureThisTestReadsFromIt(self):
        names = {section.name for section in self.binary.sections}
        self.assertIn(".gcc_except_table", names)
        self.assertIn(".eh_frame", names)
        # without this the comparisons below would pass on an empty set against an empty set
        self.assertEqual(len(self.pads), self.EXPECTED_PADS)

    def testEveryDeclaredPadOpensWithThisIsasIndirectBranchMarker(self):
        base, text = self.textBytes()
        marker = self.PAD_MARKER
        for pad in sorted(self.pads):
            offset = pad - base
            self.assertTrue(0 <= offset < len(text) - len(marker), f"0x{pad:x} is outside .text")
            self.assertEqual(text[offset : offset + len(marker)], marker, f"0x{pad:x} lacks the marker")

    def recoveredWith(self, use_landing_pads):
        config = SmdaConfig()
        config.CALCULATE_SCC = False
        config.CALCULATE_NESTING = False
        config.CALCULATE_HASHING = False
        config.USE_LSDA_LANDING_PADS = use_landing_pads
        # the interior-range rule refuses a superset of what an LSDA names, so leaving it on
        # would refuse these pads with the rule under test switched off and the comparison
        # below would show nothing either way
        config.USE_ELF_FDE_INTERIOR_GAPS = False
        # and so does the AArch64 target-type rule, for the same reason and more sharply: every
        # pad in the ARM64 fixture opens with `bti j`, which that rule refuses on the word
        # alone. It has to come off here too or the control is empty on that fixture -- which
        # also records the overlap: on AArch64 the two rules meet on exactly this population.
        config.USE_AARCH64_BTI_TARGET_TYPE = False
        # analysed through a file rather than a buffer so the ELF header picks the architecture.
        # The handle is closed before the path is handed on: Windows refuses a second open on a
        # file another handle still holds, and the loader reports that as an empty result rather
        # than as an error, so the failure would arrive as "this fixture declares no functions"
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as handle:
            handle.write(self.data)
            temp_path = handle.name
        try:
            report = Disassembler(config).disassembleFile(temp_path)
        finally:
            os.unlink(temp_path)
        return {function.offset for function in report.getFunctions()}

    def testNoDeclaredPadIsReportedAsAFunctionWhenTheRuleIsOn(self):
        recovered = self.recoveredWith(True)
        # control: the analysis found real functions, so an empty intersection below is the
        # rule working rather than the run failing
        self.assertGreater(len(recovered), self.MIN_FUNCTIONS)
        self.assertEqual(recovered & self.pads, set())

    def testTheRuleIsOnByDefaultAndTurningItOffShowsWhatItDoes(self):
        # with the rule off a declared pad is reported, which is what makes the assertion
        # above a result rather than a set that was empty either way
        self.assertTrue(SmdaConfig().USE_LSDA_LANDING_PADS)
        self.assertTrue(self.recoveredWith(False) & self.pads)

    def testAPadInsideTheImageIsNotMistakenForAnyFunctionsEntry(self):
        # every declared pad sits strictly inside some FDE range: that is what "interior" means
        # here, and it is why refusing them cannot cost a function the image declares
        eh_frame = next(section for section in self.binary.sections if section.name == ".eh_frame")
        ranges = decodeEhFrameFdeRanges(bytes(eh_frame.content), eh_frame.virtual_address)
        self.assertTrue(ranges)
        for pad in sorted(self.pads):
            inside = any(start < pad < start + length for start, length in ranges if length)
            self.assertTrue(inside, f"0x{pad:x} is not inside any declared function range")

    def testRefusingAPadResumesWhereNothingDeclaredIsSkippedOver(self):
        """The skip target is what keeps the rule from costing recall.

        Stepping one instruction on lands inside the pad, and the scan books that in the pad's
        place -- a worse candidate than the one refused. Resuming at the end of the declaring
        FDE is only safe while nothing the image declares sits in between, which is the hazard
        a whole PLT block under a single FDE would pose.
        """
        eh_frame = next(section for section in self.binary.sections if section.name == ".eh_frame")
        ranges = [
            (start, start + length)
            for start, length in decodeEhFrameFdeRanges(bytes(eh_frame.content), eh_frame.virtual_address)
            if length
        ]
        self.assertTrue(ranges)
        starts = {start for start, _ in ranges}
        for pad in sorted(self.pads):
            owner = next(((start, end) for start, end in ranges if start < pad < end), None)
            self.assertIsNotNone(owner, f"0x{pad:x} has no declaring FDE")
            resume = owner[1]
            self.assertGreater(resume, pad, "the resume point must advance past the pad")
            skipped = {start for start in starts if pad < start < resume}
            self.assertEqual(skipped, set(), f"resuming at 0x{resume:x} steps over declared starts")


class LsdaLandingPadX64Test(_LandingPadFixtureCase, unittest.TestCase):
    FIXTURE_NAME = X64_FIXTURE
    PAD_MARKER = ENDBR64
    EXPECTED_PADS = 4
    MIN_FUNCTIONS = 20


class LsdaLandingPadArm64Test(_LandingPadFixtureCase, unittest.TestCase):
    FIXTURE_NAME = ARM64_FIXTURE
    PAD_MARKER = BTI_J
    EXPECTED_PADS = 5
    MIN_FUNCTIONS = 20


class LsdaDecoderContractTest(unittest.TestCase):
    def testAnImageWithNoEhFrameDeclaresNothing(self):
        self.assertEqual(decodeEhFrameLandingPads(b"", 0x1000, lambda addr, length: b""), set())

    def testATerminatorEndsTheScanRatherThanRaising(self):
        self.assertEqual(decodeEhFrameLandingPads(b"\x00\x00\x00\x00", 0x1000, lambda a, n: b""), set())

    def testAMalformedTypeTableOffsetAbortsInsteadOfDecodingFromAWildCursor(self):
        """A `ttype` offset that never terminates must stop the parse, not shift it.

        The bundled fixture carries only well-formed LSDAs, so this path is invisible to it.
        `_read_uleb128` signals refusal in the value it returns, not in the cursor; checking
        the cursor never fires, and the call-site table below is then read from wherever the
        runaway read left off. A `ttype` table is ordinary output -- every typed catch has one.
        """
        from smda.common.EhFrameDecoder import _decodeLsdaLandingPads

        # LPStart omitted, ttype encoding udata4 (present), then a uleb128 whose continuation
        # bit never clears, with plausible call-site bytes behind it
        # call-site encoding uleb128, table length 4, one site: start 0x00, length 0x10,
        # landing pad 0x20, action 0x00 -- so a successful parse yields {function_start + 0x20}
        call_site_table = bytes([0x01, 0x04, 0x00, 0x10, 0x20, 0x00])
        # exactly ten continuation bytes: the reader gives up on the 64-bit shift bound with the
        # cursor left at index 12, which is where a valid-looking table is planted. A guard that
        # tested the cursor rather than the value would parse that table and return a pad the
        # image never declared, so this case separates the two.
        runaway = bytes([0xFF, 0x03]) + b"\xff" * 10 + call_site_table
        self.assertIsNone(_decodeLsdaLandingPads(runaway, 0x1000, 0x2000, 8))

        # control: the same table behind a terminating ttype offset decodes its one landing pad,
        # so the assertion above is the guard firing and not the header being rejected earlier
        well_formed = bytes([0xFF, 0x03, 0x04]) + call_site_table
        self.assertEqual(_decodeLsdaLandingPads(well_formed, 0x1000, 0x2000, 8), {0x2020})

    def testAnUnreadableLsdaPointerYieldsNoPadsRatherThanRaising(self):
        data, _binary = declaredPads(loadFixture())
        self.assertTrue(data)
        # the same section decoded with a reader that supplies nothing: the FDEs still parse,
        # their LSDA pointers still resolve, and nothing can be read at the far end
        fixture = loadFixture()
        binary = lief.ELF.parse(list(fixture))
        eh_frame = next(section for section in binary.sections if section.name == ".eh_frame")
        starved = decodeEhFrameLandingPads(bytes(eh_frame.content), eh_frame.virtual_address, lambda addr, length: b"")
        self.assertEqual(starved, set())


class LsdaHeaderFormTest(unittest.TestCase):
    """The header forms the bundled fixture does not use.

    g++ emits `LPStart omitted / ttype omitted / call sites uleb128`, so a real-binary test
    exercises exactly one shape. These cover the rest of what the format permits, and each
    failure case is paired with the same bytes made well-formed, so a None is the guard firing
    rather than the blob being rejected a step earlier.
    """

    #: one call site: start 0, length 0x10, landing pad 0x20, action 0 -- a successful decode
    #: therefore yields {function_start + 0x20} unless LPStart moves the base
    ULEB_TABLE = bytes([0x01, 0x04, 0x00, 0x10, 0x20, 0x00])

    def decode(self, data, lsda_va=0x1000, function_start=0x2000, pointer_size=8):
        return _decodeLsdaLandingPads(data, lsda_va, function_start, pointer_size)

    def testNoBytesAtAllDeclareNothing(self):
        self.assertIsNone(self.decode(b""))

    def testAnAbsoluteLpstartReplacesTheFunctionStartAsTheBase(self):
        # LPStart udata4 = 0x3000, ttype omitted, then the table
        data = bytes([0x03]) + (0x3000).to_bytes(4, "little") + bytes([0xFF]) + self.ULEB_TABLE
        self.assertEqual(self.decode(data), {0x3020})
        # control: the same table with LPStart omitted falls back to the function start
        self.assertEqual(self.decode(bytes([0xFF, 0xFF]) + self.ULEB_TABLE), {0x2020})

    def testAPcrelLpstartIsRelativeToItsOwnField(self):
        # LPStart pcrel|udata4; the field begins one byte into the LSDA, so the base is
        # lsda_va + 1 + value
        data = bytes([0x13]) + (0x40).to_bytes(4, "little") + bytes([0xFF]) + self.ULEB_TABLE
        self.assertEqual(self.decode(data), {0x1000 + 1 + 0x40 + 0x20})

    def testAnUnreadableLpstartAborts(self):
        # udata4 announced with only two bytes behind it
        self.assertIsNone(self.decode(bytes([0x03, 0x11, 0x22])))

    def testATruncatedHeaderAbortsAtEachStage(self):
        self.assertIsNone(self.decode(bytes([0xFF])))  # nothing after the LPStart byte
        self.assertIsNone(self.decode(bytes([0xFF, 0xFF])))  # nothing after the ttype byte
        self.assertIsNone(self.decode(bytes([0xFF, 0xFF, 0x01])))  # no table length

    def testATableLongerThanTheBytesSuppliedAborts(self):
        # length 0x40 with six bytes behind it: the read would run past the blob
        self.assertIsNone(self.decode(bytes([0xFF, 0xFF, 0x01, 0x40, 0x00, 0x10, 0x20, 0x00])))

    def testASignedLeb128CallSiteTableDecodes(self):
        # sleb128 is permitted by the encoding byte even though gcc emits uleb128
        table = bytes([0x09, 0x04, 0x00, 0x10, 0x20, 0x00])
        self.assertEqual(self.decode(bytes([0xFF, 0xFF]) + table), {0x2020})

    def testAZeroLandingPadIsNoHandlerRatherThanAnAddress(self):
        # the same site with landing pad 0 declares nothing, and the set is empty rather than None
        table = bytes([0x01, 0x04, 0x00, 0x10, 0x00, 0x00])
        self.assertEqual(self.decode(bytes([0xFF, 0xFF]) + table), set())

    def testAnLpstartApplicationModeThisDecoderCannotApplyAborts(self):
        # datarel needs a base this decoder does not have; reading it as absolute would not
        # fail, it would yield a different address, so it has to be refused
        for application in (0x30, 0x50, 0x70):
            data = bytes([application | 0x03]) + (0x3000).to_bytes(4, "little") + bytes([0xFF]) + self.ULEB_TABLE
            self.assertIsNone(self.decode(data), f"application mode 0x{application:02x} was applied anyway")
        # control: the same header in the two modes the decoder does apply
        for application in (0x00, 0x10):
            data = bytes([application | 0x03]) + (0x3000).to_bytes(4, "little") + bytes([0xFF]) + self.ULEB_TABLE
            self.assertIsNotNone(self.decode(data))

    def testACallSiteApplicationModeAborts(self):
        # a call-site entry is an offset from a base already resolved, so nothing would apply it
        self.assertEqual(self.decode(bytes([0xFF, 0xFF]) + self.ULEB_TABLE), {0x2020})
        table = bytes([0x11, 0x04, 0x00, 0x10, 0x20, 0x00])
        self.assertIsNone(self.decode(bytes([0xFF, 0xFF]) + table))

    def testAnUnsupportedCallSiteEncodingAbortsRatherThanLooping(self):
        # 0x05 is not a value format this reader knows; the loop must not spin on a cursor
        # that never advances
        table = bytes([0x05, 0x04, 0x00, 0x10, 0x20, 0x00])
        self.assertIsNone(self.decode(bytes([0xFF, 0xFF]) + table))


class EhFrameLandingPadWalkTest(unittest.TestCase):
    """Record-level shapes of the .eh_frame walk that the fixture's own section does not take."""

    #: CIE version 1, augmentation "zLR", code alignment 1, data alignment -8, return address
    #: register 16, then augmentation data naming udata4 for both the LSDA pointer and the FDE's
    #: initial location
    CIE_BODY = bytes([0x01]) + b"zLR\x00" + bytes([0x01, 0x78, 0x10, 0x02, 0x03, 0x03])
    LSDA_VA = 0x5000
    #: LPStart omitted, ttype omitted, one uleb128 call site whose landing pad is +0x20
    LSDA_BYTES = bytes([0xFF, 0xFF, 0x01, 0x04, 0x00, 0x10, 0x20, 0x00])
    #: initial location 0x2000, range 0x100, four bytes of augmentation data holding the pointer
    FDE_BODY = (
        (0x2000).to_bytes(4, "little") + (0x100).to_bytes(4, "little") + bytes([0x04]) + LSDA_VA.to_bytes(4, "little")
    )

    def sectionWith(self, *fde_bodies):
        section = (len(self.CIE_BODY) + 4).to_bytes(4, "little") + (0).to_bytes(4, "little") + self.CIE_BODY
        for body in fde_bodies:
            # each FDE names its CIE by the distance from its own id field back to the CIE's
            # start, so the pointer differs per record and copying a record verbatim would
            # leave every copy unable to find the CIE
            cie_pointer = len(section) + 4
            section += (len(body) + 4).to_bytes(4, "little") + cie_pointer.to_bytes(4, "little") + body
        return section

    def fdeBody(self, lsda_va, initial_location=0x2000, address_range=0x100):
        return (
            initial_location.to_bytes(4, "little")
            + address_range.to_bytes(4, "little")
            + bytes([0x04])
            + lsda_va.to_bytes(4, "little")
        )

    def decodeFde(self, fde_body):
        def read_va(addr, length):
            return self.LSDA_BYTES if addr == self.LSDA_VA else b""

        return decodeEhFrameLandingPads(self.sectionWith(fde_body), 0x1000, read_va)

    def rangesOf(self, fde_body):
        return decodeEhFrameFdeRanges(self.sectionWith(fde_body), 0x1000)

    def testAWellFormedFdeReachesTheLsdaItsAugmentationNames(self):
        self.assertEqual(self.decodeFde(self.FDE_BODY), {0x2020})

    def testAnFdeTooShortToHoldItsOwnRangeDeclaresNothing(self):
        self.assertEqual(self.decodeFde(self.FDE_BODY), {0x2020})
        self.assertEqual(self.decodeFde(self.FDE_BODY[:4]), set())

    def testAnFdeCarryingNoAugmentationDataDeclaresNothing(self):
        self.assertEqual(self.decodeFde(self.FDE_BODY), {0x2020})
        self.assertEqual(self.decodeFde(self.FDE_BODY[:8] + bytes([0x00])), set())

    def countingDecode(self, *fde_bodies):
        reads = []

        def counting_read(addr, length):
            reads.append(addr)
            return self.LSDA_BYTES

        return decodeEhFrameLandingPads(self.sectionWith(*fde_bodies), 0x1000, counting_read), reads

    def testAPadOutsideTheRangeItsOwnFdeDeclaresIsRefused(self):
        """The check that separates a real table from a pointer that led into arbitrary bytes.

        An LSDA pointer can land on data that decodes as a call-site table anyway, and the
        addresses it then yields are noise. A landing pad is interior to the function its own
        FDE names, so a decoded address outside that range did not come from a real table.
        """
        # control: the pad sits 0x20 into a function 0x100 long, and is reported
        self.assertEqual(self.decodeFde(self.fdeBody(self.LSDA_VA)), {0x2020})
        # the same table under an FDE declaring a function only 0x10 long puts the pad past
        # its end, and nothing is reported
        self.assertEqual(self.decodeFde(self.fdeBody(self.LSDA_VA, address_range=0x10)), set())

    def testEveryFdeNamingTheSameLsdaDecodesItOnce(self):
        """One LSDA serves one function, but nothing stops an image pointing every FDE at one.

        Decoding it per FDE rather than once is the difference between milliseconds and
        minutes on a section a sample can supply.
        """
        # control: three FDEs naming three tables read three times, which is what shows the
        # section really carries three reachable FDEs and the counter sees each of them
        distinct = [self.fdeBody(self.LSDA_VA + step, 0x2000 + step) for step in (0, 0x40, 0x80)]
        pads, reads = self.countingDecode(*distinct)
        self.assertEqual(len(reads), 3)
        self.assertEqual(pads, {0x2020, 0x2060, 0x20A0})

        same = [self.fdeBody(self.LSDA_VA) for _ in range(3)]
        pads, reads = self.countingDecode(*same)
        self.assertEqual(pads, {0x2020})
        self.assertEqual(len(reads), 1, f"the same LSDA was read {len(reads)} times")

    def testAnExhaustedBudgetStopsCallingTheReaderAtAll(self):
        # the reader is asked for MAX_LSDA_BYTES per LSDA, so a section naming a distinct one
        # per record would copy that much per record even with the decode declining each
        reads = []

        def counting_read(addr, length):
            reads.append(addr)
            return self.LSDA_BYTES

        section = self.sectionWith(*[self.fdeBody(self.LSDA_VA + step, 0x2000 + step) for step in (0, 0x40, 0x80)])
        # control: a budget with room reaches the reader once per distinct table
        self.assertEqual(len(decodeEhFrameLandingPads(section, 0x1000, counting_read, max_table_bytes=1000)), 3)
        self.assertEqual(len(reads), 3)

        reads.clear()
        self.assertEqual(decodeEhFrameLandingPads(section, 0x1000, counting_read, max_table_bytes=0), set())
        self.assertEqual(reads, [], "the reader was called with the budget already spent")

    def testTheCallSiteTableBudgetBoundsOneSection(self):
        # an exhausted budget stops the decode rather than truncating its answer, so the
        # entries it did not reach are absent rather than silently reported as none declared
        table = bytes([0x01, 0x04, 0x00, 0x10, 0x20, 0x00])
        blob = bytes([0xFF, 0xFF]) + table
        self.assertEqual(_decodeLsdaLandingPads(blob, 0x1000, 0x2000, 8, [1000]), {0x2020})
        self.assertIsNone(_decodeLsdaLandingPads(blob, 0x1000, 0x2000, 8, [0]))
        # the budget is charged the table's own length, not the blob it arrived in
        budget = [10]
        self.assertEqual(_decodeLsdaLandingPads(blob, 0x1000, 0x2000, 8, budget), {0x2020})
        self.assertEqual(budget[0], 10 - (len(table) - 2))

    def testTheBudgetClearsTheHeaviestShapeThisDecoderIsBuiltFor(self):
        # a bound sized below real input would silently drop pads, which is how the first
        # version of it lost 197 on a statically linked C++ binary
        self.assertGreater(MAX_LSDA_TABLE_BYTES, 100 * len(self.LSDA_BYTES) * 1000)

    def testTheRangeDecoderSkipsAnFdeTooShortForItsOwnRange(self):
        # both decoders share one record walk, so the same malformed FDE has to be skipped
        # by the range decoder as well rather than ending its scan
        self.assertEqual(self.rangesOf(self.FDE_BODY), [(0x2000, 0x100)])
        self.assertEqual(self.rangesOf(self.FDE_BODY[:4]), [])

    def testAnFdeWhoseLsdaPointerIsNullDeclaresNothing(self):
        # every function compiled without a handler gets this shape from a CIE that still
        # announces 'L', so it is the common case rather than a malformed one
        self.assertEqual(self.decodeFde(self.FDE_BODY), {0x2020})
        self.assertEqual(self.decodeFde(self.FDE_BODY[:8] + bytes([0x04]) + (0).to_bytes(4, "little")), set())

    def testAnExtendedLengthRecordIsSkippedRatherThanMisread(self):
        # 0xFFFFFFFF escapes to an 8-byte length; here it claims more than the blob holds
        data = b"\xff\xff\xff\xff" + (0x1000).to_bytes(8, "little")
        self.assertEqual(decodeEhFrameLandingPads(data, 0x1000, lambda a, n: b""), set())

    def testAnExtendedLengthHeaderCutShortEndsTheScan(self):
        self.assertEqual(decodeEhFrameLandingPads(b"\xff\xff\xff\xff\x01", 0x1000, lambda a, n: b""), set())

    def testARecordTooShortToHoldItsOwnIdEndsTheScan(self):
        # length 2, so the 4-byte CIE id does not fit inside the record
        data = (2).to_bytes(4, "little") + b"\x00\x00"
        self.assertEqual(decodeEhFrameLandingPads(data, 0x1000, lambda a, n: b""), set())

    def testARecordLongerThanTheSectionEndsTheScan(self):
        data = (0x1000).to_bytes(4, "little") + b"\x00" * 8
        self.assertEqual(decodeEhFrameLandingPads(data, 0x1000, lambda a, n: b""), set())


if __name__ == "__main__":
    unittest.main()
