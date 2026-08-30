#!/usr/bin/python
"""Mach-O LC_FUNCTION_STARTS as a deferred candidate source.

The linker writes the table and stripping keeps it, so an entry the primary pass
left unclaimed is a function SMDA missed. Fixture tests run real Mach-O images;
the unit tests drive the pass through a stub table to reach the filters a
well-formed image never trips.
"""

import unittest
from pathlib import Path
from unittest import mock

from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64FunctionCandidateManager
from smda.common import FunctionCandidateManager as function_candidate_manager
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelFunctionCandidateManager
from smda.SmdaConfig import SmdaConfig
from smda.utility.MachoBinary import get_active_macho_binary

FIXTURE_DIR = Path(__file__).resolve().parent
CORPUS_DIR = FIXTURE_DIR / "aarch64_macho_corpus"
FROSTYFERRET = CORPUS_DIR / "malpedia" / "osx.frostyferret_ef27a525ec0b.xored"
# the one corpus sample linked without LC_FUNCTION_STARTS
NO_TABLE_FIXTURE = CORPUS_DIR / "objective-see" / "Turtle_5f9cd91d8d1d.xored"
KOMPLEX = FIXTURE_DIR / "komplex_xored"
ELF_FIXTURE = FIXTURE_DIR / "bashlite_xored"


def _decode(path):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(path.read_bytes()))


def _report(buffer, opt_in):
    config = SmdaConfig()
    config.TIMEOUT = 300
    config.WITH_STRINGS = False
    config.USE_MACHO_FUNCTION_STARTS = opt_in
    return Disassembler(config).disassembleUnmappedBuffer(buffer)


def _table_addresses(buffer):
    binary_info = BinaryInfo(buffer)
    macho = get_active_macho_binary(binary_info.getLiefBinary())
    text = next(segment for segment in macho.segments if segment.name == "__TEXT")
    return {text.virtual_address + offset for offset in macho.function_starts.functions}


class MachoFunctionStartFixtureTestSuite(unittest.TestCase):
    def testUnclaimedTableEntriesAreRecovered(self):
        buffer = _decode(FROSTYFERRET)
        off = _report(buffer, False)
        on = _report(buffer, True)
        self.assertEqual(off.status, "ok")
        self.assertEqual(on.status, "ok")
        # eleven more of the linker's own entries than the primary pass used to find. Eight
        # are a run of branch veneers whose targets gap analysis itself discovered, which the
        # interior test refused while it could only see the candidate set snapshotted before
        # analysis; one is a routine opening on a hoisted argument check, which the gap scan
        # used to refuse for being a conditional branch; the other two the adr/adrp scan
        # reaches now that it runs on Mach-O. Every one of the eleven is an address
        # LC_FUNCTION_STARTS declares, which is what says they are the linker's own starts
        # and not ones a scan invented.
        # The function count rises by ten rather than eleven because 0x100004c48 stops being
        # reported, from both sides. It is not in the table, so that is a false positive
        # going, and it is the whole of the movement in the total with the table pass on.
        self.assertEqual(off.num_functions, 256)
        self.assertEqual(on.num_functions, 274)
        table = _table_addresses(buffer)
        off_starts = {function.offset for function in off.getFunctions()}
        on_starts = {function.offset for function in on.getFunctions()}
        self.assertEqual(len(table & off_starts), 128)
        self.assertEqual(len(table & on_starts), 146)
        # a candidate source may only add starts, never drop one the primary pass found
        self.assertEqual(off_starts - on_starts, set())

    def testIntelMachOReadsTheTableToo(self):
        # komplex's primary pass already claims all 92 entries, so the pass runs
        # through the intel backend and correctly yields nothing
        buffer = _decode(KOMPLEX)
        off = _report(buffer, False)
        on = _report(buffer, True)
        self.assertEqual(off.architecture, "intel")
        self.assertEqual(_table_addresses(buffer) - {function.offset for function in off.getFunctions()}, set())
        self.assertEqual(on.num_functions, off.num_functions)


class MachoFunctionStartUnitTestSuite(unittest.TestCase):
    def _manager(self, buffer, manager_class=IntelFunctionCandidateManager, opt_in=True, base_addr=0x100000000):
        config = SmdaConfig()
        config.USE_MACHO_FUNCTION_STARTS = opt_in
        binary_info = BinaryInfo(buffer)
        binary_info.base_addr = base_addr
        binary_info.bitness = 64
        disassembly = DisassemblyResult()
        disassembly.setBinaryInfo(binary_info)
        manager = manager_class(config)
        manager.disassembly = disassembly
        manager.bitness = 64
        return manager

    def testOptOutReadsNothing(self):
        manager = self._manager(_decode(KOMPLEX), opt_in=False)
        with mock.patch.object(BinaryInfo, "getLiefBinary", side_effect=AssertionError("must not parse")):
            self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])

    def testNonMachoBinaryIsIgnored(self):
        manager = self._manager(_decode(ELF_FIXTURE))
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])
        self.assertEqual(manager._machoActiveBinaryAndAdjustment(), (None, 0))

    def testFatBinaryWithoutAMatchingSliceIsIgnored(self):
        manager = self._manager(_decode(KOMPLEX))
        with mock.patch.object(function_candidate_manager, "get_active_macho_binary", return_value=None):
            self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])

    def testImageWithoutTheLoadCommandIsIgnored(self):
        manager = self._manager(_decode(NO_TABLE_FIXTURE))
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])

    def testEntriesAreRebasedOnTheTextSegment(self):
        # every bundled Mach-O reports the same value for both, so the distinction only
        # shows on a slice whose __TEXT does not sit at the image base
        buffer = _decode(KOMPLEX)
        binary_info = BinaryInfo(buffer)
        macho = get_active_macho_binary(binary_info.getLiefBinary())
        text = next(segment for segment in macho.segments if segment.name == "__TEXT")
        self.assertEqual(text.virtual_address, macho.imagebase)
        self.assertEqual(min(macho.function_starts.functions) + text.virtual_address, 0x1000012B0)


class _StubTable:
    def __init__(self, offsets):
        self.functions = offsets


class _StubSegment:
    def __init__(self, name, virtual_address):
        self.name = name
        self.virtual_address = virtual_address


class _StubMacho:
    # the image base lief would report; entries rebase on __TEXT, which is what the
    # load command's deltas are relative to
    imagebase = 0x200000000

    def __init__(self, offsets, text_base=0x100000000):
        self.function_starts = _StubTable(offsets)
        self.segments = [_StubSegment("__PAGEZERO", 0), _StubSegment("__TEXT", text_base)]


class _TimeoutAfter:
    """analysis_timeout that flips to True after a fixed number of reads."""

    def __init__(self, reads):
        self.remaining = reads

    def __bool__(self):
        if self.remaining <= 0:
            return True
        self.remaining -= 1
        return False


class MachoFunctionStartFilterTestSuite(unittest.TestCase):
    IMAGE_SIZE = 0x1000

    def _manager(self, offsets, manager_class=IntelFunctionCandidateManager):
        config = SmdaConfig()
        config.USE_MACHO_FUNCTION_STARTS = True
        binary_info = BinaryInfo(b"\x90" * self.IMAGE_SIZE)
        binary_info.base_addr = 0x100000000
        binary_info.bitness = 64
        binary_info.binary_size = self.IMAGE_SIZE
        disassembly = DisassemblyResult()
        disassembly.binary_info = binary_info
        manager = manager_class(config)
        manager.disassembly = disassembly
        manager.bitness = 64
        manager._machoActiveBinaryAndAdjustment = lambda: (_StubMacho(offsets), 0)
        return manager

    def testAnImageWithoutATextSegmentIsIgnored(self):
        manager = self._manager([0x100])
        macho = _StubMacho([0x100])
        macho.segments = [_StubSegment("__DATA", 0x100000000)]
        manager._machoActiveBinaryAndAdjustment = lambda: (macho, 0)
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])

    def testEntriesInsideTheImageBecomeSymbolCandidates(self):
        manager = self._manager([0x100, 0x200])
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [0x100000100, 0x100000200])
        self.assertTrue(all(manager.candidates[addr].is_symbol for addr in (0x100000100, 0x100000200)))
        # every accepted start is a known function start before the first is analyzed
        self.assertTrue({0x100000100, 0x100000200}.issubset(manager._candidate_offsets))

    def testEntriesOutsideTheImageAreDropped(self):
        manager = self._manager([0x100, self.IMAGE_SIZE + 0x10])
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [0x100000100])

    def testMisalignedEntriesAreDroppedOnAArch64(self):
        manager = self._manager([0x102, 0x200], manager_class=AArch64FunctionCandidateManager)
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [0x100000200])

    def testEntriesTheAnalysisAlreadyClaimedAreLeftAlone(self):
        manager = self._manager([0x100, 0x200])
        manager.disassembly.code_map[0x100000100] = None
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [0x100000200])

    def testAStartClaimedByAnEarlierDeferredFunctionIsNotYielded(self):
        manager = self._manager([0x100, 0x200])
        candidates = manager.locateMachoFunctionStartCandidates()
        self.assertEqual(next(candidates), 0x100000100)
        # analyzing 0x100000100 absorbed the second start before it was yielded
        manager.disassembly.code_map[0x100000200] = None
        self.assertEqual(list(candidates), [])

    def testTimeoutStopsTheCollectionPass(self):
        manager = self._manager([0x100, 0x200])
        manager.disassembly.analysis_timeout = True
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])
        self.assertEqual(manager.candidates, {})

    def testTimeoutStopsTheYieldPass(self):
        manager = self._manager([0x100, 0x200])
        # two reads for the collection loop, then the yield loop finds it tripped
        manager.disassembly.analysis_timeout = _TimeoutAfter(2)
        self.assertEqual(list(manager.locateMachoFunctionStartCandidates()), [])
        self.assertEqual(sorted(manager.candidates), [0x100000100, 0x100000200])


if __name__ == "__main__":
    unittest.main()
