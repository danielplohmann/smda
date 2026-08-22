#!/usr/bin/python
"""The late candidate pass that reads Delphi method tables.

A Delphi program's virtual methods are called only through the object's method table, so an
entry no other code names is reachable by nothing the primary pass does: no call seeds it, and
gap analysis only reaches it if it happens to sit between two recovered functions. The pass
reads such a table, but only when two independent facts agree that the run of dwords is one -
most of its entries are already recovered functions, and code takes a data reference to it.
Each test below that expects an admission is paired with a control that removes exactly one of
those facts and expects none.
"""

import struct
import unittest
from unittest import mock

from smda.common.BinaryInfo import BinaryInfo
from smda.common.FunctionCandidateManager import FunctionCandidateManager as CommonFunctionCandidateManager
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelFunctionCandidateManager
from smda.SmdaConfig import SmdaConfig

BASE = 0x400000
IMAGE_SIZE = 0x20000
CODE_RVA = 0x1000
TABLE_RVA = 0x8000
#: five method bodies, four of which the primary pass is assumed to have recovered. The
#: unrecovered one sits in the middle: a run is only read against the address span of the
#: functions already recovered, so an entry past the outermost of them is not one this pass
#: can reason about.
ENTRIES = [BASE + CODE_RVA + 0x10 * index for index in range(5)]
UNRECOVERED = ENTRIES[2]
RECOVERED = [entry for entry in ENTRIES if entry != UNRECOVERED]


def _image(table_rva=TABLE_RVA, entries=None):
    image = bytearray(IMAGE_SIZE)
    for index, entry in enumerate(entries if entries is not None else ENTRIES):
        struct.pack_into("<I", image, table_rva + 4 * index, entry)
    return bytes(image)


def _twoTableImage():
    """Two tables in one image, each with one entry the primary pass did not recover."""
    image = bytearray(_image())
    second = [BASE + CODE_RVA + 0x100 + 0x10 * index for index in range(5)]
    for index, entry in enumerate(second):
        struct.pack_into("<I", image, TABLE_RVA + 0x100 + 4 * index, entry)
    manager = _manager(
        bytes(image),
        functions=RECOVERED + [entry for entry in second if entry != second[2]],
        data_refs={BASE + CODE_RVA: {BASE + TABLE_RVA, BASE + TABLE_RVA + 0x100}},
    )
    return second[2], manager


def _manager(image, functions=RECOVERED, data_refs=None, code=(), bitness=32, delphi=True):
    binary_info = BinaryInfo(image)
    binary_info.base_addr = BASE
    binary_info.bitness = bitness
    disassembly = DisassemblyResult()
    disassembly.binary_info = binary_info
    disassembly.functions = {addr: [] for addr in functions}
    disassembly.data_refs_from = dict(data_refs if data_refs is not None else {BASE + CODE_RVA: {BASE + TABLE_RVA}})
    for addr in code:
        disassembly.code_map[addr] = 1
    manager = IntelFunctionCandidateManager(SmdaConfig())
    manager.disassembly = disassembly
    manager.bitness = bitness
    manager._delphi_detected = delphi
    return manager


class _DelphiVmtLanguageAnalyzer:
    """A language analyzer reporting the legacy VMT Delphi path and nothing else.

    No bundled fixture is a Delphi binary, and a real detection needs a valid VMT rather than
    the string and timestamp hints, so what is checked here is the wiring: whether taking the
    VMT branch is what the late pass later reads.
    """

    def __init__(self, delphi=True):
        self.delphi = delphi

    def checkGo(self):
        return False

    def checkDelphiKb(self):
        return False

    def checkDelphi(self):
        return self.delphi

    def getDelphiObjects(self):
        return []

    def getDelphiReSymObjects(self):
        return []


class PointerTableCandidateTestSuite(unittest.TestCase):
    def test_the_delphi_vmt_pass_records_that_it_ran(self):
        manager = _manager(_image(), delphi=False)
        manager.lang_analyzer = _DelphiVmtLanguageAnalyzer()
        manager.locateLangSpecCandidates()
        self.assertTrue(manager._delphi_detected)

    def test_a_binary_the_vmt_pass_declines_records_nothing(self):
        manager = _manager(_image(), delphi=False)
        manager.lang_analyzer = _DelphiVmtLanguageAnalyzer(delphi=False)
        manager.locateLangSpecCandidates()
        self.assertFalse(manager._delphi_detected)

    def test_a_table_at_the_very_end_of_the_image_is_still_read(self):
        table_rva = IMAGE_SIZE - 4 * len(ENTRIES)
        manager = _manager(_image(table_rva=table_rva))
        manager.disassembly.data_refs_from = {BASE + CODE_RVA: {BASE + table_rva}}
        self.assertEqual(list(manager.locatePointerTableCandidates()), [UNRECOVERED])

    def test_a_referenced_run_of_known_functions_admits_its_unknown_entries(self):
        manager = _manager(_image())
        self.assertEqual(list(manager.locatePointerTableCandidates()), [UNRECOVERED])
        self.assertIn(UNRECOVERED, manager.candidates)

    def test_an_unreferenced_run_admits_nothing(self):
        manager = _manager(_image(), data_refs={})
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_a_run_the_recovered_functions_do_not_validate_admits_nothing(self):
        # same table, still spanned by recovered functions, but only three of its five entries
        # are ones - below the ratio a run has to clear to be read as a table
        manager = _manager(_image(), functions=[ENTRIES[0], ENTRIES[1], ENTRIES[4]])
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_a_run_shorter_than_the_minimum_admits_nothing(self):
        short = _image(entries=ENTRIES[:3] + [0, 0])
        manager = _manager(short)
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_a_table_slot_already_claimed_as_code_ends_the_run(self):
        # the third slot decodes as an instruction, so the table is two runs of two
        manager = _manager(_image(), code=(BASE + TABLE_RVA + 8,))
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_an_entry_already_claimed_as_code_is_not_admitted_again(self):
        manager = _manager(_image(), code=(UNRECOVERED,))
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_an_entry_outside_the_declared_code_areas_is_not_admitted(self):
        manager = _manager(_image())
        manager._code_areas = [(BASE + CODE_RVA, UNRECOVERED)]
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_an_entry_repeated_across_two_tables_is_admitted_once(self):
        image = bytearray(_image())
        for index, entry in enumerate(ENTRIES):
            struct.pack_into("<I", image, TABLE_RVA + 0x100 + 4 * index, entry)
        manager = _manager(
            bytes(image),
            data_refs={BASE + CODE_RVA: {BASE + TABLE_RVA, BASE + TABLE_RVA + 0x100}},
        )
        self.assertEqual(list(manager.locatePointerTableCandidates()), [UNRECOVERED])

    def test_two_tables_each_contribute_their_own_unrecovered_entry(self):
        second_unrecovered, manager = _twoTableImage()
        self.assertEqual(list(manager.locatePointerTableCandidates()), [UNRECOVERED, second_unrecovered])

    def test_no_candidates_without_delphi_evidence(self):
        manager = _manager(_image(), delphi=False)
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_no_candidates_for_a_64_bit_image(self):
        manager = _manager(_image(), bitness=64)
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_no_candidates_before_the_primary_pass_has_recovered_anything(self):
        manager = _manager(_image(), functions=())
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_the_scan_stops_at_the_analysis_timeout(self):
        manager = _manager(_image())
        manager.disassembly.analysis_timeout = True
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])

    def test_the_scan_polls_the_budget_once_per_chunk(self):
        # the table sits in the second 64 KiB chunk of a two-chunk image, so a budget spent
        # after the first chunk has to stop the scan before the table is reached - and the
        # poll count says the budget is read per chunk rather than per entry
        manager = _manager(_image(table_rva=0x18000))
        manager.disassembly.data_refs_from = {BASE + CODE_RVA: {BASE + 0x18000}}
        polls = []

        def _tripAfterFirstChunk():
            polls.append(len(polls))
            return len(polls) > 1

        manager._cb_analysis_timeout = _tripAfterFirstChunk
        self.assertEqual(list(manager.locatePointerTableCandidates()), [])
        self.assertEqual(len(polls), 2)

    def test_a_start_claimed_as_code_before_it_is_reached_is_not_yielded(self):
        # analyzing the first start can claim a later one as its own body, so each is
        # re-checked at the moment it is handed over rather than only when it was accepted
        second_unrecovered, manager = _twoTableImage()
        candidates = manager.locatePointerTableCandidates()
        self.assertEqual(next(candidates), UNRECOVERED)
        manager.disassembly.code_map[second_unrecovered] = 1
        self.assertEqual(list(candidates), [])

    def test_every_accepted_start_is_registered_before_the_first_is_yielded(self):
        second_unrecovered, manager = _twoTableImage()
        candidates = manager.locatePointerTableCandidates()
        self.assertEqual(next(candidates), UNRECOVERED)
        self.assertLessEqual({UNRECOVERED, second_unrecovered}, manager._candidate_offsets)
        self.assertEqual(list(candidates), [second_unrecovered])

    def test_the_yield_loop_stops_at_the_analysis_timeout(self):
        second_unrecovered, manager = _twoTableImage()
        candidates = manager.locatePointerTableCandidates()
        self.assertEqual(next(candidates), UNRECOVERED)
        manager.disassembly.analysis_timeout = True
        self.assertEqual(list(candidates), [])
        self.assertIn(second_unrecovered, manager.candidates)

    def test_the_architecture_neutral_base_declares_no_late_sources(self):
        self.assertEqual(list(CommonFunctionCandidateManager(SmdaConfig()).locateLateCandidates()), [])


LATE_BODY = b"\x31\xc0\xc3"  # xor eax, eax ; ret
LATE_RVA = 0x2000
LATE_ADDR = BASE + LATE_RVA
SECOND_LATE_RVA = 0x2100
SECOND_LATE_ADDR = BASE + SECOND_LATE_RVA


def _lateImage():
    image = bytearray(IMAGE_SIZE)
    image[CODE_RVA : CODE_RVA + 6] = b"\x55\x89\xe5\x5d\xc3\x90"  # push ebp ; mov ebp, esp ; pop ebp ; ret
    image[LATE_RVA : LATE_RVA + len(LATE_BODY)] = LATE_BODY
    image[SECOND_LATE_RVA : SECOND_LATE_RVA + len(LATE_BODY)] = LATE_BODY
    return bytes(image)


def _config():
    config = SmdaConfig()
    config.CALCULATE_HASHING = False
    config.CALCULATE_SCC = False
    config.CALCULATE_NESTING = False
    config.TIMEOUT = 0
    return config


def _offsets(image):
    # the declared code area covers only the first body, so nothing the candidate manager or
    # the gap scan does can reach the two later ones - they are recoverable solely by being
    # handed to the orchestrator as late candidates
    report = Disassembler(config=_config()).disassembleBuffer(
        image,
        BASE,
        bitness=32,
        code_areas=[(BASE + CODE_RVA, BASE + CODE_RVA + 0x10)],
        architecture="intel",
    )
    return {function.offset for function in report.getFunctions()}


class LateCandidateOrchestrationTestSuite(unittest.TestCase):
    def test_the_orchestrator_analyzes_what_the_late_pass_yields(self):
        image = _lateImage()
        # control: nothing else in the pipeline reaches these two bodies
        self.assertFalse({LATE_ADDR, SECOND_LATE_ADDR} & _offsets(image))
        with mock.patch.object(
            IntelFunctionCandidateManager,
            "locateLateCandidates",
            lambda self: iter([LATE_ADDR, SECOND_LATE_ADDR]),
        ):
            recovered = _offsets(image)
        self.assertLessEqual({LATE_ADDR, SECOND_LATE_ADDR}, recovered)

    def test_the_orchestrator_stops_the_late_pass_at_the_analysis_timeout(self):
        def _spendAfterFirst(manager):
            yield LATE_ADDR
            manager.disassembly.analysis_timeout = True
            yield SECOND_LATE_ADDR

        image = _lateImage()
        with mock.patch.object(IntelFunctionCandidateManager, "locateLateCandidates", _spendAfterFirst):
            recovered = _offsets(image)
        self.assertIn(LATE_ADDR, recovered)
        self.assertNotIn(SECOND_LATE_ADDR, recovered)


if __name__ == "__main__":
    unittest.main()
