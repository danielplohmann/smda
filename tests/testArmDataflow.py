from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs

from smda.arm.analyzers import ArmJumpTableAnalyzer
from smda.arm.dataflow import RegisterTracker
from smda.common.BinaryInfo import BinaryInfo
from smda.Disassembler import Disassembler
from smda.DisassemblyResult import DisassemblyResult
from smda.SmdaConfig import SmdaConfig

BASE = 0x1000


def _decoder(thumb=False):
    engine = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    engine.detail = True
    return engine


def _tracker(buffer=bytes(64), thumb=False):
    binary = BinaryInfo(buffer)
    binary.base_addr = BASE
    binary.bitness = 32
    binary.architecture = "arm"
    disassembly = DisassemblyResult()
    disassembly.setBinaryInfo(binary)
    return RegisterTracker(SimpleNamespace(disassembly=disassembly), thumb)


def _context(encoding):
    return [
        ((ins.address, ins.size, ins.mnemonic, ins.op_str, bytes(ins.bytes)), ins)
        for ins in _decoder().disasm(bytes.fromhex(encoding), BASE)
    ]


@pytest.mark.parametrize(
    ("encoding", "thumb", "overwritten"),
    [
        ("920381e0", False, {"r0", "r1"}),
        ("d000c2e1", False, {"r0", "r1"}),
        ("100f11ee", False, {"r0"}),
        ("100f51ec", False, {"r0", "r1"}),
        ("910f82e1", False, {"r0"}),
        ("a2fb0301", True, {"r0", "r1"}),
        ("d2e90001", True, {"r0", "r1"}),
        ("11ee100f", True, {"r0"}),
        ("51ec100f", True, {"r0", "r1"}),
        ("42e80010", True, {"r0"}),
    ],
)
def test_unsupported_writes_invalidate_all_destination_values_and_slots(encoding, thumb, overwritten):
    tracker = _tracker(thumb=thumb)
    tracker.values.update(r0=0x1300, r1=0x1400, r2=0x1500)
    tracker.slots.update(r0=BASE + 32, r1=BASE + 36, r2=BASE + 40)
    tracker.step(next(_decoder(thumb).disasm(bytes.fromhex(encoding), BASE)))
    for reg in overwritten:
        assert tracker.get(reg) is None
        assert tracker.slot(reg) is None
    assert tracker.get("r2") == 0x1500
    assert tracker.slot("r2") == BASE + 40


def test_evaluation_uses_old_values_before_invalidating_the_destinations():
    tracker = _tracker()
    for ins in _decoder().disasm(bytes.fromhex("340201e3010040e3010080e2"), BASE):
        tracker.step(ins)
    assert tracker.get("r0") == 0x11235


def test_store_preserves_its_source_and_invalidates_the_writeback_base():
    tracker = _tracker()
    tracker.values.update(r0=0x1300, r1=0x1400)
    tracker.step(next(_decoder().disasm(bytes.fromhex("040081e4"), BASE)))
    assert tracker.get("r0") == 0x1300
    assert tracker.get("r1") is None


@pytest.mark.parametrize(
    ("encoding", "expected_targets"),
    [
        ("001301e3920381e031ff2fe11eff2fe1", []),
        ("001301e3000082e531ff2fe11eff2fe1", [0x1300]),
    ],
)
def test_indirect_calls_do_not_reuse_a_clobbered_second_destination(encoding, expected_targets):
    buffer = bytearray(0x400)
    caller = bytes.fromhex(encoding)
    buffer[: len(caller)] = caller
    buffer[0x300:0x308] = bytes.fromhex("0100a0e31eff2fe1")
    config = SmdaConfig()
    config.TIMEOUT = 0
    report = Disassembler(config).disassembleBuffer(bytes(buffer), BASE, 32, oep=0, architecture="arm")
    assert report.status == "ok"
    function = report.getFunction(BASE)
    assert function is not None
    assert function.outrefs.get(BASE + 8, []) == expected_targets


@pytest.mark.parametrize(
    "encoding",
    [
        "030050e33d00008a010080e2",
        "030050e33d00008a000091e5",
        "030050e33d00008a921380e0",
        "030050e33d00008a100f11ee",
        "030050e33d00008a910f82e1",
    ],
)
def test_switch_bounds_do_not_cross_index_writes(encoding):
    assert ArmJumpTableAnalyzer._bound(_context(encoding), "r0") == 0


@pytest.mark.parametrize(
    ("encoding", "index"),
    [
        ("030050e33d00008a0010a0e1", "r1"),
        ("04008de5030050e33c00008a04109de5", "r1"),
        ("030050e33d00008a000011e1", "r0"),
    ],
)
def test_switch_bounds_still_follow_copies_spills_and_read_only_instructions(encoding, index):
    assert ArmJumpTableAnalyzer._bound(_context(encoding), index) == 4


@pytest.mark.parametrize("encoding", ["030050e33d00008a0010a011", "030050e33d00008a8010a0e1"])
def test_switch_bounds_do_not_follow_conditional_or_shifted_copies(encoding):
    assert ArmJumpTableAnalyzer._bound(_context(encoding), "r1") == 0


@pytest.mark.parametrize("store", ["04208de5", "04208d15"])
def test_switch_bounds_follow_only_the_latest_stack_slot_store(store):
    encoding = "030050e33d00008a04008de5" + store + "04109de5"
    assert ArmJumpTableAnalyzer._bound(_context(encoding), "r1") == 0


def test_switch_recovery_keeps_reachable_cases_after_index_adjustment():
    buffer = bytearray(0x500)
    caller = bytes.fromhex("10402de9121ca0e3030050e30b00008a010080e200f191e7")
    buffer[: len(caller)] = caller
    buffer[0x40:0x48] = bytes.fromhex("6300a0e31080bde8")
    targets = [0x1300 + index * 8 for index in range(6)]
    for index, target in enumerate(targets):
        buffer[0x200 + index * 4 : 0x204 + index * 4] = target.to_bytes(4, "little")
        buffer[target - BASE : target - BASE + 8] = bytes.fromhex("0100a0e31080bde8")
    config = SmdaConfig()
    config.TIMEOUT = 0
    report = Disassembler(config).disassembleBuffer(bytes(buffer), BASE, 32, oep=0, architecture="arm")
    assert report.status == "ok"
    function = report.getFunction(BASE)
    assert function is not None
    assert set(targets[1:5]).issubset(function.blockrefs[BASE + 16])
    assert all(target in function.blocks for target in targets[1:5])


def test_table_writer_search_stops_at_an_overwritten_second_destination():
    context = _context("000091e5920381e0")
    assert ArmJumpTableAnalyzer._lastWriter(context, "r1") is context[-1]
