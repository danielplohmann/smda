from types import SimpleNamespace

import pytest

from smda.Disassembler import Disassembler
from smda.intel.X86Backend import X86Backend
from smda.SmdaConfig import SmdaConfig

CODE = bytes.fromhex("68171040008d45f8e8f300000058ffe0e9eb000000ebee8bc6c3")
BASE = 0x401000


def resolver(code=CODE, bitness=32, delphi=True, pushed_target=BASE + 0x17):
    block = [
        (BASE, 5, "push", hex(pushed_target)),
        (BASE + 5, 3, "lea", "eax, [ebp - 8]"),
        (BASE + 8, 5, "call", "0x401100"),
        (BASE + 13, 1, "pop", "eax"),
    ]
    d = SimpleNamespace(
        fc_manager=SimpleNamespace(_delphi_detected=delphi),
        disassembly=SimpleNamespace(
            binary_info=SimpleNamespace(bitness=bitness, isInCodeAreas=lambda addr: BASE <= addr < BASE + 0x200),
            getBytes=lambda addr, size: code[addr - BASE : addr - BASE + size],
        ),
    )
    state = SimpleNamespace(current_block=block)
    return X86Backend._resolveDelphiFinallyContinuation(d, (BASE + 14, 2, "jmp", "eax"), state)


def test_resolves_delphi_finally_stack_continuation():
    assert resolver() == BASE + 0x17


@pytest.mark.parametrize("bitness,delphi", [(64, True), (32, False)])
def test_requires_32_bit_delphi_evidence(bitness, delphi):
    assert resolver(bitness=bitness, delphi=delphi) is None


@pytest.mark.parametrize("offset,value", [(16, 0x90), (21, 0x90), (22, 0xEF)])
def test_rejects_broken_handler_or_cleanup_link(offset, value):
    code = bytearray(CODE)
    code[offset] = value
    assert resolver(bytes(code)) is None


def test_rejects_mismatched_saved_continuation():
    assert resolver(pushed_target=BASE + 0x18) is None


def test_continuation_is_booked_in_the_owning_function():
    from tests.testDelphiReSymProvider import image

    info, layout = image(vmt=0x200, method_target=0x1000)
    layout.data[0x1000 : 0x1000 + len(CODE)] = CODE
    layout.data[0x1100] = 0xC3
    info.binary = bytes(layout.data)
    info.code_areas = [(info.base_addr + 0x200, info.base_addr + 0x1800)]
    config = SmdaConfig()
    config.USE_ALIGNMENT = False
    report = Disassembler(config).disassembleBuffer(
        info.binary, info.base_addr, bitness=info.bitness, code_areas=info.code_areas
    )
    function = report.getFunction(BASE)
    instructions = {ins.offset for block in function.getBlocks() for ins in block.getInstructions()}
    assert BASE + 0x17 in instructions
    assert BASE + 0x19 in instructions
    assert BASE + 0x17 in function.blockrefs[BASE]
    assert report.getFunction(BASE + 0x17) is None


def test_real_inno_cleanup_dispatch():
    import json
    from pathlib import Path

    from smda.common.BinaryInfo import BinaryInfo
    from smda.DisassemblyResult import DisassemblyResult

    fixture = json.loads((Path(__file__).parent / "delphi_corpus/inno-7.1.0-finally-32.json").read_text())
    code = bytes.fromhex(fixture["bytes"])
    info = BinaryInfo(code)
    info.base_addr = fixture["entry"]
    info.bitness = 32
    info.code_areas = [
        (fixture["entry"], fixture["entry"] + len(code)),
        (fixture["handler_target"], fixture["handler_target"] + len(bytes.fromhex(fixture["handler_bytes"]))),
    ]
    result = DisassemblyResult()
    result.setBinaryInfo(info)
    md = X86Backend().createCapstone(32)
    block = list(md.disasm_lite(code[: fixture["jump"] - fixture["entry"]], fixture["entry"]))
    d = SimpleNamespace(disassembly=result, fc_manager=SimpleNamespace(_delphi_detected=True))
    target = X86Backend._resolveDelphiFinallyContinuation(
        d, (fixture["jump"], 2, "jmp", "eax"), SimpleNamespace(current_block=block)
    )
    assert target == fixture["continuation"]
