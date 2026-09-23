import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import binja_analyze
import binja_export
from smda.binja import BinjaExporter
from smda.binja.BinjaExporter import exportBinaryView
from smda.binja.BinjaInterface import BinjaInterface


class _FakeBlock:
    def __init__(self, start, lengths, successors=()):
        self.start = start
        self._lengths = lengths
        self.outgoing_edges = [SimpleNamespace(target=SimpleNamespace(start=target)) for target in successors]

    def __iter__(self):
        return iter([([], length) for length in self._lengths])


class _FakeFunction:
    def __init__(self, start, name, blocks, call_sites=()):
        self.start = start
        self.name = name
        self.symbol = SimpleNamespace(raw_name=name)
        self.basic_blocks = blocks
        self.call_sites = [SimpleNamespace(address=address) for address in call_sites]


class _FakeBinaryView:
    """x64 image at 0x401000: main() calls helper(), helper() returns, both as straight-line blocks."""

    CODE = {
        0x401000: bytes.fromhex("e805000000"),
        0x401005: bytes.fromhex("c3"),
        0x40100A: bytes.fromhex("31c0"),
        0x40100C: bytes.fromhex("c3"),
    }

    def __init__(self, arch_name="x86_64"):
        self.arch = SimpleNamespace(name=arch_name, address_size=8)
        self.functions = [
            _FakeFunction(0x401000, "main", [_FakeBlock(0x401000, [5, 1])], call_sites=[0x401000]),
            _FakeFunction(0x40100A, "sub_40100a", [_FakeBlock(0x40100A, [2, 1])]),
        ]
        self.file = SimpleNamespace(original_filename="/tmp/sample.exe", filename="/tmp/sample.bndb")
        self.segments = [
            SimpleNamespace(start=0x401000, end=0x401010, data_length=0x10),
            SimpleNamespace(start=0x402000, end=0x402008, data_length=8),
        ]
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_function_at(self, offset):
        return next((function for function in self.functions if function.start == offset), None)

    def get_instruction_length(self, offset):
        return len(self.CODE.get(offset, b""))

    def read(self, offset, length):
        if offset == 0x402000:
            return b"\x11" * length
        image = b"".join(self.CODE[address] for address in sorted(self.CODE))
        start = offset - 0x401000
        return image[start : start + length].ljust(length, b"\x00")

    def get_callees(self, address, func=None):
        self.calls += 1
        return [0x40100A] if address == 0x401000 else []

    def get_symbols(self):
        return [
            SimpleNamespace(
                type=SimpleNamespace(name="ImportAddressSymbol"),
                address=0x402000,
                raw_name="ExitProcess",
                namespace="KERNEL32.dll",
            ),
            SimpleNamespace(
                type=SimpleNamespace(name="ImportedFunctionSymbol"),
                address=0x402008,
                raw_name="__libc_start_main",
                namespace="BNINTERNALNAMESPACE",
            ),
            SimpleNamespace(
                type=SimpleNamespace(name="FunctionSymbol"), address=0x401000, raw_name="main", namespace=None
            ),
        ]

    def get_sections_at(self, offset):
        return [SimpleNamespace(name=".text")]


class BinjaExporterTest(unittest.TestCase):
    def test_report_carries_binary_ninja_analysis(self):
        report = exportBinaryView(_FakeBinaryView())
        self.assertEqual(report.architecture, "intel")
        self.assertEqual(report.bitness, 64)
        self.assertEqual(report.base_addr, 0x400000)
        self.assertEqual(report.num_functions, 2)
        main = report.getFunction(0x401000)
        self.assertEqual(main.function_name, "main")
        self.assertEqual([instruction.mnemonic for instruction in main.getInstructions()], ["call", "ret"])
        self.assertEqual(main.outrefs, {0x401000: [0x40100A]})
        self.assertEqual(report.getFunction(0x40100A).inrefs, [0x401000])


class BinjaHeadlessTest(unittest.TestCase):
    def test_load_binary_view_opens_through_binary_ninja(self):
        bv = _FakeBinaryView()
        binaryninja = types.SimpleNamespace(load=mock.Mock(return_value=bv))
        with mock.patch.dict(sys.modules, {"binaryninja": binaryninja}):
            self.assertIs(BinjaExporter.loadBinaryView("sample.bndb"), bv)
        binaryninja.load.assert_called_once_with("sample.bndb")

    def test_export_file_writes_the_report(self):
        bv = _FakeBinaryView()
        binaryninja = types.SimpleNamespace(load=mock.Mock(return_value=bv))
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = str(Path(temp_dir) / "report.smda")
            with mock.patch.dict(sys.modules, {"binaryninja": binaryninja}):
                report = binja_export.export_file("sample.exe", output_path)
            written = json.loads(Path(output_path).read_text(encoding="utf-8"))
        self.assertEqual(report.num_functions, 2)
        self.assertEqual(written["statistics"]["num_functions"], 2)
        self.assertEqual(sorted(written["xcfg"]), ["4198400", "4198410"])

    def test_export_file_defaults_to_the_input_path(self):
        bv = _FakeBinaryView()
        binaryninja = types.SimpleNamespace(load=mock.Mock(return_value=bv))
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = str(Path(temp_dir) / "sample.bndb")
            with mock.patch.dict(sys.modules, {"binaryninja": binaryninja}):
                binja_export.export_file(input_path)
            self.assertTrue(Path(input_path + ".smda").exists())

    def test_export_view_writes_next_to_the_open_file(self):
        bv = _FakeBinaryView()
        with tempfile.TemporaryDirectory() as temp_dir:
            bv.file = SimpleNamespace(
                original_filename="/gone/sample.exe", filename=str(Path(temp_dir) / "sample.bndb")
            )
            report = binja_export.export_view(bv)
            written = json.loads((Path(temp_dir) / "sample.bndb.smda").read_text(encoding="utf-8"))
        self.assertEqual(written["statistics"]["num_functions"], report.num_functions)

    def test_main_reports_a_missing_binary_ninja(self):
        with mock.patch.dict(sys.modules, {"binaryninja": None}):
            self.assertEqual(binja_export.main(["sample.exe"]), 1)


class BinjaAnalyzeTest(unittest.TestCase):
    def test_analyze_runs_smda_and_augments_the_view(self):
        bv = _FakeBinaryView()
        transaction = mock.MagicMock()
        bv.undoable_transaction = mock.Mock(return_value=transaction)
        bv.update_analysis_and_wait = mock.Mock()
        report = mock.Mock()
        report.getFunctions.return_value = [
            types.SimpleNamespace(offset=0x401000, function_name="entry"),
            types.SimpleNamespace(offset=0x401020, function_name=""),
        ]
        disassembler = mock.Mock()
        disassembler.disassembleBuffer.return_value = report
        with (
            mock.patch.object(binja_analyze, "Disassembler", return_value=disassembler) as disassembler_class,
            mock.patch.object(BinjaInterface, "makeFunction", side_effect=[False, True]) as make_function,
            mock.patch.object(BinjaInterface, "makeName", return_value=True) as make_name,
        ):
            result = binja_analyze.analyze(bv)

        self.assertIs(result, report)
        disassembler_class.assert_called_once_with(mock.ANY)
        disassembler.disassembleBuffer.assert_called_once_with(
            BinjaInterface(bv).getBinary(), 0x400000, bitness=64, architecture="intel"
        )
        self.assertEqual(make_function.call_count, 2)
        make_name.assert_called_once_with(0x401000, "entry")
        transaction.__enter__.assert_called_once()
        transaction.__exit__.assert_called_once()
        bv.update_analysis_and_wait.assert_called_once_with()
