import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import ida_analyze
import ida_domain_export


class TestIdaAnalyze(unittest.TestCase):
    def test_analyze_runs_smda_and_augments_ida(self):
        ida_interface = mock.Mock()
        ida_interface.getBinary.return_value = b"\x90"
        ida_interface.getBaseAddr.return_value = 0x1000
        ida_interface.getArchitecture.return_value = "intel"
        ida_interface.getBitness.return_value = 64
        ida_interface.makeFunction.side_effect = [True, False]
        ida_interface.makeNameEx.return_value = True
        report = mock.Mock()
        report.getFunctions.return_value = [
            types.SimpleNamespace(offset=0x1000, function_name="entry"),
            types.SimpleNamespace(offset=0x2000, function_name=""),
        ]
        disassembler = mock.Mock()
        disassembler.disassembleBuffer.return_value = report

        with (
            mock.patch.object(ida_analyze, "IdaInterface", return_value=ida_interface),
            mock.patch.object(ida_analyze, "Disassembler", return_value=disassembler) as disassembler_class,
        ):
            result = ida_analyze.analyze()

        self.assertIs(result, report)
        disassembler_class.assert_called_once_with(mock.ANY)
        disassembler.disassembleBuffer.assert_called_once_with(b"\x90", 0x1000, bitness=64, architecture="intel")
        self.assertEqual(ida_interface.makeFunction.call_count, 2)
        ida_interface.makeNameEx.assert_called_once_with(0x1000, "entry")


class TestIdaDomainExport(unittest.TestCase):
    def test_export_database_uses_ida_exporter(self):
        ida_interface = mock.Mock()
        ida_interface.getBinary.return_value = b"\x90"
        ida_interface.getBaseAddr.return_value = 0x1000
        database_context = mock.MagicMock()
        database_context.__enter__.return_value = ida_interface
        report = mock.Mock(num_functions=1)
        report.toDict.return_value = {"status": "ok"}
        disassembler = mock.Mock()
        disassembler.disassembleBuffer.return_value = report
        ida_exporter = mock.Mock()
        disassembler_class = mock.Mock(return_value=disassembler)
        ida_exporter_class = mock.Mock(return_value=ida_exporter)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.smda"
            with (
                mock.patch.object(ida_domain_export.IdaInterface, "fromPath", return_value=database_context),
                mock.patch.object(ida_domain_export, "Disassembler", disassembler_class),
                mock.patch.object(ida_domain_export, "IdaExporter", ida_exporter_class),
            ):
                result = ida_domain_export.export_database("sample.i64", output_path)

            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), {"status": "ok"})

        self.assertIs(result, report)
        self.assertIs(disassembler.disassembler, ida_exporter)
        self.assertTrue(disassembler._explicit_backend)
        self.assertEqual(disassembler_class.call_count, 1)
        ida_exporter_class.assert_called_once_with(disassembler_class.call_args.args[0], ida_interface=ida_interface)
        disassembler.disassembleBuffer.assert_called_once_with(b"\x90", 0x1000)
