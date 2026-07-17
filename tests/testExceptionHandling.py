import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from smda.aarch64.AArch64Disassembler import AArch64Disassembler
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.Disassembler import Disassembler
from smda.intel.IntelDisassembler import IntelDisassembler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SMDA_ROOT = PROJECT_ROOT / "smda"


class ExceptionHandlingTestSuite(unittest.TestCase):
    operational_exceptions = (
        FileNotFoundError("missing input"),
        RuntimeError("backend failed"),
        ValueError("malformed input"),
    )

    non_operational_exceptions = (
        AssertionError("broken invariant"),
        GeneratorExit("generator closed"),
        ImportError("dependency import failed"),
        KeyboardInterrupt("interrupted"),
        MemoryError("out of memory"),
        NameError("missing name"),
        ReferenceError("lost weak reference"),
        SyntaxError("invalid generated code"),
        SystemExit("exiting"),
    )

    def _call_disassemble_buffer(self, disasm):
        return disasm.disassembleBuffer(b"dummy_content", 0x1000)

    def _call_disassemble_unmapped_buffer(self, disasm):
        return disasm.disassembleUnmappedBuffer(b"dummy_content")

    def _call_disassemble_file(self, disasm):
        with patch("smda.Disassembler.FileLoader") as mock_loader_class:
            mock_loader_class.return_value = MagicMock()
            disasm._populateBinaryInfo = MagicMock(
                return_value=SimpleNamespace(architecture="intel", binary=b"dummy_content")
            )
            disasm.initDisassembler = MagicMock()
            disasm.disassembler = MagicMock()
            return disasm.disassembleFile("dummy_path")

    def _entry_points(self):
        return (
            ("disassembleBuffer", self._call_disassemble_buffer),
            ("disassembleUnmappedBuffer", self._call_disassemble_unmapped_buffer),
            ("disassembleFile", self._call_disassemble_file),
        )

    def test_operational_exceptions_return_error_reports(self):
        for entry_point_name, call_entry_point in self._entry_points():
            for exception in self.operational_exceptions:
                with self.subTest(entry_point=entry_point_name, exception=exception.__class__.__name__):
                    disasm = Disassembler()
                    disasm._disassemble = MagicMock(side_effect=exception)

                    report = call_entry_point(disasm)

                    self.assertEqual(report.status, "error")
                    self.assertIn(exception.__class__.__name__, report.message)

    def test_missing_input_file_returns_error_report(self):
        with patch("smda.Disassembler.FileLoader", side_effect=FileNotFoundError("missing input")):
            report = Disassembler().disassembleFile("non_existent_file.bin")

        self.assertEqual(report.status, "error")
        self.assertIn("FileNotFoundError", report.message)

    def test_non_operational_exceptions_bubble_up(self):
        for entry_point_name, call_entry_point in self._entry_points():
            for exception in self.non_operational_exceptions:
                with self.subTest(entry_point=entry_point_name, exception=exception.__class__.__name__):
                    disasm = Disassembler()
                    disasm._disassemble = MagicMock(side_effect=exception)

                    with self.assertRaises(exception.__class__):
                        call_entry_point(disasm)

    def test_non_operational_helper_reraises_current_exception(self):
        try:
            raise NameError("missing name")
        except Exception as exc:
            with self.assertRaises(NameError):
                reraise_non_operational_exception(exc)

    def test_init_disassembler_switches_backend_on_differing_architecture(self):
        disasm = Disassembler()
        disasm.initDisassembler("intel")
        self.assertIsInstance(disasm.disassembler, IntelDisassembler)

        disasm.initDisassembler("aarch64")
        self.assertIsInstance(disasm.disassembler, AArch64Disassembler)

    def test_init_disassembler_keeps_pinned_explicit_backend(self):
        disasm = Disassembler(backend="intel")
        self.assertIsInstance(disasm.disassembler, IntelDisassembler)

        disasm.initDisassembler("aarch64")
        self.assertIsInstance(disasm.disassembler, IntelDisassembler)

    def test_disassemble_buffer_creates_error_report_exactly_once_on_exception(self):
        disasm = Disassembler()
        disasm._disassemble = MagicMock(side_effect=RuntimeError("backend failed"))

        with patch.object(Disassembler, "_createErrorReport", wraps=disasm._createErrorReport) as mock_create_report:
            report = disasm.disassembleBuffer(b"dummy_content", 0x1000)

        mock_create_report.assert_called_once()
        self.assertEqual(report.status, "error")

    def test_disassemble_unmapped_buffer_creates_error_report_exactly_once_on_exception(self):
        disasm = Disassembler()
        disasm._disassemble = MagicMock(side_effect=RuntimeError("backend failed"))

        with patch.object(Disassembler, "_createErrorReport", wraps=disasm._createErrorReport) as mock_create_report:
            report = disasm.disassembleUnmappedBuffer(b"dummy_content")

        mock_create_report.assert_called_once()
        self.assertEqual(report.status, "error")

    def test_disassemble_file_creates_error_report_exactly_once_on_exception(self):
        disasm = Disassembler()
        disasm._disassemble = MagicMock(side_effect=RuntimeError("backend failed"))

        with patch.object(Disassembler, "_createErrorReport", wraps=disasm._createErrorReport) as mock_create_report:
            report = self._call_disassemble_file(disasm)

        mock_create_report.assert_called_once()
        self.assertEqual(report.status, "error")

    def test_all_broad_exception_handlers_reraise_non_operational_exceptions(self):
        offenders = []
        for path in sorted(SMDA_ROOT.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                for handler in node.handlers:
                    if not self._is_broad_exception_handler(handler):
                        continue
                    call_names = self._get_handler_call_names(handler)
                    if not {
                        "reraise_non_operational_exception",
                        "_handleDisassemblyException",
                    }.intersection(call_names):
                        offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{handler.lineno}")

        self.assertEqual([], offenders)

    def _is_broad_exception_handler(self, handler):
        if isinstance(handler.type, ast.Name):
            return handler.type.id == "Exception"
        if isinstance(handler.type, ast.Tuple):
            return any(isinstance(elt, ast.Name) and elt.id == "Exception" for elt in handler.type.elts)
        return False

    def _get_handler_call_names(self, handler):
        call_names = set()
        for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                call_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                call_names.add(node.func.attr)
        return call_names


if __name__ == "__main__":
    unittest.main()
