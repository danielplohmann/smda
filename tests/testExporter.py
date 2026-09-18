import ast
import inspect
import textwrap
import unittest

from smda.Disassembler import Disassembler
from smda.export.BackendInterface import BackendInterface
from smda.export.Exporter import Exporter
from smda.ida.BackendInterface import BackendInterface as IdaBackendInterface
from smda.ida.IdaExporter import IdaExporter
from smda.SmdaConfig import SmdaConfig


class _Interface(BackendInterface):
    def getArchitecture(self):
        return "intel"

    def getBitness(self):
        return 32


class ExporterTestSuite(unittest.TestCase):
    def test_interface_declares_everything_the_exporter_reads(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(Exporter)))
        read = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "interface"
        }
        declared = {name for name in vars(BackendInterface) if not name.startswith("_")}
        self.assertEqual(declared, read)

    def test_exporter_takes_any_interface(self):
        exporter = Exporter(SmdaConfig(), _Interface())
        self.assertEqual(exporter.architecture, "intel")
        self.assertEqual(exporter.bitness, 32)

    def test_ida_exporter_keeps_its_interface_name(self):
        interface = _Interface()
        exporter = IdaExporter(SmdaConfig(), ida_interface=interface)
        self.assertIsInstance(exporter, Exporter)
        self.assertIs(exporter.ida_interface, interface)
        exporter.ida_interface = other = _Interface()
        self.assertIs(exporter.interface, other)

    def test_ida_package_re_exports_the_interface(self):
        self.assertIs(IdaBackendInterface, BackendInterface)

    def test_disassembler_pins_a_set_exporter(self):
        disassembler = Disassembler()
        exporter = Exporter(disassembler.config, _Interface())
        disassembler.setExporter(exporter)
        disassembler.initDisassembler("aarch64")
        self.assertIs(disassembler.disassembler, exporter)

    def test_exporter_accepts_a_pdb_like_every_backend(self):
        Exporter(SmdaConfig(), _Interface()).addPdbFile(None, "")
