import ast
import inspect
import textwrap
import unittest

from smda.common.BinaryInfo import BinaryInfo
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


class _ThumbInterface(_Interface):
    """One Thumb function: cmp r0, #0; itt eq; moveq r0, #1; bxeq lr; movs r0, #2; bx lr,
    with the IT block split across two blocks and the code behind it reported first."""

    BASE = 0x10000
    CODE = bytes.fromhex("002804bf0120704702207047")
    BLOCKS = [[0x10008, 0x1000A], [0x10000, 0x10002, 0x10004], [0x10006]]

    def getArchitecture(self):
        return "arm"

    def getBaseAddr(self):
        return self.BASE

    def getBinary(self):
        return self.CODE

    def getFunctions(self):
        return [self.BASE]

    def isExternalFunction(self, function_offset):
        return False

    def isThumb(self, offset):
        return True

    def getBlocks(self, function_offset):
        return self.BLOCKS

    def getInstructionBytes(self, offset):
        start = offset - self.BASE
        return self.CODE[start : start + 2]

    def getCodeInRefs(self, offset):
        return []

    def getCodeOutRefs(self, offset):
        return []

    def getFunctionSymbols(self, demangle=False):
        return {}

    def getApiMap(self):
        return {}


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

    def test_thumb_instructions_keep_the_condition_of_their_it(self):
        interface = _ThumbInterface()
        binary_info = BinaryInfo(interface.CODE)
        binary_info.base_addr = interface.BASE
        disassembly = Exporter(SmdaConfig(), interface).analyzeBuffer(binary_info)
        instructions = [ins[2:4] for block in disassembly.functions[interface.BASE] for ins in block]
        self.assertEqual(
            instructions,
            [("movs", "r0, #2"), ("bx", "lr"), ("cmp", "r0, #0"), ("itt", "eq"), ("moveq", "r0, #1"), ("bxeq", "lr")],
        )
