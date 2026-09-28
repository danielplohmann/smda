from smda.Disassembler import Disassembler
from smda.export.Exporter import Exporter
from smda.SmdaConfig import SmdaConfig

from .BinjaInterface import BinjaInterface


def loadBinaryView(input_path):
    """Open *input_path* (a binary or a .bndb) in headless Binary Ninja, analysed; use it as a context manager."""
    import binaryninja  # ty: ignore[unresolved-import]

    return binaryninja.load(input_path)


def exportBinaryView(bv, config=None):
    """Convert Binary Ninja's analysis of *bv* into a SmdaReport, the way export.py does for IDA."""
    config = config if config is not None else SmdaConfig()
    interface = BinjaInterface(bv)
    disassembler = Disassembler(config)
    disassembler.setExporter(Exporter(config, interface))
    return disassembler.disassembleBuffer(interface.getBinary(), interface.getBaseAddr())
