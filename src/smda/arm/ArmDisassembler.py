#!/usr/bin/python

from smda.common.RecursiveDisassembler import RecursiveDisassembler

from .ArmBackend import ArmBackend

#: bytes handed to capstone per decode call; one 4-byte instruction per call made the
#: per-call overhead dominate, while a window this size still ends near a typical block's end
DECODE_WINDOW = 32


class ArmDisassembler(RecursiveDisassembler):
    """AArch32 disassembler: the architecture-agnostic recursive engine driven by
    :class:`~smda.arm.ArmBackend.ArmBackend`.

    The engine decodes every function with one capstone handle; this subclass selects the
    instruction set (A32 or T32) that handle decodes before each function is analysed and
    records the choice as the function's ``architecture_metadata``, which is what lets a
    report consumer decode the stored bytes the same way.
    """

    #: (disassembly, {(address, thumb): stub}) for :func:`~smda.arm.analyzers.resolveImportStub`
    import_stub_cache = None

    def __init__(self, config, forced_bitness=None):
        super().__init__(config, ArmBackend(), forced_bitness=forced_bitness)

    def _getDisasmWindowBuffer(self, addr):
        binary_info = self.disassembly.binary_info
        if binary_info is None:
            return b""
        relative_start = addr - binary_info.base_addr
        if relative_start < 0 or relative_start >= len(binary_info.binary):
            return b""
        return binary_info.binary[relative_start : relative_start + DECODE_WINDOW]

    def analyzeFunction(self, start_addr, as_gap=False, known_table_bytes=None):
        if self.capstone is None or self.fc_manager is None:
            return super().analyzeFunction(start_addr, as_gap=as_gap, known_table_bytes=known_table_bytes)
        thumb = self.fc_manager.isThumb(start_addr)
        self.capstone.binary_info = self.disassembly.binary_info
        self.capstone.setThumb(thumb)
        state = super().analyzeFunction(start_addr, as_gap=as_gap, known_table_bytes=known_table_bytes)
        if start_addr in self.disassembly.functions:
            self.disassembly.function_metadata[start_addr] = {"thumb": thumb}
        return state
