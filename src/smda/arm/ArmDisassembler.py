#!/usr/bin/python

from smda.common.RecursiveDisassembler import RecursiveDisassembler

from .ArmBackend import ArmBackend


class ArmDisassembler(RecursiveDisassembler):
    """AArch32 disassembler: the architecture-agnostic recursive engine driven by
    :class:`~smda.arm.ArmBackend.ArmBackend`.

    The engine decodes every function with one capstone handle; this subclass selects the
    instruction set (A32 or T32) that handle decodes before each function is analysed and
    records the choice as the function's ``architecture_metadata``, which is what lets a
    report consumer decode the stored bytes the same way.
    """

    def __init__(self, config, forced_bitness=None):
        super().__init__(config, ArmBackend(), forced_bitness=forced_bitness)

    def analyzeFunction(self, start_addr, as_gap=False):
        if self.capstone is None or self.fc_manager is None:
            return super().analyzeFunction(start_addr, as_gap=as_gap)
        thumb = self.fc_manager.isThumb(start_addr)
        self.capstone.binary_info = self.disassembly.binary_info
        self.capstone.setThumb(thumb)
        state = super().analyzeFunction(start_addr, as_gap=as_gap)
        if start_addr in self.disassembly.functions:
            self.disassembly.function_metadata[start_addr] = {"thumb": thumb}
        return state
