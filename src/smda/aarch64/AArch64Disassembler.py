#!/usr/bin/python

from smda.common.RecursiveDisassembler import RecursiveDisassembler

from .AArch64Backend import AArch64Backend

DECODE_WINDOW = 32


class AArch64Disassembler(RecursiveDisassembler):
    """AArch64 disassembler: the architecture-agnostic recursive engine driven by
    :class:`~smda.aarch64.AArch64Backend.AArch64Backend`."""

    def __init__(self, config, forced_bitness=None):
        super().__init__(config, AArch64Backend(), forced_bitness=forced_bitness)

    def _getDisasmWindowBuffer(self, addr, size=None):
        binary_info = self.disassembly.binary_info
        if binary_info is None:
            return b""
        relative_start = addr - binary_info.base_addr
        if relative_start < 0 or relative_start >= len(binary_info.binary):
            return b""
        window_size = DECODE_WINDOW if size is None else size
        return binary_info.binary[relative_start : relative_start + window_size]
