#!/usr/bin/python

from smda.common.RecursiveDisassembler import RecursiveDisassembler

from .AArch64Backend import AArch64Backend

DECODE_WINDOW = 32


class AArch64Disassembler(RecursiveDisassembler):
    """AArch64 disassembler: the architecture-agnostic recursive engine driven by
    :class:`~smda.aarch64.AArch64Backend.AArch64Backend`."""

    decode_window_size = DECODE_WINDOW

    def __init__(self, config, forced_bitness=None):
        super().__init__(config, AArch64Backend(), forced_bitness=forced_bitness)
