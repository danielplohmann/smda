#!/usr/bin/python

from smda.common.RecursiveDisassembler import RecursiveDisassembler

from .X86Backend import X86Backend


class SimpleIns:
    address = None
    size = None
    mnemonic = None
    op_str = None
    bytes = None

    def __init__(self, address, size, mnemonic, op_str, bytes):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = bytes


class IntelDisassembler(RecursiveDisassembler):
    """x86/x64 disassembler: the architecture-agnostic recursive engine driven by
    the x86 :class:`~smda.intel.X86Backend.X86Backend`. Kept as a named class for
    backwards compatibility with the ``"intel"`` backend selector and existing imports."""

    def __init__(self, config, forced_bitness=None):
        super().__init__(config, X86Backend(), forced_bitness=forced_bitness)
