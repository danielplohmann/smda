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
    _data_bytes_owner = None
    _data_bytes = None

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
        data_bytes = self._dataBytesByFunction()
        if start_addr in self.disassembly.functions:
            self.disassembly.function_metadata[start_addr] = {"thumb": thumb}
            if state.data_bytes:
                data_bytes[start_addr] = state.data_bytes
        for addr, conflict_thumb in self.fc_manager.takeModeConflicts():
            self._redecodeInMode(addr, conflict_thumb)
        return state

    def _dataBytesByFunction(self):
        # the literal pools each function booked, kept to take them back if it is undone
        if self._data_bytes_owner is not self.disassembly:
            self._data_bytes_owner = self.disassembly
            self._data_bytes = {}
        return self._data_bytes

    def _redecodeInMode(self, addr, thumb):
        """Undo a function decoded in the instruction set a weaker statement named, and queue
        it again in the one a stronger statement since gave it."""
        if self.fc_manager is None or self.tailcall_analyzer is None:
            return
        if (
            addr not in self.disassembly.functions
            or self.disassembly.function_metadata.get(addr, {}).get("thumb") is thumb
        ):
            return
        self._revertStoredFunction(addr, with_refs=True)
        self.tailcall_analyzer.discardFunction(addr)
        self.disassembly.function_metadata.pop(addr, None)
        data_bytes = self._dataBytesByFunction()
        booked = data_bytes.pop(addr, None)
        if booked:
            # what its loads made data was read in the wrong instruction set; another
            # function's own pool stays data
            kept = set()
            for other in data_bytes.values():
                kept.update(booked.intersection(other))
            self.disassembly.data_map.difference_update(booked - kept)
        self.fc_manager.requeueInMode(addr, thumb)
