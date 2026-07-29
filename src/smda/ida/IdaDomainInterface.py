"""IDA Domain API adapter for IDA 9.1 and newer."""

import importlib
import os
import re

from .BackendInterface import BackendInterface
from .segment_mapping import assembleSegmentBuffer

_IDA_DOMAIN_MISSING = (
    "ida-domain is not available. Install it with 'pip install \"smda[ida]\"' and "
    "ensure IDA Pro 9.1+ is installed with IDADIR configured."
)

_INTEL_PROCESSORS = {
    "metapc",
    "8086",
    "80286p",
    "80386p",
    "80486p",
    "80586p",
    "80686p",
    "p2",
    "p3",
    "p4",
    "x86",
    "x86_64",
    "x64",
}


class IdaDomainUnavailableError(ImportError):
    pass


def _getDatabaseClass():
    try:
        return importlib.import_module("ida_domain").Database
    except ImportError as exc:
        raise IdaDomainUnavailableError(_IDA_DOMAIN_MISSING) from exc


class IdaDomainInterface(BackendInterface):
    def __init__(self, database=None):
        super().__init__()
        self.version = "ida-domain (IDA Pro 9.1+)"
        self._owns_database = False
        if database is not None:
            self.db = database
        else:
            self.db = _getDatabaseClass().open()

    @classmethod
    def fromPath(cls, input_path, save_on_close=False):
        database_class = _getDatabaseClass()
        interface = cls(database=database_class.open(path=input_path, save_on_close=save_on_close))
        interface._owns_database = True
        return interface

    def close(self):
        if self._owns_database and self.db is not None:
            self.db.close()
            self.db = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def getArchitecture(self):
        procname = self.db.architecture
        if procname is None:
            raise ValueError("Unsupported Architecture")
        normalized = procname.lower()
        if normalized in ("arm", "arm64", "aarch64"):
            if self.getBitness() != 64:
                raise ValueError(f"Unsupported Architecture: {procname} ({self.getBitness()}bit)")
            return "aarch64"
        if normalized in _INTEL_PROCESSORS or "x86" in normalized or normalized.startswith("metapc"):
            return "intel"
        raise ValueError(f"Unsupported Architecture: {procname}")

    def getBitness(self):
        bits = self.db.bitness
        if bits in (16, 32, 64):
            return bits
        segment = self.db.segments.get_at(self.db.minimum_ea)
        if segment is not None:
            return self.db.segments.get_bitness(segment)
        return bits if bits else 32

    def getFunctions(self):
        return sorted(function.start_ea for function in self.db.functions.get_all())

    def getBlocks(self, function_offset):
        function = self.db.functions.get_at(function_offset)
        if function is None:
            return []
        flowchart = self.db.functions.get_flowchart(function)
        if flowchart is None:
            return []
        blocks = []
        for block in flowchart:
            if block.start_ea >= block.end_ea:
                continue
            instructions = block.get_instructions()
            extracted_block = [instruction.ea for instruction in instructions] if instructions else []
            if extracted_block:
                blocks.append(extracted_block)
        return sorted(blocks)

    def getInstructionBytes(self, offset):
        instruction = self.db.instructions.get_at(offset)
        if instruction is None:
            return b""
        return self.db.bytes.get_bytes_at(offset, instruction.size) or b""

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in self.db.xrefs.code_refs_to_ea(offset, flow=True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in self.db.xrefs.code_refs_from_ea(offset, flow=True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        for function in self.db.functions.get_all():
            function_offset = function.start_ea
            function_name = self.db.functions.get_name(function)
            if demangle and function_name and "@" in function_name:
                demangled = self.db.names.get_demangled_name(function_offset)
                if demangled:
                    function_name = demangled
            if function_name and not re.match("sub_[0-9a-fA-F]+", function_name):
                function_symbols[function_offset] = function_name
        return function_symbols

    def getBaseAddr(self):
        segment_starts = sorted(segment.start_ea for segment in self.db.segments.get_all())
        if not segment_starts:
            return 0
        return int((segment_starts[0] // 0x10000) * 0x10000)

    def getBinary(self):
        # must be addressable as buffer[addr - getBaseAddr()]; see segment_mapping
        segments = list(self.db.segments.get_all())
        ranges = [(segment.start_ea, segment.start_ea + self.db.segments.get_size(segment)) for segment in segments]
        return assembleSegmentBuffer(self.getBaseAddr(), ranges, self.db.bytes.get_bytes_at)

    def getApiMap(self):
        api_map = {}
        for imported in self.db.imports.get_all_imports():
            api_name = imported.name or f"#{imported.ordinal}"
            if imported.module_name:
                api_name = f"{imported.module_name}!{api_name}"
            api_map[imported.address] = api_name
        return api_map

    def isExternalFunction(self, function_offset):
        segment = self.db.segments.get_at(function_offset)
        if segment is None:
            return False
        return self.db.segments.get_name(segment) in ("extern", "UNDEF")

    def makeFunction(self, instruction):
        return self.db.functions.create(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        return self.db.names.set_name(address, name)

    def getInputPath(self):
        return self.db.path

    def getIdbDir(self):
        import ida_loader

        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not idb_path:
            return ""
        dirname = os.path.dirname(idb_path)
        return dirname + os.sep if dirname else ""
