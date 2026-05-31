"""SMDA's IDA backend, built on the modern ``ida-domain`` package.

This is the single supported IDA backend (SMDA dropped the legacy IDAPython
``idaapi``/``idautils``/``idc`` interface). It drives the high level
``ida_domain.Database`` handle and works both:

* inside the IDA GUI - construct it without a database handle and it grabs the
  currently open one via ``Database.open()``; and
* fully headless - open a database from disk (``.idb``/``.i64`` or any input
  binary IDA supports) and hand the resulting handle to this class.

Requires ``ida-domain >= 0.5.0`` and IDA Pro 9.1+.  See
https://ida-domain.docs.hex-rays.com/ for the API reference.
"""

import contextlib
import os
import re

from .BackendInterface import BackendInterface

with contextlib.suppress(ImportError):
    # only importable when ida-domain (and an IDA installation) is available
    from ida_domain import Database


# processor identifiers that SMDA maps onto its "intel" architecture
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


class IdaInterface(BackendInterface):
    """``BackendInterface`` implementation backed by ``ida_domain.Database``."""

    def __init__(self, database=None):
        super().__init__()
        self.version = "ida-domain (IDA Pro 9.1+)"
        self._owns_database = False
        if database is not None:
            self.db = database
        else:
            # inside the IDA GUI: get a handle to the currently open database
            self.db = Database.open()
        self._processor_map = dict.fromkeys(_INTEL_PROCESSORS, "intel")

    @classmethod
    def fromPath(cls, input_path, save_on_close=False):
        """Open a database headlessly from ``input_path`` and wrap it.

        The caller is responsible for keeping the interface alive while the
        report is being built; call :meth:`close` when done.
        """
        database = Database.open(path=input_path, save_on_close=save_on_close)
        interface = cls(database=database)
        interface._owns_database = True
        return interface

    def close(self):
        """Close the underlying database if this interface opened it."""
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
        if normalized in self._processor_map:
            return self._processor_map[normalized]
        # tolerate vendor specific suffixes like "x86_64-pc-linux"
        if "x86" in normalized or normalized.startswith("metapc"):
            return "intel"
        raise ValueError(f"Unsupported Architecture: {procname}")

    def getBitness(self):
        bits = self.db.bitness
        if bits in (16, 32, 64):
            return bits
        # ida-domain only advertises 32/64; fall back to the segment addressing
        # mode for the (rare) 16 bit case.
        segment = self.db.segments.get_at(self.db.minimum_ea)
        if segment is not None:
            return self.db.segments.get_bitness(segment)
        return bits if bits else 32

    def getFunctions(self):
        return sorted(func.start_ea for func in self.db.functions.get_all())

    def getBlocks(self, function_offset):
        blocks = []
        func = self.db.functions.get_at(function_offset)
        if func is None:
            return blocks
        flowchart = self.db.functions.get_flowchart(func)
        if flowchart is None:
            return blocks
        for block in flowchart:
            instructions = block.get_instructions()
            extracted_block = [instruction.ea for instruction in instructions] if instructions else []
            if extracted_block:
                blocks.append(extracted_block)
        return sorted(blocks)

    def getInstructionBytes(self, offset):
        instruction = self.db.instructions.get_at(offset)
        return self.db.bytes.get_bytes_at(offset, instruction.size)

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in self.db.xrefs.code_refs_to_ea(offset, flow=True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in self.db.xrefs.code_refs_from_ea(offset, flow=True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        for func in self.db.functions.get_all():
            function_offset = func.start_ea
            function_name = self.db.functions.get_name(func)
            # apply demangling if required
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
        first_segment_start = segment_starts[0]
        # re-align by 0x10000 to reflect typical allocation behaviour for IDA-mapped binaries
        first_segment_start = (first_segment_start // 0x10000) * 0x10000
        return int(first_segment_start)

    def getBinary(self):
        result = b""
        for segment in sorted(self.db.segments.get_all(), key=lambda seg: seg.start_ea):
            size = self.db.segments.get_size(segment)
            segment_bytes = self.db.bytes.get_bytes_at(segment.start_ea, size)
            if segment_bytes:
                result += segment_bytes
        return result

    def getApiMap(self):
        api_map = {}
        for imported in self.db.imports.get_all_imports():
            if imported.module_name and imported.name:
                api_map[imported.address] = f"{imported.module_name}!{imported.name}"
            elif imported.name:
                api_map[imported.address] = imported.name
            else:
                # ordinal-only import
                api_map[imported.address] = f"{imported.module_name}!#{imported.ordinal}"
        return api_map

    def isExternalFunction(self, function_offset):
        segment = self.db.segments.get_at(function_offset)
        if segment is None:
            return False
        segment_name = self.db.segments.get_name(segment)
        return segment_name in ("extern", "UNDEF")

    def makeFunction(self, instruction):
        return self.db.functions.create(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        return self.db.names.set_name(address, name)

    def getInputPath(self):
        return self.db.path

    def getIdbDir(self):
        if not self.db.path:
            return ""
        return os.path.dirname(self.db.path) + os.sep
