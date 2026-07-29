#!/usr/bin/python
import logging
import re
import struct
from collections import OrderedDict

import lief

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.utility.MachoBinary import get_active_macho_binary

from .AbstractLabelProvider import AbstractLabelProvider

lief.logging.disable()
LOGGER = logging.getLogger(__name__)

# Go symbol names are short; cap the fallback decode when no null terminator is found so a
# truncated/corrupt name table cannot pull the entire (potentially multi-MB) binary tail into
# one symbol string.
_MAX_SYMBOL_NAME_LEN = 4096
_PCLNTAB_VERSIONS = {
    0xFFFFFFFB: "1.12",
    0xFFFFFFFA: "1.16",
    0xFFFFFFF0: "1.18",
    0xFFFFFFF1: "1.20",
}
# The magic is written in the target's byte order, so accept both spellings: Go also
# targets big-endian platforms (s390x, ppc64, mips).
_PCLNTAB_HEADER_RE = re.compile(
    b"(?:(?:\xfb|\xfa|\xf0|\xf1)\xff\xff\xff|\xff\xff\xff(?:\xfb|\xfa|\xf0|\xf1))\x00\x00[\x01\x02\x04][\x04\x08]"
)


class GoSymbolProvider(AbstractLabelProvider):
    """Minimal resolver for Go symbols"""

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}

    def getPcLntabOffset(self, binary):
        from smda.common.BinaryInfo import BinaryInfo

        binary_info = None
        if isinstance(binary, BinaryInfo) or hasattr(binary, "binary"):
            binary_info = binary
            if hasattr(binary_info, "_go_pclntab_offset"):
                return binary_info._go_pclntab_offset
            binary_bytes = binary_info.binary
        else:
            binary_bytes = binary

        pclntab_offset = None
        try:
            lief_binary = None
            if binary_info is not None:
                lief_binary = binary_info.getLiefBinary()
            if lief_binary is None:
                lief_binary = lief.parse(binary_bytes)
            if lief_binary is not None:
                if isinstance(lief_binary, lief.ELF.Binary):
                    section = lief_binary.get_section(".gopclntab")
                    if section is not None:
                        pclntab_offset = section.offset
                elif isinstance(lief_binary, (lief.MachO.Binary, lief.MachO.FatBinary)):
                    macho_binary = get_active_macho_binary(
                        lief_binary,
                        bitness=getattr(binary_info, "bitness", None) if binary_info is not None else None,
                        architecture=getattr(binary_info, "architecture", "") if binary_info is not None else "",
                    )
                    if macho_binary is not None:
                        section = macho_binary.get_section("__gopclntab")
                        if section is not None:
                            pclntab_offset = section.offset
                elif isinstance(lief_binary, lief.PE.Binary):
                    section = lief_binary.get_section(".rdata")
                    symbol = lief_binary.get_symbol("runtime.pclntab")
                    if section is not None and symbol is not None:
                        pclntab_offset = section.offset + symbol.value
        except Exception as exc:
            reraise_non_operational_exception(exc)
        if pclntab_offset is None:
            # scan for offset of structure
            hits = [match.start() for match in _PCLNTAB_HEADER_RE.finditer(binary_bytes)]
            if len(hits) == 1:
                pclntab_offset = hits[0]
        if binary_info is not None:
            binary_info._go_pclntab_offset = pclntab_offset
        return pclntab_offset

    def getPcLntabInfo(self, binary):
        """Return validated Go pclntab header information, or ``None``.

        Go's own ``debug/gosym`` parser requires the version magic, two zero
        padding bytes, a valid PC quantum, and a 4- or 8-byte pointer size.
        Apply those same inexpensive structural checks before treating a table
        as language evidence. A bare magic-byte hit is not sufficient.
        """
        binary_bytes = binary.binary if hasattr(binary, "binary") else binary
        pclntab_offset = self.getPcLntabOffset(binary)
        if pclntab_offset is None or pclntab_offset < 0 or pclntab_offset + 8 > len(binary_bytes):
            return None
        header = binary_bytes[pclntab_offset : pclntab_offset + 8]
        markers = (struct.unpack("<I", header[:4])[0], struct.unpack(">I", header[:4])[0])
        marker = next((value for value in markers if value in _PCLNTAB_VERSIONS), None)
        if marker is None:
            return None
        if header[4:6] != b"\x00\x00" or header[6] not in (1, 2, 4) or header[7] not in (4, 8):
            return None
        return {"offset": pclntab_offset, "version": _PCLNTAB_VERSIONS[marker], "bitness": header[7] * 8}

    def update(self, binary_info):
        self._func_symbols = {}
        binary = binary_info.binary
        pclntab_offset = self.getPcLntabOffset(binary_info)
        # if we found a valid offset, do the pclntab parsing
        if pclntab_offset is not None:
            try:
                result = self._parse_pclntab(pclntab_offset, binary)
                if result:
                    self._func_symbols = result
            except Exception as exc:
                reraise_non_operational_exception(exc)
                return

    def isSymbolProvider(self):
        return True

    def isApiProvider(self):
        return False

    def getApi(self, to_addr, absolute_addr=None):
        return ("", "")

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def is_active(self):
        return bool(self._func_symbols)

    def _readUtf8(self, buffer):
        null_byte_index = buffer.find(b"\x00")
        if null_byte_index == -1:
            # No terminator (truncated/corrupt name table): decode a bounded prefix so a
            # genuinely-present name is preserved, without decoding the entire binary tail.
            null_byte_index = min(len(buffer), _MAX_SYMBOL_NAME_LEN)
        # errors="replace" is intentional: a single bad byte should not abort parsing of the
        # entire symbol table (the old hex-decode path raised and lost all symbols for the binary).
        return buffer[:null_byte_index].decode("utf-8", errors="replace").replace("\u00b7", ":")

    def _parse_pclntab(self, pclntab_offset, binary):
        pclntab_buffer = binary[pclntab_offset:]

        # marker are defined here https://go.dev/src/debug/gosym/pclntab.go
        marker = struct.unpack("<I", pclntab_buffer[0:4])[0]
        if marker == 0xFFFFFFFB:
            version = "1.12"
        elif marker == 0xFFFFFFFA:
            version = "1.16"
        elif marker == 0xFFFFFFF0:
            version = "1.18"
        elif marker == 0xFFFFFFF1:
            version = "1.20"
        else:
            raise ValueError(f"Could not recognize Golang version marker: 0x{marker:08X}")

        bitness_indicator = struct.unpack("<B", pclntab_buffer[7:8])[0]
        bitness = None
        if bitness_indicator == 8:
            bitness = 64
        elif bitness_indicator == 4:
            bitness = 32
        else:
            raise ValueError(f"Could not recognize Golang bitness marker: 0x{bitness_indicator:02X}")

        field_size = 8 if bitness == 64 else 4
        field_indicator = "Q" if bitness == 64 else "I"
        if version == "1.12":
            number_of_functions = struct.unpack("<I", pclntab_buffer[8:12])[0]
            function_name_offset = pclntab_offset
            weird_table_offset = pclntab_offset + 16 if bitness == 64 else pclntab_offset + 12
            start_text = 0
        elif version == "1.16":
            parsed_pclntab_fields = struct.unpack("<" + 7 * field_indicator, pclntab_buffer[8 : 8 + 7 * field_size])
            number_of_functions = parsed_pclntab_fields[0]
            function_name_offset = pclntab_offset + parsed_pclntab_fields[2]
            weird_table_offset = pclntab_offset + parsed_pclntab_fields[6]
            start_text = 0
        elif version == "1.18" or version == "1.20":
            parsed_pclntab_fields = struct.unpack("<" + 8 * field_indicator, pclntab_buffer[8 : 8 + 8 * field_size])
            number_of_functions = parsed_pclntab_fields[0]
            start_text = parsed_pclntab_fields[2]
            function_name_offset = pclntab_offset + parsed_pclntab_fields[3]
            weird_table_offset = pclntab_offset + parsed_pclntab_fields[7]

        # first parse function offsets
        offsets = OrderedDict()
        func_info_offsets = {}
        read_offset = 0
        table_buffer = binary[weird_table_offset:]
        for index in range(number_of_functions):
            # need to parse a second table in this case
            if version == "1.12":
                offsets[index] = struct.unpack(
                    "<" + field_indicator,
                    table_buffer[read_offset : read_offset + field_size],
                )[0]
                read_offset += field_size
                func_info_offsets[index] = struct.unpack(
                    "<" + field_indicator,
                    table_buffer[read_offset : read_offset + field_size],
                )[0]
                read_offset += field_size
            # advance element pointer
            if version == "1.16":
                offsets[index] = struct.unpack(
                    "<" + field_indicator,
                    table_buffer[read_offset : read_offset + field_size],
                )[0]
                read_offset += 2 * field_size
            # here we have a more compact structure for both x86/x64, no need to skip
            if version == "1.18" or version == "1.20":
                offsets[index] = struct.unpack("<I", table_buffer[read_offset : read_offset + 4])[0]
                read_offset += 8

        functions = {}
        offsets2 = offsets.copy()
        function_name_buffer = binary[function_name_offset:]
        if version == "1.12":
            for index, info_offset in func_info_offsets.items():
                function_offset = offsets[index]
                name_offset = struct.unpack(
                    "<" + field_indicator,
                    pclntab_buffer[info_offset + field_size : info_offset + 2 * field_size],
                )[0]
                # only take lower 32bit in case of 64bit binaries.
                name_offset &= 0xFFFFFFFF
                function_name = self._readUtf8(function_name_buffer[name_offset:])
                functions[function_offset + start_text] = function_name
        else:
            delete = False
            for offset, function_offset in offsets.items():
                if delete:
                    offsets2.pop(offset)
                    continue
                try:
                    bytes_read = struct.unpack("<I", table_buffer[read_offset : read_offset + 4])[0]
                    read_offset += 4
                    while bytes_read != function_offset:
                        bytes_read = struct.unpack("<I", table_buffer[read_offset : read_offset + 4])[0]
                        read_offset += 4
                    if version == "1.16" and bitness == 64:
                        read_offset += 4
                    name_offset = struct.unpack("<I", table_buffer[read_offset : read_offset + 4])[0]
                    read_offset += 4
                except struct.error:
                    delete = True
                    offsets2.pop(offset)
                    continue
                function_name = self._readUtf8(function_name_buffer[name_offset:])
                functions[function_offset + start_text] = function_name
        return functions
