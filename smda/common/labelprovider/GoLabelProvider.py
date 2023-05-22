#!/usr/bin/python
import re
import lief
lief.logging.disable()
import struct
import logging
from collections import OrderedDict

from .AbstractLabelProvider import AbstractLabelProvider

LOGGER = logging.getLogger(__name__)


class GoSymbolProvider(AbstractLabelProvider):
    """ Minimal resolver for Go symbols """

    def __init__(self, config):
        self._config = config
        # addr:func_name
        self._func_symbols = {}

    def update(self, binary_info):
        binary = binary_info.binary
        pclntab_offset = None
        try:
            lief_binary = lief.parse(binary)
            if lief_binary.format == lief.EXE_FORMATS.ELF:
                pclntab_offset = lief_binary.get_section(".gopclntab").offset
            elif lief_binary.format == lief.EXE_FORMATS.MACHO:
                pclntab_offset = lief_binary.get_section("__gopclntab").offset
            elif lief_binary.format == lief.EXE_FORMATS.PE:
                rdata_offset = lief_binary.get_section(".rdata").offset
                pclntab_offset = rdata_offset + lief_binary.get_symbol("runtime.pclntab").value
        except:
            pass
        if pclntab_offset is None:
            # scan for offset of structure
            pclntab_regex = re.compile(b".\xFF\xFF\xFF\x00\x00\x01(\x04|\x08)")
            hits = [match.start() for match in re.finditer(pclntab_regex, binary)]
            if len(hits) > 1:
                logging.error("GoLabelProvider found too many candidates for pclntab")
            elif len(hits) == 1:
                pclntab_offset = hits[0]
        # if we found a valid offset, do the pclntab parsing
        if pclntab_offset:
            try:
                result = self._parse_pclntab(pclntab_offset, binary)
                if result:
                    self._func_symbols = result
            except:
                return

    def isSymbolProvider(self):
        return True

    def getSymbol(self, address):
        return self._func_symbols.get(address, "")

    def getFunctionSymbols(self):
        return self._func_symbols

    def _readUtf8(self, buffer):
        string_read = ""
        offset = 0
        while buffer[offset] != 0:
            string_read += f"{buffer[offset]:02x}"
            offset += 1
        # need to defang special char(s)
        decoded_string = bytearray.fromhex(string_read).decode().replace('\u00b7', ':')
        return decoded_string

    def _parse_pclntab(self, pclntab_offset, binary):
        pclntab_buffer = binary[pclntab_offset:]

        marker = struct.unpack("I", pclntab_buffer[0:4])[0]
        if marker == 0xfffffffb:
            version = '1.12'
        elif marker == 0xfffffffa:
            version = '1.16'
        elif marker == 0xfffffff0:
            version = '1.18'
        else:
            raise ValueError(f"Could not recognize Golang version marker: 0x{marker}")
        
        bitness_indicator = struct.unpack("B", pclntab_buffer[7:8])[0]
        bitness = None
        if bitness_indicator == 8:
            bitness = 64
        elif bitness_indicator == 4:
            bitness = 32
        else:
            raise ValueError(f"Could not recognize Golang bitness marker: 0x{bitness_indicator}")

        field_size = 8 if bitness == 64 else 4
        field_indicator = "Q" if bitness == 64 else "I"
        if version == '1.12':
            number_of_functions = struct.unpack("I", pclntab_buffer[8:12])[0]
            function_name_offset = pclntab_offset
            weird_table_offset = pclntab_offset + 16 if bitness == 64 else pclntab_offset + 12
            start_text = 0
        elif version == '1.16':
            parsed_pclntab_fields = struct.unpack(7*field_indicator, pclntab_buffer[8:8+7*field_size])
            number_of_functions = parsed_pclntab_fields[0]
            function_name_offset = pclntab_offset + parsed_pclntab_fields[2]
            file_name_offset = pclntab_offset + parsed_pclntab_fields[3]
            weird_table_offset = pclntab_offset + parsed_pclntab_fields[6]
            start_text = 0
        elif version == '1.18':
            parsed_pclntab_fields = struct.unpack(8*field_indicator, pclntab_buffer[8:8+8*field_size])
            number_of_functions = parsed_pclntab_fields[0]
            start_text = parsed_pclntab_fields[2]
            function_name_offset = pclntab_offset + parsed_pclntab_fields[3]
            file_name_offset = pclntab_offset + parsed_pclntab_fields[5]
            weird_table_offset = pclntab_offset + parsed_pclntab_fields[7]

        # first parse function offsets
        offsets = OrderedDict()
        func_info_offsets = {}
        read_offset = 0
        table_buffer = binary[weird_table_offset:]
        for index in range(number_of_functions):
            # need to parse a second table in this case
            if version == '1.12':
                offsets[index] = struct.unpack(field_indicator, table_buffer[read_offset:read_offset+field_size])[0]
                read_offset += field_size
                func_info_offsets[index] = struct.unpack(field_indicator, table_buffer[read_offset:read_offset+field_size])[0]
                read_offset += field_size
            # advance element pointer
            if version == '1.16':
                offsets[index] = struct.unpack(field_indicator, table_buffer[read_offset:read_offset+field_size])[0]
                read_offset += 2 * field_size
            # here we have a more compact structure for both x86/x64, no need to skip
            if version == '1.18':
                offsets[index] = struct.unpack("I", table_buffer[read_offset:read_offset+4])[0]
                read_offset += 8

        functions = {}
        offsets2 = offsets.copy()
        function_name_buffer = binary[function_name_offset:]
        if version == '1.12':
            for index, info_offset in func_info_offsets.items():
                function_offset = offsets[index]
                name_offset = struct.unpack(field_indicator, pclntab_buffer[info_offset+field_size:info_offset+2*field_size])[0]
                # only take lower 32bit in case of 64bit binaries.
                name_offset &= 0xFFFFFFFF
                function_name = self._readUtf8(function_name_buffer[name_offset:])
                functions[function_offset + start_text] = function_name
        else:
            delete = False
            for offset, function_offset in offsets.items():
                if delete:
                    offsets2.pop(offset)
                bytes_read = struct.unpack("I", table_buffer[read_offset:read_offset+4])[0]
                read_offset += 4
                try:
                    while bytes_read != function_offset:
                        bytes_read = struct.unpack("I", table_buffer[read_offset:read_offset+4])[0]
                        read_offset += 4
                except ValueError:
                    delete = True
                    offsets2.pop(offset)
                    continue
                if version == '1.16' and bitness == 64:
                    read_offset += 4
                name_offset = struct.unpack('I', table_buffer[read_offset:read_offset+4])[0]
                function_name = self._readUtf8(function_name_buffer[name_offset:])
                read_offset += 4
                functions[function_offset + start_text] = function_name
        return functions
