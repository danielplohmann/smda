#!/usr/bin/python
from io import BytesIO
import re
import struct
import logging
import pefile
import sys
from collections import OrderedDict

from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider

LOGGER = logging.getLogger(__name__)


class LanguageAnalyzer(object):

    def __init__(self, disassembly):
        self.disassembly = disassembly
        self.go_resolver = GoSymbolProvider(None)
        self.strings = None

    def validPEHeader(self):
        is_pe = True
        is_pe |= self.disassembly.binary_info.binary[0:2] == "\x4D\x5A"
        if len(self.disassembly.binary_info.binary) > 0x40:
            pe_offset = struct.unpack("I", self.disassembly.binary_info.binary[0x3c:0x40])[0]
            is_pe |= (len(self.disassembly.binary_info.binary) > pe_offset and self.disassembly.binary_info.binary[pe_offset:pe_offset + 2] == "\x50\x45")
        else:
            is_pe = False
        return is_pe

    #SOURCE: https://gist.github.com/geudrik/03152ba1a148d9475e81
    def _getPETimestamp(self):
        try:
            pe_offset = struct.unpack("I", self.disassembly.binary_info.binary[0x3c:0x40])[0]
            # Seek to PE header and read second DWORD
            ts_offset = pe_offset + 8
            return struct.unpack("I", self.disassembly.binary_info.binary[ts_offset:ts_offset + 4])[0]
        except:
            return 0

    def getStrings(self):
        if not self.strings:
            self.strings = [match.group("string") for match in re.finditer(b"(?P<string>[ -~]{6,128})", self.disassembly.binary_info.binary)]
        return self.strings

    def getVisualBasicScore(self):
        #check for the typical import of msvbvm60.dll
        vb_score = 0.0
        if "MSVBVM60.DLL" in self.getStrings():
            vb_score = 0.5
        return vb_score

    def getDotNetScore(self):
        dot_net_score = 0.0
        #check for the typical import of mscorelib.dll and mscoree.dll
        if "mscorelib.dll" in self.getStrings() or "mscoree.dll" in self.getStrings():
            dot_net_score = 0.35
        #check for a functioning PE-Header and typical meta-data
        if self.validPEHeader():
            match = re.search(b"text\x00\x00\x00(?P<dword>[\S\s]{4})(?P<start>[\S\s]{4})", self.disassembly.binary_info.binary)
            if match:
                start_addr = struct.unpack("<I", match.group("start"))[0]
                if start_addr == 0x2000:
                    dot_net_score = max(dot_net_score, 0.8)
                if self.disassembly.getRawBytes(start_addr, 4) == "\xDB\x4D\x00\x79":
                    dot_net_score = max(dot_net_score, 0.9)
        return dot_net_score

    def checkDelphi(self):
        return self.getDelphiScore() > 0.5

    def getDelphiScore(self):
        delphi_score = 0.0
        #Check if Delphi-Locales are present in strings
        if "Borland\\locales" in self.getStrings():
            delphi_score = max(delphi_score, 0.5)
        if self._getPETimestamp() == 0x2a425e19:
            delphi_score = 0.5
        #Find "Delphi-Saved" Strings
        delphi_strings = [
            match.group("string")
            #Regex: <DWORD_LEN_STRING><STRING><TERMINATOR>
            for match in re.finditer(b"(?P<length>[\S\s]{4})(?P<string>[ -~]{6,128})\x00", self.disassembly.binary_info.binary)
            if len(match.group("string")) == struct.unpack("<I", match.group("length"))[0]
        ]
        if len(delphi_strings) > 100:
            delphi_score = max(delphi_score, 0.8)
        return delphi_score

    def getGoScore(self):
        go_score = 0.0
        strings = self.getStrings()
        if any(b"Go build ID" in s for s in strings):
            go_score = max(go_score, 0.6)

        return go_score

    def checkGo(self):
        return self.getGoScore() > 0.5

    def getDelphiObjects(self):
        pe =  pefile.PE(data=bytearray(self.disassembly.binary_info.binary))
        data = BytesIO(self.disassembly.binary_info.binary)
        code_sections = []
        for section in pe.sections:
                if (
                    section.Characteristics
                    & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_CODE"]
                ):
                    size = section.SizeOfRawData
                    base_va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    code_sections.append((base_va,size))
        function_offsets = set()

        while data.read(4) != b'':
            data.seek(data.tell()-4)
            offset = data.tell()
            potential_vmt_self_ptr = int.from_bytes(data.read(4), byteorder="little")
            temp_offset = data.tell()
            if offset + pe.OPTIONAL_HEADER.ImageBase + int('4C', base=16) == potential_vmt_self_ptr:
                if potential_vmt_self_ptr == 4638980:
                    print("FOUND")
                data.seek(temp_offset)
                intfTable = int.from_bytes(data.read(4), byteorder="little")
                autoTable = int.from_bytes(data.read(4), byteorder="little")
                initTable = int.from_bytes(data.read(4), byteorder="little")
                typeInfo = int.from_bytes(data.read(4), byteorder="little")
                fieldtable = int.from_bytes(data.read(4), byteorder="little")
                methodTable = int.from_bytes(data.read(4), byteorder="little")
                dynamicTable = int.from_bytes(data.read(4), byteorder="little")
                class_name = int.from_bytes(data.read(4), byteorder="little")
                instance_size = int.from_bytes(data.read(4), byteorder="little")
                temp = data.tell()
                if class_name > pe.OPTIONAL_HEADER.ImageBase:
                    data.seek(class_name-pe.OPTIONAL_HEADER.ImageBase)
                    length = int.from_bytes(data.read(1), byteorder="little")
                    class_name_string = data.read(length).decode()
                data.seek(temp)
                data.read(8)
                first_address = int.from_bytes(data.read(4), byteorder="little")

                if first_address >= base_va and first_address <= base_va+size:
                    data.seek(data.tell()-4)
                    for i in range(8):
                        function_offsets.add(int.from_bytes(data.read(4), byteorder="little"))
                    if dynamicTable > 0:
                        data.seek(dynamicTable-pe.OPTIONAL_HEADER.ImageBase)
                        len_table = int.from_bytes(data.read(2), byteorder="little")
                        data.read(2*len_table)
                        for i in range(len_table):
                            function_offsets.add(int.from_bytes(data.read(4), byteorder="little"))
                        data.seek(potential_vmt_self_ptr-pe.OPTIONAL_HEADER.ImageBase)
                        while data.tell() < dynamicTable-pe.OPTIONAL_HEADER.ImageBase:
                            function_offsets.add(int.from_bytes(data.read(4), byteorder="little"))
                    else:
                        data.seek(potential_vmt_self_ptr-pe.OPTIONAL_HEADER.ImageBase)
                        count = 0
                        while data.tell() < class_name-pe.OPTIONAL_HEADER.ImageBase:
                            count+=1
                            function_offsets.add(int.from_bytes(data.read(4), byteorder="little"))
                    if methodTable > 0:
                        data.seek(methodTable-pe.OPTIONAL_HEADER.ImageBase)
                        length = int.from_bytes(data.read(2), byteorder="little")
                        for i in range(length):
                            length_entry = int.from_bytes(data.read(2), byteorder="little")
                            method_offset = int.from_bytes(data.read(4), byteorder="little")
                            function_offsets.add(method_offset)
                            data.seek(data.tell()+length_entry-6)
                        data.seek(temp_offset)
                    if intfTable > 0:
                        data.seek(intfTable-pe.OPTIONAL_HEADER.ImageBase)
                        data.read(20)
                        start_intf = int.from_bytes(data.read(4), byteorder="little")
                        data.seek(start_intf-pe.OPTIONAL_HEADER.ImageBase)
                        bytes_read = int.from_bytes(data.read(4), byteorder="little")
                        while bytes_read >= base_va and bytes_read <= base_va+size:
                            function_offsets.add(bytes_read)
                            bytes_read = int.from_bytes(data.read(4), byteorder="little")
                        data.seek(temp_offset)
        
                else:
                    data.seek(temp_offset)
            
            else:
                data.seek(temp_offset)

        functions = {}
        for offset in function_offsets:
            if offset >= base_va and offset <= base_va+size:
                functions[offset] = ''
        return functions 

    def getGoObjects(self):
        self.go_resolver.update(self.disassembly.binary_info)
        return self.go_resolver.getFunctionSymbols()

    def identify(self):
        result = {
            #programming language : probability
            "c/asm": 0.1,  # if no other language matches, c/asm will
            "_count_thiscalls": 0,
            "_count_delphi_objects": 0,
        }
        #DELPHI
        result["delphi"] = self.getDelphiScore()
        if self.checkDelphi():
            t_objects = self.getDelphiObjects()
            functions = sum([len(t_objects[t_string]) for t_string in t_objects])
            # result["_delphi_objects"] = t_objects.keys()
            result["_count_delphi_objects"] = len(t_objects)
            if len(t_objects) > 5 and functions > 10:
                result["delphi"] = max(result.get("delphi", 0), 0.9)
        #.NET
        result[".net"] = self.getDotNetScore()
        #VISUALBASIC
        result["visualbasic"] = self.getVisualBasicScore()
        #GO
        result["go"] = self.getGoScore()
        #C++
        #check if there is a high number of the following patterns
        #in relation to the number off all functions (->the size of the sample)
        patterns = []
        # mov ecx, <stack_offset>; call XYZ
        patterns.append(b"\x8B\x4D[\S\s]\xE8[\S\s]{3}(\x00|\xFF)")
        # mov ecx, <reg>; call XYZ
        patterns.append(b"\x8B[\xC8-\xCF]\xE8[\S\s]{3}(\x00|\xFF)")
        result["c++"] = min(1, 6.0 * sum([len(re.findall(pattern, self.disassembly.binary_info.binary)) for pattern in patterns]) / max(1, len(self.disassembly.functions)))
        result["_count_thiscalls"] = sum([len(re.findall(pattern, self.disassembly.binary_info.binary)) for pattern in patterns])

        #guess the programming language and
        #return dict with probabilities for the use of certain programming languages
        guess = None
        for lang in [key for key in result if not key.startswith("_")]:
            if not (guess and result[guess] > result[lang]):
                guess = lang
        result["_guess"] = guess
        return result
