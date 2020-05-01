#!/usr/bin/python
import re
import struct
import logging

LOGGER = logging.getLogger(__name__)


class LanguageAnalyzer(object):

    def __init__(self, disassembly):
        self.disassembly = disassembly
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

    def getDelphiObjects(self):
        binary = self.disassembly.binary_info.binary
        base_addr = self.disassembly.binary_info.base_addr
        #Find T-String-Constructs
        #(T-Strings with function-addresses before them)
        #(T-Strings start with a capital T, followed by any capital letter)
        t_objects = {}
        for match in re.finditer(b"(?P<length>.)(?P<t_string>T[A-Z][a-zA-Z0-9]{4,128})", binary):
            if not len(match.group("t_string")) - ord(match.group("length")) in [-3, -2, -1, 0, 1, 2, 3]:  # ord(match.group("length")) != len(match.group("t_string")):
                continue
            t_object_name = match.group("t_string")[:ord(match.group("length"))]
            addresses = []
            t_string_pos = base_addr + match.span()[1] - (len(match.group("t_string")) + len(match.group("length")))
            num_addresses = 0
            address_offset = match.start()
            found_string_ref = False
            # filter address arrays with form <reference>?<len_t_string><t_string>
            if t_string_pos == (struct.unpack("<I", binary[address_offset - 5:address_offset - 1])[0] + 1):
                continue

            while num_addresses < 1000 and address_offset > 4:
                num_addresses += 1
                address_offset -= 4
                address = struct.unpack("<I", binary[address_offset:address_offset + 4])[0]
                if address == t_string_pos:
                    found_string_ref = True
                    LOGGER.debug("object end marker found " + str(t_object_name) + " 0x%08x " % (t_string_pos - base_addr) + "0x%08x" % (t_string_pos))
                    t_objects[t_object_name] = []
                    for address in addresses:
                        if self.disassembly.isAddrWithinMemoryImage(address):
                            t_objects[t_object_name].append(address)
                        else:
                            LOGGER.debug("outside range: 0x%08x", address)
                    break
                #if the first address is invalid, break
                elif num_addresses == 1 and not  self.disassembly.isAddrWithinMemoryImage(address):
                    break
                addresses.append(address)
            if not found_string_ref:
                LOGGER.debug("no object end marker found" + str(t_object_name) + "0x%08x" % (t_string_pos - base_addr) + "0x%08x" % (t_string_pos))
        return t_objects

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
