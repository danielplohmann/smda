#!/usr/bin/python
import logging
import re
import struct

from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider

LOGGER = logging.getLogger(__name__)


class LanguageAnalyzer:
    def __init__(self, disassembly):
        self.disassembly = disassembly
        self.go_resolver = GoSymbolProvider(None)
        self.delphi_kb_resolver = DelphiKbSymbolProvider(None)
        self.delphi_pythia_resolver = DelphiPythiaProvider(None)
        self.delphi_resym_resolver = DelphiReSymProvider(None)
        self.strings = None

    def validPEHeader(self):
        is_pe = True
        is_pe |= self.disassembly.binary_info.binary[0:2] == "\x4d\x5a"
        if len(self.disassembly.binary_info.binary) > 0x40:
            pe_offset = struct.unpack("I", self.disassembly.binary_info.binary[0x3C:0x40])[0]
            is_pe |= (
                len(self.disassembly.binary_info.binary) > pe_offset
                and self.disassembly.binary_info.binary[pe_offset : pe_offset + 2] == "\x50\x45"
            )
        else:
            is_pe = False
        return is_pe

    # SOURCE: https://gist.github.com/geudrik/03152ba1a148d9475e81
    def _getPETimestamp(self):
        try:
            pe_offset = struct.unpack("I", self.disassembly.binary_info.binary[0x3C:0x40])[0]
            # Seek to PE header and read second DWORD
            ts_offset = pe_offset + 8
            return struct.unpack("I", self.disassembly.binary_info.binary[ts_offset : ts_offset + 4])[0]
        except (struct.error, IndexError):
            return 0

    def getStrings(self):
        if not self.strings:
            self.strings = [
                match.group("string")
                for match in re.finditer(b"(?P<string>[ -~]{6,128})", self.disassembly.binary_info.binary)
            ]
        return self.strings

    def getVisualBasicScore(self):
        # check for the typical import of msvbvm60.dll
        vb_score = 0.0
        if "MSVBVM60.DLL" in self.getStrings():
            vb_score = 0.5
        return vb_score

    def getDotNetScore(self):
        dot_net_score = 0.0
        # check for the typical import of mscorelib.dll and mscoree.dll
        if "mscorelib.dll" in self.getStrings() or "mscoree.dll" in self.getStrings():
            dot_net_score = 0.35
        # check for a functioning PE-Header and typical meta-data
        if self.validPEHeader():
            match = re.search(
                b"text\x00\x00\x00(?P<dword>[\\S\\s]{4})(?P<start>[\\S\\s]{4})",
                self.disassembly.binary_info.binary,
            )
            if match:
                start_addr = struct.unpack("<I", match.group("start"))[0]
                if start_addr == 0x2000:
                    dot_net_score = max(dot_net_score, 0.8)
                if self.disassembly.getRawBytes(start_addr, 4) == "\xdb\x4d\x00\x79":
                    dot_net_score = max(dot_net_score, 0.9)
        return dot_net_score

    def checkDelphi(self):
        return self.getDelphiScore() > 0.5

    def getDelphiScore(self):
        delphi_score = 0.0
        # Check if Delphi-Locales are present in strings
        if "Borland\\locales" in self.getStrings():
            delphi_score = max(delphi_score, 0.5)
        if self._getPETimestamp() == 0x2A425E19:
            delphi_score = 0.5
        # Find "Delphi-Saved" Strings
        delphi_strings = [
            match.group("string")
            # Regex: <DWORD_LEN_STRING><STRING><TERMINATOR>
            for match in re.finditer(
                b"\x00\x00.(?P<length>.)(?P<string>[ -~]{6,128})\x00",
                self.disassembly.binary_info.binary,
            )
            if len(match.group("string")) == ord(match.group("length"))
        ]
        if len(delphi_strings) > 100:
            LOGGER.info("Detected %d Delphi-like strings.", len(delphi_strings))
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

    def parseDelphiString(self, buffer):
        parsed_string = ""
        if len(buffer) > 0:
            length = buffer[0]
            try:
                parsed_string = buffer[1 : 1 + length].decode()
            except UnicodeDecodeError:
                parsed_string = "<invalid>"
        return parsed_string

    def getDelphiObjects(self):
        """
        Extract Delphi object methods using a Pythia-style VMT scan.

        The return format intentionally remains unchanged:
            {absolute_function_address: optional_function_name}
        """
        self.delphi_pythia_resolver.update(self.disassembly.binary_info)
        return self.delphi_pythia_resolver.getFunctionSymbols()

    def getGoObjects(self):
        self.go_resolver.update(self.disassembly.binary_info)
        return self.go_resolver.getFunctionSymbols()

    def getDelphiKbScore(self):
        return 1.0 if self.disassembly.binary_info.binary.startswith(b"IDR Knowledge Base File") else 0.0

    def checkDelphiKb(self):
        return self.getDelphiKbScore() == 1

    def getDelphiKbObjects(self):
        self.delphi_kb_resolver.update(self.disassembly.binary_info)
        return self.delphi_kb_resolver.getFunctionSymbols()

    def getDelphiReSymObjects(self):
        """Extract Delphi symbols using DelphiReSym metadata parsing."""
        self.delphi_resym_resolver.update(self.disassembly.binary_info)
        return self.delphi_resym_resolver.getFunctionSymbols()

    def identify(self):
        result = {
            # programming language : probability
            "c/asm": 0.1,  # if no other language matches, c/asm will
            "_count_thiscalls": 0,
            "_count_delphi_objects": 0,
        }
        # DELPHI
        result["delphi"] = self.getDelphiScore()
        if self.checkDelphi():
            t_objects = self.getDelphiObjects()
            functions = sum([len(t_objects[t_string]) for t_string in t_objects])
            # result["_delphi_objects"] = t_objects.keys()
            result["_count_delphi_objects"] = len(t_objects)
            if len(t_objects) > 5 and functions > 10:
                result["delphi"] = max(result.get("delphi", 0), 0.9)
        result["delphi_kb_file"] = self.getDelphiKbScore()
        # .NET
        result[".net"] = self.getDotNetScore()
        # VISUALBASIC
        result["visualbasic"] = self.getVisualBasicScore()
        # GO
        result["go"] = self.getGoScore()
        # C++
        # check if there is a high number of the following patterns
        # in relation to the number off all functions (->the size of the sample)
        patterns = []
        # mov ecx, <stack_offset>; call XYZ
        patterns.append(b"\x8b\x4d[\\S\\s]\xe8[\\S\\s]{3}(\x00|\xff)")
        # mov ecx, <reg>; call XYZ
        patterns.append(b"\x8b[\xc8-\xcf]\xe8[\\S\\s]{3}(\x00|\xff)")
        thiscall_count = sum(len(re.findall(pattern, self.disassembly.binary_info.binary)) for pattern in patterns)
        result["c++"] = min(
            1,
            6.0 * thiscall_count / max(1, len(self.disassembly.functions)),
        )
        result["_count_thiscalls"] = thiscall_count

        # guess the programming language and
        # return dict with probabilities for the use of certain programming languages
        guess = None
        for lang in [key for key in result if not key.startswith("_")]:
            if not (guess and result[guess] > result[lang]):
                guess = lang
        result["_guess"] = guess
        return result
