#!/usr/bin/python
import logging
import re
import struct

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.ItaniumDemangler import is_itanium_cpp_symbol, is_msvc_cpp_symbol
from smda.common.labelprovider.RustSymbolEvidence import is_rust_language_evidence
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider

LOGGER = logging.getLogger(__name__)


class LanguageAnalyzer:
    def __init__(self, disassembly):
        self.disassembly = disassembly
        self.go_resolver = GoSymbolProvider(None)
        self.rust_resolver = RustSymbolProvider(None)
        self.delphi_kb_resolver = DelphiKbSymbolProvider(None)
        self.delphi_pythia_resolver = DelphiPythiaProvider(None)
        self.delphi_resym_resolver = DelphiReSymProvider(None)
        self.strings = None
        self._cpp_symbol_count = 0
        self._guess = None
        self._delphi_objects = None

    def validPEHeader(self):
        is_pe = self.disassembly.binary_info.binary[0:2] == b"\x4d\x5a"
        if len(self.disassembly.binary_info.binary) > 0x40:
            pe_offset = struct.unpack("I", self.disassembly.binary_info.binary[0x3C:0x40])[0]
            is_pe = is_pe and (
                len(self.disassembly.binary_info.binary) > pe_offset
                and self.disassembly.binary_info.binary[pe_offset : pe_offset + 2] == b"\x50\x45"
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
        """Score VB6 using its runtime import, with a weak string-only fallback."""
        try:
            lief_binary = self.disassembly.binary_info.getLiefBinary()
        except Exception as exc:
            reraise_non_operational_exception(exc)
            lief_binary = None
        imported_libraries = {library.lower() for library in getattr(lief_binary, "imported_libraries", []) or []}
        if "msvbvm60.dll" in imported_libraries:
            return 0.9
        # A copied string is not proof that the program uses the VB6 runtime.
        return 0.2 if b"MSVBVM60.DLL" in self.getStrings() else 0.0

    def getDotNetScore(self):
        dot_net_score = 0.0
        # check for the typical import of mscorelib.dll and mscoree.dll
        if b"mscorelib.dll" in self.getStrings() or b"mscoree.dll" in self.getStrings():
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
                if self.disassembly.getRawBytes(start_addr, 4) == b"\xdb\x4d\x00\x79":
                    dot_net_score = max(dot_net_score, 0.9)
        return dot_net_score

    def checkDelphi(self):
        return self.getDelphiScore() > 0.5

    def getDelphiScore(self):
        delphi_score = 0.0
        # Check if Delphi-Locales are present in strings
        if b"Borland\\locales" in self.getStrings():
            delphi_score = max(delphi_score, 0.25)
        if self._getPETimestamp() == 0x2A425E19:
            delphi_score = max(delphi_score, 0.25)
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
            delphi_score = max(delphi_score, 0.35)
        # A validated VMT is structural compiler evidence. Strings and a PE
        # timestamp are only hints and must not enable Delphi-only recovery.
        if b"TObject" in self.disassembly.binary_info.binary:
            delphi_objects = self.getDelphiObjects()
            if len(delphi_objects) >= 5:
                delphi_score = max(delphi_score, 0.9)
            elif delphi_objects:
                delphi_score = max(delphi_score, 0.6)
        return delphi_score

    def getGoScore(self):
        go_score = 0.0
        strings = self.getStrings()
        if any(b"Go build ID" in s for s in strings):
            go_score = max(go_score, 0.6)
        if self.go_resolver.getPcLntabInfo(self.disassembly.binary_info):
            go_score = max(go_score, 0.9)

        return go_score

    def checkGo(self):
        return self.getGoScore() > 0.5

    def getRustScore(self):
        rust_score = 0.0
        if self.rust_resolver.is_rust_binary(self.disassembly.binary_info):
            rust_score = 0.6
        return rust_score

    def checkRust(self):
        return self.getRustScore() > 0.5

    def getCppSymbolScore(self):
        """Return C++ evidence from validated Itanium or MSVC decorated symbols."""
        try:
            lief_binary = self.disassembly.binary_info.getLiefBinary()
        except Exception as exc:
            reraise_non_operational_exception(exc)
            return 0.0, 0
        if not lief_binary:
            return 0.0, 0

        cpp_symbol_names = set()
        for symbol_list_name in (
            "exported_functions",
            "exported_symbols",
            "symtab_symbols",
            "dynamic_symbols",
            "symbols",
        ):
            try:
                symbols = getattr(lief_binary, symbol_list_name, []) or []
            except (AttributeError, UnicodeDecodeError):
                continue
            for symbol in symbols:
                try:
                    symbol_name = symbol.name
                except (AttributeError, UnicodeDecodeError):
                    continue
                if (
                    symbol_name
                    and not is_rust_language_evidence(symbol_name)
                    and (is_itanium_cpp_symbol(symbol_name) or is_msvc_cpp_symbol(symbol_name))
                ):
                    cpp_symbol_names.add(symbol_name)

        cpp_symbol_count = len(cpp_symbol_names)
        if cpp_symbol_count >= 3:
            return 0.8, cpp_symbol_count
        if cpp_symbol_count:
            return 0.4, cpp_symbol_count
        return 0.0, 0

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
        if self._delphi_objects is None:
            self.delphi_pythia_resolver.update(self.disassembly.binary_info)
            self._delphi_objects = self.delphi_pythia_resolver.getFunctionSymbols()
        return self._delphi_objects

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
        }
        # DELPHI
        result["delphi"] = self.getDelphiScore()
        result["delphi"] = max(result["delphi"], self.getDelphiKbScore())
        # .NET
        result[".net"] = self.getDotNetScore()
        # VISUALBASIC
        result["visualbasic"] = self.getVisualBasicScore()
        # GO
        result["go"] = self.getGoScore()
        # RUST
        result["rust"] = self.getRustScore()
        # C++: thiscall-like instruction sequences are ABI-level patterns, not
        # language identity. They are deliberately not scored as C++ evidence.
        cpp_symbol_score, cpp_symbol_count = self.getCppSymbolScore()
        result["c++"] = cpp_symbol_score
        self._cpp_symbol_count = cpp_symbol_count

        # guess the programming language and
        # return dict with probabilities for the use of certain programming languages
        self._guess = self._deriveGuess(result)
        return result

    def getGuess(self):
        return self._guess

    @staticmethod
    def _deriveGuess(result):
        guess = None
        for lang in [key for key in result if not key.startswith("_")]:
            if not (guess and result[guess] > result[lang]):
                guess = lang
        if result.get("go", 0) > 0.5:
            # A Go build ID or a validated pclntab header is stronger evidence
            # than scores derived from optional language-specific metadata.
            guess = "go"
        if result.get("rust", 0) > 0.5:
            # A validated Rust symbol or runtime marker is stronger evidence
            # than scores derived from optional language-specific metadata.
            guess = "rust"
        return guess

    def rescore(self, result, function_count):
        """
        Refresh symbol-derived C++ evidence once disassembly has completed.

        ``function_count`` remains part of this method's compatibility
        signature; language scores no longer infer C++ from calling-convention
        instruction patterns or function counts.
        """
        cpp_symbol_score, cpp_symbol_count = self.getCppSymbolScore()
        result["c++"] = cpp_symbol_score
        self._cpp_symbol_count = cpp_symbol_count
        self._guess = self._deriveGuess(result)
        return result
