"""Legacy IDAPython adapters for supported IDA SDK generations."""

import contextlib
import re

from .BackendInterface import BackendInterface

try:
    import idaapi
    import idautils
except ImportError:
    pass

try:
    import ida_bytes
    import ida_funcs
    import ida_gdl
    import ida_idaapi
    import ida_nalt
    import ida_name
    import ida_segment
except ImportError:
    pass

with contextlib.suppress(ImportError):
    import idc


class _ModernIdapythonInterface(BackendInterface):
    def __init__(self):
        self._processor_map = {"metapc": "intel"}
        self._api_map = {}
        self._import_module_name = ""

    def getFunctions(self):
        return sorted(idautils.Functions())

    def getBlocks(self, function_offset):
        blocks = []
        function_chart = ida_gdl.FlowChart(ida_funcs.get_func(function_offset))
        for block in function_chart:
            extracted_block = []
            for instruction in idautils.Heads(block.start_ea, block.end_ea):
                if ida_bytes.is_code(ida_bytes.get_flags(instruction)):
                    extracted_block.append(instruction)
            if extracted_block:
                blocks.append(extracted_block)
        return sorted(blocks)

    def getInstructionBytes(self, offset):
        instruction = idautils.DecodeInstruction(offset)
        return ida_bytes.get_bytes(offset, instruction.size)

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in idautils.CodeRefsTo(offset, True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in idautils.CodeRefsFrom(offset, True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        for function_offset in self.getFunctions():
            function_name = ida_funcs.get_func_name(function_offset)
            if demangle and "@" in function_name:
                demangled = ida_name.demangle_name(function_name, 0)
                if demangled:
                    function_name = demangled
            if not re.match("sub_[0-9a-fA-F]+", function_name):
                function_symbols[function_offset] = function_name
        return function_symbols

    def getBaseAddr(self):
        segment_starts = list(idautils.Segments())
        if not segment_starts:
            return 0
        return int((segment_starts[0] // 0x10000) * 0x10000)

    def getBinary(self):
        result = b""
        segment = ida_segment.get_first_seg()
        while segment:
            result += ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
            segment = ida_segment.get_next_seg(segment.end_ea - 1)
        return result

    def getApiMap(self):
        self._api_map = {}
        for module_index in range(ida_nalt.get_import_module_qty()):
            self._import_module_name = ida_nalt.get_import_module_name(module_index)
            ida_nalt.enum_import_names(module_index, self._cbEnumImports)
        return self._api_map

    def isExternalFunction(self, function_offset):
        segment = ida_segment.getseg(function_offset)
        return ida_segment.get_segm_name(segment) in ["extern", "UNDEF"]

    def makeFunction(self, instruction):
        return ida_funcs.add_func(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        if warning_level is None:
            warning_level = idc.SN_NOWARN
        return idc.set_name(address, name, warning_level)

    def getIdbDir(self):
        return idautils.GetIdbDir()

    def _cbEnumImports(self, addr, name, ordinal):
        if self._import_module_name:
            self._api_map[addr] = self._import_module_name + "!" + name
        else:
            self._api_map[addr] = name
        return True


class Ida74Interface(_ModernIdapythonInterface):
    def __init__(self):
        super().__init__()
        self.version = "IDA Pro 7.4 - 8.4"

    def getArchitecture(self):
        info = ida_idaapi.get_inf_structure()
        procname = info.procname if idaapi.IDA_SDK_VERSION >= 800 else info.procName
        if procname == "ARM":
            if self.getBitness() != 64:
                raise ValueError(f"Unsupported Architecture: {procname} ({self.getBitness()}bit)")
            return "aarch64"
        if procname in self._processor_map:
            return self._processor_map[procname]
        raise ValueError("Unsupported Architecture")

    def getBitness(self):
        info = ida_idaapi.get_inf_structure()
        if info.is_64bit():
            return 64
        if info.is_32bit():
            return 32
        return 16


class Ida73Interface(BackendInterface):
    def __init__(self):
        self.version = "IDA Pro 7.3 and below"
        self._processor_map = {"metapc": "intel"}
        self._api_map = {}
        self._import_module_name = ""

    def getArchitecture(self):
        procname = idaapi.get_inf_structure().procName
        if procname == "ARM":
            if self.getBitness() != 64:
                raise ValueError(f"Unsupported Architecture: {procname} ({self.getBitness()}bit)")
            return "aarch64"
        if procname in self._processor_map:
            return self._processor_map[procname]
        raise ValueError("Unsupported Architecture")

    def getBitness(self):
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            return 64
        if info.is_32bit():
            return 32
        return 16

    def getFunctions(self):
        return sorted(idautils.Functions())

    def getBlocks(self, function_offset):
        blocks = []
        function_chart = idaapi.FlowChart(idaapi.get_func(function_offset))
        for block in function_chart:
            extracted_block = []
            for instruction in idautils.Heads(block.startEA, block.endEA):
                if idc.isCode(idc.GetFlags(instruction)):
                    extracted_block.append(instruction)
            if extracted_block:
                blocks.append(extracted_block)
        return sorted(blocks)

    def getInstructionBytes(self, offset):
        instruction = idautils.DecodeInstruction(offset)
        return idc.get_bytes(offset, instruction.size)

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in idautils.CodeRefsTo(offset, True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in idautils.CodeRefsFrom(offset, True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        for function_offset in self.getFunctions():
            function_name = idc.GetFunctionName(function_offset)
            if demangle and "@" in function_name:
                function_name = idc.demangle_name(function_name, 0)
            if not re.match("sub_[0-9a-fA-F]+", function_name):
                function_symbols[function_offset] = function_name
        return function_symbols

    def getBaseAddr(self):
        segment_starts = list(idautils.Segments())
        if not segment_starts:
            return 0
        return int((segment_starts[0] // 0x10000) * 0x10000)

    def getBinary(self):
        result = b""
        for start in idautils.Segments():
            end = idc.SegEnd(start)
            result += idc.get_bytes(start, end - start)
        return result

    def getApiMap(self):
        self._api_map = {}
        for module_index in range(idaapi.get_import_module_qty()):
            self._import_module_name = idaapi.get_import_module_name(module_index)
            idaapi.enum_import_names(module_index, self._cbEnumImports)
        return self._api_map

    def isExternalFunction(self, function_offset):
        return False

    def makeFunction(self, instruction):
        return idc.add_func(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        if warning_level is None:
            warning_level = idc.SN_NOWARN
        return idc.set_name(address, name, warning_level)

    def getIdbDir(self):
        return idautils.GetIdbDir()

    def _cbEnumImports(self, addr, name, ordinal):
        if self._import_module_name:
            self._api_map[addr] = self._import_module_name + "!" + name
        else:
            self._api_map[addr] = name
        return True


class Ida85Interface(_ModernIdapythonInterface):
    def __init__(self):
        super().__init__()
        self.version = "IDA Pro 8.5+"

    def getArchitecture(self):
        procname = idaapi.inf_get_procname()
        if procname == "ARM":
            if self.getBitness() != 64:
                raise ValueError(f"Unsupported Architecture: {procname} ({self.getBitness()}bit)")
            return "aarch64"
        if procname in self._processor_map:
            return self._processor_map[procname]
        raise ValueError("Unsupported Architecture")

    def getBitness(self):
        if idaapi.inf_is_64bit():
            return 64
        if idaapi.inf_is_32bit_exactly():
            return 32
        return 16
