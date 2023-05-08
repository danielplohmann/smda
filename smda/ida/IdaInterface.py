import re

from .BackendInterface import BackendInterface

try:
    import idaapi
    import idautils
except:
    pass

try:
    # we only need these when we are in IDA - IDA 7.4 and above
    import ida_idaapi
    import ida_funcs
    import ida_gdl
    import ida_bytes
    import ida_nalt
    import ida_segment
    import ida_name
except:
    pass

try:
    # we only need these when we are in IDA - IDA 7.3 and below
    import idc
except:
    pass


class IdaInterface(object):
    # derived from https://python-3-patterns-idioms-test.readthedocs.io/en/latest/Singleton.html
    instance = None
    def __init__(self):
        if not IdaInterface.instance:
            if idaapi.IDA_SDK_VERSION >= 740:
                IdaInterface.instance = Ida74Interface()
            else:
                IdaInterface.instance = Ida73Interface()

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def getIdbDir(self):
        return idautils.GetIdbDir()


class Ida74Interface(BackendInterface):

    def __init__(self):
        self.version = "IDA Pro 7.4"
        self._processor_map = {
            "metapc": "intel"
        }
        self._api_map = {}
        self._import_module_name = ""

    def getArchitecture(self):
        # https://reverseengineering.stackexchange.com/a/11398
        info = ida_idaapi.get_inf_structure()
        if idaapi.IDA_SDK_VERSION >= 800:
            procname = info.procname
        else:
            procname = info.procName
        if procname in self._processor_map:
            return self._processor_map[procname]
        else:
            raise ValueError("Unsupported Architecture")

    def getBitness(self):
        # https://reverseengineering.stackexchange.com/a/11398
        bits = None
        info = ida_idaapi.get_inf_structure()
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16
        return bits

    def getFunctions(self):
        return sorted([offset for offset in idautils.Functions()])

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
        ins = idautils.DecodeInstruction(offset)
        ins_bytes = ida_bytes.get_bytes(offset, ins.size)
        return ins_bytes

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in idautils.CodeRefsTo(offset, True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in idautils.CodeRefsFrom(offset, True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        function_offsets = self.getFunctions()
        for function_offset in function_offsets:
            function_name = ida_funcs.get_func_name(function_offset)
            # apply demangling if required
            if demangle and "@" in function_name:
                demangled = ida_name.demangle_name(function_name, 0)
                if demangled:
                    function_name = demangled
            if not re.match("sub_[0-9a-fA-F]+", function_name):
                function_symbols[function_offset] = function_name
        return function_symbols

    def getBaseAddr(self):
        base_addr = 0
        segment_starts = [ea for ea in idautils.Segments()]
        if segment_starts:
            first_segment_start = segment_starts[0]
            # re-align by 0x10000 to reflect typically allocation behaviour for IDA-mapped binaries
            first_segment_start = (first_segment_start / 0x10000) * 0x10000
            base_addr = int(first_segment_start)
        return base_addr

    def getBinary(self):
        result = b""
        segment = ida_segment.get_first_seg()
        while segment:
            result += ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
            segment = ida_segment.get_next_seg(segment.end_ea)
        return result

    def getApiMap(self):
        self._api_map = {}
        num_imports = ida_nalt.get_import_module_qty()
        for i in range(0, num_imports):
            self._import_module_name = ida_nalt.get_import_module_name(i)
            ida_nalt.enum_import_names(i, self._cbEnumImports)
        return self._api_map

    def isExternalFunction(self, function_offset):
        function_segment = ida_segment.getseg(function_offset)
        function_segment_name = ida_segment.get_segm_name(function_segment)
        is_extern = function_segment_name in ["extern", "UNDEF"]
        return is_extern

    def makeFunction(self, instruction):
        return ida_funcs.add_func(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        if warning_level is None:
            warning_level=idc.SN_NOWARN
        return idc.set_name(address, name, warning_level)

    def _cbEnumImports(self, addr, name, ordinal):
        # potentially use: idc.Name(addr)
        if self._import_module_name:
            self._api_map[addr] = self._import_module_name + "!" + name
        else:
            self._api_map[addr] = name
        return True



class Ida73Interface(BackendInterface):

    def __init__(self):
        self.version = "IDA Pro 7.3 and below"
        self._processor_map = {
            "metapc": "intel"
        }
        self._api_map = {}
        self._import_module_name = ""

    def getArchitecture(self):
        # https://reverseengineering.stackexchange.com/a/11398
        info = idaapi.get_inf_structure()
        procname = info.procName
        if procname in self._processor_map:
            return self._processor_map[procname]
        else:
            raise ValueError("Unsupported Architecture")

    def getBitness(self):
        # https://reverseengineering.stackexchange.com/a/11398
        bits = None
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16
        return bits

    def getFunctions(self):
        return sorted([offset for offset in idautils.Functions()])

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
        ins = idautils.DecodeInstruction(offset)
        ins_bytes = idc.get_bytes(offset, ins.size)
        return ins_bytes

    def getCodeInRefs(self, offset):
        return [(ref_from, offset) for ref_from in idautils.CodeRefsTo(offset, True)]

    def getCodeOutRefs(self, offset):
        return [(offset, ref_to) for ref_to in idautils.CodeRefsFrom(offset, True)]

    def getFunctionSymbols(self, demangle=False):
        function_symbols = {}
        function_offsets = self.getFunctions()
        for function_offset in function_offsets:
            function_name = idc.GetFunctionName(function_offset)
            # apply demangling if required
            if demangle and "@" in function_name:
                function_name = idc.demangle_name(function_name, 0)
            if not re.match("sub_[0-9a-fA-F]+", function_name):
                function_symbols[function_offset] = function_name
        return function_symbols

    def getBaseAddr(self):
        segment_starts = [ea for ea in idautils.Segments()]
        first_segment_start = segment_starts[0]
        # re-align by 0x10000 to reflect typically allocation behaviour for IDA-mapped binaries
        first_segment_start = (first_segment_start / 0x10000) * 0x10000
        return int(first_segment_start)

    def getBinary(self):
        result = b""
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.SegEnd(start)
            result += idc.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result

    def getApiMap(self):
        self._api_map = {}
        num_imports = idaapi.get_import_module_qty()
        for i in range(0, num_imports):
            self._import_module_name = idaapi.get_import_module_name(i)
            idaapi.enum_import_names(i, self._cbEnumImports)
        return self._api_map

    def isExternalFunction(self, function_offset):
        # TODO look up older function names to support this for IDA 7.3- as well
        return False

    def makeFunction(self, instruction):
        return idc.add_func(instruction)

    def makeNameEx(self, address, name, warning_level=None):
        if warning_level is None:
            warning_level=idc.SN_NOWARN
        return idc.set_name(address, name, warning_level)

    def _cbEnumImports(self, addr, name, ordinal):
        # potentially use: idc.Name(addr)
        if self._import_module_name:
            self._api_map[addr] = self._import_module_name + "!" + name
        else:
            self._api_map[addr] = name
        return True
