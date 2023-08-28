import datetime
import struct
import sys

from smda.common.BasicBlock import BasicBlock


class DisassemblyResult(object):

    def __init__(self):
        self.analysis_start_ts = datetime.datetime.utcnow()
        self.analysis_end_ts = self.analysis_start_ts
        self.analysis_timeout = False
        self.binary_info = None
        self.identified_alignment = 0
        self.oep = None
        self.code_map = {}
        self.data_map = set([])
        # key: offset, value: {"type": <str>, "instruction_bytes": <hexstr>}
        self.errors = {}
        # stored as key:
        self.functions = {}
        self.recursive_functions = set([])
        self.leaf_functions = set([])
        self.thunk_functions = set([])
        self.exported_functions = set([])
        self.failed_analysis_addr = []
        self.function_borders = {}
        # stored as key: int(i.address) = (i.size, i.mnemonic, i.op_str)
        self.instructions = {}
        self.ins2fn = {}
        self.language = {}
        self.data_refs_from = {}
        self.data_refs_to = {}
        self.code_refs_from = {}
        self.code_refs_to = {}
        # key: address of API in target DLL, value: {referencing_addr, api_name, dll_name}
        self.apis = {}
        self.addr_to_api = {}
        # address:name
        self.function_symbols = {}
        self.candidates = {}
        self._confidence_threshold = 0.0
        self.code_areas = []
        self.smda_version = ""

    def setBinaryInfo(self, binary_info):
        self.binary_info = binary_info
        exported = binary_info.getExportedFunctions()
        if exported is not None:
            self.exported_functions = set([key + binary_info.base_addr for key in exported.keys()])
        self.oep = binary_info.getOep()

    def getByte(self, addr):
        if self.isAddrWithinMemoryImage(addr):
            return self.binary_info.binary[addr - self.binary_info.base_addr]
        return None

    def getRawByte(self, offset):
        return self.binary_info.binary[offset]

    def getBytes(self, addr, num_bytes):
        if self.isAddrWithinMemoryImage(addr):
            rel_start_addr = addr - self.binary_info.base_addr
            return self.binary_info.binary[rel_start_addr:rel_start_addr + num_bytes]
        return None

    def getRawBytes(self, offset, num_bytes):
        return self.binary_info.binary[offset:offset + num_bytes]

    def setConfidenceThreshold(self, threshold):
        self._confidence_threshold = threshold

    def getConfidenceThreshold(self):
        return self._confidence_threshold

    def getAnalysisDuration(self):
        return (self.analysis_end_ts - self.analysis_start_ts).seconds + ((self.analysis_end_ts - self.analysis_start_ts).microseconds / 1000000.0)

    def getAnalysisOutcome(self):
        outcome = "ok"
        if self.analysis_timeout:
            outcome = "timeout"
        return outcome

    def getFunctions(self):
        return sorted(self.functions.keys())

    def getBlocks(self, function_addr):
        disasm_blocks = []
        if function_addr in self.functions:
            disasm_blocks = self.functions[function_addr]
        bblocks = []

        for block in disasm_blocks:
            bblock = BasicBlock()
            bblock.start_addr = block[0][0]
            bblock.end_addr = block[-1][0]
            bblock.instructions = [ins[0] for ins in block]
            if bblock.end_addr in self.code_refs_from:
                bblock.successors = [ref for ref in self.code_refs_from[bblock.end_addr]]
            bblocks.append(bblock)
        return bblocks

    def _transformInstruction(self, ins_tuple):
        ins_addr, _, ins_mnem, ins_ops, ins_raw_bytes = ins_tuple
        # python3  and python2 do handling differently...
        if sys.version_info >= (3, 0):
            ins_hexbytes = "".join(["%02x" % c for c in ins_tuple[4]])
        else:
            ins_hexbytes = ins_raw_bytes.encode("hex")
        return [ins_addr, ins_hexbytes, str(ins_mnem), str(ins_ops)]

    def getBlocksAsDict(self, function_addr):
        blocks = {}
        for block in self.functions[function_addr]:
            instructions = []
            for ins in block:
                instructions.append(self._transformInstruction(ins))
            blocks[instructions[0][0]] = instructions
        return blocks

    def getInstructions(self, block):
        return block.instructions

    def getMnemonic(self, instruction_addr):
        if instruction_addr in self.instructions:
            return self.instructions[instruction_addr][0]
        return ""

    def isCode(self, addr):
        return addr in self.code_map

    def isAddrWithinMemoryImage(self, destination):
        if destination is not None:
            return self.binary_info.base_addr <= destination < (self.binary_info.base_addr + self.binary_info.binary_size)
        return False

    def dereferenceDword(self, addr):
        if self.isAddrWithinMemoryImage(addr):
            rel_start_addr = addr - self.binary_info.base_addr
            rel_end_addr = rel_start_addr + 4
            extracted_dword = self.binary_info.binary[rel_start_addr:rel_end_addr]
            if len(extracted_dword) < 4:
                return None
            return struct.unpack("I", extracted_dword)[0]
        return None

    def dereferenceQword(self, addr):
        if self.isAddrWithinMemoryImage(addr):
            rel_start_addr = addr - self.binary_info.base_addr
            rel_end_addr = rel_start_addr + 8
            extracted_qword = self.binary_info.binary[rel_start_addr:rel_end_addr]
            if len(extracted_qword) < 8:
                return None
            return struct.unpack("Q", extracted_qword)[0]
        return None

    def addCodeRefs(self, addr_from, addr_to):
        refs_from = self.code_refs_from.get(addr_from, set([]))
        refs_from.update([addr_to])
        self.code_refs_from[addr_from] = refs_from
        refs_to = self.code_refs_to.get(addr_to, set([]))
        refs_to.update([addr_from])
        self.code_refs_to[addr_to] = refs_to

    def removeCodeRefs(self, addr_from, addr_to):
        refs_from = self.code_refs_from.get(addr_from, set([]))
        refs_from.discard(addr_to)
        self.code_refs_from[addr_from] = refs_from
        refs_to = self.code_refs_to.get(addr_to, set([]))
        refs_to.discard(addr_from)
        self.code_refs_to[addr_to] = refs_to

    def addDataRefs(self, addr_from, addr_to):
        refs_from = self.data_refs_from.get(addr_from, set([]))
        refs_from.update([addr_to])
        self.data_refs_from[addr_from] = refs_from
        refs_to = self.data_refs_to.get(addr_to, set([]))
        refs_to.update([addr_from])
        self.data_refs_to[addr_to] = refs_to

    def removeDataRefs(self, addr_from, addr_to):
        refs_from = self.data_refs_from.get(addr_from, set([]))
        refs_from.discard(addr_to)
        self.data_refs_from[addr_from] = refs_from
        refs_to = self.data_refs_to.get(addr_to, set([]))
        refs_to.discard(addr_from)
        self.data_refs_to[addr_to] = refs_to

    def getBlockRefs(self, func_addr):
        """ blocks refs should stay within function context, thus kill all references outside function """
        block_refs = {}
        ins_addrs = set([])
        for block in self.functions[func_addr]:
            for ins in block:
                ins_addr = ins[0]
                ins_addrs.add(ins_addr)
        for block in self.functions[func_addr]:
            last_ins_addr = block[-1][0]
            if last_ins_addr in self.code_refs_from:
                verified_refs = sorted(list(ins_addrs.intersection(self.code_refs_from[last_ins_addr])))
                if verified_refs:
                    block_refs[block[0][0]] = verified_refs
        return block_refs

    def getInRefs(self, func_addr):
        in_refs = []
        if func_addr in self.code_refs_to:
            in_refs = list(self.code_refs_to[func_addr])
        return sorted(in_refs)

    def getOutRefs(self, func_addr):
        ins_addrs = set([])
        code_refs = []
        out_refs = {}
        for block in self.functions[func_addr]:
            for ins in block:
                ins_addr = ins[0]
                ins_addrs.add(ins_addr)
                if ins_addr in self.code_refs_from:
                    for to_addr in self.code_refs_from[ins_addr]:
                        code_refs.append([ins_addr, to_addr])
        # function may be recursive
        if func_addr in ins_addrs:
            ins_addrs.remove(func_addr)
        # reduce outrefs to addresses within the memory image
        max_addr = self.binary_info.base_addr + self.binary_info.binary_size
        image_refs = [ref for ref in code_refs if self.binary_info.base_addr <= ref[1] <= max_addr]
        for ref in image_refs:
            if ref[1] in ins_addrs:
                continue
            if ref[0] not in out_refs:
                out_refs[ref[0]] = []
            out_refs[ref[0]].append(ref[1])
        return {src: sorted(dst) for src, dst in out_refs.items()}

    def isRecursiveFunction(self, func_addr):
        ins_addrs = set([])
        out_refs = set([])
        for block in self.functions[func_addr]:
            for ins in block:
                ins_addr = ins[0]
                ins_addrs.add(ins_addr)
                if ins_addr in self.code_refs_from:
                    for to_addr in self.code_refs_from[ins_addr]:
                        out_refs.add(to_addr)
        return func_addr in out_refs

    def isLeafFunction(self, func_addr):
        ins_addrs = set([])
        out_refs = set([])
        for block in self.functions[func_addr]:
            for ins in block:
                ins_addr = ins[0]
                ins_addrs.add(ins_addr)
                if ins_addr in self.code_refs_from:
                    for to_addr in self.code_refs_from[ins_addr]:
                        out_refs.add(to_addr)
        return len(out_refs.difference(ins_addrs)) == 0

    def _initApiRefs(self):
        for api_offset in self.apis:
            api = self.apis[api_offset]
            for ref in api["referencing_addr"]:
                self.addr_to_api[ref] = "%s!%s" % (api["dll_name"], api["api_name"])

    def getAllApiRefs(self):
        all_api_refs = {}
        for function_addr in self.functions:
            all_api_refs.update(self.getApiRefs(function_addr))
        return all_api_refs

    def getApiRefs(self, func_addr):
        if not self.addr_to_api:
            self._initApiRefs()
        api_refs = {}
        for block in self.functions[func_addr]:
            for ins in block:
                if ins[0] in self.addr_to_api:
                    api_refs[ins[0]] = self.addr_to_api[ins[0]]
        return api_refs

    def __str__(self):
        return "-> {:5.2f}s | {:5d} Func (status: {})".format(self.getAnalysisDuration(), len(self.functions), self.getAnalysisOutcome())
