import datetime

from smda.common.BasicBlock import BasicBlock


class DisassemblyResult(object):

    def __init__(self, bitness=32):
        self.analysis_start_ts = datetime.datetime.utcnow()
        self.analysis_end_ts = self.analysis_start_ts
        self.analysis_timeout = False
        self.binary = ""
        self.bitness = bitness
        self.code_map = {}
        self.data_map = set([])
        # stored as key:
        self.functions = {}
        self.recursive_functions = set([])
        self.leaf_functions = set([])
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
        self.base_addr = 0
        # address:name
        self.function_symbols = {}

    def getAnalysisDuration(self):
        return (self.analysis_end_ts - self.analysis_start_ts).seconds + (self.analysis_end_ts - self.analysis_start_ts).microseconds / 1000000

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

    def getInstructions(self, block):
        return block.instructions

    def getMnemonic(self, instruction_addr):
        if instruction_addr in self.instructions:
            return self.instructions[instruction_addr][0]
        return ""

    def collectCfg(self):
        function_results = {}
        for function_offset in sorted(self.functions):
            blocks = {}
            for block in self.functions[function_offset]:
                instructions = []
                for ins in block:
                    instructions.append([ins[0], "".join(["%02x" % c for c in ins[4]]), str(ins[2]), str(ins[3])])
                blocks[instructions[0][0]] = instructions
            function_doc = {
                "offset": function_offset,
                "inrefs": self.getInRefs(function_offset),
                "outrefs": self.getOutRefs(function_offset),
                "blockrefs": self.getBlockRefs(function_offset),
                "apirefs": self.getApiRefs(function_offset),
                "label": self.function_symbols.get(function_offset, ""),
                "blocks": blocks
            }
            function_results[function_offset] = function_doc
        return function_results

    def isCode(self, addr):
        return addr in self.code_map

    def isAddrWithinMemoryImage(self, destination):
        return destination > self.base_addr and destination < (self.base_addr + len(self.binary))

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
        block_refs = {}
        for block in self.functions[func_addr]:
            last_ins_addr = block[-1][0]
            if last_ins_addr in self.code_refs_from:
                block_refs[block[0][0]] = sorted(list(self.code_refs_from[last_ins_addr]))
        return block_refs

    def getInRefs(self, func_addr):
        in_refs = []
        if func_addr in self.code_refs_to:
            in_refs = list(self.code_refs_to[func_addr])
        return in_refs

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
        ins_addrs.remove(func_addr)
        # reduce outrefs to addresses within the memory image
        max_addr = self.base_addr + len(self.binary)
        image_refs = [ref for ref in code_refs if self.base_addr <= ref[1] <= max_addr]
        for ref in image_refs:
            if ref[1] in ins_addrs:
                continue
            if ref[0] not in out_refs:
                out_refs[ref[0]] = []
            out_refs[ref[0]].append(ref[1])
        out_refs = [ref for ref in image_refs if ref[1] not in ins_addrs]
        return out_refs

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
