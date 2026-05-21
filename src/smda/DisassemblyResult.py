import datetime
import struct

from smda.common.BasicBlock import BasicBlock


class DisassemblyResult:
    def __init__(self):
        self.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        self.analysis_end_ts = self.analysis_start_ts
        self.analysis_timeout = False
        self.binary_info = None
        self.identified_alignment = 0
        self.oep = None
        self.code_map = {}
        self.data_map = set()
        # key: offset, value: {"type": <str>, "instruction_bytes": <hexstr>}
        self.errors = {}
        # stored as key:
        self.functions = {}
        self.recursive_functions = set()
        self.leaf_functions = set()
        self.thunk_functions = set()
        self.exported_functions = set()
        self.failed_analysis_addr = []
        self.function_borders = {}
        self.function_metadata = {}
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
        # address:string
        self.stringrefs = {}
        self.candidates = {}
        self._confidence_threshold = 0.0
        self.code_areas = []
        self.smda_version = ""

    def setBinaryInfo(self, binary_info):
        self.binary_info = binary_info
        exported = binary_info.getExportedFunctions()
        if exported is not None:
            self.exported_functions = {key + binary_info.base_addr for key in exported}
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
            return self.binary_info.binary[rel_start_addr : rel_start_addr + num_bytes]
        return None

    def getRawBytes(self, offset, num_bytes):
        return self.binary_info.binary[offset : offset + num_bytes]

    def setConfidenceThreshold(self, threshold):
        self._confidence_threshold = threshold

    def getConfidenceThreshold(self):
        return self._confidence_threshold

    def getAnalysisDuration(self):
        return (self.analysis_end_ts - self.analysis_start_ts).seconds + (
            (self.analysis_end_ts - self.analysis_start_ts).microseconds / 1000000.0
        )

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
                bblock.successors = list(self.code_refs_from[bblock.end_addr])
            bblocks.append(bblock)
        return bblocks

    def _transformInstruction(self, ins_tuple):
        ins_addr, _, ins_mnem, ins_ops, ins_raw_bytes = ins_tuple
        # python3  and python2 do handling differently...
        ins_hexbytes = "".join([f"{c:02x}" for c in ins_tuple[4]])
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

    def _getContainingBlockStart(self, blocks, instruction_addr):
        for block in blocks:
            if not block:
                continue
            block_start = block[0][0]
            block_end = block[-1][0] + block[-1][1]
            if block_start <= instruction_addr < block_end:
                return block_start
        return None

    def _getExceptionSuccessors(self, func_addr, blocks):
        metadata = self.function_metadata.get(func_addr, {})
        try_ranges = metadata.get("try_ranges", [])
        if not try_ranges:
            return {}
        block_successors = {}
        for try_range in try_ranges:
            raw_targets = []
            for handler in try_range.get("handlers", []):
                target_addr = handler.get("target_addr") if isinstance(handler, dict) else None
                if target_addr is not None:
                    raw_targets.append(target_addr)
            if try_range.get("catch_all_addr") is not None:
                raw_targets.append(try_range["catch_all_addr"])
            if not raw_targets:
                continue
            normalized_targets = set()
            for target_addr in raw_targets:
                block_start = self._getContainingBlockStart(blocks, target_addr)
                if block_start is None:
                    block_start = target_addr
                normalized_targets.add(block_start)
            for block in blocks:
                if not block:
                    continue
                block_start = block[0][0]
                block_end = block[-1][0] + block[-1][1]
                if try_range["start_addr"] < block_end and block_start < try_range["end_addr"]:
                    successors = block_successors.get(block_start, set())
                    successors.update(normalized_targets)
                    block_successors[block_start] = successors
        return block_successors

    def isCode(self, addr):
        return addr in self.code_map

    def isAddrWithinMemoryImage(self, destination):
        if destination is not None:
            return (
                self.binary_info.base_addr <= destination < (self.binary_info.base_addr + self.binary_info.binary_size)
            )
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
        refs_from = self.code_refs_from.get(addr_from, set())
        refs_from.update([addr_to])
        self.code_refs_from[addr_from] = refs_from
        refs_to = self.code_refs_to.get(addr_to, set())
        refs_to.update([addr_from])
        self.code_refs_to[addr_to] = refs_to

    def removeCodeRefs(self, addr_from, addr_to):
        refs_from = self.code_refs_from.get(addr_from, set())
        refs_from.discard(addr_to)
        self.code_refs_from[addr_from] = refs_from
        refs_to = self.code_refs_to.get(addr_to, set())
        refs_to.discard(addr_from)
        self.code_refs_to[addr_to] = refs_to

    def addDataRefs(self, addr_from, addr_to):
        refs_from = self.data_refs_from.get(addr_from, set())
        refs_from.update([addr_to])
        self.data_refs_from[addr_from] = refs_from
        refs_to = self.data_refs_to.get(addr_to, set())
        refs_to.update([addr_from])
        self.data_refs_to[addr_to] = refs_to

    def removeDataRefs(self, addr_from, addr_to):
        refs_from = self.data_refs_from.get(addr_from, set())
        refs_from.discard(addr_to)
        self.data_refs_from[addr_from] = refs_from
        refs_to = self.data_refs_to.get(addr_to, set())
        refs_to.discard(addr_from)
        self.data_refs_to[addr_to] = refs_to

    def getBlockRefs(self, func_addr):
        """Return a normalized intra-function CFG keyed by block start."""
        if func_addr not in self.functions:
            return {}
        blocks = [block for block in self.functions[func_addr] if block]
        block_starts = {block[0][0] for block in blocks}
        block_refs = {block_start: [] for block_start in sorted(block_starts)}
        for block in blocks:
            last_ins_addr = block[-1][0]
            if last_ins_addr not in self.code_refs_from:
                continue
            verified_refs = sorted(block_starts.intersection(self.code_refs_from[last_ins_addr]))
            if verified_refs:
                block_refs[block[0][0]] = verified_refs
        for block_start, successors in self._getExceptionSuccessors(func_addr, blocks).items():
            merged_successors = set(block_refs.get(block_start, []))
            merged_successors.update(successors)
            block_refs[block_start] = sorted(merged_successors)
            for successor in successors:
                block_refs.setdefault(successor, [])
        return {block_start: block_refs[block_start] for block_start in sorted(block_refs)}

    def getInRefs(self, func_addr):
        in_refs = []
        if func_addr in self.code_refs_to:
            in_refs = list(self.code_refs_to[func_addr])
        return sorted(in_refs)

    def getOutRefs(self, func_addr):
        ins_addrs = set()
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
        ins_addrs = set()
        out_refs = set()
        for block in self.functions[func_addr]:
            for ins in block:
                ins_addr = ins[0]
                ins_addrs.add(ins_addr)
                if ins_addr in self.code_refs_from:
                    for to_addr in self.code_refs_from[ins_addr]:
                        out_refs.add(to_addr)
        return func_addr in out_refs

    def isLeafFunction(self, func_addr):
        ins_addrs = set()
        out_refs = set()
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
                self.addr_to_api[ref] = "{}!{}".format(api["dll_name"], api["api_name"])

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

    def addStringRef(self, func_addr, ref_addr, string):
        if func_addr not in self.stringrefs:
            self.stringrefs[func_addr] = {}
        self.stringrefs[func_addr][ref_addr] = string

    def getStringRefsForFunction(self, func_addr):
        # addr with ref: str
        if func_addr in self.stringrefs:
            return self.stringrefs[func_addr]
        return {}

    def __str__(self):
        return f"-> {self.getAnalysisDuration():5.2f}s | {len(self.functions):5d} Func (status: {self.getAnalysisOutcome()})"
