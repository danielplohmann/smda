import datetime

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from smda.DisassemblyResult import DisassemblyResult
from .IdaInterface import IdaInterface

class IdaExporter(object):

    def __init__(self, config, bitness=None):
        self.config = config
        self.ida_interface = IdaInterface()
        self.bitness = bitness if bitness else self.ida_interface.getBitness()
        self.capstone = None
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self._initCapstone()

    def _initCapstone(self):
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        if self.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)

    def _convertIdaInsToSmda(self, offset, instruction_bytes):
        cache = [i for i in self.capstone.disasm_lite(instruction_bytes, offset)]
        if cache:
            i_address, i_size, i_mnemonic, i_op_str = cache[0]
            smda_ins = (i_address, i_size, i_mnemonic, i_op_str, instruction_bytes)
        else:
            # record error and emit placeholder instruction
            bytes_as_hex = "".join(["%02x" % c for c in bytearray(instruction_bytes)])
            print("missing capstone disassembly output at 0x%x (%s)" % (offset, bytes_as_hex))
            self.disassembly.errors[offset] = {
                "type": "capstone disassembly failure",
                "instruction_bytes": bytes_as_hex
            }
            smda_ins = (offset, len(instruction_bytes), "error", "error", bytearray(instruction_bytes))
        return smda_ins

    def analyzeBuffer(self, binary_info, cb_analysis_timeout=None):
        """ instead of performing a full analysis, simply collect all data from IDA and convert it into a report """
        self.disassembly.analysis_start_ts = datetime.datetime.utcnow()
        self.disassembly.binary_info = binary_info
        self.disassembly.binary_info.architecture = self.ida_interface.getArchitecture()
        if not self.disassembly.binary_info.base_addr:
            self.disassembly.binary_info.base_addr = self.ida_interface.getBaseAddr()
        if not self.disassembly.binary_info.binary:
            self.disassembly.binary_info.binary = self.ida_interface.getBinary()
        if not self.disassembly.binary_info.bitness:
            self.disassembly.binary_info.bitness = self.bitness
        self.disassembly.function_symbols = self.ida_interface.getFunctionSymbols()
        api_map = self.ida_interface.getApiMap()
        for function_offset in self.ida_interface.getFunctions():
            if self.ida_interface.isExternalFunction(function_offset):
                continue
            converted_function = []
            for block in self.ida_interface.getBlocks(function_offset):
                converted_block = []
                for instruction_offset in block:
                    instruction_bytes = self.ida_interface.getInstructionBytes(instruction_offset)
                    smda_instruction = self._convertIdaInsToSmda(instruction_offset, instruction_bytes)
                    converted_block.append(smda_instruction)
                    self.disassembly.instructions[smda_instruction[0]] = (smda_instruction[2], smda_instruction[1])
                    in_refs = self.ida_interface.getCodeInRefs(smda_instruction[0])
                    for in_ref in in_refs:
                        self.disassembly.addCodeRefs(in_ref[0], in_ref[1])
                    out_refs = self.ida_interface.getCodeOutRefs(smda_instruction[0])
                    for out_ref in out_refs:
                        self.disassembly.addCodeRefs(out_ref[0], out_ref[1])
                        if out_ref[1] in api_map:
                            self.disassembly.addr_to_api[instruction_offset] = api_map[out_ref[1]]
                converted_function.append(converted_block)
            self.disassembly.functions[function_offset] = converted_function
            if self.disassembly.isRecursiveFunction(function_offset):
                self.disassembly.recursive_functions.add(function_offset)
            if self.disassembly.isLeafFunction(function_offset):
                self.disassembly.leaf_functions.add(function_offset)
        self.disassembly.analysis_end_ts = datetime.datetime.utcnow()
        return self.disassembly
