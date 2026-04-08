import datetime
import logging

import lief

from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState
from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)

# Basic lookup table for Dalvik opcodes.
# This covers simple CFG branching and method calls.
DALVIK_OPCODES = {
    0x00: ("nop", 1),
    0x01: ("move", 1),
    0x02: ("move/from16", 2),
    0x03: ("move/16", 3),
    0x04: ("move-wide", 1),
    0x05: ("move-wide/from16", 2),
    0x06: ("move-wide/16", 3),
    0x07: ("move-object", 1),
    0x08: ("move-object/from16", 2),
    0x09: ("move-object/16", 3),
    0x0A: ("move-result", 1),
    0x0B: ("move-result-wide", 1),
    0x0C: ("move-result-object", 1),
    0x0D: ("move-exception", 1),
    0x0E: ("return-void", 1),
    0x0F: ("return", 1),
    0x10: ("return-wide", 1),
    0x11: ("return-object", 1),
    0x12: ("const/4", 1),
    0x13: ("const/16", 2),
    0x14: ("const", 3),
    0x15: ("const/high16", 2),
    0x16: ("const-wide/16", 2),
    0x17: ("const-wide/32", 3),
    0x18: ("const-wide", 5),
    0x19: ("const-wide/high16", 2),
    0x1A: ("const-string", 2),
    0x1B: ("const-string/jumbo", 3),
    0x1C: ("const-class", 2),
    0x1D: ("monitor-enter", 1),
    0x1E: ("monitor-exit", 1),
    0x1F: ("check-cast", 2),
    0x20: ("instance-of", 2),
    0x21: ("array-length", 1),
    0x22: ("new-instance", 2),
    0x23: ("new-array", 2),
    0x24: ("filled-new-array", 3),
    0x25: ("filled-new-array/range", 3),
    0x26: ("fill-array-data", 3),
    0x27: ("throw", 1),
    0x28: ("goto", 1),
    0x29: ("goto/16", 2),
    0x2A: ("goto/32", 3),
    0x2B: ("packed-switch", 3),
    0x2C: ("sparse-switch", 3),
    0x2D: ("cmpl-float", 2),
    0x2E: ("cmpg-float", 2),
    0x2F: ("cmpl-double", 2),
    0x30: ("cmpg-double", 2),
    0x31: ("cmp-long", 2),
    0x32: ("if-eq", 2),
    0x33: ("if-ne", 2),
    0x34: ("if-lt", 2),
    0x35: ("if-ge", 2),
    0x36: ("if-gt", 2),
    0x37: ("if-le", 2),
    0x38: ("if-eqz", 2),
    0x39: ("if-nez", 2),
    0x3A: ("if-ltz", 2),
    0x3B: ("if-gez", 2),
    0x3C: ("if-gtz", 2),
    0x3D: ("if-lez", 2),
    0x6E: ("invoke-virtual", 3),
    0x6F: ("invoke-super", 3),
    0x70: ("invoke-direct", 3),
    0x71: ("invoke-static", 3),
    0x72: ("invoke-interface", 3),
    0x74: ("invoke-virtual/range", 3),
    0x75: ("invoke-super/range", 3),
    0x76: ("invoke-direct/range", 3),
    0x77: ("invoke-static/range", 3),
    0x78: ("invoke-interface/range", 3),
}

# The size is in 16-bit code units.


class DalvikDisassembler:
    def __init__(self, config):
        self.config = config
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION

    def analyzeFunction(self, dex_file, method_info):
        start_addr = method_info["offset"]
        code_item = method_info["code_item"]

        # In DEX, the code_item header is 16 bytes. The bytecode immediately follows.
        insns_size_units = code_item.insns_size
        insns_size_bytes = insns_size_units * 2
        bytecode_offset = start_addr + 16

        raw_data = method_info["raw_data"]

        if bytecode_offset + insns_size_bytes > len(raw_data):
            LOGGER.warning(
                "Bytecode range [0x%x:0x%x] exceeds raw data size (0x%x), skipping method.",
                bytecode_offset,
                bytecode_offset + insns_size_bytes,
                len(raw_data),
            )
            return None

        bytecode = raw_data[bytecode_offset : bytecode_offset + insns_size_bytes]

        state = DalvikFunctionAnalysisState(start_addr, self.disassembly)

        idx = 0
        while idx < len(bytecode):
            # A simple loop to read dalvik bytecode. LIEF returns list of bytes.
            op = bytecode[idx]

            if op not in DALVIK_OPCODES:
                LOGGER.warning(
                    "Unknown Dalvik opcode 0x%02x at offset 0x%x, aborting method disassembly.",
                    op,
                    start_addr + idx,
                )
                break
            mnemonic, length_units = DALVIK_OPCODES[op]
            length_bytes = length_units * 2

            if idx + length_bytes > len(bytecode):
                length_bytes = len(bytecode) - idx

            i_bytes = bytes(bytecode[idx : idx + length_bytes])
            i_address = start_addr + idx
            i_size = length_bytes
            i_mnemonic = mnemonic
            i_op_str = ""

            state.setNextInstructionReachable(True)

            # Simple CFG handling
            if i_mnemonic in ["return-void", "return", "return-wide", "return-object", "throw"]:
                state.setNextInstructionReachable(False)
            elif i_mnemonic.startswith("goto"):
                target_offset = 0
                if i_mnemonic == "goto":
                    target_offset = int.from_bytes(i_bytes[1:2], byteorder="little", signed=True) * 2
                elif i_mnemonic == "goto/16":
                    target_offset = int.from_bytes(i_bytes[2:4], byteorder="little", signed=True) * 2
                elif i_mnemonic == "goto/32":
                    target_offset = int.from_bytes(i_bytes[2:6], byteorder="little", signed=True) * 2
                target_address = i_address + target_offset
                state.addCodeRef(i_address, target_address, by_jump=True)
                i_op_str = hex(target_address)
                state.setNextInstructionReachable(False)
            elif i_mnemonic.startswith("if-"):
                target_offset = int.from_bytes(i_bytes[2:4], byteorder="little", signed=True) * 2
                target_address = i_address + target_offset
                state.addCodeRef(i_address, target_address, by_jump=True)
                i_op_str = hex(target_address)
            elif i_mnemonic.startswith("invoke-"):
                method_idx = int.from_bytes(i_bytes[2:4], byteorder="little")
                try:
                    target_method = dex_file.methods[method_idx]
                    i_op_str = target_method.name
                    # Also we can update API information if we want.
                except Exception:
                    i_op_str = f"method_idx_{method_idx}"

            state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
            idx += length_bytes

        state.label = method_info["name"]
        state.finalizeAnalysis()
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug(
            "Analyzing buffer with %d bytes @0x%08x",
            binary_info.binary_size,
            binary_info.base_addr,
        )
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "dalvik"
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        self.disassembly.language = "dalvik"

        # Try raw bytes first, then fallback to list
        try:
            dex_file = lief.DEX.parse(binary_info.raw_data)
        except TypeError:
            dex_file = lief.DEX.parse(list(binary_info.raw_data))

        if dex_file:
            for method in dex_file.methods:
                if not method.has_class:
                    continue
                code_info = method.code_info
                if not code_info:
                    continue
                # method.code_offset gets us an offset but if LIEF returns something we can map:
                # since DEX doesn't map directly, we use code_offset as address

                method_info = {
                    "offset": method.code_offset,
                    "name": f"{method.cls.fullname}->{method.name}",
                    "code_item": code_info,
                    "raw_data": binary_info.raw_data,
                }
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    break
                self.analyzeFunction(dex_file, method_info)

        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
