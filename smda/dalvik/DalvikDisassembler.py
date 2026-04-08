import contextlib
import datetime
import logging
import struct

import lief

from smda.dalvik.DalvikFunctionAnalysisState import DalvikFunctionAnalysisState
from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)

# Complete lookup table for Dalvik opcodes per the Android Dalvik bytecode specification.
# Each entry maps opcode -> (mnemonic, size_in_16bit_code_units).
# Reference: https://source.android.com/docs/core/runtime/dalvik-bytecode
DALVIK_OPCODES = {
    # Moves and misc (0x00-0x0D)
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
    # Returns (0x0E-0x11)
    0x0E: ("return-void", 1),
    0x0F: ("return", 1),
    0x10: ("return-wide", 1),
    0x11: ("return-object", 1),
    # Constants (0x12-0x1C)
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
    # Monitor and type checks (0x1D-0x23)
    0x1D: ("monitor-enter", 1),
    0x1E: ("monitor-exit", 1),
    0x1F: ("check-cast", 2),
    0x20: ("instance-of", 2),
    0x21: ("array-length", 1),
    0x22: ("new-instance", 2),
    0x23: ("new-array", 2),
    # Filled arrays (0x24-0x26)
    0x24: ("filled-new-array", 3),
    0x25: ("filled-new-array/range", 3),
    0x26: ("fill-array-data", 3),
    # Throw (0x27)
    0x27: ("throw", 1),
    # Gotos (0x28-0x2A)
    0x28: ("goto", 1),
    0x29: ("goto/16", 2),
    0x2A: ("goto/32", 3),
    # Switches (0x2B-0x2C)
    0x2B: ("packed-switch", 3),
    0x2C: ("sparse-switch", 3),
    # Comparisons (0x2D-0x31)
    0x2D: ("cmpl-float", 2),
    0x2E: ("cmpg-float", 2),
    0x2F: ("cmpl-double", 2),
    0x30: ("cmpg-double", 2),
    0x31: ("cmp-long", 2),
    # If-test two registers (0x32-0x37)
    0x32: ("if-eq", 2),
    0x33: ("if-ne", 2),
    0x34: ("if-lt", 2),
    0x35: ("if-ge", 2),
    0x36: ("if-gt", 2),
    0x37: ("if-le", 2),
    # If-testz single register (0x38-0x3D)
    0x38: ("if-eqz", 2),
    0x39: ("if-nez", 2),
    0x3A: ("if-ltz", 2),
    0x3B: ("if-gez", 2),
    0x3C: ("if-gtz", 2),
    0x3D: ("if-lez", 2),
    # (0x3E-0x43 are unused)
    # Array operations (0x44-0x51) - format 23x, 2 code units
    0x44: ("aget", 2),
    0x45: ("aget-wide", 2),
    0x46: ("aget-object", 2),
    0x47: ("aget-boolean", 2),
    0x48: ("aget-byte", 2),
    0x49: ("aget-char", 2),
    0x4A: ("aget-short", 2),
    0x4B: ("aput", 2),
    0x4C: ("aput-wide", 2),
    0x4D: ("aput-object", 2),
    0x4E: ("aput-boolean", 2),
    0x4F: ("aput-byte", 2),
    0x50: ("aput-char", 2),
    0x51: ("aput-short", 2),
    # Instance field operations (0x52-0x5F) - format 22c, 2 code units
    0x52: ("iget", 2),
    0x53: ("iget-wide", 2),
    0x54: ("iget-object", 2),
    0x55: ("iget-boolean", 2),
    0x56: ("iget-byte", 2),
    0x57: ("iget-char", 2),
    0x58: ("iget-short", 2),
    0x59: ("iput", 2),
    0x5A: ("iput-wide", 2),
    0x5B: ("iput-object", 2),
    0x5C: ("iput-boolean", 2),
    0x5D: ("iput-byte", 2),
    0x5E: ("iput-char", 2),
    0x5F: ("iput-short", 2),
    # Static field operations (0x60-0x6D) - format 21c, 2 code units
    0x60: ("sget", 2),
    0x61: ("sget-wide", 2),
    0x62: ("sget-object", 2),
    0x63: ("sget-boolean", 2),
    0x64: ("sget-byte", 2),
    0x65: ("sget-char", 2),
    0x66: ("sget-short", 2),
    0x67: ("sput", 2),
    0x68: ("sput-wide", 2),
    0x69: ("sput-object", 2),
    0x6A: ("sput-boolean", 2),
    0x6B: ("sput-byte", 2),
    0x6C: ("sput-char", 2),
    0x6D: ("sput-short", 2),
    # Invoke operations (0x6E-0x72) - format 35c, 3 code units
    0x6E: ("invoke-virtual", 3),
    0x6F: ("invoke-super", 3),
    0x70: ("invoke-direct", 3),
    0x71: ("invoke-static", 3),
    0x72: ("invoke-interface", 3),
    # (0x73 is unused)
    # Invoke range operations (0x74-0x78) - format 3rc, 3 code units
    0x74: ("invoke-virtual/range", 3),
    0x75: ("invoke-super/range", 3),
    0x76: ("invoke-direct/range", 3),
    0x77: ("invoke-static/range", 3),
    0x78: ("invoke-interface/range", 3),
    # (0x79-0x7A are unused)
    # Unary operations (0x7B-0x8F) - format 12x, 1 code unit
    0x7B: ("neg-int", 1),
    0x7C: ("not-int", 1),
    0x7D: ("neg-long", 1),
    0x7E: ("not-long", 1),
    0x7F: ("neg-float", 1),
    0x80: ("neg-double", 1),
    0x81: ("int-to-long", 1),
    0x82: ("int-to-float", 1),
    0x83: ("int-to-double", 1),
    0x84: ("long-to-int", 1),
    0x85: ("long-to-float", 1),
    0x86: ("long-to-double", 1),
    0x87: ("float-to-int", 1),
    0x88: ("float-to-long", 1),
    0x89: ("float-to-double", 1),
    0x8A: ("double-to-int", 1),
    0x8B: ("double-to-long", 1),
    0x8C: ("double-to-float", 1),
    0x8D: ("int-to-byte", 1),
    0x8E: ("int-to-char", 1),
    0x8F: ("int-to-short", 1),
    # Binary operations (0x90-0xAF) - format 23x, 2 code units
    0x90: ("add-int", 2),
    0x91: ("sub-int", 2),
    0x92: ("mul-int", 2),
    0x93: ("div-int", 2),
    0x94: ("rem-int", 2),
    0x95: ("and-int", 2),
    0x96: ("or-int", 2),
    0x97: ("xor-int", 2),
    0x98: ("shl-int", 2),
    0x99: ("shr-int", 2),
    0x9A: ("ushr-int", 2),
    0x9B: ("add-long", 2),
    0x9C: ("sub-long", 2),
    0x9D: ("mul-long", 2),
    0x9E: ("div-long", 2),
    0x9F: ("rem-long", 2),
    0xA0: ("and-long", 2),
    0xA1: ("or-long", 2),
    0xA2: ("xor-long", 2),
    0xA3: ("shl-long", 2),
    0xA4: ("shr-long", 2),
    0xA5: ("ushr-long", 2),
    0xA6: ("add-float", 2),
    0xA7: ("sub-float", 2),
    0xA8: ("mul-float", 2),
    0xA9: ("div-float", 2),
    0xAA: ("rem-float", 2),
    0xAB: ("add-double", 2),
    0xAC: ("sub-double", 2),
    0xAD: ("mul-double", 2),
    0xAE: ("div-double", 2),
    0xAF: ("rem-double", 2),
    # Binary operations 2addr (0xB0-0xCF) - format 12x, 1 code unit
    0xB0: ("add-int/2addr", 1),
    0xB1: ("sub-int/2addr", 1),
    0xB2: ("mul-int/2addr", 1),
    0xB3: ("div-int/2addr", 1),
    0xB4: ("rem-int/2addr", 1),
    0xB5: ("and-int/2addr", 1),
    0xB6: ("or-int/2addr", 1),
    0xB7: ("xor-int/2addr", 1),
    0xB8: ("shl-int/2addr", 1),
    0xB9: ("shr-int/2addr", 1),
    0xBA: ("ushr-int/2addr", 1),
    0xBB: ("add-long/2addr", 1),
    0xBC: ("sub-long/2addr", 1),
    0xBD: ("mul-long/2addr", 1),
    0xBE: ("div-long/2addr", 1),
    0xBF: ("rem-long/2addr", 1),
    0xC0: ("and-long/2addr", 1),
    0xC1: ("or-long/2addr", 1),
    0xC2: ("xor-long/2addr", 1),
    0xC3: ("shl-long/2addr", 1),
    0xC4: ("shr-long/2addr", 1),
    0xC5: ("ushr-long/2addr", 1),
    0xC6: ("add-float/2addr", 1),
    0xC7: ("sub-float/2addr", 1),
    0xC8: ("mul-float/2addr", 1),
    0xC9: ("div-float/2addr", 1),
    0xCA: ("rem-float/2addr", 1),
    0xCB: ("add-double/2addr", 1),
    0xCC: ("sub-double/2addr", 1),
    0xCD: ("mul-double/2addr", 1),
    0xCE: ("div-double/2addr", 1),
    0xCF: ("rem-double/2addr", 1),
    # Binary operations lit16 (0xD0-0xD7) - format 22s, 2 code units
    0xD0: ("add-int/lit16", 2),
    0xD1: ("rsub-int", 2),
    0xD2: ("mul-int/lit16", 2),
    0xD3: ("div-int/lit16", 2),
    0xD4: ("rem-int/lit16", 2),
    0xD5: ("and-int/lit16", 2),
    0xD6: ("or-int/lit16", 2),
    0xD7: ("xor-int/lit16", 2),
    # Binary operations lit8 (0xD8-0xE2) - format 22b, 2 code units
    0xD8: ("add-int/lit8", 2),
    0xD9: ("rsub-int/lit8", 2),
    0xDA: ("mul-int/lit8", 2),
    0xDB: ("div-int/lit8", 2),
    0xDC: ("rem-int/lit8", 2),
    0xDD: ("and-int/lit8", 2),
    0xDE: ("or-int/lit8", 2),
    0xDF: ("xor-int/lit8", 2),
    0xE0: ("shl-int/lit8", 2),
    0xE1: ("shr-int/lit8", 2),
    0xE2: ("ushr-int/lit8", 2),
    # (0xE3-0xF9 are unused)
    # Invoke-polymorphic (0xFA-0xFB) - format 45cc/4rcc, 4 code units
    0xFA: ("invoke-polymorphic", 4),
    0xFB: ("invoke-polymorphic/range", 4),
    # Invoke-custom (0xFC-0xFD) - format 35c/3rc, 3 code units
    0xFC: ("invoke-custom", 3),
    0xFD: ("invoke-custom/range", 3),
    # Const method handle/type (0xFE-0xFF) - format 21c, 2 code units
    0xFE: ("const-method-handle", 2),
    0xFF: ("const-method-type", 2),
}

# The size is in 16-bit code units.


class DalvikDisassembler:
    def __init__(self, config):
        self.config = config
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION

    def addPdbFile(self, binary_info, pdb_path):
        pass

    def _getPayloadSize(self, bytecode, idx):
        """Calculate the size (in bytes) of a data payload at the given index.

        Dalvik embeds data payloads (packed-switch, sparse-switch, fill-array-data)
        inline in the instruction stream. The first 16-bit code unit is a pseudo-opcode
        identifying the payload type, and the remaining data follows a defined layout.
        Returns the total size in bytes, or 0 if not a recognized payload.
        """
        if idx + 2 > len(bytecode):
            return 0
        ident = struct.unpack_from("<H", bytecode, idx)[0]
        if ident == 0x0100:
            # packed-switch-payload: ident(2) + size(2) + first_key(4) + targets(size*4)
            if idx + 4 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            return 2 + 2 + 4 + size * 4
        if ident == 0x0200:
            # sparse-switch-payload: ident(2) + size(2) + keys(size*4) + targets(size*4)
            if idx + 4 > len(bytecode):
                return 0
            size = struct.unpack_from("<H", bytecode, idx + 2)[0]
            return 2 + 2 + size * 4 + size * 4
        if ident == 0x0300:
            # fill-array-data-payload: ident(2) + element_width(2) + size(4) + data(size*width)
            if idx + 8 > len(bytecode):
                return 0
            element_width = struct.unpack_from("<H", bytecode, idx + 2)[0]
            size = struct.unpack_from("<I", bytecode, idx + 4)[0]
            data_size = size * element_width
            # Pad to 2-byte boundary
            if data_size % 2:
                data_size += 1
            return 2 + 2 + 4 + data_size
        return 0

    def _resolveSwitchTargets(self, bytecode, switch_insn_idx, payload_idx):
        """Resolve branch targets from a packed-switch or sparse-switch payload.

        Args:
            bytecode: The raw bytecode buffer.
            switch_insn_idx: The byte offset of the switch instruction within bytecode.
            payload_idx: The byte offset of the payload within bytecode.

        Returns:
            A list of absolute byte offsets (relative to bytecode start) for each target.
        """
        if payload_idx < 0 or payload_idx + 2 > len(bytecode):
            return []
        ident = struct.unpack_from("<H", bytecode, payload_idx)[0]
        if payload_idx + 4 > len(bytecode):
            return []
        size = struct.unpack_from("<H", bytecode, payload_idx + 2)[0]

        targets = []
        if ident == 0x0100:
            # packed-switch: targets start at payload + 8 (after ident + size + first_key)
            targets_start = payload_idx + 8
            for i in range(size):
                off = targets_start + i * 4
                if off + 4 > len(bytecode):
                    break
                rel_offset = struct.unpack_from("<i", bytecode, off)[0]
                # Offset is in code units (16-bit) relative to the switch instruction
                targets.append(switch_insn_idx + rel_offset * 2)
        elif ident == 0x0200:
            # sparse-switch: targets start at payload + 4 + size*4 (after ident + size + keys)
            targets_start = payload_idx + 4 + size * 4
            for i in range(size):
                off = targets_start + i * 4
                if off + 4 > len(bytecode):
                    break
                rel_offset = struct.unpack_from("<i", bytecode, off)[0]
                targets.append(switch_insn_idx + rel_offset * 2)
        return targets

    def analyzeFunction(self, dex_file, method_info):
        start_addr = method_info["offset"]

        raw_data = method_info["raw_data"]

        # In LIEF, method.code_offset (which is passed as start_addr) points directly to the
        # Dalvik bytecode instructions, NOT the start of the 16-byte code_item header.
        bytecode_offset = start_addr
        header_offset = start_addr - 16

        if header_offset < 0 or header_offset + 16 > len(raw_data):
            return None

        # The LIEF Python API for CodeInfo does not expose insns_size. We manually parse
        # it from the code_item header. It's a 4-byte integer at offset 12.
        insns_size_units = struct.unpack_from("<I", raw_data, header_offset + 12)[0]
        insns_size_bytes = insns_size_units * 2

        if bytecode_offset + insns_size_bytes > len(raw_data):
            LOGGER.warning(
                "Bytecode range [0x%x:0x%x] exceeds raw data size (0x%x), skipping method.",
                bytecode_offset,
                bytecode_offset + insns_size_bytes,
                len(raw_data),
            )
            return None

        bytecode = raw_data[bytecode_offset : bytecode_offset + insns_size_bytes]

        # Addresses are relative to bytecode_offset (where instructions actually start),
        # not start_addr (which points to the code_item header).
        state = DalvikFunctionAnalysisState(bytecode_offset, self.disassembly)

        # Use block_queue for recursive traversal instead of linear sweep.
        # This avoids misinterpreting data payloads (packed-switch-payload,
        # sparse-switch-payload, fill-array-data-payload) as instructions.
        visited_offsets = set()

        while state.hasUnprocessedBlocks():
            block_start_addr = state.chooseNextBlock()
            idx = block_start_addr - bytecode_offset

            while 0 <= idx < len(bytecode):
                if idx in visited_offsets:
                    break
                visited_offsets.add(idx)

                op = bytecode[idx]

                if op not in DALVIK_OPCODES:
                    LOGGER.warning(
                        "Unknown Dalvik opcode 0x%02x at offset 0x%x, aborting block disassembly.",
                        op,
                        bytecode_offset + idx,
                    )
                    break
                mnemonic, length_units = DALVIK_OPCODES[op]
                length_bytes = length_units * 2

                if idx + length_bytes > len(bytecode):
                    break

                i_bytes = bytes(bytecode[idx : idx + length_bytes])
                i_address = bytecode_offset + idx
                i_size = length_bytes
                i_mnemonic = mnemonic
                i_op_str = ""

                state.setNextInstructionReachable(True)

                # CFG handling
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
                    state.addBlockToQueue(target_address)
                    i_op_str = hex(target_address)
                    state.setNextInstructionReachable(False)
                elif i_mnemonic.startswith("if-"):
                    target_offset = int.from_bytes(i_bytes[2:4], byteorder="little", signed=True) * 2
                    target_address = i_address + target_offset
                    state.addCodeRef(i_address, target_address, by_jump=True)
                    state.addBlockToQueue(target_address)
                    # Fall-through is also a valid path
                    fall_through = i_address + i_size
                    state.addBlockToQueue(fall_through)
                    i_op_str = hex(target_address)
                elif i_mnemonic in ("packed-switch", "sparse-switch"):
                    # The operand is a relative offset (in code units) to the payload
                    payload_rel_offset = int.from_bytes(i_bytes[2:6], byteorder="little", signed=True) * 2
                    payload_byte_idx = idx + payload_rel_offset
                    switch_targets = self._resolveSwitchTargets(bytecode, idx, payload_byte_idx)
                    for target_byte_idx in switch_targets:
                        target_addr = bytecode_offset + target_byte_idx
                        state.addCodeRef(i_address, target_addr, by_jump=True)
                        state.addBlockToQueue(target_addr)
                    # Fall-through after switch is also possible (default case)
                    fall_through = i_address + i_size
                    state.addBlockToQueue(fall_through)
                    i_op_str = f"payload@{hex(bytecode_offset + payload_byte_idx)}"
                elif i_mnemonic.startswith("invoke-"):
                    method_idx = int.from_bytes(i_bytes[2:4], byteorder="little")
                    try:
                        target_method = dex_file.methods[method_idx]
                        # Include class name for context (e.g. "Ljava/lang/Object;-><init>")
                        i_op_str = f"{target_method.cls.fullname}->{target_method.name}"
                    except Exception:
                        i_op_str = f"method_idx_{method_idx}"

                state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                idx += length_bytes

                # If this instruction ends the block (return, throw, goto), stop
                if not state.is_next_instruction_reachable:
                    break

            state.endBlock()

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

        # Try raw bytes first, then fallback to list() conversion
        # LIEF's Python bindings for parse() interpret bytes() as a filename string!
        # Parsing a massive binary blob via list() is extremely slow in Python (taking minutes).
        # We must prioritize loading the file natively using C++ fstream if a file path is provided.
        dex_file = None
        if getattr(binary_info, "file_path", "") and not getattr(binary_info, "is_buffer", False):
            with contextlib.suppress(Exception):
                dex_file = lief.DEX.parse(binary_info.file_path)

        if not dex_file:
            # Fallback to in-memory list() conversion for raw buffers
            try:
                dex_file = lief.DEX.parse(binary_info.raw_data)
            except (TypeError, Exception):
                dex_file = None
            if not dex_file:
                dex_file = lief.DEX.parse(list(binary_info.raw_data))

        if dex_file:
            for method in dex_file.methods:
                if not method.has_class:
                    continue
                code_info = method.code_info
                if not code_info:
                    continue

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
