import datetime
import logging

from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs

from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)


class Exporter:
    """Builds a DisassemblyResult from a frontend's analysis, read through a BackendInterface."""

    def __init__(self, config, interface, bitness=None):
        self.config = config
        self.interface = interface
        self.bitness = bitness if bitness else self.interface.getBitness()
        self.architecture = self.interface.getArchitecture()
        self.capstone = None
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)
        self._initCapstone()

    def _initCapstone(self):
        if self.architecture == "aarch64":
            self.capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        elif self.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)

    def addPdbFile(self, binary_info, pdb_path):
        """The frontend's analysis already carries its symbols; a PDB is not applied on top."""
        return

    @staticmethod
    def _splitInstructionBytes(capstone, offset, instruction_bytes, architecture, errors=None):
        """Split *instruction_bytes* (which a frontend may report as N×4 bytes for an AArch64
        MOV-macro head) into one ``(addr, size, mnemonic, op_str, bytes)`` tuple per
        decoded 4-byte instruction.

        Background
        ----------
        A frontend that reports macro heads (IDA does) collapses a ``MOVZ+MOVK`` pair (materialising a 32-bit
        constant in a Wn register across two 4-byte AArch64 instructions) into one
        logical "head" whose reported size is 8 bytes.  Without splitting,
        :meth:`analyzeBuffer` would pass the whole 8-byte buffer to
        :meth:`capstone.disasm_lite` and then take only ``cache[0]`` (the MOVZ),
        silently dropping the MOVK and producing an exported report that drifted from
        SMDA's own per-instruction AArch64 output.

        This static helper iterates every instruction capstone decoded from the buffer
        and emits one tuple per sub-instruction with correctly sliced 4-byte payloads,
        so both the MOVZ (head) and the MOVK (head+4) appear as their own records.
        """
        cache = list(capstone.disasm_lite(instruction_bytes, offset))
        out = []
        consumed = 0
        for i_address, i_size, i_mnemonic, i_op_str in cache:
            sub_bytes = bytes(instruction_bytes[consumed : consumed + i_size])
            out.append((i_address, i_size, i_mnemonic, i_op_str, sub_bytes))
            consumed += i_size
        while consumed < len(instruction_bytes):
            chunk = 4 if architecture == "aarch64" else (len(instruction_bytes) - consumed)
            chunk = min(chunk, len(instruction_bytes) - consumed)
            sub_bytes = bytes(instruction_bytes[consumed : consumed + chunk])
            bytes_hex = sub_bytes.hex()
            LOGGER.warning("missing capstone disassembly output at 0x%x (%s)", offset + consumed, bytes_hex)
            if errors is not None:
                errors[offset + consumed] = {"type": "capstone disassembly failure", "instruction_bytes": bytes_hex}
            out.append((offset + consumed, chunk, "error", "error", sub_bytes))
            consumed += chunk
        return out

    def _convertInstruction(self, offset, instruction_bytes):
        return self._splitInstructionBytes(
            self.capstone, offset, instruction_bytes, self.architecture, self.disassembly.errors
        )

    def analyzeBuffer(self, binary_info, cb_analysis_timeout=None):
        """instead of performing a full analysis, collect the frontend's analysis and convert it into a report"""
        # every other backend re-allocates here (common/RecursiveDisassembler.analyzeBuffer,
        # cil/CilDisassembler, dalvik/DalvikDisassembler). Reusing the instance built in
        # __init__ made a second analyzeBuffer/disassembleFile on the same exporter merge the
        # previous database's functions, instructions, code_refs_*, addr_to_api, errors,
        # recursive_functions and leaf_functions into the new report - and a
        # Disassembler(backend="IDA") is pinned, so it is never rebuilt between runs.
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setConfidenceThreshold(self.config.CONFIDENCE_THRESHOLD)
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        # setBinaryInfo (not a bare assignment) so exported_functions and oep get populated
        self.disassembly.setBinaryInfo(binary_info)
        binary_info.architecture = self.interface.getArchitecture()
        if not binary_info.base_addr:
            binary_info.base_addr = self.interface.getBaseAddr()
        if not binary_info.binary:
            binary_info.binary = self.interface.getBinary()
        if not binary_info.bitness:
            binary_info.bitness = self.bitness
        self.disassembly.function_symbols = self.interface.getFunctionSymbols()
        api_map = self.interface.getApiMap()
        for function_offset in self.interface.getFunctions():
            if cb_analysis_timeout and cb_analysis_timeout():
                self.disassembly.analysis_timeout = True
                break
            if self.interface.isExternalFunction(function_offset):
                continue
            converted_function = []
            for block in self.interface.getBlocks(function_offset):
                converted_block = []
                for instruction_offset in block:
                    instruction_bytes = self.interface.getInstructionBytes(instruction_offset)
                    smda_instructions = self._convertInstruction(instruction_offset, instruction_bytes)
                    num_subs = len(smda_instructions)
                    for idx, smda_instruction in enumerate(smda_instructions):
                        converted_block.append(smda_instruction)
                        self.disassembly.instructions[smda_instruction[0]] = (
                            smda_instruction[2],
                            smda_instruction[1],
                        )
                        # a frontend that reports macro heads (IDA does) tracks code refs at the
                        # macro-head level only; for split
                        # macro heads, attach in-refs to the first sub-instruction (entry)
                        # and out-refs to the last sub-instruction (exit).
                        if idx == 0:
                            for in_ref in self.interface.getCodeInRefs(instruction_offset):
                                self.disassembly.addCodeRefs(in_ref[0], in_ref[1])
                        if idx == num_subs - 1:
                            for out_ref in self.interface.getCodeOutRefs(instruction_offset):
                                # the frontend reports the edge leaving the macro head; the
                                # instruction that actually leaves is the last sub, which is
                                # the address the api_map entry below already uses
                                self.disassembly.addCodeRefs(smda_instruction[0], out_ref[1])
                                if out_ref[1] in api_map:
                                    self.disassembly.addr_to_api[smda_instruction[0]] = api_map[out_ref[1]]
                                    # api_map is keyed by the import entry, so out_ref[1] is
                                    # the slot this API is reached through
                                    dll, _, api = api_map[out_ref[1]].rpartition("!")
                                    self.disassembly.addImportSlot(out_ref[1], dll, api)
                converted_function.append(converted_block)
            self.disassembly.functions[function_offset] = converted_function
            if self.disassembly.isRecursiveFunction(function_offset):
                self.disassembly.recursive_functions.add(function_offset)
            if self.disassembly.isLeafFunction(function_offset):
                self.disassembly.leaf_functions.add(function_offset)
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        return self.disassembly
