#!/usr/bin/env python3
import hashlib
import logging
import re
import struct
from typing import Iterator

from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.Tarjan import Tarjan
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .SmdaInstruction import SmdaInstruction

LOGGER = logging.getLogger(__name__)


class SmdaFunction:
    smda_report = None
    offset = None
    blocks = None
    apirefs = None
    stringrefs = None
    blockrefs = None
    inrefs = None
    outrefs = None
    code_inrefs = None
    code_outrefs = None
    is_exported = None
    architecture_metadata = None
    # metadata
    binweight = 0
    characteristics = ""
    confidence = 0.0
    function_name = ""
    pic_hash = None
    opc_hash = None
    nesting_depth = 0
    strongly_connected_components = None
    tfidf = None

    def __init__(self, disassembly=None, function_offset=None, config=None, smda_report=None):
        self.smda_report = smda_report
        self.nesting_depth = 0
        if disassembly is not None and function_offset is not None:
            self._escaper = IntelInstructionEscaper if disassembly.binary_info.architecture in ["intel"] else None
            self.offset = function_offset
            self._parseBlocks(disassembly.getBlocksAsDict(function_offset))
            self.apirefs = disassembly.getApiRefs(function_offset)
            self.blockrefs = disassembly.getBlockRefs(function_offset)
            self.inrefs = disassembly.getInRefs(function_offset)
            self.outrefs = disassembly.getOutRefs(function_offset)
            self.is_exported = self.offset in disassembly.exported_functions
            self.architecture_metadata = disassembly.function_metadata.get(function_offset, {})
            self.blockrefs = self.getNormalizedBlockRefs()
            # metadata
            self.function_name = disassembly.function_symbols.get(function_offset, "")
            self.characteristics = (
                disassembly.candidates[function_offset].getCharacteristics()
                if function_offset in disassembly.candidates
                else None
            )
            self.confidence = (
                disassembly.candidates[function_offset].getConfidence()
                if function_offset in disassembly.candidates
                else None
            )
            self.tfidf = (
                disassembly.candidates[function_offset].getTfIdf()
                if function_offset in disassembly.candidates
                else None
            )
            # DEX strings are part of the parsed file structure, so they're always
            # populated for Dalvik regardless of WITH_STRINGS — no extra extraction
            # cost. For other architectures, honor WITH_STRINGS as usual.
            is_dalvik_with_strings = (
                disassembly.binary_info.architecture == "dalvik"
                and disassembly.getStringRefsForFunction(function_offset)
            )
            if (config and config.WITH_STRINGS) or is_dalvik_with_strings:
                self.stringrefs = (
                    self._normalizeDalvikStringRefs(disassembly.getStringRefsForFunction(function_offset))
                    if disassembly.binary_info.architecture == "dalvik"
                    else disassembly.getStringRefsForFunction(function_offset)
                )
            if config and config.CALCULATE_HASHING:
                self.pic_hash = self.getPicHash(disassembly.binary_info)
            if config and config.CALCULATE_SCC:
                self.strongly_connected_components = self._calculateSccs()
            if config and config.CALCULATE_NESTING:
                self.nesting_depth = self._calculateNestingDepth()

    @property
    def num_edges(self):
        return sum(len(value) for value in self.blockrefs.values())

    @property
    def num_inrefs(self):
        return len(self.inrefs)

    @property
    def num_outrefs(self):
        return sum(len(dsts) for dsts in self.outrefs.values())

    @property
    def num_blocks(self):
        return len(self.blocks)

    @property
    def num_instructions(self):
        return sum(len(block) for block in self.blocks.values())

    @property
    def num_calls(self):
        architecture = self.smda_report.architecture if self.smda_report else ""
        if architecture == "dalvik":
            return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic.startswith("invoke-"))
        return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic == "call")

    @property
    def num_returns(self):
        architecture = self.smda_report.architecture if self.smda_report else ""
        if architecture == "dalvik":
            return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic.startswith("return"))
        return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic in ("ret", "retn"))

    def isApiThunk(self):
        if self.num_instructions != 1:
            return False
        first_ins = self.blocks[self.offset][0]
        if first_ins.mnemonic not in ["jmp", "call"]:
            return False
        return len(self.apirefs) != 0

    def isExported(self):
        return self.is_exported

    def getBlocks(self) -> Iterator["SmdaBasicBlock"]:
        for _, block in sorted(self.blocks.items()):
            yield SmdaBasicBlock(block, smda_function=self)

    def getPicHashAsLong(self):
        return self.pic_hash

    def getPicHashAsHex(self):
        return struct.pack("<Q", self.pic_hash).hex()

    def getInstructions(self):
        for block in self.getBlocks():
            yield from block.getInstructions()

    def getInstructionsForBlock(self, offset) -> Iterator["SmdaInstruction"]:
        if offset is None:
            offset = self.offset
        if offset not in self.blocks:
            return []
        return self.blocks[offset]

    def getCodeInrefs(self):
        self.smda_report.initCodeXrefs()
        # potentially lazy initialize CodeXrefs externally via SmdaReport
        yield from self.code_inrefs

    def getCodeOutrefs(self):
        self.smda_report.initCodeXrefs()
        # potentially lazy initialize CodeXrefs externally via SmdaReport
        yield from self.code_outrefs

    def _calculateSccs(self):
        tarjan = Tarjan(self.getNormalizedBlockRefs())
        tarjan.calculateScc()
        return tarjan.getResult()

    def _calculateNestingDepth(self):
        nesting_depth = 0
        try:
            normalized_blockrefs = self.getNormalizedBlockRefs()
            root = self._getCfgRoot(normalized_blockrefs)
            if normalized_blockrefs and root is not None:
                tree = build_dominator_tree(normalized_blockrefs, root)
                if tree:
                    nesting_depth = get_nesting_depth(normalized_blockrefs, tree, root)
        except Exception:
            pass
        return nesting_depth

    def getPicHash(self, binary_info):
        return struct.unpack("<Q", hashlib.sha256(self.getPicHashSequence(binary_info)).digest()[:8])[0]

    def getPicHashSequence(self, binary_info):
        escaped_binary_seqs = []
        for _, block in sorted(self.blocks.items()):
            for instruction in block:
                escaped_binary_seqs.append(
                    instruction.getEscapedBinary(
                        self._escaper,
                        escape_intraprocedural_jumps=True,
                        lower_addr=binary_info.base_addr,
                        upper_addr=binary_info.base_addr + binary_info.binary_size,
                    )
                )
        return bytes([ord(c) for c in "".join(escaped_binary_seqs)])

    def getOpcHash(self):
        return struct.unpack("<Q", hashlib.sha256(self.getOpcHashSequence()).digest()[:8])[0]

    def getOpcHashSequence(self):
        escaped_binary_seqs = []
        for _, block in sorted(self.blocks.items()):
            for instruction in block:
                escaped_binary_seqs.append(instruction.getEscapedToOpcodeOnly(self._escaper))
        return bytes([ord(c) for c in "".join(escaped_binary_seqs)])

    def _parseBlocks(self, block_dict):
        self.blocks = {}
        for offset, block in block_dict.items():
            instructions = [SmdaInstruction(ins, smda_function=self) for ins in block]
            self.blocks[int(offset)] = instructions
            self.binweight += sum(len(ins.bytes) / 2 for ins in instructions)

    @staticmethod
    def _normalizeDalvikStringRefs(stringrefs):
        if not stringrefs:
            return []
        if isinstance(stringrefs, list):
            normalized = []
            for entry in stringrefs:
                if isinstance(entry, dict):
                    normalized.append(
                        {
                            "string": entry.get("string", ""),
                            "ins_addr": int(entry.get("ins_addr", 0)),
                            "data_addr": entry.get("data_addr", None),
                            "type": entry.get("type", "dex"),
                        }
                    )
            return normalized
        if isinstance(stringrefs, dict):
            return [
                {
                    "string": string_value,
                    "ins_addr": int(referencing_addr),
                    "data_addr": None,
                    "type": "dex",
                }
                for referencing_addr, string_value in sorted(stringrefs.items())
            ]
        return stringrefs

    def _getContainingBlockStart(self, instruction_addr):
        for block_start, block in self.blocks.items():
            if not block:
                continue
            block_end = block[-1].offset + (len(block[-1].bytes) // 2)
            if block_start <= instruction_addr < block_end:
                return block_start
        return None

    def _getCfgRoot(self, normalized_blockrefs):
        if self.offset in normalized_blockrefs:
            return self.offset
        block_start = self._getContainingBlockStart(self.offset)
        if block_start is not None:
            return block_start
        if normalized_blockrefs:
            # No entry block found for self.offset — refuse to fabricate a root,
            # since dominator/nesting derived from a wrong root is silently misleading.
            LOGGER.warning(
                "Normalized CFG for %s (0x%x) has no entry block; skipping root-dependent analysis.",
                self.function_name or "<unnamed>",
                self.offset,
            )
            return None
        LOGGER.warning("Normalized CFG for %s (0x%x) is empty.", self.function_name or "<unnamed>", self.offset)
        return None

    def getNormalizedBlockRefs(self):
        current_blockrefs = self.blockrefs or {}
        normalized_blockrefs = {
            block_start: sorted(current_blockrefs.get(block_start, [])) for block_start in self.blocks
        }
        try_ranges = self.architecture_metadata.get("try_ranges", []) if self.architecture_metadata else []
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
                block_start = self._getContainingBlockStart(target_addr)
                if block_start is None:
                    block_start = target_addr
                normalized_targets.add(block_start)
                normalized_blockrefs.setdefault(block_start, [])
            for block_start, block in self.blocks.items():
                if not block:
                    continue
                block_end = block[-1].offset + (len(block[-1].bytes) // 2)
                if try_range["start_addr"] < block_end and block_start < try_range["end_addr"]:
                    successors = set(normalized_blockrefs.get(block_start, []))
                    successors.update(normalized_targets)
                    normalized_blockrefs[block_start] = sorted(successors)
        return {block_start: normalized_blockrefs[block_start] for block_start in sorted(normalized_blockrefs)}

    def toDotGraph(self, with_api=False):
        dot_graph = f'digraph "CFG for 0x{self.offset:x}" {{\n'
        dot_graph += f'  label="CFG for 0x{self.offset:x}";\n'
        for smda_block in self.getBlocks():
            block_entry = f'  Node0x{smda_block.offset:x} [shape=record,label="'
            instructions_as_strings = []
            for smda_ins in smda_block.getInstructions():
                printable_api = ""
                if with_api:
                    apiref_str = self.apirefs.get(smda_ins.offset, "")
                    if apiref_str:
                        printable_api = f"[{apiref_str}]"
                if printable_api:
                    instructions_as_strings.append(f"{smda_ins.offset:x}: {smda_ins.mnemonic} {printable_api}")
                else:
                    instructions_as_strings.append(f"{smda_ins.offset:x}: {smda_ins.mnemonic} {smda_ins.operands}")
            block_entry += r"\l".join(instructions_as_strings)
            dot_graph += block_entry + '"];\n'
            if smda_block.offset in self.blockrefs:
                for target_offset in self.blockrefs[smda_block.offset]:
                    dot_graph += f"  Node0x{smda_block.offset:x} -> Node0x{target_offset:x};\n"
        dot_graph += "}"
        return dot_graph

    @classmethod
    def fromDict(cls, function_dict, binary_info=None, version=None, smda_report=None) -> "SmdaFunction":
        smda_function = cls(None)
        smda_function.smda_report = smda_report
        smda_function.offset = function_dict["offset"]
        smda_function.blocks = {}
        for addr, block in function_dict["blocks"].items():
            smda_function.blocks[int(addr)] = [SmdaInstruction.fromDict(ins, smda_function) for ins in block]
        smda_function.apirefs = {int(k): v for k, v in function_dict["apirefs"].items()}
        smda_function.blockrefs = {int(k): v for k, v in function_dict["blockrefs"].items()}
        smda_function.inrefs = function_dict["inrefs"]
        smda_function.outrefs = {int(k): v for k, v in function_dict["outrefs"].items()}
        # provide some legacy support by assuming functions are not exported for SMDA reports < 1.7.0
        smda_function.is_exported = function_dict.get("is_exported", False)
        smda_function.architecture_metadata = function_dict.get("architecture_metadata", {})
        smda_function.blockrefs = smda_function.getNormalizedBlockRefs()
        smda_function.binweight = function_dict["metadata"]["binweight"]
        smda_function.characteristics = function_dict["metadata"]["characteristics"]
        smda_function.confidence = function_dict["metadata"]["confidence"]
        smda_function.function_name = function_dict["metadata"]["function_name"]
        smda_function.pic_hash = function_dict["metadata"].get("pic_hash", None)
        smda_function.strongly_connected_components = function_dict["metadata"]["strongly_connected_components"]
        smda_function.tfidf = function_dict["metadata"]["tfidf"]
        stringrefs = function_dict.get("stringrefs", {})
        function_architecture = None
        if smda_report is not None:
            function_architecture = smda_report.architecture
        elif binary_info is not None:
            function_architecture = binary_info.architecture
        if function_architecture == "dalvik":
            smda_function.stringrefs = smda_function._normalizeDalvikStringRefs(stringrefs)
        else:
            smda_function.stringrefs = stringrefs
        if binary_info and binary_info.architecture:
            smda_function._escaper = IntelInstructionEscaper if binary_info.architecture in ["intel"] else None
        else:
            smda_function._escaper = None
        # sanitize MCRIT plugin generated version strings
        if version and version.startswith("MCRIT4IDA"):
            version = version.rsplit(" ", 1)[-1]
        # modernize older reports on import
        if version and re.match(r"(v)?\d+(.\d+)*", version):
            version = version.replace("v", "")
            version = [int(v) for v in version.split(".")]
            if version < [1, 3, 0]:
                smda_function.nesting_depth = smda_function._calculateNestingDepth()
                if smda_function._escaper:
                    smda_function.pic_hash = smda_function.getPicHash(binary_info)
            else:
                smda_function.nesting_depth = function_dict["metadata"]["nesting_depth"]
        # if we don't have valid version information, always recalculate
        else:
            smda_function.nesting_depth = smda_function._calculateNestingDepth()
            if smda_function._escaper:
                smda_function.pic_hash = smda_function.getPicHash(binary_info)
            # as last resort, assume we analyze Intel
            elif binary_info:
                smda_function._escaper = IntelInstructionEscaper
                smda_function.pic_hash = smda_function.getPicHash(binary_info)
        return smda_function

    def toDict(self) -> dict:
        blocks_as_dict = {}
        for addr, block in self.blocks.items():
            blocks_as_dict[addr] = [ins.toDict() for ins in block]
        return {
            "offset": self.offset,
            "blocks": blocks_as_dict,
            "apirefs": self.apirefs,
            "stringrefs": self.stringrefs if self.stringrefs is not None else {},
            "blockrefs": self.blockrefs,
            "inrefs": self.inrefs,
            "outrefs": self.outrefs,
            "is_exported": self.is_exported,
            "architecture_metadata": self.architecture_metadata if self.architecture_metadata is not None else {},
            "metadata": {
                "binweight": self.binweight,
                "characteristics": self.characteristics,
                "confidence": self.confidence,
                "function_name": self.function_name,
                "pic_hash": self.pic_hash,
                "nesting_depth": self.nesting_depth,
                "strongly_connected_components": self.strongly_connected_components,
                "tfidf": self.tfidf,
            },
        }

    def __int__(self):
        return self.offset

    def __str__(self):
        return f"0x{self.offset:08x}: (->{self.num_inrefs:>4d}, {self.num_outrefs:>4d}->) {self.num_blocks:>3d} blocks, {self.num_instructions:>4d} instructions."
