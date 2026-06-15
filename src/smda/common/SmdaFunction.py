#!/usr/bin/env python3
import bisect
import hashlib
import logging
import re
import struct
from typing import Iterator, List

from smda.common.CodeXref import CodeXref
from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.Tarjan import Tarjan
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .SmdaInstruction import SmdaInstruction

LOGGER = logging.getLogger(__name__)


class LazyIntKeyDict(dict):
    def __init__(self, data=None):
        if data:
            self._raw_data = data
            self._is_converted = False
        else:
            dict.__init__(self)
            self._is_converted = True

    def _convert(self):
        if not self._is_converted:
            for k, v in self._raw_data.items():
                dict.__setitem__(self, int(k), v)
            self._is_converted = True
            self._raw_data = None

    def __getitem__(self, key):
        self._convert()
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        self._convert()
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        self._convert()
        dict.__delitem__(self, key)

    def __iter__(self):
        self._convert()
        return dict.__iter__(self)

    def __len__(self):
        if not self._is_converted:
            return len(self._raw_data)
        return dict.__len__(self)

    def __contains__(self, key):
        self._convert()
        return dict.__contains__(self, key)

    def get(self, key, default=None):
        self._convert()
        return dict.get(self, key, default)

    def items(self):
        self._convert()
        return dict.items(self)

    def keys(self):
        self._convert()
        return dict.keys(self)

    def values(self):
        self._convert()
        return dict.values(self)

    def copy(self):
        self._convert()
        return dict.copy(self)


class SmdaFunction:
    smda_report = None
    offset = None
    blocks = None
    _sorted_block_keys = None
    apirefs = None
    stringrefs = None
    blockrefs = None
    _blockrefs_reverse = None
    _normalized_blockrefs = None
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
        self._normalized_blockrefs = None
        self._basic_blocks = None
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

    def getBlocks(self) -> List["SmdaBasicBlock"]:
        if self._basic_blocks is None:
            self._basic_blocks = [
                SmdaBasicBlock(self.blocks[key], smda_function=self) for key in self._sorted_block_keys
            ]
        return self._basic_blocks

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
        if self.code_inrefs is None:
            self.code_inrefs = []
            for inref in self.inrefs:
                if inref in self.smda_report._offset2ins:
                    self.code_inrefs.append(
                        CodeXref(self.smda_report._offset2ins[inref], self.smda_report._offset2ins[self.offset])
                    )
        yield from self.code_inrefs

    def getCodeOutrefs(self):
        self.smda_report.initCodeXrefs()
        if self.code_outrefs is None:
            self.code_outrefs = []
            for outref_src, outref_dsts in self.outrefs.items():
                for target in outref_dsts:
                    if target in self.smda_report._offset2ins:
                        self.code_outrefs.append(
                            CodeXref(self.smda_report._offset2ins[outref_src], self.smda_report._offset2ins[target])
                        )
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
        except Exception as exc:
            reraise_non_operational_exception(exc)
        return nesting_depth

    def getPicHash(self, binary_info):
        return struct.unpack("<Q", hashlib.sha256(self.getPicHashSequence(binary_info)).digest()[:8])[0]

    def getPicHashSequence(self, binary_info):
        escaped_binary_seqs = []
        for key in self._sorted_block_keys:
            for instruction in self.blocks[key]:
                escaped_binary_seqs.append(
                    instruction.getEscapedBinary(
                        self._escaper,
                        escape_intraprocedural_jumps=True,
                        lower_addr=binary_info.base_addr,
                        upper_addr=binary_info.base_addr + binary_info.binary_size,
                    )
                )
        return "".join(escaped_binary_seqs).encode("ascii")

    def getOpcHash(self):
        return struct.unpack("<Q", hashlib.sha256(self.getOpcHashSequence()).digest()[:8])[0]

    def getOpcHashSequence(self):
        escaped_binary_seqs = []
        for key in self._sorted_block_keys:
            for instruction in self.blocks[key]:
                escaped_binary_seqs.append(instruction.getEscapedToOpcodeOnly(self._escaper))
        return "".join(escaped_binary_seqs).encode("ascii")

    def _parseBlocks(self, block_dict):
        self.blocks = {}
        for offset, block in block_dict.items():
            instructions = [SmdaInstruction(ins, smda_function=self) for ins in block]
            self.blocks[int(offset)] = instructions
            self.binweight += sum(len(ins.bytes) / 2 for ins in instructions)
        self._sorted_block_keys = sorted(self.blocks.keys())
        # invalidate any cached SmdaBasicBlock objects built from a previous block set
        self._basic_blocks = None

    @staticmethod
    def _normalizeDalvikStringRefs(stringrefs):
        if not stringrefs:
            return []
        if isinstance(stringrefs, list):
            return stringrefs
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
        if not self._sorted_block_keys:
            return None
        idx = bisect.bisect_right(self._sorted_block_keys, instruction_addr)
        if idx > 0:
            block_start = self._sorted_block_keys[idx - 1]
            block = self.blocks[block_start]
            if block:
                block_end = block[-1].offset + (len(block[-1].bytes) // 2)
                if instruction_addr < block_end:
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
        if getattr(self, "_normalized_blockrefs", None) is not None:
            return self._normalized_blockrefs

        current_blockrefs = self.blockrefs or {}
        normalized_blockrefs = {}

        # 1. Preprocess active try ranges and prepare all normalized targets
        try_ranges = self.architecture_metadata.get("try_ranges", []) if self.architecture_metadata else []
        active_try_ranges = []
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

            active_try_ranges.append(
                {"start": try_range["start_addr"], "end": try_range["end_addr"], "targets": normalized_targets}
            )

        # 2. Iterate blocks once to build normalized_blockrefs and apply try_ranges
        for block_start, block in self.blocks.items():
            successors = set(current_blockrefs.get(block_start, []))
            if block:
                block_end = block[-1].offset + (len(block[-1].bytes) // 2)
                for r in active_try_ranges:
                    if r["start"] < block_end and block_start < r["end"]:
                        successors.update(r["targets"])
            normalized_blockrefs[block_start] = sorted(successors)

        # 3. Ensure any targets that are not in self.blocks are also keys in normalized_blockrefs
        for r in active_try_ranges:
            for target in r["targets"]:
                if target not in normalized_blockrefs:
                    normalized_blockrefs[target] = []

        result = {block_start: normalized_blockrefs[block_start] for block_start in sorted(normalized_blockrefs)}
        self._normalized_blockrefs = result
        return result

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
        smda_function._sorted_block_keys = sorted(smda_function.blocks.keys())
        smda_function._basic_blocks = None
        smda_function.apirefs = LazyIntKeyDict(function_dict["apirefs"])
        smda_function.blockrefs = LazyIntKeyDict(function_dict["blockrefs"])
        smda_function.inrefs = function_dict["inrefs"]
        smda_function.outrefs = LazyIntKeyDict(function_dict["outrefs"])
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
