#!/usr/bin/env python3
import re
import struct
import hashlib
from typing import Iterator

from smda.common.Tarjan import Tarjan
from smda.common.CodeXref import CodeXref
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
from .SmdaInstruction import SmdaInstruction


class SmdaFunction(object):

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
    # metadata
    binweight = 0
    characteristics = ""
    confidence = 0.0
    function_name = ""
    pic_hash = None
    opc_hash = None
    strongly_connected_components = None
    tfidf = None

    def __init__(self, disassembly=None, function_offset=None, config=None, smda_report=None):
        self.smda_report = smda_report
        if disassembly is not None and function_offset is not None:
            self._escaper = IntelInstructionEscaper if disassembly.binary_info.architecture in ["intel"] else None
            self.offset = function_offset
            self._parseBlocks(disassembly.getBlocksAsDict(function_offset))
            self.apirefs = disassembly.getApiRefs(function_offset)
            self.blockrefs = disassembly.getBlockRefs(function_offset)
            self.inrefs = disassembly.getInRefs(function_offset)
            self.outrefs = disassembly.getOutRefs(function_offset)
            self.is_exported = self.offset in disassembly.exported_functions
            # metadata
            self.function_name = disassembly.function_symbols.get(function_offset, "")
            self.characteristics = disassembly.candidates[function_offset].getCharacteristics() if function_offset in disassembly.candidates else None
            self.confidence = disassembly.candidates[function_offset].getConfidence() if function_offset in disassembly.candidates else None
            self.tfidf = disassembly.candidates[function_offset].getTfIdf() if function_offset in disassembly.candidates else None
            self.pic_hash = self.getPicHash(disassembly.binary_info)
            if config and config.CALCULATE_SCC:
                self.strongly_connected_components = self._calculateSccs()
            if config and config.CALCULATE_NESTING:
                self.nesting_depth = self._calculateNestingDepth()

    @property
    def num_edges(self):
        return sum([len(value) for key, value in self.blockrefs.items()])

    @property
    def num_inrefs(self):
        return len(self.inrefs)

    @property
    def num_outrefs(self):
        return sum([len(dsts) for src, dsts in self.outrefs.items()])

    @property
    def num_blocks(self):
        return len(self.blocks)

    @property
    def num_instructions(self):
        return sum([1 for ins in self.getInstructions()])

    @property
    def num_calls(self):
        return sum([1 for ins in self.getInstructions() if ins.mnemonic == "call"])

    @property
    def num_returns(self):
        return sum([1 for ins in self.getInstructions() if ins.mnemonic in ["ret", "retn"]])
    
    @property
    def opc_hash(self):
        return self.getOpcHash()

    def isApiThunk(self):
        if self.num_instructions != 1:
            return False
        first_ins = self.blocks[self.offset][0]
        if first_ins.mnemonic not in ["jmp", "call"]:
            return False
        if len(self.apirefs) == 0:
            return False
        return True

    def isExported(self):
        return self.is_exported

    def getBlocks(self) -> Iterator["SmdaBasicBlock"]:
        for _, block in sorted(self.blocks.items()):
            yield SmdaBasicBlock(block, smda_function=self)

    def getPicHashAsLong(self):
        return self.pic_hash

    def getPicHashAsHex(self):
        return struct.pack("l", self.pic_hash).hex()

    def getInstructions(self):
        for block in self.getBlocks():
            for ins in block.getInstructions():
                yield ins

    def getInstructionsForBlock(self, offset) -> Iterator["SmdaInstruction"]:
        if offset is None:
            offset = self.offset
        if offset not in self.blocks:
            return []
        return self.blocks[offset]

    def getCodeInrefs(self):
        self.smda_report.initCodeXrefs()
        # potentially lazy initialize CodeXrefs externally via SmdaReport
        for inref in self.code_inrefs:
            yield inref

    def getCodeOutrefs(self):
        self.smda_report.initCodeXrefs()
        # potentially lazy initialize CodeXrefs externally via SmdaReport
        for outref in self.code_outrefs:
            yield outref

    def _calculateSccs(self):
        tarjan = Tarjan(self.blockrefs)
        tarjan.calculateScc()
        return tarjan.getResult()

    def _calculateNestingDepth(self):
        nesting_depth = 0
        try:
            if self.blockrefs:
                tree = build_dominator_tree(self.blockrefs, self.offset)
                if tree:
                    nesting_depth = get_nesting_depth(self.blockrefs, tree, self.offset)
        except:
            pass
        return nesting_depth

    def getPicHash(self, binary_info):
        return struct.unpack("Q", hashlib.sha256(self.getPicHashSequence(binary_info)).digest()[:8])[0]

    def getPicHashSequence(self, binary_info):
        escaped_binary_seqs = []
        for _, block in sorted(self.blocks.items()):
            for instruction in block:
                escaped_binary_seqs.append(instruction.getEscapedBinary(self._escaper, escape_intraprocedural_jumps=True, lower_addr=binary_info.base_addr, upper_addr=binary_info.base_addr + binary_info.binary_size))
        return bytes([ord(c) for c in "".join(escaped_binary_seqs)])
    
    def getOpcHash(self):
        return struct.unpack("Q", hashlib.sha256(self.getOpcHashSequence()).digest()[:8])[0]

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
            self.binweight += sum([len(ins.bytes) / 2 for ins in instructions])

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
                    instructions_as_strings.append(f'{smda_ins.offset:x}: {smda_ins.mnemonic} {printable_api}')
                else:
                    instructions_as_strings.append(f'{smda_ins.offset:x}: {smda_ins.mnemonic} {smda_ins.operands}')
            block_entry += "\l".join(instructions_as_strings)
            dot_graph += block_entry + '"];\n'
            if smda_block.offset in self.blockrefs:
                for target_offset in self.blockrefs[smda_block.offset]:
                    dot_graph += f'  Node0x{smda_block.offset:x} -> Node0x{target_offset:x};\n'
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
        smda_function.is_exported = function_dict["is_exported"] if "is_exported" in function_dict else False
        smda_function.binweight = function_dict["metadata"]["binweight"]
        smda_function.characteristics = function_dict["metadata"]["characteristics"]
        smda_function.confidence = function_dict["metadata"]["confidence"]
        smda_function.function_name = function_dict["metadata"]["function_name"]
        smda_function.pic_hash = function_dict["metadata"]["pic_hash"] if "pic_hash" in function_dict["metadata"] else None
        smda_function.strongly_connected_components = function_dict["metadata"]["strongly_connected_components"]
        smda_function.tfidf = function_dict["metadata"]["tfidf"]
        smda_function.stringrefs = {addr: string.decode("utf-8") for addr, string in function_dict["stringrefs"].items()} if "stringrefs" in function_dict["stringrefs"] else {}
        if binary_info and binary_info.architecture:
            smda_function._escaper = IntelInstructionEscaper if binary_info.architecture in ["intel"] else None
        # sanitize MCRIT plugin generated version strings
        if version and version.startswith("MCRIT4IDA"):
            version = version.rsplit(" ", 1)[-1]
        # modernize older reports on import
        if version and re.match("(v)?\d+(.\d+)*", version):
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
            else:
                smda_function._escaper = IntelInstructionEscaper
                smda_function.pic_hash = smda_function.getPicHash(binary_info)
        return smda_function

    def toDict(self) -> dict:
        blocks_as_dict = {}
        for addr, block in self.blocks.items():
            blocks_as_dict[addr] = [ins.toDict() for ins in block]
        return  {
            "offset": self.offset,
            "blocks": blocks_as_dict,
            "apirefs": self.apirefs,
            "stringrefs": {addr: string.encode("utf-8").hex() for addr, string in self.stringrefs.items()} if self.stringrefs is not None else {},
            "blockrefs": self.blockrefs,
            "inrefs": self.inrefs,
            "outrefs": self.outrefs,
            "is_exported": self.is_exported,
            "metadata": {
                "binweight": self.binweight,
                "characteristics": self.characteristics,
                "confidence": self.confidence,
                "function_name": self.function_name,
                "pic_hash": self.pic_hash,
                "nesting_depth": self.nesting_depth,
                "strongly_connected_components": self.strongly_connected_components,
                "tfidf": self.tfidf
            }
        }

    def __int__(self):
        return self.offset

    def __str__(self):
        return "0x{:08x}: (->{:>4d}, {:>4d}->) {:>3d} blocks, {:>4d} instructions.".format(self.offset, self.num_inrefs, self.num_outrefs, self.num_blocks, self.num_instructions)
