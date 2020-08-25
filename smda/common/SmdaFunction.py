#!/usr/bin/env python3
import hashlib
import struct

from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
from smda.common.Tarjan import Tarjan
from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth
from .SmdaInstruction import SmdaInstruction


class SmdaFunction(object):

    offset = None
    blocks = None
    apirefs = None
    blockrefs = None
    inrefs = None
    outrefs = None
    # metadata
    binweight = 0
    characteristics = ""
    confidence = 0.0
    function_name = ""
    pic_hash = None
    strongly_connected_components = None
    tfidf = None

    def __init__(self, disassembly=None, function_offset=None, config=None):
        if disassembly is not None and function_offset is not None:
            self._escaper = IntelInstructionEscaper if disassembly.binary_info.architecture in ["intel"] else None
            self.offset = function_offset
            self._parseBlocks(disassembly.getBlocksAsDict(function_offset))
            self.apirefs = disassembly.getApiRefs(function_offset)
            self.blockrefs = disassembly.getBlockRefs(function_offset)
            self.inrefs = disassembly.getInRefs(function_offset)
            self.outrefs = disassembly.getOutRefs(function_offset)
            # metadata
            self.function_name = disassembly.function_symbols.get(function_offset, "")
            self.characteristics = disassembly.candidates[function_offset].getCharacteristics() if function_offset in disassembly.candidates else None
            self.confidence = disassembly.candidates[function_offset].getConfidence() if function_offset in disassembly.candidates else None
            self.tfidf = disassembly.candidates[function_offset].getTfIdf() if function_offset in disassembly.candidates else None
            self.pic_hash = self._calculatePicHash(disassembly.binary_info)
            if config and config.CALCULATE_SCC:
                self.strongly_connected_components = self._calculateSccs()
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

    def getBlocks(self):
        for _, block in sorted(self.blocks.items()):
            yield block

    def getPicHashAsLong(self):
        return self.pic_hash

    def getPicHashAsHex(self):
        return struct.pack("l", self.pic_hash).hex()

    def getInstructions(self):
        for block in self.getBlocks():
            for ins in block:
                yield ins

    def getInstructionsForBlock(self, offset):
        if offset is None:
            offset = self.offset
        if offset not in self.blocks:
            return []
        return self.blocks[offset]

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

    def _calculatePicHash(self, binary_info):
        escaped_binary_seqs = []
        for _, block in sorted(self.blocks.items()):
            for instruction in block:
                escaped_binary_seqs.append(instruction.getEscapedBinary(self._escaper, lower_addr=binary_info.base_addr, upper_addr=binary_info.base_addr + binary_info.binary_size))
        as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seqs)])
        return struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]

    def _parseBlocks(self, block_dict):
        self.blocks = {}
        for offset, block in block_dict.items():
            instructions = [SmdaInstruction(ins) for ins in block]
            self.blocks[int(offset)] = instructions
            self.binweight += sum([len(ins.bytes) / 2 for ins in instructions])

    @classmethod
    def fromDict(cls, function_dict, binary_info=None, version=None):
        smda_function = cls(None)
        smda_function.offset = function_dict["offset"]
        smda_function.blocks = {}
        for addr, block in function_dict["blocks"].items():
            smda_function.blocks[int(addr)] = [SmdaInstruction.fromDict(ins) for ins in block]
        smda_function.apirefs = {int(k): v for k, v in function_dict["apirefs"].items()}
        smda_function.blockrefs = {int(k): v for k, v in function_dict["blockrefs"].items()}
        smda_function.inrefs = function_dict["inrefs"]
        smda_function.outrefs = {int(k): v for k, v in function_dict["outrefs"].items()}
        smda_function.binweight = function_dict["metadata"]["binweight"]
        smda_function.characteristics = function_dict["metadata"]["characteristics"]
        smda_function.confidence = function_dict["metadata"]["confidence"]
        smda_function.function_name = function_dict["metadata"]["function_name"]
        smda_function.pic_hash = function_dict["metadata"]["pic_hash"]
        smda_function.strongly_connected_components = function_dict["metadata"]["strongly_connected_components"]
        smda_function.tfidf = function_dict["metadata"]["tfidf"]
        if binary_info.architecture:
            smda_function._escaper = IntelInstructionEscaper if binary_info.architecture in ["intel"] else None
        # modernize older reports on import
        if version and version.startswith("1.2"):
            smda_function.nesting_depth = smda_function._calculateNestingDepth()
            smda_function.pic_hash = smda_function._calculatePicHash(binary_info)
        else:
            smda_function.nesting_depth = function_dict["metadata"]["nesting_depth"]
        return smda_function

    def toDict(self):
        blocks_as_dict = {}
        for addr, block in self.blocks.items():
            blocks_as_dict[addr] = [ins.toDict() for ins in block]
        return  {
            "offset": self.offset,
            "blocks": blocks_as_dict,
            "apirefs": self.apirefs,
            "blockrefs": self.blockrefs,
            "inrefs": self.inrefs,
            "outrefs": self.outrefs,
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

    def __str__(self):
        return "0x{:08x}: (->{:>4d}, {:>4d}->) {:>3d} blocks, {:>4d} instructions.".format(self.offset, self.num_inrefs, self.num_outrefs, self.num_blocks, self.num_instructions)
