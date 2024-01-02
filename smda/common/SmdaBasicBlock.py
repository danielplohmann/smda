import struct
import hashlib
from typing import Iterator

from smda.common.SmdaInstruction import SmdaInstruction


class SmdaBasicBlock:

    smda_function = None
    instructions = None
    picblockhash = None
    opcblockhash = None
    offset = None
    length = None

    def __init__(self, instructions, smda_function=None):
        assert isinstance(instructions, list)
        self.smda_function = smda_function
        if instructions:
            self.instructions = instructions
            self.offset = instructions[0].offset
            self.length = len(instructions)
            self.picblockhash = self.getPicBlockHash()
            self.opcblockhash = self.getOpcBlockHash()

    def getInstructions(self) -> Iterator["SmdaInstruction"]:
        for instruction in self.instructions:
            yield instruction

    def getPicBlockHash(self):
        if self.picblockhash is not None:
            return self.picblockhash
        picblockhash_sequence = self.getPicBlockHashSequence()
        if picblockhash_sequence is not None:
            self.picblockhash = struct.unpack("Q", hashlib.sha256(picblockhash_sequence).digest()[:8])[0]
        return self.picblockhash

    def getPicBlockHashSequence(self):
        """ if we have a SmdaFunction as parent, we can try to generate the PicBlockHash ad-hoc """
        # check all the prerequisites
        if self.smda_function and self.smda_function.smda_report and self.smda_function._escaper and self.smda_function.smda_report.base_addr is not None and self.smda_function.smda_report.binary_size:
            escaped_binary_seqs = []
            for instruction in self.getInstructions():
                escaped_binary_seqs.append(instruction.getEscapedBinary(self.smda_function._escaper, escape_intraprocedural_jumps=True, lower_addr=self.smda_function.smda_report.base_addr, upper_addr=self.smda_function.smda_report.base_addr + self.smda_function.smda_report.binary_size))
            return bytes([ord(c) for c in "".join(escaped_binary_seqs)])
    
    def getOpcBlockHash(self):
        if self.opcblockhash is not None:
            return self.opcblockhash
        opcblockhash_sequence = self.getOpcBlockHashSequence()
        if opcblockhash_sequence is not None:
            self.opcblockhash = struct.unpack("Q", hashlib.sha256(opcblockhash_sequence).digest()[:8])[0]
        return self.opcblockhash

    def getOpcBlockHashSequence(self):
        """ if we have a SmdaFunction as parent, we can try to generate the OpcBlockHash ad-hoc """
        # check all the prerequisites
        if self.smda_function and self.smda_function.smda_report and self.smda_function._escaper:
            escaped_binary_seqs = []
            for instruction in self.getInstructions():
                escaped_binary_seqs.append(instruction.getEscapedToOpcodeOnly(self.smda_function._escaper))
            return bytes([ord(c) for c in "".join(escaped_binary_seqs)])
        
    def getPredecessors(self):
        predecessors = []
        if self.smda_function is not None:
            for frm, to in self.smda_function.blockrefs.items():
                if self.offset in to:
                    predecessors.append(frm)
        return predecessors
    
    def getSuccessors(self):
        successors = []
        if self.smda_function is not None:
            if self.offset in self.smda_function.blockrefs:
                successors.extend(self.smda_function.blockrefs[self.offset])
        return successors

    @classmethod
    def fromDict(cls, block_dict, smda_function=None) -> "SmdaBasicBlock":
        smda_block = cls(None)
        smda_block.smda_function = smda_function
        smda_block.instructions = [SmdaInstruction.fromDict(d, smda_function=smda_function) for d in block_dict]
        return smda_block

    def toDict(self) -> dict:
        return [smda_ins.toDict() for smda_ins in self.instructions]

    def __int__(self):
        return self.offset

    def __str__(self):
        return "0x{:08x}: ({:>4})".format(self.offset, self.length)
