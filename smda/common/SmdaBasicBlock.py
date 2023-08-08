import struct
import hashlib

from smda.common.SmdaInstruction import SmdaInstruction


class SmdaBasicBlock:

    smda_function = None
    instructions = None
    picblockhash = None
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

    def getInstructions(self):
        for instruction in self.instructions:
            yield instruction

    def getPicBlockHash(self):
        """ if we have a SmdaFunction as parent, we can try to generate the PicBlockHash ad-hoc """
        # check all the prerequisites
        if self.picblockhash is not None:
            return self.picblockhash
        if self.smda_function and self.smda_function.smda_report and self.smda_function._escaper and self.smda_function.smda_report.base_addr is not None and self.smda_function.smda_report.binary_size:
            escaped_binary_seqs = []
            for instruction in self.getInstructions():
                escaped_binary_seqs.append(instruction.getEscapedBinary(self.smda_function._escaper, escape_intraprocedural_jumps=True, lower_addr=self.smda_function.smda_report.base_addr, upper_addr=self.smda_function.smda_report.base_addr + self.smda_function.smda_report.binary_size))
            as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seqs)])
            self.picblockhash = struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]
            return self.picblockhash
        return None

    @classmethod
    def fromDict(cls, block_dict, smda_function=None):
        smda_block = cls(None)
        smda_block.smda_function = smda_function
        smda_block.instructions = [SmdaInstruction.fromDict(d, smda_function=smda_function) for d in block_dict]
        return smda_block

    def toDict(self):
        return [smda_ins.toDict() for smda_ins in self.instructions]

    def __int__(self):
        return self.offset

    def __str__(self):
        return "0x{:08x}: ({:>4})".format(self.offset, self.length)
