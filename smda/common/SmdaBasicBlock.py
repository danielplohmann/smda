from smda.common.SmdaInstruction import SmdaInstruction


class SmdaBasicBlock:

    smda_function = None
    instructions = None
    offset = None
    length = None

    def __init__(self, instructions, smda_function=None):
        assert isinstance(instructions, list)
        self.smda_function = smda_function
        if instructions:
            self.instructions = instructions
            self.offset = instructions[0].offset
            self.length = len(instructions)

    def getInstructions(self):
        for instruction in self.instructions:
            yield instruction

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
