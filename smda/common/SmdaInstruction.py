class SmdaInstruction:

    offset = None
    bytes = None
    mnemonic = None
    operands = None

    def __init__(self, ins_list=None):
        if ins_list is not None:
            self.offset = ins_list[0]
            self.bytes = ins_list[1]
            self.mnemonic = ins_list[2]
            self.operands = ins_list[3]

    def getMnemonicGroup(self, escaper):
        if escaper:
            return escaper.escapeMnemonic(self.mnemonic)
        return self.bytes

    def getEscapedOperands(self, escaper):
        if escaper:
            return escaper.escapeOperands(self)
        return self.bytes

    def getMaskedOperands(self, escaper):
        if escaper:
            return escaper.escapeOperands(self, offsets_only=True)
        return self.bytes

    def getEscapedBinary(self, escaper, lower_addr=None, upper_addr=None):
        if escaper:
            return escaper.escapeBinary(self, lower_addr=lower_addr, upper_addr=upper_addr)
        return self.bytes

    @classmethod
    def fromDict(cls, instruction_dict):
        smda_instruction = cls(None)
        smda_instruction.offset = instruction_dict[0]
        smda_instruction.bytes = instruction_dict[1]
        smda_instruction.mnemonic = instruction_dict[2]
        smda_instruction.operands = instruction_dict[3]
        return smda_instruction

    def toDict(self):
        return [self.offset, self.bytes, self.mnemonic, self.operands]

    def __str__(self):
        return "0x{:08x}: ({:>14s}) - {} {}".format(self.offset, self.bytes, self.mnemonic, self.operands)
