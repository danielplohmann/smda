class SmdaInstruction:

    def __init__(self, ins_list):
        self.offset = ins_list[0]
        self.bytes = ins_list[1]
        self.mnemonic = ins_list[2]
        self.operands = ins_list[3]

    def getMnemonicGroup(self, escaper):
        return escaper.escapeMnemonic(self.mnemonic)

    def getEscapedOperands(self, escaper):
        return escaper.escapeOperands(self)

    def getMaskedOperands(self, escaper):
        return escaper.escapeOperands(self, offsets_only=True)

    def getEscapedBinary(self, escaper, lower_addr=None, upper_addr=None):
        return escaper.escapeBinary(self, lower_addr=lower_addr, upper_addr=upper_addr)

    def __str__(self):
        return "0x{:08x}: ({}) - {} {}".format(self.offset, self.bytes, self.mnemonic, self.operands)
