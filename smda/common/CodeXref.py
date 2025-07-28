class CodeXref:
    def __init__(self, smda_ins_from, smda_ins_to):
        self.smda_ins_from = smda_ins_from
        self.smda_ins_to = smda_ins_to

    @property
    def from_function(self):
        return self.smda_ins_from.smda_function

    @property
    def to_function(self):
        return self.smda_ins_to.smda_function

    @property
    def from_instruction(self):
        return self.smda_ins_from

    @property
    def to_instruction(self):
        return self.smda_ins_to

    def __str__(self):
        return f"0x{self.smda_ins_from.offset:x} (0x{self.smda_ins_from.smda_function.offset:x}) -> 0x{self.smda_ins_to.offset:x} (0x{self.smda_ins_to.smda_function.offset:x})"

    def __repr__(self):
        return f"<CodeXref(SmdaInstruction({self.smda_ins_from.offset}), SmdaInstruction({self.smda_ins_to.offset}))>"
