

class CodeXref(object):

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
        return "0x%x (0x%x) -> 0x%x (0x%x)" % (self.smda_ins_from.offset, self.smda_ins_from.smda_function.offset, self.smda_ins_to.offset, self.smda_ins_to.smda_function.offset)

    def __repr__(self):
        return "<CodeXref(SmdaInstruction({}), SmdaInstruction({}))>".format(self.smda_ins_from.offset, self.smda_ins_to.offset)
