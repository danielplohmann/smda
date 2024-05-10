from typing import Optional
import logging

from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

LOGGER = logging.getLogger(__name__)


class SmdaInstruction:

    smda_function = None
    offset = None
    bytes = None
    mnemonic = None
    operands = None
    detailed = None

    def __init__(self, ins_list=None, smda_function=None):
        self.smda_function = smda_function
        if ins_list is not None:
            self.offset = ins_list[0]
            self.bytes = ins_list[1]
            self.mnemonic = ins_list[2]
            self.operands = ins_list[3]

    def getDataRefs(self):
        if self.getMnemonicGroup(IntelInstructionEscaper) != "C":
            detailed = self.getDetailed()
            if len(detailed.operands) > 0:
                for i in detailed.operands:
                    value = None
                    if i.type == X86_OP_IMM:
                        value = i.imm
                    if i.type == X86_OP_MEM:
                        value = i.mem.disp
                        if detailed.reg_name(i.mem.base) == "rip":
                            # add RIP value
                            value += detailed.address + detailed.size
                    if value is not None and self.smda_function.smda_report.isAddrWithinMemoryImage(value):
                        yield value

    def getDetailed(self):
        if self.detailed is None:
            capstone = self.smda_function.smda_report.getCapstone()
            with_details = [i for i in capstone.disasm(bytes.fromhex(self.bytes), self.offset)]
            # TODO
            # this may diverge on instructions like 
            # 9bd93c24 - 
            # <CsInsn 0x4d3f1f0 [9b]: wait >
            # 1 wait 
            # <CsInsn 0x4d3f1f1 [d93c24]: fnstcw word ptr [esp]>
            # 3 fnstcw word ptr [esp]
            # which is split by capstone but treated as one / prefix by IDA
            # https://fragglet.github.io/dos-help-files/alang.hlp/FLDCW.html
            # FSTCW has wait and no-wait versions. The wait version (FSTCW)
            # checks for unmasked numeric errors; the no-wait version (FNSTCW)
            # does not. When the .8087 directive is used, the assembler puts the
            # WAIT instruction before the wait version and the NOP instruction
            # before the no-wait version.
            if len(with_details) > 1:
                LOGGER.warn(f"Sequence {self.bytes} disassembles to {len(with_details)} instructions but expected one - taking the last instruction only!")
                self.detailed = with_details[-1]
            else:
                assert len(with_details) == 1
                self.detailed = with_details[0]
        return self.detailed

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

    def getEscapedToOpcodeOnly(self, escaper):
        if escaper:
            return escaper.escapeToOpcodeOnly(self)
        return self.bytes

    def getEscapedBinary(self, escaper, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        if escaper:
            return escaper.escapeBinary(self, escape_intraprocedural_jumps=escape_intraprocedural_jumps, lower_addr=lower_addr, upper_addr=upper_addr)
        return self.bytes

    @classmethod
    def fromDict(cls, instruction_dict, smda_function=None) -> Optional["SmdaInstruction"]:
        smda_instruction = cls(None)
        smda_instruction.smda_function = smda_function
        smda_instruction.offset = instruction_dict[0]
        smda_instruction.bytes = instruction_dict[1]
        smda_instruction.mnemonic = instruction_dict[2]
        smda_instruction.operands = instruction_dict[3]
        return smda_instruction

    def toDict(self) -> dict:
        return [self.offset, self.bytes, self.mnemonic, self.operands]

    def __int__(self):
        return self.offset

    def __str__(self):
        return "0x{:08x}: ({:>14s}) - {} {}".format(self.offset, self.bytes, self.mnemonic, self.operands)
