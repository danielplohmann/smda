import logging
from typing import Optional

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
    _data_refs = None
    # x87 instructions have explicit-WAIT and no-WAIT encodings (e.g. FSTCW vs FNSTCW).
    # For the WAIT-prefixed form Capstone decodes the 0x9b prefix as a standalone
    # `wait`/`fwait` instruction, so it must be skipped when picking the operation detail.
    _WAIT_PREFIX_MNEMONICS = frozenset({"wait", "fwait"})

    def __init__(self, ins_list=None, smda_function=None):
        self.smda_function = smda_function
        if ins_list is not None:
            self.offset = ins_list[0]
            self.bytes = ins_list[1]
            self.mnemonic = ins_list[2]
            self.operands = ins_list[3]

    def getDataRefs(self):
        if getattr(self, "_data_refs", None) is not None:
            yield from self._data_refs
            return

        data_refs = []
        emitted = set()
        smda_report = self.smda_function.smda_report
        if smda_report.data_refs_from is not None and self.offset in smda_report.data_refs_from:
            for value in smda_report.data_refs_from[self.offset]:
                if value not in emitted:
                    emitted.add(value)
                    data_refs.append(value)
        if (
            smda_report.architecture == "intel"
            and self.getMnemonicGroup(IntelInstructionEscaper) != "C"
            and self.operands
            and "0x" in self.operands
        ):
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
                    if value is not None and value not in emitted and smda_report.isAddrWithinMemoryImage(value):
                        emitted.add(value)
                        data_refs.append(value)
        self._data_refs = data_refs
        yield from self._data_refs

    def getDetailed(self):
        arch = self.smda_function.smda_report.architecture
        if arch is not None and arch != "intel":
            raise NotImplementedError(f"getDetailed() is only available for Intel architecture, not '{arch}'")
        if self.detailed is None:
            capstone = self.smda_function.smda_report.getCapstone()
            with_details = list(capstone.disasm(bytes.fromhex(self.bytes), self.offset))
            if not with_details:
                raise ValueError(f"Capstone could not disassemble stored bytes '{self.bytes}' at 0x{self.offset:x}")
            if len(with_details) == 1:
                self.detailed = with_details[0]
            else:
                # Capstone can split a single SMDA/IDA instruction whose bytes carry an x87
                # WAIT prefix, e.g. `9bd93c24` -> `wait` + `fnstcw word ptr [esp]`. The trailing
                # operation carries the operands and its (address + size) still reaches the end of
                # the stored byte span, so it is the span-consistent detail to return. We drop any
                # standalone WAIT/FWAIT prefix instruction(s) before selecting it.
                # See https://fragglet.github.io/dos-help-files/alang.hlp/FLDCW.html
                operation_insns = [insn for insn in with_details if insn.mnemonic not in self._WAIT_PREFIX_MNEMONICS]
                self.detailed = (operation_insns or with_details)[-1]
                if len(operation_insns) != 1:
                    # not the known WAIT-prefix pattern - surface the unexpected split
                    LOGGER.warning(
                        "Sequence %s disassembled to %d instructions (%s) but expected one - using '%s'.",
                        self.bytes,
                        len(with_details),
                        ", ".join(insn.mnemonic for insn in with_details),
                        self.detailed.mnemonic,
                    )
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

    def getEscapedBinary(
        self,
        escaper,
        escape_intraprocedural_jumps=False,
        lower_addr=None,
        upper_addr=None,
    ):
        if escaper:
            return escaper.escapeBinary(
                self,
                escape_intraprocedural_jumps=escape_intraprocedural_jumps,
                lower_addr=lower_addr,
                upper_addr=upper_addr,
            )
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
        return f"0x{self.offset:08x}: ({self.bytes:>14s}) - {self.mnemonic} {self.operands}"
