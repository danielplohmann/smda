import logging
from typing import Any, Iterator, List, Optional

from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.arm.definitions import IT_MNEMONICS
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

LOGGER = logging.getLogger(__name__)


class SmdaInstruction:
    __slots__ = (
        "smda_function",
        "offset",
        "bytes",
        "mnemonic",
        "operands",
        "detailed",
        "_data_refs",
    )
    smda_function: Optional[Any]
    offset: Optional[int]
    bytes: Optional[str]
    mnemonic: Optional[str]
    operands: Optional[str]
    detailed: Optional[Any]
    _data_refs: Optional[List[int]]
    # x87 instructions have explicit-WAIT and no-WAIT encodings (e.g. FSTCW vs FNSTCW).
    # For the WAIT-prefixed form Capstone decodes the 0x9b prefix as a standalone
    # `wait`/`fwait` instruction, so it must be skipped when picking the operation detail.
    _WAIT_PREFIX_MNEMONICS = frozenset({"wait", "fwait"})

    def __init__(self, ins_list=None, smda_function=None):
        self.smda_function = smda_function
        self.offset = None
        self.bytes = None
        self.mnemonic = None
        self.operands = None
        self.detailed = None
        self._data_refs = None
        if ins_list is not None:
            self.offset = ins_list[0]
            self.bytes = ins_list[1]
            self.mnemonic = ins_list[2]
            self.operands = ins_list[3]

    @classmethod
    def from_tuple(cls, ins, smda_function=None):
        instruction = cls.__new__(cls)
        instruction.smda_function = smda_function
        instruction.offset = ins[0]
        instruction.bytes = ins[4].hex()
        mnemonic = ins[2]
        instruction.mnemonic = mnemonic if mnemonic.__class__ is str else str(mnemonic)
        operands = ins[3]
        instruction.operands = operands if operands.__class__ is str else str(operands)
        instruction.detailed = None
        instruction._data_refs = None
        return instruction

    def getDataRefs(self) -> Iterator[int]:
        # direct read rather than getattr(): __setstate__ fills every slot, which covers the
        # unpickled case the getattr guarded, and it keeps the declared Optional[List[int]]
        # instead of widening to Any
        data_refs_cached = self._data_refs
        if data_refs_cached is not None:
            yield from data_refs_cached
            return

        data_refs: List[int] = []
        emitted = set()
        smda_function = self.smda_function
        if smda_function is None:
            return
        smda_report = smda_function.smda_report
        if smda_report is None:
            return
        if smda_report.data_refs_from is not None and self.offset in smda_report.data_refs_from:
            for value in smda_report.data_refs_from[self.offset]:
                if value not in emitted:
                    emitted.add(value)
                    data_refs.append(value)
        if smda_report.architecture == "intel" and self.operands and "0x" in self.operands:
            if self.getMnemonicGroup(IntelInstructionEscaper) == "C":
                self._data_refs = data_refs
                yield from self._data_refs
                return
            detailed = self.getDetailed()
            if len(detailed.operands) > 0:
                for i in detailed.operands:
                    if i.type == X86_OP_IMM:
                        value = i.imm
                    elif i.type == X86_OP_MEM:
                        value = i.mem.disp
                        if detailed.reg_name(i.mem.base) == "rip":
                            # add RIP value
                            value += detailed.address + detailed.size
                    else:
                        # register/other operand kinds carry no address to dereference;
                        # a 0 placeholder would be a valid in-image address on a base-0 dump
                        continue
                    if value not in emitted and smda_report.isAddrWithinMemoryImage(value):
                        emitted.add(value)
                        data_refs.append(value)
        elif (
            smda_report.architecture == "aarch64"
            and not smda_report.data_refs_from
            and self.operands
            and "0x" in self.operands
        ):
            # AArch64 CFG recovery derives per-instruction data refs with this same
            # IMM/MEM(base==0)/in-image/not-in-code-area filter (AArch64Backend._recordDataRefs)
            # and stores them in the report as data_refs_from, so re-deriving them here via a
            # capstone re-decode is redundant whenever the report carries recorded refs. Only
            # fall back for reports without any (e.g. serialized by versions predating
            # xdata_refs_from).
            if self.getMnemonicGroup(AArch64InstructionEscaper) == "C":
                self._data_refs = data_refs
                yield from self._data_refs
                return
            detailed = self.getDetailed()
            for operand in detailed.operands:
                value = None
                if operand.type == ARM64_OP_IMM:
                    value = operand.imm
                elif operand.type == ARM64_OP_MEM and operand.mem.base == 0:
                    value = operand.mem.disp
                if (
                    value is not None
                    and value not in emitted
                    and smda_report.isAddrWithinMemoryImage(value)
                    and not any(start <= value < end for start, end in (smda_report.code_areas or []))
                ):
                    emitted.add(value)
                    data_refs.append(value)
        self._data_refs = data_refs
        yield from self._data_refs

    def __getstate__(self):
        # the cached capstone CsInsn holds ctypes pointers and cannot be pickled, so it is left
        # out and getDetailed() re-creates it on demand
        return {slot: getattr(self, slot, None) for slot in SmdaInstruction.__slots__ if slot != "detailed"}

    def __setstate__(self, state):
        # pickles written before __slots__ only carry the attributes that were set on the
        # instance, so a slot missing from the state falls back to None
        for slot in SmdaInstruction.__slots__:
            setattr(self, slot, None if slot == "detailed" else state.get(slot))

    def getDetailed(self):
        if self.smda_function is None or self.smda_function.smda_report is None:
            raise ValueError("SmdaFunction or SmdaReport not set on instruction")
        arch = self.smda_function.smda_report.architecture
        if arch is not None and arch not in {"intel", "aarch64", "arm"}:
            raise NotImplementedError(f"getDetailed() is only available for Intel, AArch64 and ARM, not '{arch}'")
        if self.detailed is None:
            thumb = False
            if arch == "arm":
                metadata = self.smda_function.architecture_metadata or {}
                thumb = len(self.bytes or "") == 4 or bool(metadata.get("thumb"))
                capstone = self.smda_function.smda_report.getCapstone(thumb=thumb)
            else:
                capstone = self.smda_function.smda_report.getCapstone()
            with_details = list(capstone.disasm(bytes.fromhex(self.bytes or ""), self.offset))
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
            if thumb and self.detailed.mnemonic != self.mnemonic:
                self.detailed = self._decodeInItBlock(capstone) or self.detailed
        return self.detailed

    def _decodeInItBlock(self, capstone):
        """Decode this T32 instruction together with the ``it`` up to four instructions before it.

        Capstone applies an IT instruction's conditions only to the instructions decoded in the
        same call (see ArmCapstone), so decoded alone, ``moveq`` reads as ``movs``.
        """
        address = self.offset
        smda_function = self.smda_function
        if address is None or smda_function is None:
            return None
        code = bytes.fromhex(self.bytes or "")
        for distance in range(1, 5):
            previous = None
            for size in (2, 4):
                candidate = smda_function.getInstructionAt(address - size)
                if candidate is not None and len(candidate.bytes or "") == 2 * size:
                    previous = candidate
                    address -= size
                    break
            if previous is None:
                return None
            try:
                code = bytes.fromhex(previous.bytes or "") + code
            except ValueError:
                return None
            if previous.mnemonic in IT_MNEMONICS:
                if distance >= len(previous.mnemonic):
                    return None
                return next((insn for insn in capstone.disasm(code, address) if insn.address == self.offset), None)
        return None

    def getMnemonicGroup(self, escaper):
        if escaper:
            if escaper is AArch64InstructionEscaper:
                return escaper.escapeMnemonicForInstruction(self)
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
    def fromDict(cls, instruction_dict, smda_function=None) -> "SmdaInstruction":
        smda_instruction = cls(None)
        smda_instruction.smda_function = smda_function
        smda_instruction.offset = instruction_dict[0]
        smda_instruction.bytes = instruction_dict[1]
        smda_instruction.mnemonic = instruction_dict[2]
        smda_instruction.operands = instruction_dict[3]
        return smda_instruction

    def toDict(self) -> list:
        return [self.offset, self.bytes, self.mnemonic, self.operands]

    def __int__(self):
        return self.offset

    def __str__(self):
        offset = f"0x{self.offset:08x}" if self.offset is not None else "0x????????"
        return f"{offset}: ({self.bytes or '':>14s}) - {self.mnemonic} {self.operands}"
