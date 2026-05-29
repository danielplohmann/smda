import hashlib
import struct
from typing import Iterator

from smda.common.SmdaInstruction import SmdaInstruction


class SmdaBasicBlock:
    smda_function = None
    instructions = None
    _picblockhash = None
    _opcblockhash = None
    offset = None
    length = None

    def __init__(self, instructions, smda_function=None):
        assert isinstance(instructions, list)
        self.smda_function = smda_function
        self.instructions = instructions
        self.offset = instructions[0].offset if instructions else None
        self.length = len(instructions)
        self._picblockhash = None
        self._opcblockhash = None

    @property
    def picblockhash(self):
        if self._picblockhash is None:
            self.getPicBlockHash()
        return self._picblockhash

    @picblockhash.setter
    def picblockhash(self, value):
        self._picblockhash = value

    @property
    def opcblockhash(self):
        if self._opcblockhash is None:
            self.getOpcBlockHash()
        return self._opcblockhash

    @opcblockhash.setter
    def opcblockhash(self, value):
        self._opcblockhash = value

    def getInstructions(self) -> Iterator["SmdaInstruction"]:
        if self.instructions is None:
            return
        yield from self.instructions

    def getPicBlockHash(self):
        if self._picblockhash is not None:
            return self._picblockhash
        picblockhash_sequence = self.getPicBlockHashSequence()
        if picblockhash_sequence is not None:
            self._picblockhash = struct.unpack("<Q", hashlib.sha256(picblockhash_sequence).digest()[:8])[0]
        return self._picblockhash

    def getPicBlockHashSequence(self):
        """if we have a SmdaFunction as parent, we can try to generate the PicBlockHash ad-hoc"""
        # check all the prerequisites
        if (
            self.smda_function
            and self.smda_function.smda_report
            and self.smda_function._escaper
            and self.smda_function.smda_report.base_addr is not None
            and self.smda_function.smda_report.binary_size
        ):
            escaped_binary_seqs = []
            for instruction in self.getInstructions():
                escaped_binary_seqs.append(
                    instruction.getEscapedBinary(
                        self.smda_function._escaper,
                        escape_intraprocedural_jumps=True,
                        lower_addr=self.smda_function.smda_report.base_addr,
                        upper_addr=self.smda_function.smda_report.base_addr
                        + self.smda_function.smda_report.binary_size,
                    )
                )
            return "".join(escaped_binary_seqs).encode("ascii")

    def getOpcBlockHash(self):
        if self._opcblockhash is not None:
            return self._opcblockhash
        opcblockhash_sequence = self.getOpcBlockHashSequence()
        if opcblockhash_sequence is not None:
            self._opcblockhash = struct.unpack("<Q", hashlib.sha256(opcblockhash_sequence).digest()[:8])[0]
        return self._opcblockhash

    def getOpcBlockHashSequence(self):
        """if we have a SmdaFunction as parent, we can try to generate the OpcBlockHash ad-hoc"""
        # check all the prerequisites
        if self.smda_function and self.smda_function.smda_report and self.smda_function._escaper:
            escaped_binary_seqs = []
            for instruction in self.getInstructions():
                escaped_binary_seqs.append(instruction.getEscapedToOpcodeOnly(self.smda_function._escaper))
            return "".join(escaped_binary_seqs).encode("ascii")

    def getPredecessors(self):
        if self.smda_function is None:
            return []
        if self.smda_function._blockrefs_reverse is None:
            rev: dict = {}
            for frm, tos in self.smda_function.blockrefs.items():
                for to in tos:
                    rev.setdefault(to, []).append(frm)
            self.smda_function._blockrefs_reverse = rev
        return list(self.smda_function._blockrefs_reverse.get(self.offset, []))

    def getSuccessors(self):
        successors = []
        if self.smda_function is not None and self.offset in self.smda_function.blockrefs:
            successors.extend(self.smda_function.blockrefs[self.offset])
        return successors

    @classmethod
    def fromDict(cls, block_dict, smda_function=None) -> "SmdaBasicBlock":
        return cls([SmdaInstruction.fromDict(d, smda_function=smda_function) for d in block_dict], smda_function)

    def toDict(self) -> dict:
        if self.instructions is None:
            return []
        return [smda_ins.toDict() for smda_ins in self.instructions]

    def __int__(self):
        return self.offset

    def __str__(self):
        if self.offset is None:
            return f"0x????????: ({self.length:>4})"
        return f"0x{self.offset:08x}: ({self.length:>4})"
