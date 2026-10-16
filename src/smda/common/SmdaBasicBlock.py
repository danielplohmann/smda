import hashlib
import struct
from typing import TYPE_CHECKING, Any, Iterator, List, Optional

from smda.common.SmdaInstruction import SmdaInstruction

if TYPE_CHECKING:
    from smda.common.SmdaFunction import SmdaFunction

# sentinel distinguishing "hash not yet computed" from "hash computed as None (uncomputable)"
_UNSET = object()


class SmdaBasicBlock:
    __slots__ = (
        "smda_function",
        "instructions",
        "_picblockhash",
        "_opcblockhash",
        "offset",
        "length",
    )
    smda_function: Optional["SmdaFunction"]
    instructions: Optional[List[SmdaInstruction]]
    _picblockhash: Any
    _opcblockhash: Any
    offset: Optional[int]
    length: Optional[int]

    def __init__(self, instructions, smda_function=None):
        assert isinstance(instructions, list)
        self.smda_function = smda_function
        self.instructions = instructions
        self.offset = instructions[0].offset if instructions else None
        self.length = len(instructions)
        self._picblockhash = _UNSET
        self._opcblockhash = _UNSET

    def __getstate__(self):
        # an uncomputed hash is left out: the _UNSET sentinel would not survive pickling as
        # itself, and a copy of it would read as an already computed hash
        state = {slot: getattr(self, slot, None) for slot in self.__slots__}
        for slot in ("_picblockhash", "_opcblockhash"):
            if state[slot] is _UNSET:
                del state[slot]
        return state

    def __setstate__(self, state):
        for slot in self.__slots__:
            setattr(self, slot, state.get(slot))
        for slot in ("_picblockhash", "_opcblockhash"):
            value = state.get(slot, _UNSET)
            # pickles written before __slots__ carry a copy of the sentinel as a bare object()
            setattr(self, slot, _UNSET if type(value) is object else value)

    @property
    def picblockhash(self):
        return self.getPicBlockHash()

    @property
    def opcblockhash(self):
        return self.getOpcBlockHash()

    def getInstructions(self) -> Iterator["SmdaInstruction"]:
        if self.instructions is None:
            return
        yield from self.instructions

    def getPicBlockHash(self):
        if self._picblockhash is _UNSET:
            picblockhash_sequence = self.getPicBlockHashSequence()
            self._picblockhash = (
                struct.unpack("<Q", hashlib.sha256(picblockhash_sequence).digest()[:8])[0]
                if picblockhash_sequence is not None
                else None
            )
        return self._picblockhash

    def getPicBlockHashSequence(self):
        """if we have a SmdaFunction as parent, we can try to generate the PicBlockHash ad-hoc"""
        if not self.instructions:
            return None
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
        if self._opcblockhash is _UNSET:
            opcblockhash_sequence = self.getOpcBlockHashSequence()
            self._opcblockhash = (
                struct.unpack("<Q", hashlib.sha256(opcblockhash_sequence).digest()[:8])[0]
                if opcblockhash_sequence is not None
                else None
            )
        return self._opcblockhash

    def getOpcBlockHashSequence(self):
        """if we have a SmdaFunction as parent, we can try to generate the OpcBlockHash ad-hoc"""
        if not self.instructions:
            return None
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

    def toDict(self) -> list:
        if self.instructions is None:
            return []
        return [smda_ins.toDict() for smda_ins in self.instructions]

    def __int__(self):
        return self.offset

    def __str__(self):
        if self.offset is None:
            return f"0x????????: ({self.length:>4})"
        return f"0x{self.offset:08x}: ({self.length:>4})"
