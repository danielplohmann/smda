#!/usr/bin/env python3
import bisect
import hashlib
import logging
import re
import struct
from typing import Any, Dict, List, Optional

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.aarch64.definitions import CALL_INS as AARCH64_CALL_INS
from smda.aarch64.definitions import EXCEPTION_RETURN_INS as AARCH64_EXCEPTION_RETURN_INS
from smda.aarch64.definitions import INDIRECT_JUMP_INS as AARCH64_INDIRECT_JUMP_INS
from smda.aarch64.definitions import RET_INS as AARCH64_RET_INS
from smda.aarch64.definitions import UNCOND_JUMP_INS as AARCH64_UNCOND_JUMP_INS
from smda.cil.CilInstructionEscaper import CilInstructionEscaper
from smda.common.CodeXref import CodeXref
from smda.common.DominatorTree import build_dominator_tree, get_nesting_depth
from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.SmdaBasicBlock import SmdaBasicBlock
from smda.common.Tarjan import Tarjan
from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .SmdaInstruction import SmdaInstruction

LOGGER = logging.getLogger(__name__)

# AArch64 PIC hashing changed in 4.1.0 when control-flow opcode masking was unified,
# and again in 4.2.0 when `escapeBinary` was made per-mnemonic immediate-aware
# (nibble-keep-mask) so that relocated instructions produce the same pic_hash.
AARCH64_PIC_HASH_ESCAPE_VERSION = [4, 2, 0]

# Intel PIC hashing changed in 4.3.5 when escapeBinary's immediate regex was widened
# to match 64-bit immediates (previously truncated to the first 8 hex digits, so an
# in-image mov r64, imm64 constant was never escaped and stayed relocation-variant).
INTEL_PIC_HASH_ESCAPE_VERSION = [4, 3, 5]

# CIL PIC hashing changed in 4.3.8 when escapeBinary was made operand-type-driven,
# adding token wildcarding for ldstr/cpobj/ldelema/ldelem/stelem/ldvirtftn/sizeof
# and branch wildcarding for leave/leave.s. Older reports have metadata-token bytes
# leaking into pic_hash and need to be recomputed.
CIL_PIC_HASH_ESCAPE_VERSION = [4, 3, 8]

# Dalvik PIC hashing introduced format-aware pool/imm/branch masking via
# DalvikInstructionEscaper in 4.3.10, and changed again in 4.4.2 when
# escape_intraprocedural_jumps was corrected: it had been inverted relative to the Intel
# and CIL escapers, clearing the mask for the branch-only formats (10t/20t/21t/22t/30t)
# on the pic_hash path and so retaining the raw signed branch offset. Older reports have
# position-dependent Dalvik pic_hash values and must recalculate on import.
DALVIK_PIC_HASH_ESCAPE_VERSION = [4, 4, 2]

MAX_ADDRESS_VALUE = 1 << 64
REQUIRED_FUNCTION_FIELDS = frozenset({"offset", "blocks", "apirefs", "blockrefs", "inrefs", "outrefs", "metadata"})
REQUIRED_FUNCTION_METADATA = frozenset(
    {"binweight", "characteristics", "confidence", "function_name", "strongly_connected_components", "tfidf"}
)


class LazyIntKeyDict(dict):
    def __new__(cls, data=None):
        # Pickle reconstructs dict subclasses via __new__ + update, bypassing
        # __init__, so the lazy-conversion state must be initialized here to
        # survive being passed to a multiprocessing worker.
        instance = super().__new__(cls)
        instance._is_converted = True
        instance._raw_data = None
        return instance

    def __init__(self, data=None):
        if data:
            for k, v in data.items():
                dict.__setitem__(self, int(k), v)
            self._is_converted = True
            self._raw_data = None
        else:
            dict.__init__(self)
            self._is_converted = True

    def _convert(self):
        if not self._is_converted and self._raw_data is not None:
            for k, v in self._raw_data.items():
                dict.__setitem__(self, int(k), v)
            self._is_converted = True
            self._raw_data = None

    def __getitem__(self, key):
        self._convert()
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        self._convert()
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        self._convert()
        dict.__delitem__(self, key)

    def __iter__(self):
        self._convert()
        return dict.__iter__(self)

    def __len__(self):
        if not self._is_converted:
            return len(self._raw_data) if self._raw_data is not None else 0
        return dict.__len__(self)

    def __contains__(self, key):
        self._convert()
        return dict.__contains__(self, key)

    def __eq__(self, other):
        self._convert()
        if isinstance(other, LazyIntKeyDict):
            other._convert()
        return dict.__eq__(self, other)

    def __ne__(self, other):
        self._convert()
        if isinstance(other, LazyIntKeyDict):
            other._convert()
        return dict.__ne__(self, other)

    def __repr__(self):
        self._convert()
        return dict.__repr__(self)

    def get(self, key, default=None):
        self._convert()
        return dict.get(self, key, default)

    def items(self):
        self._convert()
        return dict.items(self)

    def keys(self):
        self._convert()
        return dict.keys(self)

    def values(self):
        self._convert()
        return dict.values(self)

    def copy(self):
        self._convert()
        return dict.copy(self)


class SmdaFunction:
    smda_report = None
    offset: Optional[int] = None
    # Class-level defaults are immutable sentinels only; every real instance rebinds
    # these to fresh containers in __init__ (a mutable class default would be shared
    # by every SmdaFunction). They stay declared here because tests build instances
    # via __new__, bypassing __init__.
    blocks: Dict[int, List[Any]] = {}
    _sorted_block_keys: List[int] = []
    apirefs: Dict[int, Any] = {}
    stringrefs: Dict[int, Any] = {}
    blockrefs: Dict[int, Any] = {}
    _blockrefs_reverse = None
    _normalized_blockrefs = None
    inrefs: List[int] = []
    outrefs: Dict[int, Any] = {}
    code_inrefs = None
    code_outrefs = None
    is_exported = False
    architecture_metadata: Dict[str, Any] = {}
    # metadata
    binweight = 0
    characteristics: Optional[str] = ""
    confidence: Optional[float] = 0.0
    function_name = ""
    pic_hash = None
    opc_hash = None
    _escaper = None
    nesting_depth = 0
    strongly_connected_components = None
    tfidf = None

    def __init__(self, disassembly=None, function_offset=None, config=None, smda_report=None):
        self.smda_report = smda_report
        self.nesting_depth = 0
        self._normalized_blockrefs = None
        self._exception_blockrefs = None
        self._basic_blocks = None
        # fresh per-instance containers, never the shared class-level defaults
        self.blocks = {}
        self._sorted_block_keys = []
        self.apirefs = {}
        self.stringrefs = {}
        self.blockrefs = {}
        self.inrefs = []
        self.outrefs = {}
        self.architecture_metadata = {}
        if disassembly is not None and function_offset is not None:
            binary_info = disassembly.binary_info
            architecture = binary_info.architecture if binary_info is not None else None
            self._escaper = self.getInstructionEscaper(architecture)
            self.offset = function_offset
            self._parseBlocksFromTuples(disassembly.functions.get(function_offset, []))
            self.apirefs = disassembly.getApiRefs(function_offset)
            self.blockrefs = disassembly.getBlockRefs(function_offset)
            self.inrefs = disassembly.getInRefs(function_offset)
            self.outrefs = disassembly.getOutRefs(function_offset)
            self.is_exported = self.offset in disassembly.exported_functions
            self.architecture_metadata = disassembly.function_metadata.get(function_offset, {})
            self.blockrefs = self.getNormalizedBlockRefs()
            self.function_name = disassembly.function_symbols.get(function_offset, "")
            self.characteristics = (
                disassembly.candidates[function_offset].getCharacteristics()
                if function_offset in disassembly.candidates
                else None
            )
            self.confidence = (
                disassembly.candidates[function_offset].getConfidence()
                if function_offset in disassembly.candidates
                else None
            )
            self.tfidf = (
                disassembly.candidates[function_offset].getTfIdf()
                if function_offset in disassembly.candidates
                else None
            )
            # DEX strings are part of the parsed file structure, so they're always
            # populated for Dalvik regardless of WITH_STRINGS — no extra extraction
            # cost. For other architectures, honor WITH_STRINGS as usual.
            is_dalvik_with_strings = architecture == "dalvik" and disassembly.getStringRefsForFunction(function_offset)
            if (config and config.WITH_STRINGS) or is_dalvik_with_strings:
                self.stringrefs = (
                    self._normalizeDalvikStringRefs(disassembly.getStringRefsForFunction(function_offset))
                    if architecture == "dalvik"
                    else disassembly.getStringRefsForFunction(function_offset)
                )
            if config and config.CALCULATE_HASHING and binary_info is not None:
                self.pic_hash = self.getPicHash(binary_info)
            if config and config.CALCULATE_SCC:
                self.strongly_connected_components = self._calculateSccs()
            if config and config.CALCULATE_NESTING:
                self.nesting_depth = self._calculateNestingDepth()

    @property
    def num_edges(self):
        return sum(len(value) for value in self.blockrefs.values())

    @staticmethod
    def getInstructionEscaper(architecture):
        if architecture == "intel":
            return IntelInstructionEscaper
        if architecture == "aarch64":
            return AArch64InstructionEscaper
        if architecture == "cil":
            return CilInstructionEscaper
        if architecture == "dalvik":
            return DalvikInstructionEscaper
        return None

    @property
    def num_inrefs(self):
        return len(self.inrefs)

    @property
    def num_outrefs(self):
        return sum(len(dsts) for dsts in self.outrefs.values())

    @property
    def num_blocks(self):
        return len(self.blocks)

    @property
    def num_instructions(self):
        return sum(len(block) for block in self.blocks.values())

    @staticmethod
    def _baseMnemonic(mnemonic):
        # capstone prepends mandatory prefixes (bnd/rep/lock/...) to the mnemonic string
        return mnemonic.split(" ")[-1]

    @property
    def num_calls(self):
        architecture = self.smda_report.architecture if self.smda_report else ""
        if architecture == "dalvik":
            return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic.startswith("invoke-"))
        if architecture == "aarch64":
            call_mnemonics = AARCH64_CALL_INS
        elif architecture == "cil":
            call_mnemonics = {"call", "calli", "callvirt"}
        else:
            call_mnemonics = {"call"}
        return sum(
            1 for block in self.blocks.values() for ins in block if self._baseMnemonic(ins.mnemonic) in call_mnemonics
        )

    @property
    def num_returns(self):
        architecture = self.smda_report.architecture if self.smda_report else ""
        if architecture == "dalvik":
            return sum(1 for block in self.blocks.values() for ins in block if ins.mnemonic.startswith("return"))
        if architecture == "aarch64":
            return_mnemonics = AARCH64_RET_INS | AARCH64_EXCEPTION_RETURN_INS
        else:
            return_mnemonics = {"ret", "retn"}
        return sum(
            1 for block in self.blocks.values() for ins in block if self._baseMnemonic(ins.mnemonic) in return_mnemonics
        )

    # AArch64 PLT/Mach-O import stubs: optional bti/nop, then adrp + add/ldr + br.
    # Kept intentionally tight so ordinary short functions with an API call are not
    # misclassified as thunks.
    _AARCH64_API_THUNK_BODY = frozenset(
        {
            "adrp",
            "adr",
            "add",
            "ldr",
            "nop",
            "bti",
            "autia1716",
            "autib1716",
        }
    )
    _AARCH64_API_THUNK_MAX_INSNS = 8

    def isApiThunk(self):
        if not self.apirefs:
            return False
        architecture = self.smda_report.architecture if self.smda_report else ""
        if architecture == "aarch64":
            return self._isAArch64ApiThunk()
        if self.num_instructions != 1:
            return False
        if self.offset is None:
            return False
        block = self.blocks.get(self.offset)
        if not block:
            return False
        first_ins = block[0]
        if architecture == "dalvik":
            return first_ins.mnemonic.startswith("invoke-")
        mnemonic = self._baseMnemonic(first_ins.mnemonic)
        if architecture == "cil":
            return mnemonic in ("call", "calli", "callvirt", "jmp")
        return mnemonic in ("jmp", "call")

    def _isAArch64ApiThunk(self):
        # Import stubs are a single straight-line block ending in a transfer that
        # carries the API ref (single b/br, or multi-insn adrp+ldr+br PLT shape).
        if self.num_blocks != 1 or self.num_instructions > self._AARCH64_API_THUNK_MAX_INSNS:
            return False
        block = self.blocks.get(self.offset)
        if not block:
            return False
        transfer = AARCH64_CALL_INS | AARCH64_UNCOND_JUMP_INS | AARCH64_INDIRECT_JUMP_INS
        last = block[-1]
        if self._baseMnemonic(last.mnemonic) not in transfer:
            return False
        if not any(ins.offset in self.apirefs and self._baseMnemonic(ins.mnemonic) in transfer for ins in block):
            return False
        return all(self._baseMnemonic(ins.mnemonic) in self._AARCH64_API_THUNK_BODY for ins in block[:-1])

    def isExported(self):
        return self.is_exported

    def getBlocks(self) -> List["SmdaBasicBlock"]:
        if self._basic_blocks is None:
            self._basic_blocks = [
                SmdaBasicBlock(self.blocks[key], smda_function=self) for key in self._sorted_block_keys
            ]
        return self._basic_blocks

    def getPicHashAsLong(self):
        return self.pic_hash

    def getPicHashAsHex(self):
        if self.pic_hash is None:
            return None
        return struct.pack("<Q", self.pic_hash).hex()

    def getInstructions(self):
        for block in self.getBlocks():
            yield from block.getInstructions()

    def getInstructionsForBlock(self, offset) -> List["SmdaInstruction"]:
        if offset is None:
            offset = self.offset
        if offset is None:
            return []
        if offset not in self.blocks:
            return []
        return self.blocks[offset]

    def getCodeInrefs(self):
        self.smda_report.initCodeXrefs()
        if self.code_inrefs is None:
            self.code_inrefs = []
            own_instruction = self.smda_report._offset2ins.get(self.offset)
            if own_instruction is not None:
                for inref in self.inrefs:
                    if inref in self.smda_report._offset2ins:
                        self.code_inrefs.append(CodeXref(self.smda_report._offset2ins[inref], own_instruction))
        yield from self.code_inrefs

    def getCodeOutrefs(self):
        self.smda_report.initCodeXrefs()
        if self.code_outrefs is None:
            self.code_outrefs = []
            for outref_src, outref_dsts in self.outrefs.items():
                source_instruction = self.smda_report._offset2ins.get(outref_src)
                if source_instruction is None:
                    continue
                for target in outref_dsts:
                    if target in self.smda_report._offset2ins:
                        self.code_outrefs.append(CodeXref(source_instruction, self.smda_report._offset2ins[target]))
        yield from self.code_outrefs

    def _calculateSccs(self):
        tarjan = Tarjan(self.getNormalizedBlockRefs())
        tarjan.calculateScc()
        return tarjan.getResult()

    def _calculateNestingDepth(self):
        nesting_depth = 0
        try:
            normalized_blockrefs = self.getNormalizedBlockRefs()
            root = self._getCfgRoot(normalized_blockrefs)
            if normalized_blockrefs and root is not None:
                tree = build_dominator_tree(normalized_blockrefs, root)
                if tree:
                    nesting_depth = get_nesting_depth(normalized_blockrefs, tree, root)
        except Exception as exc:
            reraise_non_operational_exception(exc)
        return nesting_depth

    def getPicHash(self, binary_info):
        return struct.unpack("<Q", hashlib.sha256(self.getPicHashSequence(binary_info)).digest()[:8])[0]

    def getPicHashSequence(self, binary_info):
        escaped_binary_seqs = []
        for key in self._sorted_block_keys:
            for instruction in self.blocks[key]:
                escaped_binary_seqs.append(
                    instruction.getEscapedBinary(
                        self._escaper,
                        escape_intraprocedural_jumps=True,
                        lower_addr=binary_info.base_addr,
                        upper_addr=binary_info.base_addr + binary_info.binary_size,
                    )
                )
        return "".join(escaped_binary_seqs).encode("ascii")

    def getOpcHash(self):
        return struct.unpack("<Q", hashlib.sha256(self.getOpcHashSequence()).digest()[:8])[0]

    def getOpcHashSequence(self):
        escaped_binary_seqs = []
        for key in self._sorted_block_keys:
            for instruction in self.blocks[key]:
                escaped_binary_seqs.append(instruction.getEscapedToOpcodeOnly(self._escaper))
        return "".join(escaped_binary_seqs).encode("ascii")

    def _parseBlocksFromTuples(self, disasm_blocks):
        """Build SmdaInstructions straight from the raw disassembly tuples.

        getBlocksAsDict() allocates one intermediate 4-element list per instruction plus a list
        and dict entry per block, only to have them consumed immediately here. The transform is
        inlined rather than removed - the stored bytes remain the same hex string and the str()
        coercions are preserved, because the IDA path may hand back non-str mnemonics/operands.
        Precedent for bypassing it: the TF-IDF scoring pass in RecursiveDisassembler.
        """
        self.blocks = {}
        for block in disasm_blocks:
            instructions = []
            block_start = block[0][0]
            for ins_addr, _, ins_mnem, ins_ops, ins_raw_bytes in block:
                instructions.append(
                    SmdaInstruction([ins_addr, ins_raw_bytes.hex(), str(ins_mnem), str(ins_ops)], smda_function=self)
                )
            self.blocks[block_start] = instructions
            self.binweight += sum(len(ins.bytes or "") / 2 for ins in instructions)
        self._sorted_block_keys = sorted(self.blocks.keys())
        # invalidate any cached SmdaBasicBlock objects built from a previous block set
        self._basic_blocks = None

    @staticmethod
    def _normalizeDalvikStringRefs(stringrefs: Any):
        if not stringrefs:
            return []
        if isinstance(stringrefs, list):
            return stringrefs
        if isinstance(stringrefs, dict):
            items: List[Any] = sorted(stringrefs.items())
            return [
                {
                    "string": string_value,
                    "ins_addr": int(referencing_addr),
                    "data_addr": None,
                    "type": "dex",
                }
                for referencing_addr, string_value in items
            ]
        return stringrefs

    def _getContainingBlockStart(self, instruction_addr):
        if not self._sorted_block_keys:
            return None
        idx = bisect.bisect_right(self._sorted_block_keys, instruction_addr)
        if idx > 0:
            block_start = self._sorted_block_keys[idx - 1]
            block = self.blocks[block_start]
            if block:
                block_end = (block[-1].offset or 0) + (len(block[-1].bytes or "") // 2)
                if instruction_addr < block_end:
                    return block_start
        return None

    def _getCfgRoot(self, normalized_blockrefs):
        if self.offset in normalized_blockrefs:
            return self.offset
        block_start = self._getContainingBlockStart(self.offset)
        if block_start is not None:
            return block_start
        if normalized_blockrefs:
            # No entry block found for self.offset — refuse to fabricate a root,
            # since dominator/nesting derived from a wrong root is silently misleading.
            LOGGER.warning(
                "Normalized CFG for %s (0x%x) has no entry block; skipping root-dependent analysis.",
                self.function_name or "<unnamed>",
                self.offset,
            )
            return None
        LOGGER.warning("Normalized CFG for %s (0x%x) is empty.", self.function_name or "<unnamed>", self.offset)
        return None

    def getNormalizedBlockRefs(self):
        if getattr(self, "_normalized_blockrefs", None) is not None:
            return self._normalized_blockrefs

        current_blockrefs = self.blockrefs or {}
        normalized_blockrefs = {}

        # 1. Preprocess active try ranges and prepare all normalized targets
        try_ranges = self.architecture_metadata.get("try_ranges", []) if self.architecture_metadata else []
        active_try_ranges: List[Dict[str, Any]] = []
        for try_range in try_ranges:
            raw_targets = []
            for handler in try_range.get("handlers", []):
                target_addr = handler.get("target_addr") if isinstance(handler, dict) else None
                if target_addr is not None:
                    raw_targets.append(target_addr)
            if try_range.get("catch_all_addr") is not None:
                raw_targets.append(try_range["catch_all_addr"])
            if not raw_targets:
                continue
            range_start = try_range.get("start_addr")
            range_end = try_range.get("end_addr")
            if range_start is None or range_end is None:
                continue

            normalized_targets = set()
            for target_addr in raw_targets:
                block_start = self._getContainingBlockStart(target_addr)
                if block_start is None:
                    block_start = target_addr
                normalized_targets.add(block_start)

            active_try_ranges.append({"start": range_start, "end": range_end, "targets": normalized_targets})

        # 2. Iterate blocks once to build normalized_blockrefs and apply try_ranges
        for block_start, block in self.blocks.items():
            successors = set(current_blockrefs.get(block_start, []))
            if block:
                block_end = (block[-1].offset or 0) + (len(block[-1].bytes or "") // 2)
                for r in active_try_ranges:
                    if r["start"] < block_end and block_start < r["end"]:
                        successors.update(r["targets"])
            normalized_blockrefs[block_start] = sorted(successors)

        # 3. Ensure any targets that are not in self.blocks are also keys in normalized_blockrefs
        for r in active_try_ranges:
            for target in r["targets"]:
                if target not in normalized_blockrefs:
                    normalized_blockrefs[target] = []

        result = {block_start: normalized_blockrefs[block_start] for block_start in sorted(normalized_blockrefs)}
        self._normalized_blockrefs = result
        return result

    def getExceptionEdges(self):
        """Instruction-level typed exception edges from architecture_metadata (Dalvik)."""
        if not self.architecture_metadata:
            return []
        return list(self.architecture_metadata.get("exception_edges") or [])

    def getExceptionBlockRefs(self):
        """
        Block-level map: source_block_start -> sorted list of exception successor blocks.

        Built from typed exception_edges (kind=exception) rather than ordinary blockrefs,
        so consumers can distinguish exceptional control flow from normal/branch edges.
        """
        if getattr(self, "_exception_blockrefs", None) is not None:
            return self._exception_blockrefs
        exception_blockrefs = {}
        for edge in self.getExceptionEdges():
            if not isinstance(edge, dict) or edge.get("kind") != "exception":
                continue
            from_addr = edge.get("from_addr")
            to_addr = edge.get("to_addr")
            if from_addr is None or to_addr is None:
                continue
            src_block = self._getContainingBlockStart(from_addr)
            if src_block is None:
                src_block = from_addr
            dst_block = self._getContainingBlockStart(to_addr)
            if dst_block is None:
                dst_block = to_addr
            exception_blockrefs.setdefault(src_block, set()).add(dst_block)
        result = {block: sorted(targets) for block, targets in sorted(exception_blockrefs.items())}
        self._exception_blockrefs = result
        return result

    def toDotGraph(self, with_api=False):
        dot_graph = f'digraph "CFG for 0x{self.offset:x}" {{\n'
        dot_graph += f'  label="CFG for 0x{self.offset:x}";\n'
        for smda_block in self.getBlocks():
            block_entry = f'  Node0x{smda_block.offset:x} [shape=record,label="'
            instructions_as_strings = []
            for smda_ins in smda_block.getInstructions():
                printable_api = ""
                if with_api:
                    apiref_str = self.apirefs.get(smda_ins.offset, "")
                    if apiref_str:
                        printable_api = f"[{apiref_str}]"
                if printable_api:
                    instructions_as_strings.append(f"{smda_ins.offset:x}: {smda_ins.mnemonic} {printable_api}")
                else:
                    instructions_as_strings.append(f"{smda_ins.offset:x}: {smda_ins.mnemonic} {smda_ins.operands}")
            block_entry += r"\l".join(instructions_as_strings)
            dot_graph += block_entry + '"];\n'
            if smda_block.offset in self.blockrefs:
                for target_offset in self.blockrefs[smda_block.offset]:
                    dot_graph += f"  Node0x{smda_block.offset:x} -> Node0x{target_offset:x};\n"
        dot_graph += "}"
        return dot_graph

    @classmethod
    def fromDict(cls, function_dict, binary_info=None, version=None, smda_report=None) -> "SmdaFunction":
        if not isinstance(function_dict, dict):
            raise ValueError("serialized function must be a dictionary")
        if not REQUIRED_FUNCTION_FIELDS.issubset(function_dict):
            raise ValueError("serialized function is incomplete")
        blocks = function_dict.get("blocks")
        if not isinstance(blocks, dict):
            raise ValueError("serialized function blocks must be a dictionary")
        for block in blocks.values():
            if not isinstance(block, list):
                raise ValueError("serialized basic block must be a list")
            if any(
                not isinstance(instruction, (list, tuple))
                or len(instruction) < 4
                or not isinstance(instruction[0], int)
                or not 0 <= instruction[0] < MAX_ADDRESS_VALUE
                or any(not isinstance(field, str) for field in instruction[1:4])
                for instruction in block
            ):
                raise ValueError("serialized instruction must contain four fields")
        for reference_field in ("apirefs", "blockrefs", "outrefs"):
            references = function_dict.get(reference_field)
            if not isinstance(references, dict):
                raise ValueError(f"serialized function {reference_field} must be a dictionary")
            if reference_field in ("blockrefs", "outrefs") and any(
                not isinstance(targets, (list, tuple)) or not all(isinstance(target, int) for target in targets)
                for targets in references.values()
            ):
                raise ValueError(f"serialized function {reference_field} must map addresses to lists")
        if not isinstance(function_dict.get("inrefs"), list):
            raise ValueError("serialized function inrefs must be a list")
        metadata = function_dict.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("serialized function metadata must be a dictionary")
        if not REQUIRED_FUNCTION_METADATA.issubset(metadata):
            raise ValueError("serialized function metadata is incomplete")
        architecture_metadata = function_dict.get("architecture_metadata", {})
        if not isinstance(architecture_metadata, dict):
            raise ValueError("serialized function architecture metadata must be a dictionary")
        # checked after the container shape so each malformed field reports itself
        addresses = [function_dict["offset"], *(int(address) for address in blocks)]
        if any(isinstance(a, bool) or not isinstance(a, int) or not 0 <= a < MAX_ADDRESS_VALUE for a in addresses):
            raise ValueError("serialized function addresses must be in the 64-bit space")
        smda_function = cls(None)
        smda_function.smda_report = smda_report
        smda_function.offset = function_dict["offset"]
        smda_function.blocks = {}
        for addr, block in blocks.items():
            smda_function.blocks[int(addr)] = [SmdaInstruction.fromDict(ins, smda_function) for ins in block]
        smda_function._sorted_block_keys = sorted(smda_function.blocks.keys())
        smda_function._basic_blocks = None
        smda_function.apirefs = LazyIntKeyDict(function_dict["apirefs"])
        smda_function.blockrefs = LazyIntKeyDict(function_dict["blockrefs"])
        smda_function.inrefs = function_dict["inrefs"]
        smda_function.outrefs = LazyIntKeyDict(function_dict["outrefs"])
        # provide some legacy support by assuming functions are not exported for SMDA reports < 1.7.0
        smda_function.is_exported = function_dict.get("is_exported", False)
        smda_function.architecture_metadata = architecture_metadata
        smda_function.blockrefs = smda_function.getNormalizedBlockRefs()
        smda_function.binweight = metadata["binweight"]
        smda_function.characteristics = metadata["characteristics"]
        smda_function.confidence = metadata["confidence"]
        smda_function.function_name = metadata["function_name"]
        smda_function.pic_hash = metadata.get("pic_hash", None)
        smda_function.strongly_connected_components = metadata["strongly_connected_components"]
        smda_function.tfidf = metadata["tfidf"]
        stringrefs = function_dict.get("stringrefs", {})
        function_architecture = None
        if smda_report is not None:
            function_architecture = smda_report.architecture
        elif binary_info is not None:
            function_architecture = binary_info.architecture
        if function_architecture == "dalvik":
            smda_function.stringrefs = smda_function._normalizeDalvikStringRefs(stringrefs)
        else:
            smda_function.stringrefs = stringrefs
        smda_function._escaper = cls.getInstructionEscaper(function_architecture)
        hash_context = binary_info
        if hash_context is not None and (hash_context.base_addr is None or hash_context.binary_size is None):
            hash_context = None
        if (
            hash_context is None
            and smda_report is not None
            and smda_report.base_addr is not None
            and smda_report.binary_size is not None
        ):
            hash_context = smda_report
        # sanitize MCRIT plugin generated version strings
        if version and version.startswith("MCRIT4IDA"):
            version = version.rsplit(" ", 1)[-1]
        # modernize older reports on import
        if version and re.fullmatch(r"v?\d+(\.\d+)*", version):
            version = version.replace("v", "")
            version = [int(v) for v in version.split(".")]
            recalculate_pic_hash = version < [1, 3, 0]
            if (
                not recalculate_pic_hash
                and function_architecture == "aarch64"
                and version < AARCH64_PIC_HASH_ESCAPE_VERSION
            ):
                recalculate_pic_hash = True
            if (
                not recalculate_pic_hash
                and function_architecture == "intel"
                and version < INTEL_PIC_HASH_ESCAPE_VERSION
            ):
                recalculate_pic_hash = True
            if not recalculate_pic_hash and function_architecture == "cil" and version < CIL_PIC_HASH_ESCAPE_VERSION:
                recalculate_pic_hash = True
            if (
                not recalculate_pic_hash
                and function_architecture == "dalvik"
                and version < DALVIK_PIC_HASH_ESCAPE_VERSION
            ):
                recalculate_pic_hash = True
            if recalculate_pic_hash:
                smda_function.nesting_depth = smda_function._calculateNestingDepth()
                if smda_function._escaper and hash_context:
                    smda_function.pic_hash = smda_function.getPicHash(hash_context)
            elif "nesting_depth" in metadata:
                smda_function.nesting_depth = metadata["nesting_depth"]
            else:
                smda_function.nesting_depth = smda_function._calculateNestingDepth()
        # if we don't have valid version information, always recalculate
        else:
            smda_function.nesting_depth = smda_function._calculateNestingDepth()
            if smda_function._escaper and hash_context:
                smda_function.pic_hash = smda_function.getPicHash(hash_context)
            # as last resort, assume we analyze Intel
            elif binary_info and binary_info.architecture in (None, "intel"):
                smda_function._escaper = cls.getInstructionEscaper("intel")
                smda_function.pic_hash = smda_function.getPicHash(binary_info)
        return smda_function

    def toDict(self) -> dict:
        blocks_as_dict = {}
        for addr, block in self.blocks.items():
            blocks_as_dict[addr] = [ins.toDict() for ins in block]
        return {
            "offset": self.offset,
            "blocks": blocks_as_dict,
            "apirefs": self.apirefs,
            "stringrefs": self.stringrefs if self.stringrefs is not None else {},
            "blockrefs": self.blockrefs,
            "inrefs": self.inrefs,
            "outrefs": self.outrefs,
            "is_exported": self.is_exported,
            "architecture_metadata": self.architecture_metadata if self.architecture_metadata is not None else {},
            "metadata": {
                "binweight": self.binweight,
                "characteristics": self.characteristics,
                "confidence": self.confidence,
                "function_name": self.function_name,
                "pic_hash": self.pic_hash,
                "nesting_depth": self.nesting_depth,
                "strongly_connected_components": self.strongly_connected_components,
                "tfidf": self.tfidf,
            },
        }

    def __int__(self):
        return self.offset

    def __str__(self):
        offset = f"0x{self.offset:08x}" if self.offset is not None else "0x????????"
        return (
            f"{offset}: (->{self.num_inrefs:>4d}, {self.num_outrefs:>4d}->) "
            f"{self.num_blocks:>3d} blocks, {self.num_instructions:>4d} instructions."
        )
