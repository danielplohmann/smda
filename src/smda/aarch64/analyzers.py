"""AArch64 collaborators for the recursive engine.

Provides TF-IDF mnemonic frequency analysis, register-based indirect call
resolution, and jump table analysis for AArch64.
"""

import contextlib
import logging
import math
import struct
from collections import Counter
from copy import deepcopy

from capstone.arm64_const import ARM64_SFT_LSL

from .dataflow import (
    _applyConstantWrite,
    gatherContextInstructions,
    norm_reg,
    propagateConstants,
    propagateConstantsHistory,
)

LOGGER = logging.getLogger(__name__)

# Bounded predecessor-block hops fed into gatherContextInstructions when the seed
# block alone doesn't resolve a jump-table base/index (e.g. an adrp/add chain that
# lives in a prior block). Kept small and fixed: jump tables resolve eagerly,
# mid-function, so code_refs_to is only partially populated and deep chases would
# just burn time chasing edges that don't exist yet.
JUMPTABLE_PREDECESSOR_DEPTH = 2


def _updateConstantTracking(d, cap_ins, constants):
    """Extend `constants` from one instruction via the shared dataflow tracker."""
    _applyConstantWrite(cap_ins, constants, d)


def _registerValue(reg_name, constants):
    """Look up a register's tracked constant, treating wzr/xzr as literal 0."""
    normalized = norm_reg(reg_name)
    if normalized == "xzr":
        return 0
    return constants.get(normalized)


def _isSpWriteback(op_str):
    """Whether op_str shows an sp-based pre/post-index writeback (mutates sp).

    Capstone's python binding exposes no `.writeback` flag on this build, so this
    matches its op_str syntax directly: pre-index ends the operand string with a
    trailing `!` (e.g. "x29, x30, [sp, #-16]!"); post-index appends an immediate
    after the closing bracket (e.g. "x29, x30, [sp], #16").
    """
    if "[sp" not in op_str:
        return False
    return op_str.rstrip().endswith("!") or "], #" in op_str or "],#" in op_str


def _mutatesStackPointer(cap_ins):
    """Whether this instruction changes sp's value: explicit dest-is-sp arithmetic
    (sub/add/mov) or an sp-based pre/post-index writeback. Any earlier tracked
    stack-relative offsets become meaningless once sp moves."""
    if cap_ins.operands and cap_ins.operands[0].type == 1 and cap_ins.reg_name(cap_ins.operands[0].reg) == "sp":
        return True
    return _isSpWriteback(cap_ins.op_str)


_SINGLE_STORE_WIDTH = {"strb": 1, "sturb": 1, "strh": 2, "sturh": 2}
_SINGLE_STORE_MNEMONICS = frozenset({"str", "stur", "strb", "sturb", "strh", "sturh"})
#: minimum/maximum length of a reconstructed stack string (avoid single-byte
#: noise and pathological runs from misclassified constants)
_MIN_STACK_STRING_LEN = 4
_MAX_STACK_STRING_LEN = 128


def _recordStackStore(cap_ins, mnemonic, constants, stack_bytes):
    """Record the byte(s) an sp-relative store writes into `stack_bytes`
    (offset -> (byte_value, instruction_addr)), if the stored value is a
    currently-tracked constant. Handles single-register str/strb/strh/stur*
    and the two-register stp (frame-adjacent stack-string writes)."""
    operands = cap_ins.operands
    if mnemonic in _SINGLE_STORE_MNEMONICS and len(operands) == 2:
        src_op, mem_op = operands
        if src_op.type != 1 or mem_op.type != 3:  # REG, MEM
            return
        if not mem_op.mem.base or cap_ins.reg_name(mem_op.mem.base) != "sp" or mem_op.mem.index != 0:
            return
        src_name = cap_ins.reg_name(src_op.reg)
        value = _registerValue(src_name, constants)
        if value is None:
            return
        width = _SINGLE_STORE_WIDTH.get(mnemonic, 4 if src_name.lower().startswith("w") else 8)
        offset = mem_op.mem.disp
        for b in range(width):
            stack_bytes[offset + b] = ((value >> (8 * b)) & 0xFF, cap_ins.address)
    elif mnemonic == "stp" and len(operands) == 3:
        reg1_op, reg2_op, mem_op = operands
        if reg1_op.type != 1 or reg2_op.type != 1 or mem_op.type != 3:
            return
        if not mem_op.mem.base or cap_ins.reg_name(mem_op.mem.base) != "sp" or mem_op.mem.index != 0:
            return
        reg1_name = cap_ins.reg_name(reg1_op.reg)
        reg2_name = cap_ins.reg_name(reg2_op.reg)
        width = 4 if reg1_name.lower().startswith("w") else 8
        offset = mem_op.mem.disp
        for reg_name, base_offset in ((reg1_name, offset), (reg2_name, offset + width)):
            value = _registerValue(reg_name, constants)
            if value is None:
                continue
            for b in range(width):
                stack_bytes[base_offset + b] = ((value >> (8 * b)) & 0xFF, cap_ins.address)


def _emitStackStrings(d, analysis_state, stack_bytes):
    """Reconstruct contiguous printable-ASCII runs from `stack_bytes` and record
    each as a stringref anchored at the store that wrote the run's first byte."""
    if not stack_bytes:
        return

    def flush(run):
        if len(run) < _MIN_STACK_STRING_LEN:
            return
        run = run[:_MAX_STACK_STRING_LEN]
        first_addr = run[0][1]
        string = "".join(chr(byte_val) for byte_val, _addr in run)
        d.disassembly.addStringRef(analysis_state.start_addr, first_addr, string)

    run = []
    prev_offset = None
    for offset in sorted(stack_bytes):
        byte_val, addr = stack_bytes[offset]
        is_printable = 0x20 <= byte_val <= 0x7E
        if not is_printable or (prev_offset is not None and offset != prev_offset + 1):
            flush(run)
            run = []
        if is_printable:
            run.append((byte_val, addr))
            prev_offset = offset
        else:
            prev_offset = None
    flush(run)


class AArch64TfIdf:
    """Mnemonic TF-IDF scorer for AArch64 function confidence.

    Document-frequency histogram harvested from SMDA-recovered AArch64 functions
    across a Linux static fixture and Windows ARM64 PE samples (v0 corpus;
    ~1.8k functions). Scoring matches the intel ``MnemonicTfIdf`` contract:
    probabilistic IDF, raw TF, OOV terms use max observed IDF. Negative scores
    boost confidence; positive scores are "unusual" relative to the corpus.
    """

    # v0 histogram: num_functions is the document count; remaining keys are
    # Capstone mnemonic strings with per-function document frequency.
    all_histograms = Counter(
        {
            "num_functions": 1776,
            "ret": 1460,
            "mov": 1408,
            "add": 1317,
            "ldr": 1316,
            "stp": 1303,
            "ldp": 1272,
            "adrp": 1147,
            "bl": 1117,
            "str": 1111,
            "b": 945,
            "cmp": 864,
            "cbz": 831,
            "cbnz": 711,
            "blr": 708,
            "sub": 656,
            "b.eq": 473,
            "pacibsp": 443,
            "b.ne": 442,
            "autibsp": 430,
            "ldar": 372,
            "csel": 303,
            "and": 280,
            "ldrb": 250,
            "tbz": 250,
            "tbnz": 240,
            "ldrh": 202,
            "strh": 197,
            "strb": 196,
            "b.ls": 190,
            "b.hi": 187,
            "b.lo": 179,
            "orr": 179,
            "cmn": 166,
            "br": 165,
            "nop": 153,
            "lsl": 145,
            "ccmp": 124,
            "b.gt": 123,
            "ubfx": 123,
            "b.le": 121,
            "movk": 121,
            "lsr": 117,
            "ldaxr": 115,
            "asr": 113,
            "stlxr": 113,
            "uxtb": 111,
            "dmb": 109,
            "b.hs": 103,
            "sxtw": 98,
            "cset": 95,
            "tst": 94,
            "ldur": 80,
            "ldrsh": 77,
            "mrs": 71,
            "brk": 68,
            "svc": 62,
            "movz": 60,
            "mul": 51,
            "neg": 50,
            "movi": 49,
            "stur": 47,
            "eor": 46,
            "b.lt": 43,
            "ldrsb": 43,
            "madd": 43,
            "udf": 41,
            "adr": 40,
            "xpaclri": 40,
            "udiv": 37,
            "stlr": 35,
            "msub": 33,
            "mvn": 32,
            "ubfiz": 32,
            "rev16": 30,
            "ldrsw": 28,
            "uxth": 28,
            "subs": 26,
            "ldurh": 24,
            "csinc": 22,
            "stxr": 20,
            "rev": 19,
            "b.ge": 18,
            "ldxr": 18,
            "fmov": 17,
            "cinc": 13,
            "smull": 13,
            "stlrb": 12,
            "addv": 11,
            "ands": 11,
            "csdb": 11,
            "ldapr": 11,
            "uaddw": 11,
            "uaddw2": 11,
            "bfi": 9,
            "sturh": 9,
            "bic": 8,
            "sturb": 8,
            "umaddl": 8,
            "umull": 8,
            "ldadd": 7,
            "ror": 7,
            "cas": 6,
            "csinv": 6,
            "ldurb": 6,
            "sdiv": 6,
            "dup": 5,
            "sbfiz": 5,
            "sbfx": 5,
            "ushr": 5,
            "bics": 4,
            "bti": 4,
            "csetm": 4,
            "shl": 4,
            "bfxil": 3,
            "csneg": 3,
            "ldaddl": 3,
            "ldarb": 3,
            "ldclr": 3,
            "negs": 3,
            "smaddl": 3,
            "umulh": 3,
            "ushll": 3,
            "casal": 2,
            "ccmn": 2,
            "fcvtzs": 2,
            "fdiv": 2,
            "ldursb": 2,
            "mvni": 2,
            "scvtf": 2,
            "swpal": 2,
            "uzp1": 2,
            "adds": 1,
            "b.pl": 1,
            "casa": 1,
            "cneg": 1,
            "dc": 1,
            "fcvtzu": 1,
            "fmul": 1,
            "fsub": 1,
            "ld1b": 1,
            "ldadda": 1,
            "ldaprb": 1,
            "ldpsw": 1,
            "ldset": 1,
            "ldursh": 1,
            "ldxp": 1,
            "mneg": 1,
            "msr": 1,
            "prfm": 1,
            "smulh": 1,
            "st4": 1,
            "stnp": 1,
            "sttr": 1,
            "swp": 1,
            "swpa": 1,
            "swpl": 1,
            "sxtb": 1,
            "sxth": 1,
            "ucvtf": 1,
            "uqadd": 1,
            "uzp2": 1,
            "xtn2": 1,
        }
    )

    def __init__(self, bitness=64):
        self.bitness = bitness
        self.idf = {}
        counts = deepcopy(self.all_histograms)
        num_documents = counts.pop("num_functions")
        for term, term_count in counts.items():
            self.idf[term] = (
                self._calculateIdf(num_documents, term_count) if term_count else self._calculateIdf(num_documents, 1)
            )

    def getTfIdfFromBlocks(self, blocks):
        term_counts = Counter()
        for _, block in blocks.items():
            for ins in block:
                term_counts[str(ins[2])] += 1
        return self.tfidf(term_counts)

    def tfidf(self, term_counts):
        if not term_counts:
            return 0.0
        score = 0
        sum_term_counts = sum(term_counts.values())
        max_count = max(term_counts.values())
        for term, term_count in term_counts.items():
            score += self._calculateTf(sum_term_counts, term_count, max_count) * self.getFrequency(term)
        return score

    def _calculateTf(self, num_terms, term_count, max_term_count=0):
        del num_terms, max_term_count
        return term_count

    def _calculateIdf(self, num_documents, value_count):
        return math.log(1.0 * (num_documents - value_count) / value_count)

    def getFrequency(self, term):
        return self.idf[term] if term in self.idf else max(self.idf.values())


class AArch64IndirectCallAnalyzer:
    """Perform basic dataflow analysis to resolve AArch64 indirect call targets."""

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly

    def searchBlock(self, analysis_state, address):
        # Lazy-cache an {instruction_addr: containing_block} index on the
        # analysis_state (mirrors intel.IndirectCallAnalyzer.searchBlock) so
        # repeated lookups during the same function analysis are O(1) instead of
        # O(blocks * instructions). Only safe to build once block reconstruction
        # has finished (resolveRegisterCalls runs after state.finalizeAnalysis(),
        # so getBlocks() here returns/caches the real, complete block layout).
        block_index = getattr(analysis_state, "_block_index", None)
        if not isinstance(block_index, dict):
            block_index = {}
            for block in analysis_state.getBlocks():
                for ins in block:
                    addr = ins[0]
                    if addr not in block_index:
                        block_index[addr] = block
            with contextlib.suppress(AttributeError):
                analysis_state._block_index = block_index
        return block_index.get(address, [])

    def _resolveRegister(self, analysis_state, calling_addr, reg_name, block_depth):
        self.searchBlock(analysis_state, calling_addr)  # ensures _block_index is built
        block_index = getattr(analysis_state, "_block_index", {})
        cap_insns = gatherContextInstructions(
            self.disassembler,
            analysis_state,
            calling_addr,
            block_depth,
            block_index=block_index,
        )
        constants = propagateConstants(cap_insns, self.disassembler)
        return constants.get(norm_reg(reg_name))

    def recoverStackStrings(self, analysis_state):
        """danielplohmann/smda#173: reconstruct strings built byte-by-byte on the
        stack (mov <reg>, #imm; strb <reg>, [sp, #off]; ... or stp with tracked
        register values) into disassembly.stringrefs, mirroring what dalvik/cil
        already do for their single-instruction string literals. Runs once per
        finalized function block, after the whole function's instructions and
        block structure are known (unlike analyzeInstruction's streaming pass,
        this needs no speculative-candidate rollback).

        Known limitation (v1): only tracks str/strb/strh/stur*/stp with an sp
        base; a SIMD-register stack-string materialization (e.g. `ldr q0, <lit>;
        str q0, [sp]`) is not decomposed into constant bytes and is silently
        skipped, same as any other value this backend's constant tracker can't
        resolve.
        """
        d = self.disassembler
        if not d.config.WITH_STRINGS:
            return
        for block in analysis_state.getBlocks():
            constants = {}
            stack_bytes = {}
            for ins in block:
                bytes_ins = d.disassembly.getBytes(ins[0], ins[1])
                if not bytes_ins:
                    continue
                cap_ins = next(d.capstone.disasm(bytes_ins, ins[0]), None)
                if not cap_ins:
                    continue
                mnemonic = cap_ins.mnemonic.lower()

                if _mutatesStackPointer(cap_ins):
                    _emitStackStrings(d, analysis_state, stack_bytes)
                    stack_bytes = {}
                else:
                    _recordStackStore(cap_ins, mnemonic, constants, stack_bytes)

                _updateConstantTracking(d, cap_ins, constants)
            _emitStackStrings(d, analysis_state, stack_bytes)

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        self.recoverStackStrings(analysis_state)
        if not analysis_state.call_register_ins:
            return

        d = self.disassembler
        max_calls_per_block = getattr(getattr(d, "config", None), "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK", 50)
        calls_per_block = {}
        for calling_addr in analysis_state.call_register_ins:
            block = self.searchBlock(analysis_state, calling_addr)
            start_block = [ins for ins in block if ins[0] <= calling_addr]
            if not start_block:
                continue
            block_key = start_block[0][0]
            calls_per_block[block_key] = calls_per_block.get(block_key, 0) + 1
            # we only process at most MAX_INDIRECT_CALLS_PER_BASIC_BLOCK register-calls
            # per block to avoid extreme cases (e.g. a Go binary with huge switch-like
            # register-call fan-out in a single block).
            if calls_per_block[block_key] > max_calls_per_block:
                continue

            bytes_ins = d.disassembly.getBytes(calling_addr, 4)
            if not bytes_ins:
                continue
            cap_ins = next(d.capstone.disasm(bytes_ins, calling_addr), None)
            if not cap_ins or not cap_ins.operands:
                continue
            target_op = cap_ins.operands[0]
            if target_op.type != 1:  # REG
                continue
            reg_name = cap_ins.reg_name(target_op.reg)

            candidate = self._resolveRegister(analysis_state, calling_addr, reg_name, block_depth)
            if candidate:
                analysis_state.setLeaf(False)
                dll, api = d.resolveApi(candidate, candidate)
                if dll or api:
                    d.disassembly.addApiReference(candidate, calling_addr, dll, api)
                elif d.disassembly.isAddrWithinMemoryImage(candidate):
                    d.fc_manager.addCandidate(candidate, reference_source=calling_addr)


class AArch64JumpTableAnalyzer:
    """Perform jump table analysis by tracing register values back to their load sites."""

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly

    def _nextKnownBoundary(self, after_addr):
        """Nearest known function candidate/border start after `after_addr`, if any.

        Used to stop a runaway table read before it overruns into the next
        function - relevant both for tables placed in .rodata ahead of an
        unrelated later function and for tables a compiler places inline in .text.
        """
        d = self.disassembler
        candidates = getattr(getattr(d, "fc_manager", None), "candidates", None) or {}
        borders = getattr(d.disassembly, "function_borders", None) or {}
        candidate_boundary = min((addr for addr in candidates if addr > after_addr), default=None)
        border_boundary = min((fn_min for fn_min, _fn_max in borders.values() if fn_min > after_addr), default=None)
        boundaries = [b for b in (candidate_boundary, border_boundary) if b is not None]
        return min(boundaries) if boundaries else None

    def getJumpTargets(self, jump_instruction, state):
        jump_instruction_address = jump_instruction[0]
        jump_instruction_size = jump_instruction[1]

        d = self.disassembler
        ins_bytes = d.disassembly.getBytes(jump_instruction_address, jump_instruction_size)
        if not ins_bytes:
            return []

        detailed_jump = next(d.capstone.disasm(ins_bytes, jump_instruction_address), None)
        if not detailed_jump or not detailed_jump.operands:
            return []

        target_op = detailed_jump.operands[0]
        if target_op.type != 1:  # REG
            return []

        target_reg = norm_reg(detailed_jump.reg_name(target_op.reg))
        if not target_reg:
            return []

        detailed_insns = gatherContextInstructions(d, state, jump_instruction_address, JUMPTABLE_PREDECESSOR_DEPTH)
        if not detailed_insns:
            return []

        # A per-instruction history (not one trailing dict) is required here: the reverse
        # scan below inspects an instruction's *source* operands, but that same
        # instruction may also write an unresolved value to the register it reads (e.g.
        # the table-base register reused as the destination of the very load it
        # addresses) - only the map as of just before that instruction still shows the
        # base it actually used.
        constants_before = propagateConstantsHistory(detailed_insns, d)

        tracked_regs = {target_reg}
        table_base = None
        index_reg = None
        entry_size = 8
        is_signed = False
        is_relative = False
        entry_shift = 0

        for idx in range(len(detailed_insns) - 1, -1, -1):
            ins = detailed_insns[idx]
            constants = constants_before[idx]
            mnemonic = ins.mnemonic.lower()
            if not ins.operands:
                continue
            dest_op = ins.operands[0]
            if dest_op.type != 1:  # REG
                continue
            dest_reg = norm_reg(ins.reg_name(dest_op.reg))
            if dest_reg not in tracked_regs:
                continue
            tracked_regs.remove(dest_reg)

            if mnemonic == "add" and len(ins.operands) >= 3:
                op1 = ins.operands[1]
                op2 = ins.operands[2]
                if op1.type == 1 and op2.type == 1:  # REG + REG (incl. extended/shifted reg)
                    reg1 = norm_reg(ins.reg_name(op1.reg))
                    reg2 = norm_reg(ins.reg_name(op2.reg))
                    tracked_regs.add(reg1)
                    tracked_regs.add(reg2)
                    # Detect relative base and capture the index register's shift
                    index_op = None
                    if reg1 in constants:
                        table_base = constants[reg1]
                        is_relative = True
                        index_op = op2
                    elif reg2 in constants:
                        table_base = constants[reg2]
                        is_relative = True
                        index_op = op1
                    if index_op is not None and index_op.shift.type == ARM64_SFT_LSL:
                        entry_shift = index_op.shift.value
                elif op1.type == 1 and op2.type == 2:  # REG + IMM
                    reg1 = norm_reg(ins.reg_name(op1.reg))
                    tracked_regs.add(reg1)
            elif mnemonic in ("ldr", "ldrsw", "ldrh", "ldrb", "ldrsh", "ldrsb") and len(ins.operands) >= 2:
                op1 = ins.operands[1]
                if op1.type == 3:  # MEM
                    base_reg = norm_reg(ins.reg_name(op1.mem.base))
                    if base_reg in constants:
                        table_base = constants[base_reg]
                    if op1.mem.index:
                        index_reg = norm_reg(ins.reg_name(op1.mem.index))

                    if mnemonic == "ldrsw":
                        entry_size = 4
                        is_signed = True
                        is_relative = True
                    elif mnemonic == "ldr":
                        entry_size = 4 if ins.reg_name(dest_op.reg).lower().startswith("w") else 8
                    elif mnemonic in ("ldrh", "ldrsh"):
                        entry_size = 2
                        is_signed = mnemonic == "ldrsh"
                        is_relative = True
                    elif mnemonic in ("ldrb", "ldrsb"):
                        entry_size = 1
                        is_signed = mnemonic == "ldrsb"
                        is_relative = True
            elif mnemonic in ("mov", "movz", "movk", "movn") and len(ins.operands) >= 2:
                op1 = ins.operands[1]
                if op1.type == 1:  # REG
                    tracked_regs.add(norm_reg(ins.reg_name(op1.reg)))
            elif (
                mnemonic in ("sxtb", "sxth", "sxtw", "sxtx", "uxtb", "uxth", "uxtw", "uxtx") and len(ins.operands) >= 2
            ):
                # Standalone sign/zero-extend feeding the final add/br chain (e.g. a plain
                # `ldr` of a raw entry followed by an explicit `sxtw`/`uxtw` rather than
                # `ldrsw` directly) - continue the chase into the source register and
                # record the entry's signedness.
                op1 = ins.operands[1]
                if op1.type == 1:  # REG
                    tracked_regs.add(norm_reg(ins.reg_name(op1.reg)))
                    is_signed = mnemonic.startswith("sxt")
            elif mnemonic == "ubfx" and len(ins.operands) >= 4:
                # Capstone prints the UXTW alias as `ubfx Xd, Xn, #0, #0x20` rather than
                # `uxtw`. Treat that form as an unsigned 32-bit extend so the reverse
                # chase continues into the source register of a plain-ldr table load.
                op1, op_immr, op_imms = ins.operands[1], ins.operands[2], ins.operands[3]
                # Capstone reports the width operand as #0x20 (32) for the UXTW alias,
                # not the raw UBFM imms field (31). Accept both encodings.
                if (
                    op1.type == 1
                    and op_immr.type == 2
                    and op_imms.type == 2
                    and op_immr.imm == 0
                    and op_imms.imm in (31, 0x1F, 32, 0x20)
                ):
                    tracked_regs.add(norm_reg(ins.reg_name(op1.reg)))
                    is_signed = False

        # Try to find table size from a bounds check (cmp <idx>, #imm or subs <dst>, <idx>, #imm)
        table_size = 0
        if index_reg:
            index_regs_to_match = {index_reg}
            if index_reg.startswith("x"):
                index_regs_to_match.add("w" + index_reg[1:])
            elif index_reg.startswith("w"):
                index_regs_to_match.add("x" + index_reg[1:])

            for ins in reversed(detailed_insns):
                mnemonic = ins.mnemonic.lower()
                cmp_reg_op, cmp_imm_op = None, None
                if mnemonic == "cmp" and len(ins.operands) >= 2:
                    cmp_reg_op, cmp_imm_op = ins.operands[0], ins.operands[1]
                elif mnemonic == "subs" and len(ins.operands) >= 3:
                    cmp_reg_op, cmp_imm_op = ins.operands[1], ins.operands[2]
                if cmp_reg_op is None or cmp_reg_op.type != 1 or cmp_imm_op.type != 2:
                    continue
                reg_name = ins.reg_name(cmp_reg_op.reg).lower()
                if reg_name in index_regs_to_match:
                    table_size = cmp_imm_op.imm + 1
                    break

        if not table_base:
            return []

        if not table_size:
            table_size = 32

        next_boundary = self._nextKnownBoundary(table_base)

        targets = []
        for i in range(table_size):
            entry_addr = table_base + i * entry_size
            if next_boundary is not None and entry_addr >= next_boundary:
                break
            if not d.disassembly.isAddrWithinMemoryImage(entry_addr):
                break

            raw_bytes = d.disassembly.getBytes(entry_addr, entry_size)
            if not raw_bytes or len(raw_bytes) != entry_size:
                break

            if entry_size == 4:
                val = struct.unpack("<i" if is_signed else "<I", raw_bytes)[0]
            elif entry_size == 8:
                val = struct.unpack("<q" if is_signed else "<Q", raw_bytes)[0]
            elif entry_size == 2:
                val = struct.unpack("<h" if is_signed else "<H", raw_bytes)[0]
            elif entry_size == 1:
                val = struct.unpack("<b" if is_signed else "<B", raw_bytes)[0]
            else:
                break

            target = (table_base + (val << entry_shift)) & d.getBitMask() if is_relative else val & d.getBitMask()

            if not d.disassembly.isAddrWithinMemoryImage(target):
                break

            if d.disassembly.binary_info.isInCodeAreas(target):
                targets.append(target)
                state.addDataRef(jump_instruction_address, entry_addr, size=entry_size)
            else:
                break

        return targets
