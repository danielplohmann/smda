"""AArch32 collaborators for the recursive engine.

TF-IDF mnemonic scoring, register-indirect call resolution, jump-table recovery and
import-stub decoding, all built on the straight-line tracker in :mod:`smda.arm.dataflow`.
"""

import logging
import math
from collections import Counter

from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

from .dataflow import RegisterTracker, decode, norm_reg, pc_value, precedingInstructions, track
from .definitions import split_mnemonic

LOGGER = logging.getLogger(__name__)

#: instructions of straight-line context read back from a register branch
CONTEXT_INSTRUCTIONS = 24
#: most entries read from a table whose bound no comparison states
MAX_UNBOUNDED_ENTRIES = 512
#: most entries read from any table (TBH indexes 16 bits; nothing real comes close)
MAX_TABLE_ENTRIES = 4096
#: instructions an import stub may take before its branch
MAX_STUB_INSTRUCTIONS = 6
_STUB_BASES = frozenset({"add", "sub", "adr", "ldr", "movw", "movt", "mov", "nop", "bx"})
_BOUND_BRANCHES = frozenset({"hi", "ls", "hs", "lo", "cs", "cc", "gt", "le", "ge", "lt"})
#: libgcc's Thumb-1 switch helpers (``__gnu_thumb1_case_*`` in lib1funcs.S), by their
#: instruction sequence, since a stripped image does not name them: the entry size, whether
#: an entry is signed, and whether it is a word offset from the aligned table (``si``) rather
#: than a halfword count from the return address
_CASE_HELPERS = {
    ("push", "mov", "lsr", "lsl", "ldrsb", "lsl", "add", "pop", "bx"): (1, True, False),
    ("push", "mov", "lsr", "lsl", "ldrb", "lsl", "add", "pop", "bx"): (1, False, False),
    ("push", "mov", "lsr", "lsl", "lsl", "ldrsh", "lsl", "add", "pop", "bx"): (2, True, False),
    ("push", "mov", "lsr", "lsl", "lsl", "ldrh", "lsl", "add", "pop", "bx"): (2, False, False),
    ("push", "mov", "add", "lsr", "lsl", "lsl", "ldr", "add", "mov", "pop", "mov"): (4, True, True),
}
_CASE_HELPER_LENGTH = max(len(sequence) for sequence in _CASE_HELPERS)


class ArmTfIdf:
    """Mnemonic TF-IDF scorer for AArch32 function confidence.

    Document frequencies of base mnemonics (condition and width qualifier stripped, so
    ``bxeq`` and ``pop.w`` count as ``bx`` and ``pop``) over the functions of fourteen
    clang-built A32, T32 and mixed images of three compression libraries at -O0, -O2 and
    -Os. Scoring matches the intel ``MnemonicTfIdf`` contract.
    """

    all_histograms = Counter(
        {
            "num_functions": 5697,
            "ldr": 4903,
            "add": 4761,
            "mov": 4129,
            "sub": 3811,
            "str": 3791,
            "pop": 3749,
            "push": 3748,
            "cmp": 3545,
            "b": 3469,
            "movw": 2976,
            "bl": 2644,
            "lsr": 1666,
            "mvn": 1651,
            "lsl": 1638,
            "and": 1528,
            "ldrb": 1506,
            "movt": 1408,
            "strd": 1315,
            "orr": 1234,
            "bx": 1170,
            "it": 1161,
            "ldrd": 1158,
            "blx": 1157,
            "strb": 982,
            "eor": 980,
            "rsb": 942,
            "ldrh": 936,
            "cbz": 900,
            "clz": 888,
            "cmn": 851,
            "mul": 811,
            "strh": 688,
            "mla": 676,
            "itt": 601,
            "umull": 567,
            "bic": 553,
            "stm": 541,
            "ldm": 476,
            "tst": 425,
            "asr": 388,
            "rbit": 343,
            "pld": 311,
            "uxth": 298,
            "sbc": 289,
            "uxtb": 283,
            "ittt": 260,
            "vldr": 250,
            "cbnz": 232,
            "adc": 220,
            "vmrs": 210,
            "vcmp.f64": 188,
            "vmov.f64": 188,
            "addw": 178,
            "bfc": 178,
            "ubfx": 175,
            "vstr": 173,
            "vmov": 156,
            "vpop": 152,
            "vpush": 152,
            "vcvt.f64.u32": 146,
            "itttt": 143,
            "stmib": 129,
            "vsub.f64": 93,
            "vmul.f64": 88,
            "ite": 83,
            "vadd.f64": 80,
            "tbb": 76,
            "ror": 67,
            "bfi": 66,
            "ldrsh": 59,
            "vdiv.f64": 59,
            "vmla.f64": 57,
            "itee": 42,
            "ldrsb": 39,
            "tbh": 38,
            "ldmib": 35,
            "rsc": 34,
            "itte": 31,
            "vmls.f64": 29,
            "subw": 28,
            "uxtah": 28,
            "smlabb": 27,
            "vsub.f32": 25,
            "uxtab": 24,
            "vcvt.u32.f64": 23,
            "vcmp.f32": 22,
            "vstmia": 22,
            "vadd.f32": 21,
            "rev": 18,
            "vmov.f32": 18,
            "vnmls.f64": 17,
            "orn": 16,
            "vcvt.f32.f64": 16,
            "sxth": 15,
            "sxtb": 13,
            "iteee": 10,
            "vneg.f64": 9,
            "mls": 8,
            "sbfx": 8,
            "sxtab": 8,
            "smmul": 7,
            "teq": 6,
            "vcvt.f32.u32": 5,
            "vldmia": 4,
        }
    )

    def __init__(self, bitness=32):
        self.bitness = bitness
        self.idf = {}
        counts = Counter(self.all_histograms)
        num_documents = counts.pop("num_functions")
        for term, term_count in counts.items():
            self.idf[term] = self._calculateIdf(num_documents, max(1, min(term_count, num_documents - 1)))
        self._max_idf = max(self.idf.values()) if self.idf else 0.0

    def getTfIdfFromBlocks(self, blocks):
        term_counts = Counter()
        for _, block in blocks.items():
            for ins in block:
                term_counts[split_mnemonic(str(ins[2]))[0]] += 1
        return self.tfidf(term_counts)

    def tfidf(self, term_counts):
        if not term_counts:
            return 0.0
        return sum(count * self.getFrequency(term) for term, count in term_counts.items())

    @staticmethod
    def _calculateIdf(num_documents, value_count):
        return math.log(1.0 * (num_documents - value_count) / value_count)

    def getFrequency(self, term):
        return self.idf.get(term, self._max_idf)


def _thumbOf(disassembler):
    return disassembler.capstone.is_thumb


def _context(disassembler, state, address):
    return decode(disassembler, precedingInstructions(state, address, CONTEXT_INSTRUCTIONS))


def resolveImportStub(disassembler, start, thumb):
    """Decode an import stub at ``start``: ``(end, slot, value)`` or None.

    Covers the shapes linkers emit in front of a GOT or IAT slot: the ELF PLT entry
    (``add ip, pc, #...``; ``add ip, ip, #...``; ``ldr pc, [ip, #...]!``) in its short and
    long forms, lld's literal-pool form, the T32 ``bx pc`` prefix that switches a Thumb
    caller into an A32 entry, and the MSVC ``movw``/``movt``/``ldr``/``bx`` import thunk.
    It also covers the linker's long-branch veneers, which compute their target instead of
    loading it (``movw``/``movt``/``add ip, pc``/``bx ip``, ``ldr pc, [pc, #-4]``): those
    return a ``slot`` of None and the target, with bit 0 selecting Thumb, as ``value``.
    ``end`` is the address after the branch, ``slot`` the address of the pointer the stub
    loads and ``value`` the pointer read from it (None when outside the image).
    """
    d = disassembler
    capstone = d.capstone
    address = start
    if thumb:
        prefix = d.disassembly.getBytes(address, 2)
        if prefix and bytes(prefix) == b"\x78\x47":
            address = (address + 4) & ~3
            thumb = False
    data = d.disassembly.getBytes(address, 4 * MAX_STUB_INSTRUCTIONS)
    if not data:
        return None
    engine = capstone.thumb if thumb else capstone.arm
    tracker = RegisterTracker(d, thumb)
    for ins in engine.disasm(bytes(data), address, MAX_STUB_INSTRUCTIONS):
        base, condition, _ = split_mnemonic(ins.mnemonic)
        if condition not in (None, "al") or base not in _STUB_BASES:
            return None
        operands = ins.operands
        end = ins.address + ins.size
        if base == "ldr" and len(operands) == 2 and norm_reg(ins.reg_name(operands[0].reg)) == "pc":
            slot = tracker.memoryAddress(ins, operands[1])
            if slot is None:
                return None
            return end, slot, tracker.readWord(slot)
        if base in ("bx", "mov") and operands and operands[-1].type == ARM_OP_REG:
            target_reg = norm_reg(ins.reg_name(operands[-1].reg))
            if base == "mov" and norm_reg(ins.reg_name(operands[0].reg)) != "pc":
                tracker.step(ins)
                continue
            slot = tracker.slot(target_reg)
            value = tracker.get(target_reg)
            if slot is None and value is None:
                return None
            return end, slot, value
        tracker.step(ins)
    return None


class ArmIndirectCallAnalyzer:
    """Resolve register-indirect calls and branches from straight-line constant tracking."""

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly

    def _resolve(self, state, address):
        d = self.disassembler
        context = _context(d, state, address)
        instruction = decode(d, [self._booked(state, address)]) if self._booked(state, address) else []
        if not instruction:
            return None, None
        ins = instruction[0][1]
        tracker = track(d, context, _thumbOf(d))
        operands = ins.operands
        if not operands:
            return None, None
        if split_mnemonic(ins.mnemonic)[0] == "ldr" and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
            slot = tracker.memoryAddress(ins, operands[1])
            return (None, None) if slot is None else (tracker.readWord(slot), slot)
        register = operands[-1]
        if register.type != ARM_OP_REG:
            return None, None
        name = norm_reg(ins.reg_name(register.reg))
        return tracker.get(name), tracker.slot(name)

    @staticmethod
    def _booked(state, address):
        index = getattr(state, "_arm_by_start", None)
        if index is None or getattr(state, "_arm_by_start_count", -1) != len(state.instructions):
            index = {ins[0]: ins for ins in state.instructions}
            state._arm_by_start = index
            state._arm_by_start_count = len(state.instructions)
        return index.get(address)

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        del block_depth
        d = self.disassembler
        max_per_function = getattr(d.config, "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK", 50)
        resolved = 0
        for is_call, addresses in (
            (True, analysis_state.call_register_ins),
            (False, analysis_state.arm_indirect_jumps),
        ):
            for address in addresses:
                if resolved >= max_per_function * 4:
                    return
                value, slot = self._resolve(analysis_state, address)
                if value is None and slot is None:
                    continue
                resolved += 1
                if slot is not None and d._handleApiTarget(
                    address, slot, value if value is not None else slot, slot=slot
                ):
                    continue
                if value is None:
                    continue
                dll, api = d.resolveApi(value, value)
                if dll or api:
                    d.disassembly.addApiReference(value, address, dll, api)
                elif d.disassembly.isAddrWithinMemoryImage(value & ~1):
                    if is_call:
                        d.fc_manager.addCallCandidate(value & ~1, bool(value & 1), address)
                        d.disassembly.addCodeRefs(address, value & ~1)
                    else:
                        d.fc_manager.addTailcallCandidate(value & ~1, bool(value & 1))
                        d.disassembly.addCodeRefs(address, value & ~1)


class ArmJumpTableAnalyzer:
    """Recover the targets of AArch32 switch dispatches.

    Handles the dispatch shapes compilers emit: T32 ``tbb``/``tbh`` (A8.8.237) with the
    offset table right behind the instruction; an absolute table read by
    ``ldr pc, [rn, rm, lsl #2]`` (inline behind the instruction or reached through a base
    register); a table of branch instructions entered by ``add pc, pc, rm, lsl #2``; and
    the position-independent ``add pc, rt, rx`` where rx was loaded from a table of
    offsets relative to rt, the base rt was set up with ``adr`` or a pc-relative ``add``.
    The index bound comes from the ``cmp`` guarding the dispatch; a table without one is
    read until an entry stops naming code, and a table inside the code section stops
    where its first target begins.
    """

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly
        self._case_helpers = {}

    def _caseHelper(self, address):
        """The ``_CASE_HELPERS`` shape of the Thumb code at ``address``, or None."""
        if address not in self._case_helpers:
            shape = None
            data = self.disassembly.getBytes(address, 2 * _CASE_HELPER_LENGTH)
            if data:
                sequence = []
                for ins in self.disassembler.capstone.thumb.disasm(bytes(data), address, _CASE_HELPER_LENGTH):
                    mnemonic = ins.mnemonic.split(".")[0]
                    sequence.append(mnemonic[:-1] if mnemonic in ("lsls", "lsrs", "adds", "movs") else mnemonic)
                    if tuple(sequence) in _CASE_HELPERS and ins.op_str.replace(" ", "") in ("lr", "pc,lr"):
                        shape = _CASE_HELPERS[tuple(sequence)]
                        break
            self._case_helpers[address] = shape
        return self._case_helpers[address]

    def getCaseTargets(self, call_instruction, state, helper):
        """Cases of a Thumb-1 switch dispatched by a call to a libgcc case helper.

        The helper reads its table at the call's return address and returns into the case
        it selects, so the call ends the block and the table behind it is data. The index
        is r0; its bound comes from the ``cmp`` guarding the call, which usually reaches it
        by a conditional branch rather than by falling through.
        """
        shape = self._caseHelper(helper)
        if shape is None:
            return []
        entry_size, signed, word_offsets = shape
        address = call_instruction[0]
        origin = address + call_instruction[1]
        context = _context(self.disassembler, state, address)
        if not context:
            context = self._branchContext(state, address)
        bound = self._bound(context, "r0")
        if word_offsets:
            table = (origin + 3) & ~3
            return self._readTable(
                state, address, table, 4, bound, lambda entry: (table + entry) & 0xFFFFFFFE, signed=True
            )
        return self._readTable(
            state, address, origin, entry_size, bound, lambda entry: origin + 2 * entry, signed=signed
        )

    def _branchContext(self, state, address):
        # the straight-line context of a conditional branch to ``address``
        for ins in state.instructions:
            base, condition, _ = split_mnemonic(ins[2])
            if base == "b" and condition in _BOUND_BRANCHES and ins[3] == f"#0x{address:x}":
                return decode(self.disassembler, precedingInstructions(state, ins[0] + ins[1], CONTEXT_INSTRUCTIONS))
        return []

    def getJumpTargets(self, jump_instruction, state):
        d = self.disassembler
        address = jump_instruction[0]
        decoded = decode(d, [jump_instruction])
        if not decoded:
            return []
        ins = decoded[0][1]
        thumb = _thumbOf(d)
        base = split_mnemonic(jump_instruction[2])[0]
        context = _context(d, state, address)
        tracker = track(d, context, thumb)
        operands = ins.operands
        if base in ("tbb", "tbh") and operands and operands[0].type == ARM_OP_MEM:
            return self._tableBranch(state, ins, context, tracker, 1 if base == "tbb" else 2)
        if not operands or operands[0].type != ARM_OP_REG:
            return self._registerBranch(state, ins, context, tracker)
        if base == "ldr" and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
            memory = operands[1]
            if not memory.mem.index:
                return []
            table = self._baseValue(ins, memory, tracker, thumb)
            index = norm_reg(ins.reg_name(memory.mem.index))
            return self._absoluteTable(state, address, table, self._bound(context, index), thumb)
        if base == "add" and len(operands) == 3:
            left, right = operands[1], operands[2]
            if left.type == ARM_OP_REG and norm_reg(ins.reg_name(left.reg)) == "pc" and right.type == ARM_OP_REG:
                index = norm_reg(ins.reg_name(right.reg))
                return self._branchTable(state, address, pc_value(address, thumb), self._bound(context, index))
            return self._relativeTable(state, ins, context, tracker, thumb)
        return self._registerBranch(state, ins, context, tracker)

    @staticmethod
    def _baseValue(ins, memory, tracker, thumb):
        base_reg = norm_reg(ins.reg_name(memory.mem.base))
        if base_reg == "pc":
            return pc_value(ins.address, thumb, aligned=True)
        return tracker.get(base_reg)

    def _registerBranch(self, state, ins, context, tracker):
        # bx rx / mov pc, rx whose value came out of a table
        operands = ins.operands
        if not operands or operands[-1].type != ARM_OP_REG:
            return []
        register = norm_reg(ins.reg_name(operands[-1].reg))
        writer = self._lastWriter(context, register)
        if writer is None:
            return []
        writer_base = split_mnemonic(writer[0][2])[0]
        detailed = writer[1]
        if writer_base == "ldr" and len(detailed.operands) == 2 and detailed.operands[1].type == ARM_OP_MEM:
            memory = detailed.operands[1]
            if not memory.mem.index:
                return []
            prefix = context[: context.index(writer)]
            table = self._baseValue(
                detailed,
                memory,
                track(self.disassembler, prefix, _thumbOf(self.disassembler)),
                _thumbOf(self.disassembler),
            )
            index = norm_reg(detailed.reg_name(memory.mem.index))
            return self._absoluteTable(
                state, ins.address, table, self._bound(prefix, index), _thumbOf(self.disassembler)
            )
        if writer_base == "add" and len(detailed.operands) == 3:
            prefix = context[: context.index(writer)]
            return self._relativeTable(
                state,
                detailed,
                prefix,
                track(self.disassembler, prefix, _thumbOf(self.disassembler)),
                _thumbOf(self.disassembler),
                jump_address=ins.address,
            )
        return []

    @staticmethod
    def _lastWriter(context, register):
        for pair in reversed(context):
            detailed = pair[1]
            if not detailed.operands or detailed.operands[0].type != ARM_OP_REG:
                continue
            base = split_mnemonic(pair[0][2])[0]
            if base in ("cmp", "cmn", "tst", "teq") or base.startswith("str"):
                continue
            if norm_reg(detailed.reg_name(detailed.operands[0].reg)) == register:
                return pair
        return None

    def _relativeTable(self, state, ins, context, tracker, thumb, jump_address=None):
        jump_address = ins.address if jump_address is None else jump_address
        operands = ins.operands
        if len(operands) != 3 or operands[1].type != ARM_OP_REG or operands[2].type != ARM_OP_REG:
            return []
        first = norm_reg(ins.reg_name(operands[1].reg))
        second = norm_reg(ins.reg_name(operands[2].reg))
        for anchor_reg, loaded_reg in ((first, second), (second, first)):
            anchor = tracker.get(anchor_reg)
            if anchor is None:
                continue
            writer = self._lastWriter(context, loaded_reg)
            if writer is None or split_mnemonic(writer[0][2])[0] != "ldr":
                continue
            detailed = writer[1]
            if len(detailed.operands) != 2 or detailed.operands[1].type != ARM_OP_MEM:
                continue
            memory = detailed.operands[1]
            if not memory.mem.index:
                continue
            prefix = context[: context.index(writer)]
            table = self._baseValue(detailed, memory, track(self.disassembler, prefix, thumb), thumb)
            if table is None:
                continue
            index = norm_reg(detailed.reg_name(memory.mem.index))
            return self._readTable(
                state,
                jump_address,
                table,
                4,
                self._bound(prefix, index),
                lambda entry, anchor=anchor: (anchor + entry) & 0xFFFFFFFF,
                signed=True,
            )
        return []

    def _absoluteTable(self, state, address, table, bound, thumb):
        if table is None:
            return []

        def target(entry):
            if thumb and not entry & 1:
                return None
            return entry & ~1

        return self._readTable(state, address, table, 4, bound, target)

    def _tableBranch(self, state, ins, context, tracker, entry_size):
        memory = ins.operands[0]
        thumb = True
        table = self._baseValue(ins, memory, tracker, thumb)
        if table is None or not memory.mem.index:
            return []
        if norm_reg(ins.reg_name(memory.mem.base)) == "pc":
            table = ins.address + 4
        index = norm_reg(ins.reg_name(memory.mem.index))
        origin = ins.address + 4
        return self._readTable(
            state, ins.address, table, entry_size, self._bound(context, index), lambda entry: origin + 2 * entry
        )

    def _branchTable(self, state, address, table, bound):
        # add pc, pc, rm, lsl #2: the entries are the branch instructions themselves
        d = self.disassembler
        limit = bound if bound else MAX_UNBOUNDED_ENTRIES
        targets = []
        for index in range(min(limit, MAX_TABLE_ENTRIES)):
            entry = table + 4 * index
            data = d.disassembly.getBytes(entry, 4)
            if not data or len(data) != 4:
                break
            word = int.from_bytes(data, "little")
            if not bound and (word & 0x0F000000) != 0x0A000000:
                break
            if not d.disassembly.binary_info.isInCodeAreas(entry):
                break
            targets.append(entry)
        del state
        return targets

    def _readTable(self, state, address, table, entry_size, bound, to_target, signed=False):
        d = self.disassembler
        disassembly = d.disassembly
        limit = bound if bound else MAX_UNBOUNDED_ENTRIES
        targets = []
        inline = disassembly.binary_info.isInCodeAreas(table)
        lowest_target = None
        for index in range(min(limit, MAX_TABLE_ENTRIES)):
            entry_addr = table + index * entry_size
            if inline and lowest_target is not None and entry_addr >= lowest_target:
                break
            if entry_addr in disassembly.code_map:
                break
            data = disassembly.getBytes(entry_addr, entry_size)
            if not data or len(data) != entry_size:
                break
            entry = int.from_bytes(data, "little", signed=signed)
            target = to_target(entry)
            if target is None or not disassembly.isAddrWithinMemoryImage(target):
                break
            if not disassembly.binary_info.isInCodeAreas(target):
                break
            if inline and table <= target < entry_addr + entry_size:
                break
            targets.append(target)
            state.addDataRef(address, entry_addr, size=entry_size)
            if inline and target > table and (lowest_target is None or target < lowest_target):
                lowest_target = target
        return targets

    @staticmethod
    def _bound(context, index):
        """Entry count from the comparison guarding the dispatch, or 0 when none is found.

        Follows the index back through register copies and a spill to and reload from the
        stack, which is how unoptimised code carries it from its ``cmp`` to the dispatch.
        """
        tracked = {index}
        slots = set()
        # comparisons met walking backwards whose register is not yet known to hold the
        # index: -O0 code stores the value to its stack slot before comparing it
        compared = {}
        for pair in reversed(context):
            ins, detailed = pair
            base, condition, _ = split_mnemonic(ins[2])
            operands = detailed.operands
            if not operands:
                continue
            first = operands[0]
            first_reg = norm_reg(detailed.reg_name(first.reg)) if first.type == ARM_OP_REG else None
            if base == "cmp" and first_reg is not None and len(operands) == 2 and operands[1].type == ARM_OP_IMM:
                if first_reg in tracked:
                    return operands[1].imm + 1
                compared.setdefault(first_reg, operands[1].imm + 1)
                continue
            if base == "b" and condition in _BOUND_BRANCHES:
                continue
            if first_reg is None:
                continue
            if base == "str" and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
                memory = operands[1]
                if norm_reg(detailed.reg_name(memory.mem.base)) == "sp" and memory.mem.disp in slots:
                    if first_reg in compared:
                        return compared[first_reg]
                    tracked.add(first_reg)
                continue
            compared.pop(first_reg, None)
            if base == "ldr" and first_reg in tracked and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
                memory = operands[1]
                if norm_reg(detailed.reg_name(memory.mem.base)) == "sp" and not memory.mem.index:
                    slots.add(memory.mem.disp)
                    tracked.discard(first_reg)
                continue
            if base == "mov" and first_reg in tracked and len(operands) == 2 and operands[1].type == ARM_OP_REG:
                tracked.discard(first_reg)
                tracked.add(norm_reg(detailed.reg_name(operands[1].reg)))
        return 0
