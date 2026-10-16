"""AArch32 collaborators for the recursive engine.

TF-IDF mnemonic scoring, register-indirect call resolution, jump-table recovery and
import-stub decoding, all built on the straight-line tracker in :mod:`smda.arm.dataflow`.
"""

import logging
import math
from collections import Counter

from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_SFT_INVALID

from .dataflow import RegisterTracker, decode, norm_reg, pc_value, precedingInstructions, track, written_registers
from .definitions import CALL_BASES, split_mnemonic

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
#: guard conditions under which the compared immediate is not itself a valid index
_EXCLUSIVE_BOUNDS = frozenset({"hs", "lo", "cs", "cc", "ge", "lt"})
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
#: entry size of the signed offset loads feeding MSVC's ``add pc, rt`` switch
_SIGNED_OFFSET_LOADS = {"ldrsb": 1, "ldrsh": 2}


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
    cache = disassembler.import_stub_cache
    if cache is None or cache[0] is not disassembler.disassembly:
        # every call and branch target is looked up, most of them many times over
        cache = disassembler.import_stub_cache = (disassembler.disassembly, {})
    key = (start, thumb)
    if key not in cache[1]:
        cache[1][key] = _decodeImportStub(disassembler, start, thumb)
    return cache[1][key]


def _decodeImportStub(disassembler, start, thumb):
    d = disassembler
    capstone = d.capstone
    address = start
    if thumb:
        prefix = d.disassembly.getBytes(address, 2)
        if prefix and bytes(prefix) == b"\x78\x47":
            address = pc_value(address, True, aligned=True)
            thumb = False
    data = d.disassembly.getBytes(address, 4 * MAX_STUB_INSTRUCTIONS)
    if not data:
        return None
    engine = capstone.thumb if thumb else capstone.arm
    data = bytes(data)
    # most lookups land on an ordinary function: reject it before the detailed decode,
    # which only a run of stub instructions ending in a transfer can pass
    for _address, _size, mnemonic, op_str in engine.disasm_lite(data, address, MAX_STUB_INSTRUCTIONS):
        base, condition, _ = split_mnemonic(mnemonic)
        if condition not in (None, "al") or base not in _STUB_BASES:
            return None
        if _isStubTransfer(base, op_str):
            break
    else:
        return None
    tracker = RegisterTracker(d, thumb)
    for ins in engine.disasm(data, address, MAX_STUB_INSTRUCTIONS):
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


def _isStubTransfer(base, op_str):
    """Whether a stub instruction is the branch that leaves it."""
    return base == "bx" or (base in ("ldr", "mov") and op_str.startswith("pc"))


def isImportStub(instructions):
    """Whether a function's single block of :class:`SmdaInstruction` is an import stub.

    The report-side counterpart of :func:`resolveImportStub`: a stored function carries no
    image to read slots from, so the stub shapes it decodes are matched on their operands
    instead - the PLT entry (``add ip, pc``; ``add ip, ip``; ``ldr pc, [ip]``), lld's literal
    form, the MSVC ``movw``/``movt``/``ldr``/``bx`` thunk and the T32 ``bx pc`` prefix in
    front of any of them. Both accept only :data:`_STUB_BASES`, unconditionally, up to the
    branch :func:`_isStubTransfer` names, within :data:`MAX_STUB_INSTRUCTIONS`.
    """
    if len(instructions) > MAX_STUB_INSTRUCTIONS:
        return False
    if any(split_mnemonic(ins.mnemonic)[1] not in (None, "al") for ins in instructions):
        return False
    bases = [split_mnemonic(ins.mnemonic)[0].split(".", 1)[0] for ins in instructions]
    operands = [(ins.operands or "").lower().replace(" ", "") for ins in instructions]
    if any(base not in _STUB_BASES for base in bases):
        return False
    if bases and bases[0] == "bx" and operands[0] == "pc":
        # the T32 prefix in front of an A32 entry
        if len(bases) == 1:
            return True
        bases, operands = bases[1:], operands[1:]
    body = [(base, op_str) for base, op_str in zip(bases, operands, strict=True) if base != "nop"]
    if not body or not _isStubTransfer(*body[-1]):
        return False
    bases = [base for base, _ in body]
    operands = [op_str for _, op_str in body]
    final_base, final_operands = body[-1]
    if final_base == "ldr":
        if not final_operands.startswith("pc,"):
            return False
        if len(body) == 1:
            return "[pc" in final_operands
        if len(body) != 3 or bases not in (["add", "add", "ldr"], ["ldr", "add", "ldr"]):
            return False
        first, second = operands[0], operands[1]
        if bases[0] == "add":
            return (
                first.startswith(("ip,pc", "r12,pc"))
                and second.startswith(("ip,ip", "ip,r12", "r12,ip", "r12,r12"))
                and ("[ip" in final_operands or "[r12" in final_operands)
            )
        return (
            first.startswith(("ip,[pc", "r12,[pc"))
            and second.startswith(("ip,pc", "r12,pc"))
            and ("[ip" in final_operands or "[r12" in final_operands)
        )
    if final_base == "bx":
        target = final_operands
    elif final_operands.startswith("pc,"):
        target = final_operands.split(",", 1)[1]
    else:
        return False
    if target not in {f"r{index}" for index in range(13)} | {"ip"}:
        return False
    seeded_address = False
    for base, op_str in body[:-1]:
        parts = op_str.split(",", 1)
        destination = parts[0]
        source = parts[1] if len(parts) > 1 else ""
        if destination != target:
            return False
        if base in ("movw", "movt") and source.startswith("#"):
            seeded_address = seeded_address or base == "movw"
            continue
        if base == "adr" and source:
            seeded_address = True
            continue
        if base == "ldr" and source.startswith(("[pc", f"[{target}")):
            seeded_address = seeded_address or source.startswith("[pc")
            continue
        if base in ("add", "sub") and source.startswith(("pc", f"{target},")):
            seeded_address = seeded_address or source.startswith("pc")
            continue
        return False
    return seeded_address


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
    offsets relative to rt, the base rt was set up with ``adr`` or a pc-relative ``add``;
    and MSVC's Thumb ``add pc, rt`` taking a signed byte or halfword offset from the pc.
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
        condition = None
        if not context:
            context, condition = self._branchContext(state, address)
        bound = self._bound(context, "r0", condition)
        if word_offsets:
            table = (origin + 3) & ~3
            return self._readTable(
                state, address, table, 4, bound, lambda entry: (table + entry) & 0xFFFFFFFE, signed=True
            )
        return self._readTable(
            state, address, origin, entry_size, bound, lambda entry: origin + 2 * entry, signed=signed
        )

    def _branchContext(self, state, address):
        # the straight-line context of a conditional branch to ``address``, and its condition
        for ins in state.instructions:
            base, condition, _ = split_mnemonic(ins[2])
            if base == "b" and condition in _BOUND_BRANCHES and ins[3] == f"#0x{address:x}":
                return decode(self.disassembler, precedingInstructions(state, ins[0], CONTEXT_INSTRUCTIONS)), condition
        return [], None

    def getJumpTargets(self, jump_instruction, state):
        d = self.disassembler
        address = jump_instruction[0]
        decoded = decode(d, [jump_instruction])
        if not decoded:
            return []
        ins = decoded[0][1]
        thumb = _thumbOf(d)
        base, condition, _ = split_mnemonic(jump_instruction[2])
        context = _context(d, state, address)
        tracker = track(d, context, thumb)
        operands = ins.operands
        if base in ("tbb", "tbh") and operands and operands[0].type == ARM_OP_MEM:
            return self._tableBranch(state, ins, context, tracker, 1 if base == "tbb" else 2, condition)
        if not operands or operands[0].type != ARM_OP_REG:
            return self._registerBranch(state, ins, context, tracker)
        if base == "ldr" and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
            memory = operands[1]
            if not memory.mem.index:
                return []
            table = self._baseValue(ins, memory, tracker, thumb)
            index = norm_reg(ins.reg_name(memory.mem.index))
            return self._absoluteTable(state, address, table, self._bound(context, index, condition), thumb)
        if base == "add" and len(operands) == 3:
            left, right = operands[1], operands[2]
            if left.type == ARM_OP_REG and norm_reg(ins.reg_name(left.reg)) == "pc" and right.type == ARM_OP_REG:
                index = norm_reg(ins.reg_name(right.reg))
                bound = self._bound(context, index, condition)
                return self._branchTable(state, address, pc_value(address, thumb), bound)
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
        if writer_base in _SIGNED_OFFSET_LOADS and len(operands) == 2:
            return self._offsetTable(state, ins, context, writer)
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
        if writer_base == "add" and len(detailed.operands) in (2, 3):
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

    def _offsetTable(self, state, ins, context, writer):
        # MSVC: adr rt, table ; ldrsb rt, [rt, ri] (ldrsh.w ..., lsl #1) ; add pc, rt
        thumb = _thumbOf(self.disassembler)
        if not thumb or norm_reg(ins.reg_name(ins.operands[0].reg)) != "pc":
            return []
        detailed = writer[1]
        entry_size = _SIGNED_OFFSET_LOADS[split_mnemonic(writer[0][2])[0]]
        if len(detailed.operands) != 2 or detailed.operands[1].type != ARM_OP_MEM:
            return []
        memory = detailed.operands[1]
        shift = memory.shift
        if not memory.mem.index or memory.mem.disp or (shift.value if shift.type else 0) != entry_size // 2:
            return []
        prefix = context[: context.index(writer)]
        table = self._baseValue(detailed, memory, track(self.disassembler, prefix, thumb), thumb)
        if table is None:
            return []
        index = norm_reg(detailed.reg_name(memory.mem.index))
        origin = pc_value(ins.address, thumb)
        return self._readTable(
            state,
            ins.address,
            table,
            entry_size,
            self._bound(prefix, index),
            lambda entry: (origin + entry) & 0xFFFFFFFE,
            signed=True,
        )

    @staticmethod
    def _lastWriter(context, register):
        for pair in reversed(context):
            detailed = pair[1]
            base = split_mnemonic(pair[0][2])[0]
            if register in written_registers(detailed, base):
                return pair
        return None

    def _relativeTable(self, state, ins, context, tracker, thumb, jump_address=None):
        jump_address = ins.address if jump_address is None else jump_address
        # the two-operand Thumb ``add rd, rm`` adds into its destination
        operands = ins.operands[-2:] if len(ins.operands) == 3 else ins.operands
        if len(operands) != 2 or any(operand.type != ARM_OP_REG for operand in operands):
            return []
        first = norm_reg(ins.reg_name(operands[0].reg))
        second = norm_reg(ins.reg_name(operands[1].reg))
        # Thumb offsets carry the interworking bit for the ``bx`` that takes them
        mask = 0xFFFFFFFE if thumb else 0xFFFFFFFF
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
                lambda entry, anchor=anchor: (anchor + entry) & mask,
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

    def _tableBranch(self, state, ins, context, tracker, entry_size, condition):
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
            state,
            ins.address,
            table,
            entry_size,
            self._bound(context, index, condition),
            lambda entry: origin + 2 * entry,
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
            state.addDataRef(address, entry_addr, size=entry_size, is_table=True)
            if inline and target > table and (lowest_target is None or target < lowest_target):
                lowest_target = target
        return targets

    @staticmethod
    def _bound(context, index, condition=None):
        """Entry count from the comparison guarding the dispatch, or 0 when none is found.

        Follows the index back through register copies and a spill to and reload from the
        stack, which is how unoptimised code carries it from its ``cmp`` to the dispatch.
        The branch closest behind the ``cmp`` decides whether its immediate is itself a valid
        index: ``hi``/``gt`` leaving or ``ls``/``le`` reaching the dispatch admit it,
        ``hs``/``ge`` leaving or ``lo``/``lt`` reaching it do not. ``condition`` is the one
        under which the end of ``context`` reaches the dispatch (``ldrls pc``, or the branch
        to a case helper), when there is one. A write predicated on the condition of a
        conditional exit behind the ``cmp`` (clang's ``itt hi; movhi r0, #-1; bxhi lr``)
        only happens on the way out of range, so it leaves the index alone.
        """
        tracked = {index}
        slots = set()
        # comparisons met walking backwards whose register is not yet known to hold the
        # index: -O0 code stores the value to its stack slot before comparing it
        compared = {}
        # conditions under which an instruction met so far leaves before the dispatch
        exits = set()
        for pair in reversed(context):
            ins, detailed = pair
            base, branch, _ = split_mnemonic(ins[2])
            operands = detailed.operands
            if not operands:
                continue
            first = operands[0]
            first_reg = norm_reg(detailed.reg_name(first.reg)) if first.type == ARM_OP_REG else None
            if base == "cmp" and first_reg is not None and len(operands) == 2 and operands[1].type == ARM_OP_IMM:
                entries = operands[1].imm + (0 if condition in _EXCLUSIVE_BOUNDS else 1)
                condition = None
                exits.clear()
                if first_reg in tracked:
                    return entries
                compared.setdefault(first_reg, entries)
                continue
            writes = written_registers(detailed, base)
            if branch in _BOUND_BRANCHES and (base == "b" or (base not in CALL_BASES and "pc" in writes)):
                condition = branch
                exits.add(branch)
                continue
            if branch in exits:
                continue
            if "sp" in writes:
                slots.clear()
            if base == "str" and len(operands) == 2 and operands[1].type == ARM_OP_MEM:
                memory = operands[1]
                if (
                    norm_reg(detailed.reg_name(memory.mem.base)) == "sp"
                    and not memory.mem.index
                    and memory.mem.disp in slots
                ):
                    slots.discard(memory.mem.disp)
                    if branch not in (None, "al"):
                        return 0
                    if first_reg in compared:
                        return compared[first_reg]
                    tracked.add(first_reg)
                continue
            for reg in writes:
                compared.pop(reg, None)
            if (
                base == "ldr"
                and branch in (None, "al")
                and first_reg in tracked
                and len(operands) == 2
                and operands[1].type == ARM_OP_MEM
                and not detailed.writeback
            ):
                memory = operands[1]
                if norm_reg(detailed.reg_name(memory.mem.base)) == "sp" and not memory.mem.index:
                    slots.add(memory.mem.disp)
                    tracked.discard(first_reg)
                    continue
            if (
                base == "mov"
                and branch in (None, "al")
                and first_reg in tracked
                and len(operands) == 2
                and operands[1].type == ARM_OP_REG
                and operands[1].shift.type == ARM_SFT_INVALID
            ):
                tracked.discard(first_reg)
                tracked.add(norm_reg(detailed.reg_name(operands[1].reg)))
                continue
            tracked.difference_update(writes)
            if not tracked and not slots:
                return 0
        return 0
