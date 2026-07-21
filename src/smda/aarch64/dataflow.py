"""Shared AArch64 constant-propagation and predecessor-context helpers.

``AArch64IndirectCallAnalyzer`` and ``AArch64JumpTableAnalyzer`` used to carry two
independent copies of the same adrp/adr/add/mov/ldr constant-tracking forward pass
over capstone operands. This module is the single, maintained copy.
"""

import struct

from capstone.arm64_const import ARM64_SFT_LSL

from .definitions import INSTRUCTION_SIZE, adrp_page_value


def norm_reg(name):
    """Normalize register names to handle wD vs xD classes."""
    if not name:
        return ""
    name = name.lower()
    if name.startswith(("w", "x")):
        return "x" + name[1:]
    return name


def movImmediateValue(op):
    """Value contributed by an IMM operand of mov/movz/movk, with LSL applied.

    Capstone leaves ``op.imm`` as the raw unshifted 16-bit field
    (e.g. ``movk w8, #0x6c6c, lsl #16`` reports imm=0x6c6c, not 0x6c6c0000).
    """
    shift = op.shift.value if op.shift.type == ARM64_SFT_LSL else 0
    return op.imm << shift, shift


def _applyConstantWrite(cap_ins, constants, disassembler):
    """Apply one instruction's effect (if any) to a dest-register -> value map, in place."""
    d = disassembler
    if not cap_ins.operands:
        return
    mnemonic = cap_ins.mnemonic.lower()
    dest_op = cap_ins.operands[0]
    if dest_op.type != 1:  # REG
        return
    dest_reg = norm_reg(cap_ins.reg_name(dest_op.reg))

    if mnemonic == "adrp" and len(cap_ins.operands) >= 2:
        word = int.from_bytes(cap_ins.bytes, "little")
        constants[dest_reg] = adrp_page_value(word, cap_ins.address)
    elif mnemonic == "adr" and len(cap_ins.operands) >= 2:
        if cap_ins.operands[1].type == 2:  # IMM
            constants[dest_reg] = cap_ins.operands[1].imm
    elif mnemonic == "add" and len(cap_ins.operands) >= 3:
        op1 = cap_ins.operands[1]
        op2 = cap_ins.operands[2]
        if op1.type == 1 and op2.type == 2:  # REG + IMM
            src_reg = norm_reg(cap_ins.reg_name(op1.reg))
            if src_reg in constants:
                constants[dest_reg] = constants[src_reg] + op2.imm
            else:
                constants.pop(dest_reg, None)
        elif op1.type == 1 and op2.type == 1:  # REG + REG (incl. extended/shifted register)
            reg1 = norm_reg(cap_ins.reg_name(op1.reg))
            reg2 = norm_reg(cap_ins.reg_name(op2.reg))
            if reg1 in constants and reg2 in constants:
                constants[dest_reg] = constants[reg1] + constants[reg2]
            else:
                constants.pop(dest_reg, None)
    elif mnemonic in ("mov", "movz", "movk") and len(cap_ins.operands) >= 2:
        op1 = cap_ins.operands[1]
        if op1.type == 2:  # IMM
            imm_value, shift = movImmediateValue(op1)
            if mnemonic == "movk" and dest_reg in constants:
                constants[dest_reg] = (constants[dest_reg] & ~(0xFFFF << shift)) | imm_value
            elif mnemonic == "movk":
                constants.pop(dest_reg, None)
            else:
                constants[dest_reg] = imm_value
        elif op1.type == 1:  # REG
            src_reg = norm_reg(cap_ins.reg_name(op1.reg))
            if src_reg in constants:
                constants[dest_reg] = constants[src_reg]
            else:
                constants.pop(dest_reg, None)
    elif mnemonic in ("ldr", "ldur") and len(cap_ins.operands) >= 2:
        op1 = cap_ins.operands[1]
        resolved = False
        if op1.type == 3:  # MEM
            base_reg = norm_reg(cap_ins.reg_name(op1.mem.base))
            if base_reg in constants and op1.mem.index == 0:
                slot_addr = constants[base_reg] + op1.mem.disp
                if d.disassembly.isAddrWithinMemoryImage(slot_addr):
                    raw_val = d.disassembly.getBytes(slot_addr, 8)
                    if raw_val and len(raw_val) == 8:
                        constants[dest_reg] = struct.unpack("<Q", raw_val)[0]
                        resolved = True
        if not resolved:
            constants.pop(dest_reg, None)


def propagateConstants(cap_insns, disassembler):
    """Forward constant-propagation pass over a sequence of decoded capstone instructions.

    Tracks adrp/adr/add (reg+imm, reg+reg)/mov(z|k)/ldr(image-slot dereference) into a
    dest-register -> value map, popping the destination register on any unresolved write
    by one of these mnemonics so a stale value never survives past a redefinition. Returns
    the final map, i.e. constants as of right after the last instruction.
    """
    constants = {}
    for cap_ins in cap_insns:
        _applyConstantWrite(cap_ins, constants, disassembler)
    return constants


def propagateConstantsHistory(cap_insns, disassembler):
    """Like :func:`propagateConstants`, but returns one map per instruction, each holding
    constants as they stood immediately BEFORE that instruction executes.

    Needed when a later step inspects instruction i's own *source* operands: if
    instruction i also writes an unresolved value to the same register it reads (e.g. a
    jump-table base register reused as the destination of the very load it addresses),
    the single trailing map from :func:`propagateConstants` no longer reflects the value
    instruction i actually read - only the map as of just before it does.
    """
    constants = {}
    history = []
    for cap_ins in cap_insns:
        history.append(dict(constants))
        _applyConstantWrite(cap_ins, constants, disassembler)
    return history


def gatherContextInstructions(disassembler, state, seed_addr, depth, block_index=None, window=200):
    """Collect the seed block's prefix plus up to ``depth`` unique predecessor blocks.

    Instructions come back decoded (capstone ``CsInsn``) and in ascending address order,
    ready for :func:`propagateConstants`. Predecessor blocks are discovered via
    ``state.code_refs_to`` (populated incrementally as instructions are decoded, so this
    is safe to call at any point during a function's analysis).

    ``block_index`` is an optional ``{instruction_addr: block}`` map built from
    ``state.getBlocks()`` (see ``AArch64IndirectCallAnalyzer.searchBlock``) — only safe to
    build once block reconstruction has finished, i.e. after ``state.finalizeAnalysis()``.
    Jump tables are resolved eagerly, mid-function, before that point, so they must omit
    ``block_index``: ``FunctionAnalysisState.getBlocks`` caches its result on first call, so
    calling it before the function's instructions are complete would poison that cache with
    a partial block layout. Without ``block_index``, the window is the *flat*
    ``state.backtrackInstructions`` result, unfiltered by block boundaries — exactly the
    pre-existing behavior — because ``state.jump_targets`` only reflects jumps seen so far
    and is a poor, easily-wrong proxy for a real block boundary; filtering the window by it
    was found to *discard* legitimate preceding context whenever an unrelated jump target
    happened to land inside the window (common in dense real-world code), which is strictly
    worse than the old unfiltered window. The approximate block start is still computed and
    used, additively, to seed the predecessor-hop search below.
    """
    d = disassembler
    code_refs_to = getattr(state, "code_refs_to", {})
    seen_addrs = set()
    ordered_ins = []

    def approx_block_start(addr):
        # Default to 0 (not `addr`) when the state doesn't expose start_addr/jump_targets,
        # so predecessor-hop lookups still get a well-defined (if imprecise) seed key.
        best = getattr(state, "start_addr", 0)
        if best > addr:
            best = addr
        for jump_target in getattr(state, "jump_targets", None) or ():
            if best < jump_target <= addr:
                best = jump_target
        return best

    def block_and_start(addr):
        if block_index is not None:
            block = block_index.get(addr, [])
            return (block, block[0][0]) if block else ([], None)
        return state.backtrackInstructions(addr + INSTRUCTION_SIZE, window), approx_block_start(addr)

    def collect(addr, upper_bound):
        block, block_start = block_and_start(addr)
        if block_start is None:
            return None
        for ins in block:
            if ins[0] < upper_bound and ins[0] not in seen_addrs:
                seen_addrs.add(ins[0])
                ordered_ins.append(ins)
        return block_start

    seed_block_start = collect(seed_addr, seed_addr)
    if seed_block_start is None:
        return []

    visited_block_starts = {seed_block_start}
    frontier_starts = {seed_block_start}
    for _ in range(depth):
        pred_addrs = set()
        for start in frontier_starts:
            pred_addrs.update(code_refs_to.get(start, ()))
        pred_addrs -= visited_block_starts
        if not pred_addrs:
            break
        next_frontier = set()
        for pred_addr in sorted(pred_addrs):
            pred_block_start = collect(pred_addr, pred_addr + INSTRUCTION_SIZE)
            if pred_block_start is None or pred_block_start in visited_block_starts:
                continue
            visited_block_starts.add(pred_block_start)
            next_frontier.add(pred_block_start)
        frontier_starts = next_frontier

    ordered_ins.sort(key=lambda ins: ins[0])
    detailed = []
    for ins in ordered_ins:
        raw = d.disassembly.getBytes(ins[0], ins[1])
        if not raw:
            continue
        cap_ins = next(d.capstone.disasm(raw, ins[0]), None)
        if cap_ins:
            detailed.append(cap_ins)
    return detailed
