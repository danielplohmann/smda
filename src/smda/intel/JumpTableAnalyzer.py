import logging
import re
import struct

from smda.intel.definitions import RET_INS, canonicalRegister, stripFlatSegmentOverride

LOGGER = logging.getLogger(__name__)

_DIRECT_TABLE_RE = re.compile(r"[a-z0-9]{2,3}, dword ptr \[[^ ]+ \+ 0x[0-9a-f]+\]")
_X64_LEA_TABLE_RE = re.compile(r"[a-z0-9]{2,3}, \[rip (\+|\-) 0x[0-9a-f]+\]")
_X64_BONUS_OFFSET_RE = re.compile(r"[a-z0-9]{2,3},.*0x[0-9a-f]+\]")
_SCALED_INDEX_RE = re.compile(r"\[(?:[a-z][a-z0-9]{1,3} \+ )?(?P<index>[a-z][a-z0-9]{1,3})\*[1248]")
_IMMEDIATE_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9]{1,4}")
_INDEX_COPY_MNEMONICS = frozenset({"mov", "movzx", "movsx", "movsxd", "movabs"})
# first operand read but not written, so it redefines no index
_INDEX_READ_ONLY_MNEMONICS = frozenset({"test", "push", "bt", "nop"})


class JumpTableAnalyzer:
    """Perform jump table handling.
    There are generally a few typical patterns here:
    A) multiplicative
        cmp     eax, jumptable_size
        ja      loc_default
        mov     eax, ds:off_jumptable[eax*4]
        jmp     eax
    B) additive
        cmp     [ebp+arg_4], jumptable_size
        ja      loc_default
        mov     eax, [ebp+arg_4]
        shl     eax, 2
        add     eax, off_jumptable
        mov     eax, [eax]
        jmp     eax
    C) multiplicative, relative
        cmp     rcx, jumptable_size
        lea     r11, off_jumptable
        movsxd  rcx, ds:(off_jumptable)[r11+rdx*4]
        lea     rcx, [r11+rcx]
        jmp     rcx
    """

    # Deliberately register-only. The pattern-B bound check above compares a stack slot, but
    # widening this to any `cmp <mem>, <imm>` matches unrelated compares in the backtrack
    # window, and _findJumpTableSize takes the first hit without tying it to the jump index:
    # measured on the bundled mirai_x64 fixture, that enables a bogus direct table and costs
    # one recovered function. Recognizing pattern B needs index tracking, not a wider regex.
    RE_CMP_SIZE = re.compile(r"[a-z0-9]{2,4}, (([0-9])|(0x[0-9a-f]+))")

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly
        self.table_offsets = self._findJumpTables()

    def _findJumpTables(self):
        jumptables = set()
        for match_offset in re.finditer(
            b"(\x48|\x4c)\x8d.{5}(.\x63|\x77|.\x89..\x63)",
            self.disassembly.binary_info.binary,
            re.DOTALL,
        ):
            raw_offset_bytes = self.disassembly.getRawBytes(match_offset.start() + 3, 4)
            if len(raw_offset_bytes) < 4:
                continue
            # the lea disp32 is signed; a backward-referencing lea (e.g. -0x1000) must
            # unpack as a signed value or the table offset overflows and gets dropped.
            rel_table_offset = struct.unpack("<i", raw_offset_bytes)[0]
            ins_offset = self.disassembly.binary_info.base_addr + match_offset.start()
            table_offset = ins_offset + rel_table_offset + 7
            if self.disassembly.isAddrWithinMemoryImage(table_offset):
                jumptables.add(table_offset)
        return jumptables

    @staticmethod
    def _operandKey(operand):
        """A comparable name for whatever an operand reads: a register family or a memory cell.

        A memory key keeps its size prefix. "dword ptr [rbp - 8]" and "byte ptr [rbp - 8]" name
        overlapping storage but not the same value, so treating them as one key ties a bound to
        an index that was never compared against it.
        """
        operand = stripFlatSegmentOverride(operand.strip())
        register = canonicalRegister(operand)
        if register:
            return register
        if operand.startswith("[") or "ptr [" in operand:
            return operand
        return None

    @staticmethod
    def _keyRegisters(key):
        """The register families a memory key addresses through, empty for a register key."""
        if "[" not in key:
            return frozenset()
        return frozenset(
            register for register in (canonicalRegister(token) for token in _IDENTIFIER_RE.findall(key)) if register
        )

    @classmethod
    def _invalidated(cls, tracked, destination_key):
        """tracked with everything the write to destination_key just made stale.

        A memory cell is only as stable as the registers that address it: once the base is
        written, the same text names different storage.
        """
        return {key for key in tracked if key != destination_key and destination_key not in cls._keyRegisters(key)}

    @classmethod
    def _dispatchIndexKeys(cls, operand):
        """The operand a table read takes its index from, as a one-element set.

        A scaled memory operand ("[r11 + rdx*4]") indexes with its scaled register, so that
        register is what a bound check tests; anything else reads as a whole.
        """
        scaled = _SCALED_INDEX_RE.search(operand)
        if scaled:
            key = cls._operandKey(scaled.group("index"))
            return {key} if key else set()
        key = cls._operandKey(operand)
        return {key} if key else set()

    def _findJumpTableSize(self, backtracked, index_keys=None):
        """Recover the switch bound, preferring a compare against the dispatch's own index.

        Walking back to the first `cmp <reg>, <imm>` finds an unrelated compare whenever one
        sits between the real bound check and the dispatch, and misses pattern B entirely,
        where the bound is checked against the memory cell the index is loaded from. Following
        the index backwards through its copies answers both: the compare that bounds the table
        is the one testing whatever the dispatch ends up indexing with.
        """
        tracked = set(index_keys) if index_keys else set()
        untied_size = 0
        for instr in backtracked[::-1]:
            mnemonic = instr[2].split(" ")[-1]
            if mnemonic in RET_INS:
                break
            operands = instr[3]
            if mnemonic == "cmp":
                left, _, right = operands.partition(",")
                right = right.strip()
                if _IMMEDIATE_RE.match(right):
                    bound = int(right, 16 if right.startswith("0x") else 10) + 1
                    if tracked and self._operandKey(left) in tracked:
                        return bound
                    if not untied_size and self.RE_CMP_SIZE.match(operands):
                        untied_size = bound
                continue
            if not tracked or mnemonic in _INDEX_READ_ONLY_MNEMONICS:
                continue
            destination, _, source = operands.partition(",")
            destination_key = self._operandKey(destination)
            if destination_key is None:
                continue
            if mnemonic in _INDEX_COPY_MNEMONICS:
                carried = self._dispatchIndexKeys(source) if destination_key in tracked else set()
                tracked = self._invalidated(tracked, destination_key) | carried
                continue
            # Anything else redefines whatever it writes, and several x86 instructions write a
            # register they do not name first - xchg and xadd write both operands, mul and div
            # write rdx:rax, cpuid writes four. Invalidating only the named one would leave a
            # tie to a compare that bounds a value the dispatch never indexes with, so the tie
            # is dropped whole and the untied scan answers instead.
            tracked = set()
        return untied_size

    def _directHandler(self, jump_instruction_op_str, state, backtracked):
        register = jump_instruction_op_str.lower()
        data_ref_instruction_addr = None
        off_jumptable = None
        for instr in backtracked[::-1]:
            if instr[2] == "mov" and _DIRECT_TABLE_RE.match(instr[3]):
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.disassembler.getReferencedAddr(instr[3])
                state.addDataRef(data_ref_instruction_addr, off_jumptable, size=4)
                # print("    0x%x: _directHandler() found potential jump table offset (mov) with backtracking: 0x%x (%s %s)" % (instr[0], off_jumptable, instr[2], instr[3]))
                break
            elif instr[2] == "add" and instr[3].startswith(register):
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.disassembler.getReferencedAddr(instr[3])
                state.addDataRef(data_ref_instruction_addr, off_jumptable, size=4)
                # print("  0x%x: _directHandler() found potential jump table offset (add) with backtracking: 0x%x (%s %s)" % (instr[0], off_jumptable, instr[2], instr[3]))
                break
        return off_jumptable

    def _x64Handler(self, state, backtracked, target_register=None):
        off_jumptable = None
        for instr in backtracked[::-1]:
            if instr[2] == "lea" and _X64_LEA_TABLE_RE.match(instr[3]):
                if target_register and target_register not in instr[3]:
                    continue
                data_ref_instruction_addr = instr[0]
                # getReferencedAddr() preserves the displacement sign
                offset = self.disassembler.getReferencedAddr(instr[3])
                off_jumptable = instr[0] + instr[1] + offset
                state.addDataRef(data_ref_instruction_addr, off_jumptable, size=4)
                # print("  0x%x: _addHandler() found potential jump table offset (mov) with backtracking: 0x%x (%s %s)" % (instr[0], off_jumptable, instr[2], instr[3]))
                break
        return off_jumptable

    def _getx64BonusOffset(self, backtracked):
        bonus_offset = 0
        for instr in backtracked[::-1][:3]:
            if instr[2] == "mov" and _X64_BONUS_OFFSET_RE.match(instr[3]):
                bonus_offset = self.disassembler.getReferencedAddr(instr[3])
                break
        return bonus_offset

    def _extractDirectTableOffsets(self, jumptable_size, off_jumptable, state=None, jump_instruction_address=None):
        bound_was_recovered = bool(jumptable_size)
        jumptable_size = jumptable_size if bound_was_recovered else 0xFF
        jump_targets = set()
        if off_jumptable and self.disassembly.isAddrWithinMemoryImage(off_jumptable):
            for index in range(jumptable_size):
                raw_entry_bytes = self.disassembly.getBytes(off_jumptable + index * 4, 4)
                if raw_entry_bytes is None or len(raw_entry_bytes) < 4:
                    break
                entry = struct.unpack("<I", raw_entry_bytes)[0]
                if not entry or not self.disassembly.isAddrWithinMemoryImage(entry):
                    if bound_was_recovered:
                        continue
                    break
                jump_targets.add(entry)
                if state is not None:
                    state.addDataRef(jump_instruction_address, off_jumptable + index * 4, size=4)
        return sorted(jump_targets)

    def _extractRelativeTableOffsets(
        self,
        jumptable_size,
        off_jumptable,
        alternative_base=None,
        bonus_offset=0,
        state=None,
        jump_instruction_address=None,
    ):
        jumptable_size = jumptable_size if jumptable_size else 0xFF
        jump_targets = set()
        jump_base = alternative_base if alternative_base else off_jumptable
        if jumptable_size and off_jumptable and self.disassembly.isAddrWithinMemoryImage(off_jumptable):
            rebased = off_jumptable + bonus_offset - self.disassembly.binary_info.base_addr
            # loop-invariant, so it decides the whole scan on the first entry rather than
            # once per declared entry
            if rebased < 0:
                return sorted(jump_targets)
            for index in range(jumptable_size):
                raw_entry_bytes = self.disassembly.getRawBytes(rebased + index * 4, 4)
                # the read offset only grows, so a short one means the table has run off the
                # end of the image and every later entry reads the same way. The bound is
                # recovered from a compare against attacker-controlled bytes, so continuing
                # here spends it as an iteration count: 0xffffffff is a four-billion-entry
                # walk over an image that holds a few thousand.
                if len(raw_entry_bytes) < 4:
                    break
                # relative entries are target - table_base as int32 and are negative
                # whenever the switch bodies precede the table; unpack signed so the
                # real offset is recovered, then mask before the bounds check (line 140
                # already masks when building the target).
                entry = struct.unpack("<i", raw_entry_bytes)[0]
                # check if we are hitting a known jump table
                if index and (off_jumptable + index * 4) in self.table_offsets:
                    # print("  Hit limit for jump table: 0x%x" % (off_jumptable + index * 4))
                    break
                if not self.disassembly.isAddrWithinMemoryImage((jump_base + entry) & self.disassembler.getBitMask()):
                    break
                if entry:
                    target = (jump_base + entry) & self.disassembler.getBitMask()
                    jump_targets.add(target)
                    if state is not None:
                        # Claim the entry as data. `rebased` is an image offset, so the address
                        # has to be rebuilt from off_jumptable -- without this the table bytes
                        # stay unclaimed and the gap scan seeds function candidates inside them.
                        state.addDataRef(
                            jump_instruction_address,
                            off_jumptable + bonus_offset + index * 4,
                            size=4,
                        )
                elif not alternative_base:
                    break
        return sorted(jump_targets)

    def _resolveExplicitTable(self, jump_instruction_address, state, jumptable_address, jumptable_size=None):
        # _findJumpTableSize reports an unrecovered bound as 0, not None, so testing against
        # None here read "zero entries" and abandoned the table -- mirror the truthiness test
        # _extractRelativeTableOffsets uses, and let the per-entry image bound stop the scan.
        jumptable_size = jumptable_size if jumptable_size else 0xFF
        jumptable_addresses = []
        bitness = self.disassembly.binary_info.bitness
        if bitness == 32:
            entry_size = 4
            entry_format = "<I"
        elif bitness == 64:
            entry_size = 8
            entry_format = "<Q"
        else:
            LOGGER.warning("Unsupported %s-bit jump table analysis", bitness)
            return jumptable_addresses
        if jumptable_address and self.disassembly.isAddrWithinMemoryImage(jumptable_address):
            for i in range(jumptable_size):
                raw_entry_bytes = self.disassembly.getBytes(jumptable_address + i * entry_size, entry_size)
                if raw_entry_bytes is None or len(raw_entry_bytes) < entry_size:
                    break
                table_entry = struct.unpack(entry_format, raw_entry_bytes)[0]
                if not table_entry or not self.disassembly.isAddrWithinMemoryImage(table_entry):
                    break
                state.addDataRef(
                    jump_instruction_address,
                    jumptable_address + i * entry_size,
                    size=entry_size,
                )
                jumptable_addresses.append(table_entry)
        return jumptable_addresses

    def getJumpTargets(self, jump_instruction, state):
        (
            jump_instruction_address,
            jump_instruction_size,
            jump_instruction_mnemonic,
            jump_instruction_op_str,
        ) = jump_instruction
        table_offsets = []
        off_jumptable = None
        # Every consumer of this window matches anchored operand patterns, and a segment
        # override renders inside the operand, so the byte that makes a dispatch a notrack
        # dispatch also hides its table base and its bound compare. Normalizing the window
        # at its single source keeps the strip off the stored instruction, whose operand
        # text and escaped form still describe the bytes that are there.
        backtracked = [
            (instr[0], instr[1], instr[2], stripFlatSegmentOverride(instr[3]), *instr[4:])
            for instr in state.backtrackInstructions(jump_instruction_address, 50)
        ]
        backtracked_sequence = "-".join([ins[2] for ins in backtracked[::-1]][:3])
        index_keys = self._dispatchIndexKeys(stripFlatSegmentOverride(jump_instruction_op_str))
        jumptable_size = self._findJumpTableSize(backtracked, index_keys)
        # if False and jump_instruction_address:
        #     print("0x%x %s %s -> %s" % (jump_instruction_address, jump_instruction_mnemonic, jump_instruction_op_str, backtracked_sequence))
        if jump_instruction_op_str.startswith(("dword ptr [", "qword ptr [")):
            off_jumptable = self.disassembler.getReferencedAddr(jump_instruction_op_str)
            table_offsets = self._resolveExplicitTable(jump_instruction_address, state, off_jumptable, jumptable_size)
        else:
            # 32bit cases typically load into target register directly
            if backtracked_sequence.startswith("mov"):
                off_jumptable = self._directHandler(jump_instruction_op_str, state, backtracked)
                table_offsets = self._extractDirectTableOffsets(
                    jumptable_size,
                    off_jumptable,
                    state=state,
                    jump_instruction_address=jump_instruction_address,
                )
            elif backtracked_sequence.startswith("add-movsxd"):
                off_jumptable = self._x64Handler(state, backtracked)
                alternative_base = 0
                if "rsi" in backtracked[::-1][0][3]:
                    alternative_base = self._x64Handler(state, backtracked, "rsi")
                table_offsets = self._extractRelativeTableOffsets(
                    jumptable_size,
                    off_jumptable,
                    alternative_base=alternative_base,
                    state=state,
                    jump_instruction_address=jump_instruction_address,
                )
            elif backtracked_sequence.startswith(("lea", "add-add", "add-shr")):
                off_jumptable = self._x64Handler(state, backtracked)
                table_offsets = self._extractRelativeTableOffsets(
                    jumptable_size, off_jumptable, state=state, jump_instruction_address=jump_instruction_address
                )
            elif backtracked_sequence.startswith("add-mov"):
                off_jumptable = self._x64Handler(state, backtracked)
                bonus = self._getx64BonusOffset(backtracked)
                table_offsets = self._extractRelativeTableOffsets(
                    jumptable_size,
                    off_jumptable,
                    bonus_offset=bonus,
                    state=state,
                    jump_instruction_address=jump_instruction_address,
                )
        # if False and off_jumptable and table_offsets:
        #     print("  Found jump table: 0x%x -> %d" % (off_jumptable, len(table_offsets)))
        #     for offset in sorted(list(set(table_offsets))):
        #         print("    0x%x" % offset)
        return table_offsets
