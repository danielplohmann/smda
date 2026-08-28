import logging
import re
import struct

from smda.intel.definitions import (
    CALL_INS,
    RET_INS,
    VALUE_PRESERVING_MNEMONICS,
    canonicalRegister,
    stripFlatSegmentOverride,
)

LOGGER = logging.getLogger(__name__)

_DIRECT_TABLE_RE = re.compile(r"[a-z0-9]{2,3}, dword ptr \[[^ ]+ \+ 0x[0-9a-f]+\]")
# A 64-bit absolute table stores whole pointers, so its entries are qword rather than dword.
# Deliberately narrower than the dword form above: it requires the scaled index and admits no
# base register, because an 8-byte load off a plain base - `mov rax, qword ptr [rbp + 0x10]`,
# an ordinary stack read - would otherwise be taken for a table whose base is the displacement.
# With a base register present the effective address is not the displacement at all.
_DIRECT_TABLE_QWORD_RE = re.compile(r"[a-z0-9]{2,3}, qword ptr \[[a-z][a-z0-9]{1,3}\*[1248] \+ 0x[0-9a-f]+\]")
# Capstone spells a displacement below 10 as bare decimal and a zero one as plain "[rip]", so
# neither form matches. Both would put the table within ten bytes of the `lea` that addresses it,
# which no compiler emits - a switch table lives in a read-only section, not in the middle of the
# code reading it - and the walk that consults this stops at an unmatched `lea` rather than
# resolving one, so the residue is a table not found and never a wrong one.
_X64_LEA_TABLE_RE = re.compile(r"[a-z0-9]{2,3}, \[rip (\+|\-) 0x[0-9a-f]+\]")
# The other 64-bit absolute form keeps the table base in a register, so the operand carries no
# displacement to recognize it by and the base is what has to be resolved. It is written either
# into the branch register ("rax, qword ptr [rsi + rax*8]") or read by the branch itself
# ("qword ptr [rax + rdx*8]"), hence the optional destination.
_BASEREG_TABLE_RE = re.compile(
    r"(?:[a-z][a-z0-9]{1,3}, )?qword ptr \[(?P<base>[a-z][a-z0-9]{1,3}) \+ [a-z][a-z0-9]{1,3}\*8\]$"
)
_X64_BONUS_OFFSET_RE = re.compile(r"[a-z0-9]{2,3},.*0x[0-9a-f]+\]")
_SCALED_INDEX_RE = re.compile(r"\[(?:[a-z][a-z0-9]{1,3} \+ )?(?P<index>[a-z][a-z0-9]{1,3})\*[1248]")
_IMMEDIATE_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9]{1,4}")
_INDEX_COPY_MNEMONICS = frozenset({"mov", "movzx", "movsx", "movsxd", "movabs"})
# Mnemonics whose only register write is the operand they name first, so a backward walk can
# carry a value past one that names a different register.
_NAMED_DESTINATION_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "bswap",
        "dec",
        "inc",
        "lea",
        "mov",
        "movabs",
        "movsx",
        "movsxd",
        "movzx",
        "neg",
        "not",
        "or",
        "rol",
        "ror",
        "sal",
        "sar",
        "sbb",
        "shl",
        "shr",
        "sub",
        "xor",
    }
)
# What these write on top of whatever operand they name. A walk only has to stop at one when the
# register it is chasing is among them: a `cdqe` sign-extending the switch index sits between the
# table read and the `lea` that produced its base in ordinary compiler output, and stopping there
# would abandon the table. The one-operand forms of mul and imul write rdx:rax and name their
# other factor, so the pair is listed for both; the multi-operand `imul` writes only what it
# names, and _writesRegister asks that question separately.
#
# Two deliberate imprecisions, both of which only ever stop a walk that could have carried on.
# The pair is listed for mul and div without regard to operand size, though the 8-bit forms
# write ax alone and leave rdx untouched. And cwd/cdq/cqo are listed as writing rdx only,
# where capstone reports rax as written too: the value of rax is unchanged by them, so
# following capstone here would abandon a table for no reason. Do not "fix" either against a
# regs_write sweep without a measurement showing the precision is worth something.
_IMPLICIT_REGISTER_WRITES = {
    "cbw": ("rax",),
    "cwde": ("rax",),
    "cdqe": ("rax",),
    "cwd": ("rdx",),
    "cdq": ("rdx",),
    "cqo": ("rdx",),
    "mul": ("rax", "rdx"),
    "imul": ("rax", "rdx"),
    "div": ("rax", "rdx"),
    "idiv": ("rax", "rdx"),
    "rdtsc": ("rax", "rdx"),
    "rdtscp": ("rax", "rcx", "rdx"),
    "xgetbv": ("rax", "rdx"),
    "cpuid": ("rax", "rbx", "rcx", "rdx"),
    "syscall": ("rax", "rcx", "r11"),
}
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

    def _isCodePointer(self, address):
        """Whether an absolute table entry holds an address a case body could start at.

        The mapped image is too coarse a test on its own: whatever follows the table reads as
        more entries, and a data address comes back as a case target - measured at 49 entries
        running out of .text and into .rodata on a static glibc, which cost 20 recovered
        functions across the labelled corpus. A case body is code, so an entry outside the
        executable areas is not one, whether it is past the end of a table or a bound recovered
        from the sample's own compare was too large. A memory dump carries no section table,
        and isInCodeAreas then answers for the whole image exactly as the image bound alone did.
        """
        return self.disassembly.isAddrWithinMemoryImage(address) and self.disassembly.binary_info.isInCodeAreas(address)

    @classmethod
    def _addsTableBase(cls, mnemonic, destination_key, source):
        """Whether this instruction adds a table base to the value it overwrites.

        A relative dispatch ends by adding the table's base to the entry the table read
        produced - "add rax, rdi", or "lea rcx, [r11 + rcx]" - so the register the branch
        reads is that sum and not the switch index. A walk that treats the add as a
        redefinition stops one instruction short of the table read, which is where the index
        the bound was checked against is named. `lea` only does this when it reads the
        register it writes: "lea rax, [rip + 0x2004]" loads a base and derives nothing from
        rax. An immediate source is index arithmetic rather than a base, and is left to
        redefine as before, as is a write to a memory cell: the step this recognizes ends in
        the register the branch reads, and a compare against a cell that has since been
        written back to is not a bound on what is loaded out of it afterwards.

        Only the instruction the branch reads is asked. An `add <reg>, <reg>` further back is
        index arithmetic - "add rax, rcx" before the table read makes the index a sum, and a
        compare bounding one summand does not bound it - so carrying the tie across that one
        would report a bound smaller than the table and truncate the scan.
        """
        if canonicalRegister(destination_key) is None:
            return False
        if mnemonic == "add":
            return cls._operandKey(source) is not None
        if mnemonic == "lea":
            return destination_key in cls._keyRegisters(source.strip())
        return False

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
        for position, instr in enumerate(backtracked[::-1]):
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
            if mnemonic in CALL_INS:
                # A call returns its value in rax and clobbers what the ABI lets it, but its
                # operand is a bare address, so the destination parse below reads no key and
                # the tie survived it. The window is address-ordered rather than a path, so a
                # compare from before a call is not a bound this dispatch was checked against.
                tracked = set()
                continue
            destination, _, source = operands.partition(",")
            destination_key = self._operandKey(destination)
            if destination_key is None:
                continue
            if mnemonic in _INDEX_COPY_MNEMONICS:
                carried = self._dispatchIndexKeys(source) if destination_key in tracked else set()
                tracked = self._invalidated(tracked, destination_key) | carried
                continue
            if position == 0 and destination_key in tracked and self._addsTableBase(mnemonic, destination_key, source):
                tracked = self._invalidated(tracked, destination_key) | {destination_key}
                continue
            # Anything else redefines whatever it writes, and several x86 instructions write a
            # register they do not name first - xchg and xadd write both operands, mul and div
            # write rdx:rax, cpuid writes four. Invalidating only the named one would leave a
            # tie to a compare that bounds a value the dispatch never indexes with, so the tie
            # is dropped whole and the untied scan answers instead.
            tracked = set()
        return untied_size

    def _directHandler(self, jump_instruction_op_str, state, backtracked):
        """Locate an absolute jump table and the width of one of its entries."""
        register = jump_instruction_op_str.lower()
        data_ref_instruction_addr = None
        off_jumptable = None
        entry_size = 4
        for instr in backtracked[::-1]:
            qword_table = instr[2] == "mov" and _DIRECT_TABLE_QWORD_RE.match(instr[3])
            if instr[2] == "mov" and (qword_table or _DIRECT_TABLE_RE.match(instr[3])):
                entry_size = 8 if qword_table else 4
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.disassembler.getReferencedAddr(instr[3])
                state.addDataRef(data_ref_instruction_addr, off_jumptable, size=entry_size)
                # print("    0x%x: _directHandler() found potential jump table offset (mov) with backtracking: 0x%x (%s %s)" % (instr[0], off_jumptable, instr[2], instr[3]))
                break
            elif instr[2] == "add" and instr[3].startswith(register):
                data_ref_instruction_addr = instr[0]
                off_jumptable = self.disassembler.getReferencedAddr(instr[3])
                state.addDataRef(data_ref_instruction_addr, off_jumptable, size=4)
                # print("  0x%x: _directHandler() found potential jump table offset (add) with backtracking: 0x%x (%s %s)" % (instr[0], off_jumptable, instr[2], instr[3]))
                break
        return off_jumptable, entry_size

    @staticmethod
    def _writesRegister(mnemonic, operands, canonical_register):
        """Whether this instruction writes canonical_register, or None when that is unknowable.

        An unnamed write is one the instruction makes *in addition* to the operand it names,
        so a mnemonic that has one is still asked about its named destination: `imul rbx, rcx`
        writes rbx and leaves rdx:rax alone, while `imul rcx` writes rdx:rax and leaves rcx.

        Anything neither table describes writes something the operand text does not show - a
        call writes whatever its ABI allows, xchg writes both its operands - so it answers None
        rather than False, and a walk relying on this has to stop there.
        """
        if mnemonic in VALUE_PRESERVING_MNEMONICS:
            return False
        implicit = _IMPLICIT_REGISTER_WRITES.get(mnemonic)
        # Only the implicit *form* makes those writes. Every entry here is operand-less or
        # single-operand except `imul`, whose two- and three-operand forms write nothing but
        # the register they name - so applying the pair to those stops a walk chasing a base
        # held in rax or rdx at an `imul rcx, rsi` that cannot touch it, and abandons the
        # table. The syscall walk in the backend already draws the same distinction.
        names_its_destination = implicit is not None
        if implicit is not None and operands.count(",") > 0:
            implicit = None
        if implicit is not None and canonical_register in implicit:
            return True
        if names_its_destination or mnemonic in _NAMED_DESTINATION_MNEMONICS:
            return canonicalRegister(operands.split(",")[0]) == canonical_register
        return None

    def _ripRelativeBase(self, base_register, preceding, state):
        """The address a rip-relative `lea` left in base_register, reading back from the table.

        Carrying the value past a write the walk does not model would resolve the base from
        before that write, which names a different table rather than none, so the walk ends at
        the first instruction that is not known to leave the register alone. The window is the
        instructions at lower addresses, not the path that reached the dispatch, so a `lea` on
        a branch of the switch that was not taken reads here as if it had been - the same
        window every other arm of this analyzer already backtracks over.
        """
        canonical_base = canonicalRegister(base_register)
        if canonical_base is None:
            return None
        for instruction in preceding[::-1]:
            mnemonic = instruction[2].split(" ")[-1]
            operands = instruction[3]
            if (
                mnemonic == "lea"
                and _X64_LEA_TABLE_RE.match(operands)
                and canonicalRegister(operands.split(",")[0]) == canonical_base
            ):
                # getReferencedAddr() preserves the displacement sign
                off_jumptable = instruction[0] + instruction[1] + self.disassembler.getReferencedAddr(operands)
                state.addDataRef(instruction[0], off_jumptable, size=8)
                return off_jumptable
            if self._writesRegister(mnemonic, operands, canonical_base) is not False:
                return None
        return None

    def _resolveRegisterBaseTable(
        self, jump_instruction_address, jump_instruction_op_str, state, backtracked, jumptable_size
    ):
        """Targets of a 64-bit absolute table whose base a rip-relative `lea` put in a register.

        The displacement forms are recognized by the table address standing in the operand
        text. Here the operand names only registers, so the base is chased back to the `lea`
        that produced it instead. Entries are whole pointers and one that does not address the
        image ends the table, so a table of some other shape read this way yields nothing.
        """
        if self.disassembly.binary_info.isPositionIndependentElf():
            # A shared object stores no absolute address a compiler did not have to relocate,
            # and a switch table is emitted as offsets exactly so that it needs no relocation.
            # An absolute table here is the function-pointer table a tail call dispatches
            # through, whose entries are separate functions: reading it as a switch merged
            # four of them into one 14 KB routine in libc and two multi-megabyte ones in
            # libcrypto, all of which the labelled corpus - executables only - could not see.
            return []
        branch_operand = stripFlatSegmentOverride(jump_instruction_op_str)
        match = _BASEREG_TABLE_RE.match(branch_operand)
        preceding = backtracked
        if match is None:
            branch_register = canonicalRegister(branch_operand)
            if branch_register is None:
                return []
            for position, instruction in enumerate(backtracked[::-1]):
                mnemonic = instruction[2].split(" ")[-1]
                if self._writesRegister(mnemonic, instruction[3], branch_register) is False:
                    continue
                # whatever last wrote the branch register decides the dispatch; if it is not a
                # table read of this shape there is nothing here to resolve
                if mnemonic == "mov":
                    match = _BASEREG_TABLE_RE.match(instruction[3])
                preceding = backtracked[: len(backtracked) - 1 - position]
                break
            if match is None:
                return []
        off_jumptable = self._ripRelativeBase(match.group("base"), preceding, state)
        if off_jumptable is None:
            return []
        return self._extractDirectTableOffsets(
            jumptable_size,
            off_jumptable,
            state=state,
            jump_instruction_address=jump_instruction_address,
            entry_size=8,
        )

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

    def _extractDirectTableOffsets(
        self, jumptable_size, off_jumptable, state=None, jump_instruction_address=None, entry_size=4
    ):
        bound_was_recovered = bool(jumptable_size)
        jumptable_size = jumptable_size if bound_was_recovered else 0xFF
        unpack_format = "<Q" if entry_size == 8 else "<I"
        jump_targets = set()
        if off_jumptable and self.disassembly.isAddrWithinMemoryImage(off_jumptable):
            for index in range(jumptable_size):
                raw_entry_bytes = self.disassembly.getBytes(off_jumptable + index * entry_size, entry_size)
                if raw_entry_bytes is None or len(raw_entry_bytes) < entry_size:
                    break
                entry = struct.unpack(unpack_format, raw_entry_bytes)[0]
                if not entry or not self._isCodePointer(entry):
                    if bound_was_recovered:
                        continue
                    break
                jump_targets.add(entry)
                if state is not None:
                    state.addDataRef(jump_instruction_address, off_jumptable + index * entry_size, size=entry_size)
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
                # the same test the absolute forms apply: what the scan reads back past the end
                # of a table is whatever follows it, and a relative entry resolving into a data
                # section is not a case body. 221 of 5045 entries admitted by the image bound
                # alone resolve outside every code area across five of the labelled binaries.
                if not self._isCodePointer((jump_base + entry) & self.disassembler.getBitMask()):
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
                if not table_entry or not self._isCodePointer(table_entry):
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
                off_jumptable, entry_size = self._directHandler(jump_instruction_op_str, state, backtracked)
                table_offsets = self._extractDirectTableOffsets(
                    jumptable_size,
                    off_jumptable,
                    state=state,
                    jump_instruction_address=jump_instruction_address,
                    entry_size=entry_size,
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
        if not table_offsets:
            # Every arm above recognizes its table by an address standing in the operand text of
            # the dispatch or of the instruction feeding it. A base register holds no address,
            # so those arms come back empty on a table the compiler addressed that way and this
            # is the only place it can be recovered.
            table_offsets = self._resolveRegisterBaseTable(
                jump_instruction_address, jump_instruction_op_str, state, backtracked, jumptable_size
            )
        # if False and off_jumptable and table_offsets:
        #     print("  Found jump table: 0x%x -> %d" % (off_jumptable, len(table_offsets)))
        #     for offset in sorted(list(set(table_offsets))):
        #         print("    0x%x" % offset)
        return table_offsets
