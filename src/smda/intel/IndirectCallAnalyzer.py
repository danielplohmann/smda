import contextlib
import logging
import re
import struct

LOGGER = logging.getLogger(__name__)


class IndirectCallAnalyzer:
    """Perform basic dataflow analysis to resolve indirect call targets"""

    # [a-z0-9]{2,4} covers legacy 2/3-char regs (ax, eax, rax) as well as the
    # r8-r15 family and their d/w/b suffixed forms (r8, r10d, r15w, r9b);
    # {1,16} hex digits covers 64-bit immediates/addresses, not just 32-bit.
    RE_MOV_REG_REG = re.compile(r"(?P<reg1>[a-z0-9]{2,4}), (?P<reg2>[a-z0-9]{2,4})$")
    RE_MOV_REG_CONST = re.compile(r"(?P<reg>[a-z0-9]{2,4}), (?P<val>0x[0-9a-f]{1,16})$")
    RE_REG_DWORD_PTR_ADDR = re.compile(r"(?P<reg>[a-z0-9]{2,4}), dword ptr \[(?P<addr>0x[0-9a-f]{1,16})\]$")
    RE_REG_QWORD_PTR_RIP_ADDR = re.compile(r"(?P<reg>[a-z0-9]{2,4}), qword ptr \[rip \+ (?P<addr>0x[0-9a-f]{1,16})\]$")
    RE_REG_ADDR = re.compile(r"(?P<reg>[a-z0-9]{2,4}), \[(?P<addr>0x[0-9a-f]{1,16})\]$")

    def __init__(self, disassembler):
        self.disassembler = disassembler
        self.disassembly = self.disassembler.disassembly
        self.current_calling_addr = 0
        self.current_slot = None
        self.state = None

    def searchBlock(self, analysis_state, address):
        # Lazy-cache an {instruction_addr: containing_block} index on the
        # analysis_state so subsequent lookups during the same function
        # analysis are O(1) instead of O(blocks * instructions). The cache
        # lives on the state (not on self) so the analyzer stays
        # re-entrancy-safe and the index can't outlive the function being
        # analyzed.
        block_index = getattr(analysis_state, "_block_index", None)
        if not isinstance(block_index, dict):
            block_index = {}
            # Preserve "first matching block wins" — overlapping
            # potential_starts in FunctionAnalysisState.getBlocks() can
            # place the same instruction in more than one block; the
            # legacy linear scan returned the first.
            for block in analysis_state.getBlocks():
                for ins in block:
                    addr = ins[0]
                    if addr not in block_index:
                        block_index[addr] = block
            # Objects with __slots__ or read-only attribute surfaces (and some
            # test doubles) reject the assignment; the lookup below still works
            # on the freshly built index.
            with contextlib.suppress(AttributeError):
                analysis_state._block_index = block_index
        return block_index.get(address, [])

    def getDword(self, addr):
        if not self.disassembly.isAddrWithinMemoryImage(addr):
            return None
        raw_bytes = self.disassembly.getBytes(addr, 4)
        if raw_bytes is None or len(raw_bytes) < 4:
            return None
        return struct.unpack("<I", raw_bytes)[0]

    def _resolveDwordPointerValue(self, addr):
        dll, api = self.disassembler.resolveApi(addr, addr)
        if dll or api:
            return addr, dll, api
        return self.getDword(addr), dll, api

    def _recordComputedImportSlot(self, base_value, displacement, ptr_size):
        slot = base_value + displacement
        dereferenced = (
            self.disassembly.dereferenceQword(slot) if ptr_size == 8 else self.disassembly.dereferenceDword(slot)
        )
        if dereferenced is None:
            return
        dll, api = self.disassembler.resolveApi(slot, dereferenced)
        if dll or api:
            LOGGER.debug("resolved computed import slot 0x%08x: %s %s", slot, dll, api)
            self.disassembly.addApiReference(dereferenced, self.current_calling_addr, dll, api)
            self.disassembly.addImportSlot(slot, dll, api)

    def resolveComputedImportSlots(self, analysis_state, block_depth=3):
        """Resolve "call/jmp dword ptr [<reg> + <disp>]", the shape a runtime-built IAT is used through.

        Records the API and the slot it lives in without booking a code ref or a function
        candidate, so a heuristic base-register value cannot move CFG recovery.
        """
        # same backward walk as resolveRegisterCalls, so it takes the same per-block cap.
        # That one was forced by a Go sample with 130k register calls; this shape -
        # call through a register plus displacement - is C++ virtual dispatch, which packs
        # denser per block than "call <reg>" ever did, so it needs the backstop more.
        max_calls = getattr(self.disassembler.config, "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK", 50)
        calls_per_block = {}
        for calling_addr, register_name, displacement, ptr_size in analysis_state.call_memreg_ins:
            self.current_calling_addr = calling_addr
            self.current_slot = (displacement, ptr_size)
            self.state = analysis_state
            start_block = [ins for ins in self.searchBlock(analysis_state, calling_addr) if ins[0] <= calling_addr]
            if not start_block:
                continue
            # keyed on the block's start address rather than its first instruction: the
            # instruction is a sequence, and only happens to be a hashable one
            block_addr = start_block[0][0]
            calls_per_block[block_addr] = calls_per_block.get(block_addr, 0) + 1
            if calls_per_block[block_addr] > max_calls:
                continue
            self.processBlock(analysis_state, start_block, {}, register_name, [], block_depth)
        self.current_slot = None

    def processBlock(self, analysis_state, block, registers, register_name, processed, depth):
        if not block:
            return False
        if block in processed:
            LOGGER.debug("already processed block 0x%08x; skipping", block[0][0])
            return False
        processed.append(block)
        debug_logging = LOGGER.isEnabledFor(logging.DEBUG)
        if debug_logging:
            LOGGER.debug(
                "start processing block: 0x%08x\nlooking for register %s",
                block[0][0],
                register_name,
            )
        abs_value_found = False
        for ins in reversed(block):
            if debug_logging:
                LOGGER.debug("0x%08x: %s %s", ins[0], ins[2], ins[3])
            if ins[2] == "mov":
                # mov <reg>, <reg>
                match1 = self.RE_MOV_REG_REG.match(ins[3])
                if match1 and match1.group("reg1") == register_name:
                    register_name = match1.group("reg2")
                # mov <reg>, <const>
                match2 = self.RE_MOV_REG_CONST.match(ins[3])
                if match2:
                    registers[match2.group("reg")] = int(match2.group("val"), 16)
                    LOGGER.debug(
                        "**moved value 0x%08x to register %s",
                        int(match2.group("val"), 16),
                        match2.group("reg"),
                    )
                    if match2.group("reg") == register_name:
                        abs_value_found = True
                # mov <reg>, dword ptr [<addr>]
                match3 = self.RE_REG_DWORD_PTR_ADDR.match(ins[3])
                if match3:
                    # Import resolvers may key APIs by the pointer slot address,
                    # so preserve known import slots instead of dereferencing them.
                    addr = int(match3.group("addr"), 16)
                    pointer_value, dll, api = self._resolveDwordPointerValue(addr)
                    if dll or api:
                        registers[match3.group("reg")] = pointer_value
                        LOGGER.debug(
                            "**moved API ref (%s:%s) @0x%08x to register %s",
                            dll,
                            api,
                            pointer_value,
                            match3.group("reg"),
                        )
                        if match3.group("reg") == register_name:
                            abs_value_found = True
                    else:
                        if pointer_value:
                            registers[match3.group("reg")] = pointer_value
                            LOGGER.debug(
                                "**moved value 0x%08x to register %s",
                                pointer_value,
                                match3.group("reg"),
                            )
                            if match3.group("reg") == register_name:
                                abs_value_found = True
                # mov <reg>, qword ptr [reg + <addr>]
                match4 = self.RE_REG_QWORD_PTR_RIP_ADDR.match(ins[3])
                if match4:
                    # rip-relative addressing already resolves the slot; the register then
                    # receives the whole qword stored there, not rip plus its low half
                    rip = ins[0] + ins[1]
                    slot = rip + int(match4.group("addr"), 16)
                    qword = self.disassembly.dereferenceQword(slot)
                    if qword:
                        registers[match4.group("reg")] = qword
                        LOGGER.debug(
                            "**moved value 0x%08x from slot 0x%08x to register %s",
                            qword,
                            slot,
                            match4.group("reg"),
                        )
                        if match4.group("reg") == register_name:
                            abs_value_found = True
            elif ins[2] == "lea":
                LOGGER.debug("*checking %s %s", ins[2], ins[3])
                # lea <reg>, dword ptr [<addr>] and lea <reg>, [<addr>]
                # lea computes an address; the register receives the address itself, so
                # dereferencing it here would resolve the call against the wrong target
                for pattern in (self.RE_REG_DWORD_PTR_ADDR, self.RE_REG_ADDR):
                    match1 = pattern.match(ins[3])
                    if match1:
                        address = int(match1.group("addr"), 16)
                        registers[match1.group("reg")] = address
                        LOGGER.debug(
                            "**moved address 0x%08x to register %s",
                            address,
                            match1.group("reg"),
                        )
                        if match1.group("reg") == register_name:
                            abs_value_found = True
                # not handled: lea <reg>, dword ptr [<reg> +- <val>]
                # requires state-keeping of multiple registers
            # if the absolute value was found for the call <reg> instruction, detect API
            if abs_value_found:
                candidate = registers.get(register_name, None)
                if self.current_slot is not None:
                    # annotation only: leave leaf state and the CFG to the regular analysis
                    if candidate:
                        self._recordComputedImportSlot(candidate, *self.current_slot)
                    return True
                self.state.setLeaf(False)
                if candidate:
                    LOGGER.debug(
                        "candidate: 0x%x - %s, register: %s",
                        candidate,
                        ins[3],
                        register_name,
                    )
                    dll, api = self.disassembler.resolveApi(candidate, candidate)
                    if dll or api:
                        LOGGER.debug("successfully resolved: %s %s", dll, api)
                        self.disassembly.addApiReference(candidate, self.current_calling_addr, dll, api)
                        # _resolveDwordPointerValue keeps a known import slot instead of
                        # dereferencing it, so an in-image candidate is that slot
                        if self.disassembly.isAddrWithinMemoryImage(candidate):
                            self.disassembly.addImportSlot(candidate, dll, api)
                    elif self.disassembly.isAddrWithinMemoryImage(candidate):
                        LOGGER.debug("successfully resolved: 0x%x", candidate)
                        self.disassembler.fc_manager.addCandidate(candidate, reference_source=self.current_calling_addr)
                    else:
                        LOGGER.debug("candidate not resolved")
                else:
                    LOGGER.debug("no candidate to resolved")

                return True
        # process previous blocks
        if depth >= 0:
            processed_addrs = frozenset(ins[0] for blk in processed for ins in blk)
            # Use the reverse index (addr_to -> {addr_from}) maintained by
            # add/removeCodeRef instead of scanning the full code_refs set per block.
            # Default to () (cached singleton, no allocation) since we only iterate it.
            refs_in = [fr for fr in analysis_state.code_refs_to.get(block[0][0], ()) if fr not in processed_addrs]
            LOGGER.debug(
                "start processing previous blocks, searching in %d in_refs with remaining depth: %d",
                len(refs_in),
                depth - 1,
            )
            if any(
                self.processBlock(
                    analysis_state,
                    b,
                    registers.copy(),
                    register_name,
                    processed,
                    depth - 1,
                )
                for b in [self.searchBlock(analysis_state, i) for i in refs_in]
            ):
                return True
        return False

    def resolveRegisterCalls(self, analysis_state, block_depth=3):
        # after block reconstruction do simple data flow analysis to resolve open cases like "call <register>" as stored in self.call_register_ins
        if analysis_state.call_register_ins:
            LOGGER.debug(
                "Trying to resolve %d register calls in function: 0x%x",
                len(analysis_state.call_register_ins),
                analysis_state.start_addr,
            )
        max_calls_per_block = 10
        calls_per_block = {}
        for calling_addr in analysis_state.call_register_ins:
            LOGGER.debug("#" * 20)
            self.current_calling_addr = calling_addr
            self.state = analysis_state
            start_block = [ins for ins in self.searchBlock(analysis_state, calling_addr) if ins[0] <= calling_addr]
            if not start_block:
                continue
            # we only process at most 10 register-calls per block to avoid extreme cases
            # found one Go sample with 130k register calls.
            if start_block[0] not in calls_per_block:
                calls_per_block[start_block[0]] = 0
            calls_per_block[start_block[0]] += 1
            # if we have an old config, default to 50
            max_calls = (
                self.disassembler.config.MAX_INDIRECT_CALLS_PER_BASIC_BLOCK
                if hasattr(self.disassembler.config, "MAX_INDIRECT_CALLS_PER_BASIC_BLOCK")
                else 50
            )
            if calls_per_block[start_block[0]] > max_calls:
                continue
            LOGGER.debug(
                "For this block, we can still analyze %d indirect calls.",
                max_calls_per_block - calls_per_block[start_block[0]],
            )
            if start_block:
                self.processBlock(
                    analysis_state,
                    start_block,
                    {},
                    start_block[-1][3],
                    [],
                    block_depth,
                )
