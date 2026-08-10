"""Architecture-neutral per-function analysis state.

Holds the recursive traversal's block queue, decoded instructions, code/data
references and block reconstruction (:meth:`getBlocks`) shared by every native
backend. Subclasses only set the two mnemonic class attributes that drive
basic-block boundary decisions.
"""

import logging
from operator import itemgetter

LOGGER = logging.getLogger(__name__)


class FunctionAnalysisState:
    # Mnemonic sets consulted by getBlocks() for basic-block boundary decisions.
    # Subclasses (smda.intel / smda.aarch64) set these to their architecture's
    # call and block-ending mnemonics. Calls must NOT terminate a block;
    # ret/trap instructions must.
    CALL_MNEMONICS = frozenset()
    END_MNEMONICS = frozenset()

    def __init__(self, start_addr, disassembly):
        self.start_addr = start_addr
        self.disassembly = disassembly
        self.block_queue = [start_addr]
        self._queued_blocks = {start_addr}
        self.current_block = []
        self.blocks = []
        self.num_blocks_analyzed = 0
        self.instructions = []
        self._instructions_sorted = True
        self.instruction_start_bytes = set()
        self.max_instruction_start = -1
        self.processed_blocks = set()
        self.processed_bytes = set()
        self.jump_targets = set()
        self.jump_refs = set()
        self.call_register_ins = []
        self.call_memreg_ins = []
        self.block_start = 0xFFFFFFFF
        self.data_bytes = set()
        self.data_refs = set()
        self.code_refs = set()
        self.code_refs_from = {}
        self.code_refs_to = {}
        self.suspicious_ins_count = 0
        self.is_jmp = False
        self.is_next_instruction_reachable = True
        self.is_block_ending_instruction = False
        self.is_sanely_ending = False
        self.has_collision = False
        self.colliding_addresses = set()
        # set a flag that this tailcall has already been resolved so it does not have to be reanalyzed several times
        self.is_tailcall_function = False
        self.is_leaf_function = True
        self.is_recursive = False
        self.is_thunk_call = False
        self.label = ""

    def chooseNextBlock(self):
        self.is_block_ending_instruction = False
        # is_jmp is a one-instruction latch, consumed by the addInstruction of the branch
        # that set it; a block left without booking that instruction must not carry it out
        self.is_jmp = False
        self.block_start = self.block_queue.pop()
        self._queued_blocks.discard(self.block_start)
        self.processed_blocks.add(self.block_start)
        return self.block_start

    def addBlockToQueue(self, block_start):
        if block_start not in self.processed_blocks and block_start not in self._queued_blocks:
            self._queued_blocks.add(block_start)
            self.block_queue.append(block_start)

    def endBlock(self):
        self.is_jmp = False
        if self.current_block:
            self.num_blocks_analyzed += 1
            # self.blocks.append(self.current_block)
        self.current_block = []

    def addInstruction(self, i_address, i_size, i_mnemonic, i_op_str, i_bytes):
        ins = (i_address, i_size, i_mnemonic, i_op_str, i_bytes)
        self.instructions.append(ins)
        self._instructions_sorted = False
        self.instruction_start_bytes.add(ins[0])
        if ins[0] > self.max_instruction_start:
            self.max_instruction_start = ins[0]
        self.current_block.append(ins)
        self.processed_bytes.update(range(i_address, i_address + i_size))
        if self.is_next_instruction_reachable:
            self.addCodeRef(i_address, i_address + i_size, self.is_jmp)
        self.is_jmp = False

    def addCodeRef(self, addr_from, addr_to, by_jump=False):
        self.code_refs.add((addr_from, addr_to))
        refs_from = self.code_refs_from.get(addr_from)
        if refs_from is None:
            self.code_refs_from[addr_from] = {addr_to}
        else:
            refs_from.add(addr_to)
        refs_to = self.code_refs_to.get(addr_to)
        if refs_to is None:
            self.code_refs_to[addr_to] = {addr_from}
        else:
            refs_to.add(addr_from)
        if by_jump:
            self.is_jmp = True
            self.jump_refs.add((addr_from, addr_to))
            self.jump_targets.add(addr_to)

    def removeCodeRef(self, addr_from, addr_to):
        if (addr_from, addr_to) in self.code_refs:
            self.code_refs.remove((addr_from, addr_to))
        if addr_from in self.code_refs_from and addr_to in self.code_refs_from[addr_from]:
            self.code_refs_from[addr_from].remove(addr_to)
        if addr_to in self.code_refs_to and addr_from in self.code_refs_to[addr_to]:
            self.code_refs_to[addr_to].remove(addr_from)
        if (addr_from, addr_to) in self.jump_refs:
            self.jump_refs.remove((addr_from, addr_to))
            if not any(to == addr_to for _, to in self.jump_refs):
                self.jump_targets.discard(addr_to)

    def addDataRef(self, addr_from, addr_to, size=1):
        self.data_refs.add((addr_from, addr_to))
        self.data_bytes.update(range(addr_to, addr_to + size))

    def backtrackInstructions(self, addr_from, num_instructions):
        if not self._instructions_sorted:
            self.instructions.sort(key=itemgetter(0))
            self._instructions_sorted = True
        # Binary search for the first instruction with address >= addr_from
        low = 0
        high = len(self.instructions)
        while low < high:
            mid = (low + high) // 2
            if self.instructions[mid][0] < addr_from:
                low = mid + 1
            else:
                high = mid
        return self.instructions[max(0, low - num_instructions) : low]

    def identifyCallConflicts(self, all_refs):
        conflicts = {}
        non_instruction_start_bytes = self.processed_bytes.difference(self.instruction_start_bytes)
        # iterate this function's processed bytes (bounded by the function size)
        # instead of rebuilding a set from the whole-binary all_refs on every call;
        # same conflict set, but avoids an O(total_refs) copy per analyzed function.
        for candidate_source_ref in non_instruction_start_bytes:
            if candidate_source_ref not in all_refs:
                continue
            candidate = all_refs[candidate_source_ref]
            if candidate not in conflicts:
                conflicts[candidate] = []
            conflicts[candidate].append(candidate_source_ref)
        return conflicts

    def _finalizeRegularAnalysis(self):
        fn_min = min(ins[0] for ins in self.instructions)
        fn_max = max(ins[0] + ins[1] for ins in self.instructions)

        self.disassembly.function_symbols[self.start_addr] = self.label
        self.disassembly.function_borders[self.start_addr] = (fn_min, fn_max)
        instructions_map = self.disassembly.instructions
        code_map = self.disassembly.code_map
        ins2fn = self.disassembly.ins2fn
        start_addr = self.start_addr
        for ins in self.instructions:
            ins_addr = ins[0]
            instructions_map[ins_addr] = (ins[2], ins[1])
            for byte_addr in range(ins_addr, ins_addr + ins[1]):
                code_map[byte_addr] = ins_addr
                ins2fn[byte_addr] = start_addr
        self.disassembly.data_map.update(self.data_bytes)
        self.disassembly.functions[self.start_addr] = self.getBlocks()
        for cref in self.code_refs:
            self.disassembly.addCodeRefs(cref[0], cref[1])
        for dref in self.data_refs:
            self.disassembly.addDataRefs(dref[0], dref[1])
        if self.is_recursive:
            self.disassembly.recursive_functions.add(self.start_addr)
        if self.is_leaf_function:
            self.disassembly.leaf_functions.add(self.start_addr)
        if self.is_thunk_call:
            self.disassembly.thunk_functions.add(self.start_addr)

    def finalizeAnalysis(self, as_gap=False):
        if as_gap:
            LOGGER.debug(
                "0x%08x had sanity state: %s (%d ins, blocks: %d)",
                self.start_addr,
                self.is_sanely_ending,
                len(self.instructions),
                self.num_blocks_analyzed,
            )
            # for instruction in sorted(self.instructions):
            #    print("0x%08x: %s %s" % (instruction[0], instruction[2], instruction[3]))
        if as_gap and not self.is_sanely_ending:
            # capstone prepends mandatory prefixes (bnd/rep/lock/...) to the mnemonic string
            if len(self.instructions) == 1 and self.instructions[0][2].split(" ")[-1] == "jmp":
                byte = self.disassembly.getByte(self.instructions[0][0])
                if isinstance(byte, int):
                    byte = chr(byte)
                if byte == "\xeb":
                    return False
                # sane case, stub found that just jumps to a referenced function
            elif self.num_blocks_analyzed == 1 and self.instructions[-1][2].split(" ")[-1] in [
                "jmp",
                "call",
            ]:
                # similar case to the one above, mostly stubs with tailcalls to a function or shared tail block.
                pass
            else:
                return False
        # in case we have a successful analysis, forward results to disassembly
        if self.num_blocks_analyzed:
            self._finalizeRegularAnalysis()
        return True

    def revertAnalysis(self):
        """
        Remove the analysis results from the disassembly
        """
        self.disassembly.function_borders.pop(self.start_addr, None)
        self.disassembly.function_symbols.pop(self.start_addr, None)
        self.disassembly.recursive_functions.discard(self.start_addr)
        self.disassembly.leaf_functions.discard(self.start_addr)
        self.disassembly.thunk_functions.discard(self.start_addr)
        for ins in self.instructions:
            self.disassembly.instructions.pop(ins[0], None)
            for byte in range(ins[1]):
                self.disassembly.code_map.pop(ins[0] + byte, None)
                self.disassembly.ins2fn.pop(ins[0] + byte, None)
        for cref in self.code_refs:
            self.disassembly.removeCodeRefs(cref[0], cref[1])
        for dref in self.data_refs:
            self.disassembly.removeDataRefs(dref[0], dref[1])
        self.disassembly.functions.pop(self.start_addr, None)

    def getBlocks(self):
        """
        block derivation strategy:
        walk over all potential block starts, which are the start_addr + all "jump" targets (i.e. CFG redirection targets)
        then, for consecutive instructions, break if
        * they have more than 1 outgoing edge
        * the following instruction has more than 1 incoming edge
        """
        if self.blocks:
            return self.blocks
        if not self._instructions_sorted:
            self.instructions.sort(key=itemgetter(0))
            self._instructions_sorted = True
        instructions = self.instructions
        last_index = len(instructions) - 1
        code_refs_from = self.code_refs_from
        code_refs_to = self.code_refs_to
        colliding_addresses = self.colliding_addresses
        call_mnemonics = self.CALL_MNEMONICS
        end_mnemonics = self.END_MNEMONICS
        ins = {i[0]: ind for ind, i in enumerate(instructions)}
        potential_starts = {self.start_addr}
        potential_starts.update(self.jump_targets)
        blocks = []
        for start in sorted(potential_starts):
            if start not in ins:
                continue
            block = []
            for i in range(ins[start], last_index + 1):
                current = instructions[i]
                current_mnemonic = current[2]
                if " " in current_mnemonic:
                    current_mnemonic = current_mnemonic.rpartition(" ")[2]
                block.append(current)
                current_addr = current[0]
                is_last = i == last_index
                next_ins_addr = -1 if is_last else instructions[i + 1][0]
                # if one code reference is to another address than the next
                refs_from = code_refs_from.get(current_addr)
                if refs_from is not None:
                    num_refs_from = len(refs_from)
                    if (
                        current_mnemonic not in call_mnemonics
                        and not is_last
                        and (num_refs_from > 1 or (num_refs_from == 1 and next_ins_addr not in refs_from))
                    ):
                        break
                    # if we can reach a colliding address from here, the block is broken and should end.
                    if colliding_addresses:
                        reachable_collisions = refs_from.intersection(colliding_addresses)
                        next_addr = current_addr + current[1]
                        is_next_addr = next_addr in reachable_collisions
                        if reachable_collisions and is_next_addr:
                            # we should remove the from/to code references for this collision as there should be no non CFG instruction references between instructions of different functions
                            self.removeCodeRef(current_addr, next_addr)
                            break
                if (
                    not is_last
                    and next_ins_addr in code_refs_to
                    and (next_ins_addr in potential_starts or len(code_refs_to[next_ins_addr]) > 1)
                ):
                    break
                if current_mnemonic in end_mnemonics:
                    break
            if block:
                blocks.append(block)
        self.blocks = blocks
        return self.blocks

    def hasUnprocessedBlocks(self):
        return bool(self._queued_blocks - self.processed_blocks)

    def isProcessed(self, addr):
        return addr in self.processed_bytes

    def isProcessedFunction(self):
        return self.start_addr in self.disassembly.code_map

    def isNextInstructionReachable(self):
        return self.is_next_instruction_reachable

    def setNextInstructionReachable(self, is_reachable):
        self.is_next_instruction_reachable = is_reachable

    def isBlockEndingInstruction(self):
        return self.is_block_ending_instruction

    def isFirstInstruction(self):
        return len(self.instructions) == 0

    def setBlockEndingInstruction(self, is_ending):
        self.is_block_ending_instruction = is_ending

    def setSanelyEnding(self, is_sanely_ending):
        self.is_sanely_ending = is_sanely_ending

    def addCollision(self, colliding_address):
        self.has_collision = True
        self.colliding_addresses.add(colliding_address)

    def setRecursion(self, is_recursive):
        self.is_recursive = is_recursive

    def setThunkCall(self, is_thunk_call):
        self.is_thunk_call = is_thunk_call

    def setLeaf(self, is_leaf):
        self.is_leaf_function = is_leaf

    def __str__(self):
        result = "0x{:x} | current: 0x{:x} | blocks: {} | queue: {} | processed: {} | crefs: {} | drefs: {} | suspicious: {} | ending: {}".format(
            self.start_addr,
            self.block_start,
            len(self.getBlocks()),
            ",".join([f"0x{b:x}" for b in sorted(self.block_queue)]),
            ",".join([f"0x{b:x}" for b in sorted(self.processed_blocks)]),
            len(self.code_refs),
            len(self.data_refs),
            self.suspicious_ins_count,
            self.is_sanely_ending,
        )
        return result
