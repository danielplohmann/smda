import logging

LOGGER = logging.getLogger(__name__)

CALL_INS = ["call", "calli", "callvirt"]
END_INS = ["ret"]

class FunctionAnalysisState(object):

    def __init__(self, start_addr, code_start_addr, disassembly):
        self.start_addr = start_addr
        self.code_start_addr = code_start_addr
        self.disassembly = disassembly
        self.block_queue = [start_addr]
        self.current_block = []
        self.blocks = []
        self.num_blocks_analyzed = 0
        self.instructions = []
        self.instruction_start_bytes = set([])
        self.processed_blocks = set([])
        self.processed_bytes = set([])
        self.jump_targets = set([])
        self.call_register_ins = []
        self.block_start = 0xFFFFFFFF
        self.data_bytes = set([])
        self.data_refs = set([])
        self.code_refs = set([])
        self.code_refs_from = {}
        self.code_refs_to = {}
        self.prev_opcode = ""
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

    def addInstruction(self, i_address, i_size, i_mnemonic, i_op_str, i_bytes):
        ins = (i_address, i_size, i_mnemonic, i_op_str, i_bytes)
        self.instructions.append(ins)
        self.instruction_start_bytes.add(ins[0])
        for byte in range(i_size):
            self.processed_bytes.add(i_address + byte)
        if self.is_next_instruction_reachable:
            self.addCodeRef(i_address, i_address + i_size, self.is_jmp)
        self.is_jmp = False

    def addCodeRef(self, addr_from, addr_to, by_jump=False):
        self.code_refs.update([(addr_from, addr_to)])
        refs_from = self.code_refs_from.get(addr_from, set([]))
        refs_from.update([addr_to])
        self.code_refs_from[addr_from] = refs_from
        refs_to = self.code_refs_to.get(addr_to, set([]))
        refs_to.update([addr_from])
        self.code_refs_to[addr_to] = refs_to
        if by_jump:
            self.is_jmp = True
            self.jump_targets.update([addr_to])

    def removeCodeRef(self, addr_from, addr_to):
        if (addr_from, addr_to) in self.code_refs:
            self.code_refs.remove((addr_from, addr_to))
        if addr_from in self.code_refs_from and addr_to in self.code_refs_from[addr_from]:
            self.code_refs_from[addr_from].remove(addr_to)
        if addr_to in self.code_refs_to and addr_from in self.code_refs_to[addr_to]:
            self.code_refs_to[addr_to].remove(addr_from)
        if addr_to in self.jump_targets:
            self.jump_targets.remove(addr_to)

    def addDataRef(self, addr_from, addr_to, size=1):
        self.data_refs.update([(addr_from, addr_to)])
        for i in range(size):
            self.data_bytes.update([addr_to + i])

    def finalizeAnalysis(self, as_gap=False):
        fn_min = min([ins[0] for ins in self.instructions])
        fn_max = max([ins[0] + ins[1] for ins in self.instructions])

        self.disassembly.function_symbols[self.start_addr] = self.label
        self.disassembly.function_borders[self.start_addr] = (fn_min, fn_max)
        for ins in self.instructions:
            self.disassembly.instructions[ins[0]] = (ins[2], ins[1])
            for offset in range(ins[1]):
                self.disassembly.code_map[ins[0] + offset] = ins[0]
                self.disassembly.ins2fn[ins[0] + offset] = self.start_addr
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
        return True

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
        self.instructions.sort()
        ins = {i[0]:ind for ind, i in enumerate(self.instructions)}
        potential_starts = set([self.code_start_addr])
        potential_starts.update(list(self.jump_targets))
        blocks = []
        for start in sorted(potential_starts):
            if not start in ins:
                continue
            block = []
            for i in range(ins[start], len(self.instructions)):
                current = self.instructions[i]
                block.append(current)
                # if one code reference is to another address than the next
                if current[0] in self.code_refs_from:
                    if not current[2] in CALL_INS and not i == len(self.instructions) - 1:
                        if any([r != self.instructions[i+1][0] for r in self.code_refs_from[current[0]]]):
                            break
                    # if we can reach a colliding address from here, the block is broken and should end.
                    reachable_collisions = self.code_refs_from[current[0]].intersection(self.colliding_addresses)
                    next_addr = current[0] + current[1]
                    is_next_addr = next_addr in reachable_collisions
                    if reachable_collisions and is_next_addr:
                        # we should remove the from/to code references for this collision as there should be no non CFG instruction references between instructions of different functions
                        self.removeCodeRef(current[0], next_addr)
                        break
                if not i == len(self.instructions) - 1 and self.instructions[i+1][0] in self.code_refs_to:
                    if len(self.code_refs_to[self.instructions[i+1][0]]) > 1 or self.instructions[i+1][0] in potential_starts:
                        break
                if current[2] in END_INS:
                    break
            if block:
                blocks.append(block)
        self.blocks = blocks
        return self.blocks

    def isProcessed(self, addr):
        return addr in self.processed_bytes

    def isProcessedFunction(self):
        return self.start_addr in self.disassembly.code_map

    def isNextInstructionReachable(self):
        return self.is_next_instruction_reachable

    def setNextInstructionReachable(self, is_reachable):
        self.is_next_instruction_reachable = is_reachable

    def __str__(self):
        result = "0x{:x} | current: 0x{:x} | blocks: {} | queue: {} | processed: {} | crefs: {} | drefs: {} | suspicious: {} | ending: {}".format(
            self.start_addr,
            self.block_start,
            len(self.getBlocks()),
            ",".join(["0x%x" % b for b in sorted(self.block_queue)]),
            ",".join(["0x%x" % b for b in sorted(list(self.processed_blocks))]),
            len(self.code_refs),
            len(self.data_refs),
            self.suspicious_ins_count,
            self.is_sanely_ending
        )
        return result
