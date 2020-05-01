from collections import defaultdict
from operator import itemgetter
import bisect
import json

class TailcallAnalyzer(object):

    def __init__(self):
        self.__jumps = defaultdict(set)
        self.__tmp_jumps = defaultdict(list)
        self.__functions = list()

    def initFunction(self):
        self.__tmp_jumps = defaultdict(list)

    def addJump(self, source, destination):
        self.__tmp_jumps[source].append(destination)

    def finalizeFunction(self, function_state):
        for source, destinations in self.__tmp_jumps.items():
            self.__jumps[source].update(destinations)
        self.__tmp_jumps.clear()
        self.__functions.append(function_state)

    def getTailcalls(self):
        result = list()
        # jumps sorted by (destination, source)
        jumps = list(sorted(((s, d) for s in self.__jumps for d in self.__jumps[s]), key=itemgetter(1, 0)))
        jumps_dest = [d for s, d in jumps]
        # for each function generate the intervals that contain the instructions
        for function in self.__functions:
            # check if there are any jumps from outside the function to inside the function
            function_intervals = self.__getFunctionIntervals(function)
            if not function_intervals:
                # empty function?
                continue
            min_addr = min(interval[0] for interval in function_intervals)
            max_addr = max(interval[1] for interval in function_intervals)
            for source, destination in jumps[bisect.bisect_left(jumps_dest, min_addr):bisect.bisect_right(jumps_dest, max_addr)]:
                if (
                        # the jumps destination is different from the functions start address
                        destination != function.start_addr and
                        # the jumps destination is in one of the functions intervals
                        any((first <= destination <= last) for first, last in function_intervals) and
                        # the jump originates from outside the function (outside all intervals)
                        all((source < first or source > last) for first, last in function_intervals)):

                    result.append({
                        "source_addr": source,
                        "destination_addr": destination,
                        "destination_function": function.start_addr
                    })

        return result

    def __getFunctionIntervals(self, function_state):
        intervals = list()
        instructions = sorted(function_state.instructions, key=itemgetter(0))
        first_instruction = instructions[0] if instructions else None
        last_instruction = first_instruction
        for instruction in instructions:
            if instruction[0] > last_instruction[0] + last_instruction[1]:
                intervals.append((first_instruction[0], last_instruction[0]))
                first_instruction = instruction
            last_instruction = instruction
        if last_instruction:
            intervals.append((first_instruction[0], last_instruction[0]))
        return intervals

    def __getFunctionByStartAddr(self, start_addr):
        for function in self.__functions:
            if function.start_addr == start_addr:
                return function

    def __printIntervals(self, intervals):
        # return
        if len(intervals) < 25:
            for one, two in intervals:
                print("  0x{:x} -> 0x{:x}".format(one, two))
        else: print("Function has too many intervals to display")

    def resolveTailcalls(self, disassembler, verbose=False):
        newly_created_functions = set([])
        for tailcall in self.getTailcalls():
            if verbose:
                print("Processing tailcall:\n{}".format(json.dumps(tailcall, indent=2, sort_keys=True)))
            # remove the information from the function-analysis state of the disassembly
            function = self.__getFunctionByStartAddr(tailcall["destination_function"])
            if not function or function.is_tailcall_function:
                disassembler.analyzeFunction(tailcall["destination_function"])
                continue

            self.__functions.remove(function)
            if function:
                if verbose:
                    print("Old function:")
                    self.__printIntervals(self.__getFunctionIntervals(function))
                function.revertAnalysis()

            # analyze the tailcall destination as function
            disassembler.analyzeFunction(tailcall["destination_addr"])
            newly_created_functions.add(tailcall["destination_addr"])
            function = self.__getFunctionByStartAddr(tailcall["destination_addr"])
            if function and not tailcall["destination_function"] in function.instruction_start_bytes:
                # analyze the (previously) broken function a second time
                try:
                    disassembler.analyzeFunction(tailcall["destination_function"])
                    function = self.__getFunctionByStartAddr(tailcall["destination_function"])
                    function.is_tailcall_function = True
                except:
                    pass
                    # print ("0x{:x} -> 0x{:x}".format(tailcall["destination_function"], tailcall["destination_addr"]))
            elif verbose:
                print("**** 0x{:x} IS NOW PART OF 0x{:x}".format(tailcall["destination_function"], tailcall["destination_addr"]))

            if verbose:
                function = self.__getFunctionByStartAddr(tailcall["destination_function"])
                new_function = self.__getFunctionByStartAddr(tailcall["destination_addr"])
                print("New function:")
                if new_function:
                    self.__printIntervals(self.__getFunctionIntervals(new_function))
                print("Re-disassembled old function:")
                if function:
                    self.__printIntervals(self.__getFunctionIntervals(function))
        return sorted(list(newly_created_functions))
