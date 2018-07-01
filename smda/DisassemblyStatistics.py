

class DisassemblyStatistics(object):

    def __init__(self, disassembly_result):
        self._disassembly = disassembly_result

    def _countBlocks(self):
        num_blocks = 0
        for _, blocks in self._disassembly.functions.items():
            num_blocks += len(blocks)
        return num_blocks

    def _countApiCalls(self):
        return len(self._disassembly.getAllApiRefs())

    def _countInstructions(self):
        num_ins = 0
        for function_offset in sorted(self._disassembly.functions):
            for block in self._disassembly.functions[function_offset]:
                num_ins += len(block)
        return num_ins

    def _countFunctionCalls(self):
        num_calls = 0
        for function_start in self._disassembly.functions:
            if function_start in self._disassembly.code_refs_to:
                num_calls += len(self._disassembly.code_refs_to[function_start])
        return num_calls

    def calculate(self):
        summary = {
            "num_functions": len(self._disassembly.functions),
            "num_recursive_functions": len(self._disassembly.recursive_functions),
            "num_leaf_functions": len(self._disassembly.leaf_functions),
            "num_basic_blocks": self._countBlocks(),
            "num_instructions": self._countInstructions(),
            "num_api_calls": self._countApiCalls(),
            "num_function_calls": self._countFunctionCalls(),
            "num_disassembly_errors": len(self._disassembly.failed_analysis_addr),
        }
        return summary
