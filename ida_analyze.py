"""Run from inside IDA (File -> Script file...) to disassemble the currently
open database with SMDA and push the recovered functions and names back into
IDA. Uses the ida-domain backend (IDA Pro 9.1+).
"""

from export import detectBackend
from smda.Disassembler import Disassembler
from smda.ida.IdaInterface import IdaInterface
from smda.SmdaConfig import SmdaConfig

if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        ida_interface = IdaInterface()
        binary = ida_interface.getBinary()
        base_addr = ida_interface.getBaseAddr()
        config = SmdaConfig()
        DISASSEMBLER = Disassembler(config)
        REPORT = DISASSEMBLER.disassembleBuffer(binary, base_addr)
        smda_function_count = 0
        smda_name_count = 0
        for smda_function in REPORT.getFunctions():
            smda_function_count += ida_interface.makeFunction(smda_function.offset)
            if smda_function.function_name != "":
                smda_name_count += ida_interface.makeNameEx(smda_function.offset, smda_function.function_name)
        print(f"Defined {smda_function_count} functions and assigned {smda_name_count} function names.")
    else:
        raise Exception("Run this script from within IDA (ida-domain required, IDA Pro 9.1+).")
