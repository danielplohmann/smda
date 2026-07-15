"""Run SMDA in IDA and push recovered functions and names into the database."""

from export import detectBackend
from smda.Disassembler import Disassembler
from smda.ida.IdaInterface import IdaInterface
from smda.SmdaConfig import SmdaConfig


def analyze():
    ida_interface = IdaInterface()
    binary = ida_interface.getBinary()
    base_addr = ida_interface.getBaseAddr()
    architecture = ida_interface.getArchitecture()
    bitness = ida_interface.getBitness()
    disassembler = Disassembler(SmdaConfig())
    report = disassembler.disassembleBuffer(binary, base_addr, bitness=bitness, architecture=architecture)
    smda_function_count = 0
    smda_name_count = 0
    for smda_function in report.getFunctions():
        smda_function_count += ida_interface.makeFunction(smda_function.offset)
        if smda_function.function_name != "":
            smda_name_count += ida_interface.makeNameEx(smda_function.offset, smda_function.function_name)
    print(f"Defined {smda_function_count} functions and assigned {smda_name_count} function names.")
    return report


if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        analyze()
    else:
        raise Exception("Run this script from within IDA.")
