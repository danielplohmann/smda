"""Run SMDA in Binary Ninja and push recovered functions and names into the view.

Run this file through *Run Script...* with a binary open. Only functions Binary Ninja left with a
default ``sub_`` name are renamed, and the changes land as one undo step.
"""

from smda.binja.BinjaInterface import BinjaInterface
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig


def analyze(bv):
    interface = BinjaInterface(bv)
    binary = interface.getBinary()
    base_addr = interface.getBaseAddr()
    architecture = interface.getArchitecture()
    bitness = interface.getBitness()
    disassembler = Disassembler(SmdaConfig())
    report = disassembler.disassembleBuffer(binary, base_addr, bitness=bitness, architecture=architecture)
    smda_function_count = 0
    smda_name_count = 0
    with bv.undoable_transaction():
        for smda_function in report.getFunctions():
            smda_function_count += interface.makeFunction(smda_function.offset)
            if smda_function.function_name != "":
                smda_name_count += interface.makeName(smda_function.offset, smda_function.function_name)
    bv.update_analysis_and_wait()
    print(f"Defined {smda_function_count} functions and assigned {smda_name_count} function names.")
    return report


if __name__ == "__main__":
    if globals().get("bv") is None:
        raise Exception("Run this script from within Binary Ninja.")
    analyze(globals()["bv"])
