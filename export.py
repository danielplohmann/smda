"""Export the current IDA database to a SMDA report.

For headless IDA 9.1+ export, use ``ida_domain_export.py`` instead.
"""

import json

from smda.Disassembler import Disassembler
from smda.ida.IdaInterface import getIdaSdkVersion
from smda.SmdaConfig import SmdaConfig


def detectBackend():
    try:
        return ("IDA", getIdaSdkVersion())
    except ImportError:
        return ("", "")


if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        config = SmdaConfig()
        disassembler = Disassembler(config, backend=BACKEND)
        ida_interface = disassembler.disassembler.ida_interface
        binary = ida_interface.getBinary()
        base_addr = ida_interface.getBaseAddr()
        REPORT = disassembler.disassembleBuffer(binary, base_addr)
        output_filepath = ida_interface.getIdbDir() + "ConvertedFromIdb.smda"
        with open(output_filepath, "w") as fout:
            json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
            print(f"Output saved to: {output_filepath}")
    else:
        raise Exception("Run this script from within IDA.")
