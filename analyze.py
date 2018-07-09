import sys
import os
import json
import time
import traceback

import config
from smda.Disassembler import Disassembler
from smda.utility.helpers import load_file, get_base_addr_from_path
from smda.common.SmdaExceptions import TimeoutException


def disassembleFile(filePath):
    print("now analyzing {}".format(filePath))
    file_content = load_file(filePath)
    base_addr = get_base_addr_from_path(filePath)
    disasm = Disassembler(config)
    start = time.clock()
    try:
        disassembly = disasm.disassemble(file_content, base_addr, timeout=config.TIMEOUT)
        report = disasm.getDisassemblyReport(disassembly)
        report["filename"] = os.path.basename(filePath)
        print(disassembly)
    except Exception as exc:
        print("-> an error occured (", str(exc), ").")
        report = {"status":"error", "message":traceback.format_exc(exc), "execution_time": time.clock() - start}
    return report


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("usage: <%s> <input_filepath> <output_filepath>" % sys.argv[0])
        sys.exit()
    REPORT = {}
    if len(sys.argv) > 1:
        INPUT_FILE = sys.argv[1]
        if os.path.isfile(INPUT_FILE):
            REPORT = disassembleFile(INPUT_FILE)
    if len(sys.argv) > 2:
        OUTPUT_FILE = sys.argv[2]
        with open(OUTPUT_FILE, "w") as fout:
            json.dump(REPORT, fout, indent=1, sort_keys=True)

