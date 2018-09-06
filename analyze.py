import argparse
import json
import os
import re
import sys
import time
import traceback

import config
from smda.Disassembler import Disassembler
from smda.utility.FileLoader import FileLoader
from smda.common.SmdaExceptions import TimeoutException


def parseBaseAddrFromArgs(args):
    if args.base_addr:
        return int(args.base_addr, 16) if args.base_addr.startswith("0x") else int(args.base_addr)
    # try to infer base addr from filename:
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), args.input_path)
    if baddr_match:
        return int(baddr_match.group("base_addr"), 16)
    return 0


def disassembleFile(file_path, base_addr, map_file=False):
    print("now analyzing {}".format(file_path))
    loader = FileLoader(file_path, base_addr=base_addr, map_file=map_file)
    file_content = loader.getData()
    disasm = Disassembler(config)
    start = time.clock()
    try:
        disassembly = disasm.disassemble(file_content, base_addr, timeout=config.TIMEOUT)
        report = disasm.getDisassemblyReport(disassembly)
        report["filename"] = os.path.basename(file_path)
        print(disassembly)
    except Exception as exc:
        print("-> an error occured (", str(exc), ").")
        report = {"status":"error", "meta": {"traceback": traceback.format_exc(exc)}, "execution_time": time.clock() - start}
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Demo: Use SMDA to disassemble a given file (loaded memory view), optionally map it first and/or write the output to a file.')
    parser.add_argument('-m', '--map_file', action='store_true', default=False, help='Perform mapping of the file as normalization.')
    parser.add_argument('-b', '--base_addr', type=str, default='', help='Set base address to given value (int or 0x-hex format).')
    parser.add_argument('-o', '--output_path', type=str, default='', help='Optionally write the output to a file (JSON format).')
    parser.add_argument('input_path', type=str, default='', help='Path to file to analyze.')

    args = parser.parse_args()
    if args.input_path:
        REPORT = {}
        if os.path.isfile(args.input_path):
            base_addr = parseBaseAddrFromArgs(args)
            REPORT = disassembleFile(args.input_path, base_addr, map_file=args.map_file)
        if args.output_path:
            with open(args.output_path, "w") as fout:
                json.dump(REPORT, fout, indent=1, sort_keys=True)
    else:
        parser.print_help()

