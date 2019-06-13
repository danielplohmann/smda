import argparse
import json
import logging
import os
import re
import time
import traceback

import config
from smda.Disassembler import Disassembler

LOGGER = logging.getLogger(__name__)


def parseBaseAddrFromArgs(args):
    if args.base_addr:
        parsed_base_addr = int(args.base_addr, 16) if args.base_addr.startswith("0x") else int(args.base_addr)
        LOGGER.info("using provided base address: 0x%08x % %d", parsed_base_addr, parsed_base_addr)
        return parsed_base_addr
    # try to infer base addr from filename:
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), args.input_path)
    if baddr_match:
        parsed_base_addr = int(baddr_match.group("base_addr"), 16)
        LOGGER.info("Parsed base address from file name: 0x%08x % %d", parsed_base_addr, parsed_base_addr)
        return parsed_base_addr
    LOGGER.warn("No base address recognized, using 0.")
    return 0


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description='Demo: Use SMDA to disassemble a given file (loaded memory view), optionally map it first and/or write the output to a file.')
    PARSER.add_argument('-p', '--parse_header', action='store_true', default=False, help='Parse header/symbols and perform mapping of the file as normalization.')
    PARSER.add_argument('-d', '--pdb_path', type=str, default='', help='If available, use a PDB file to enhance disassembly (function offsets and names).')
    PARSER.add_argument('-b', '--base_addr', type=str, default='', help='When analyzing a buffer, set base address to given value (int or 0x-hex format).')
    PARSER.add_argument('-o', '--output_path', type=str, default='', help='Optionally write the output to a file (JSON format).')
    PARSER.add_argument('input_path', type=str, default='', help='Path to file to analyze.')

    ARGS = PARSER.parse_args()
    if ARGS.input_path:
        REPORT = {}
        INPUT_FILENAME = ""
        if os.path.isfile(ARGS.input_path):
            disassembler = Disassembler(config)
            print("now analyzing {}".format(ARGS.input_path))
            INPUT_FILENAME = os.path.basename(ARGS.input_path)
            if ARGS.parse_header:
                REPORT = disassembler.disassembleFile(ARGS.input_path, pdb_path=ARGS.pdb_path)
            else:
                BUFFER = readFileContent(ARGS.input_path)
                BASE_ADDR = parseBaseAddrFromArgs(ARGS)
                REPORT = disassembler.disassembleBuffer(BUFFER, BASE_ADDR)
        if REPORT and os.path.isdir(ARGS.output_path):
            with open(ARGS.output_path + os.sep + INPUT_FILENAME + ".smda", "w") as fout:
                json.dump(REPORT, fout, indent=1, sort_keys=True)
    else:
        PARSER.print_help()
