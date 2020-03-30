import argparse
import json
import os
import re
import time
import traceback

import config
from smda.Disassembler import Disassembler
from smda.utility.FileLoader import FileLoader

DISASM = None


def parseBaseAddrFromArgs(filename):
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})"), filename)
    if baddr_match:
        return int(baddr_match.group("base_addr"), 16)
    return 0


def getBitnessFromFilename(filename):
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})"), filename)
    if baddr_match:
        return 32 if len(baddr_match.group("base_addr")) == 8 else 64
    return 0


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


def get_msvc_version(file_path):
    empty_msvc_start = file_path.find("empty_msvc")
    version, _, mode, exe = file_path[empty_msvc_start + len("empty_msvc") + 1:].split(os.sep)
    _, bitness, mode, compileflag = exe[:-4].split("_")
    return "%s_%s_%s_%s" % (version.split("_")[1], mode, bitness, compileflag)


def generate_output_filename(file_path):
    return "msvc_%s.smda" % get_msvc_version(file_path)


if __name__ == "__main__":
    REPORT = {}
    msvc_path = "/data/Repositories/empty_msvc"
    output_path = "/data/professional/smda_msvc"
    disassembler = Disassembler(config)
    for root, subdir, files in os.walk(msvc_path):
        for filename in files:
            REPORT = {}
            INPUT_FILEPATH = root + os.sep + filename
            INPUT_FILENAME = os.path.basename(INPUT_FILEPATH)
            if not filename.endswith(".exe"):
                continue
            filepath = os.path.join(root, filename)
            output_filename = generate_output_filename(filepath)
            if os.path.exists(output_path + os.sep + generate_output_filename(INPUT_FILEPATH)):
                print("Skipping file {}".format(filepath))
                continue
            print("Analyzing file: {}".format(INPUT_FILEPATH))
            REPORT = disassembler.disassembleFile(INPUT_FILEPATH, INPUT_FILEPATH[:-4] + ".pdb")
            if REPORT:
                REPORT["metadata"]["family"] = "msvc"
                REPORT["metadata"]["version"] = get_msvc_version(INPUT_FILEPATH)
                with open(output_path + os.sep + generate_output_filename(INPUT_FILEPATH), "w") as fout:
                    json.dump(REPORT, fout, indent=1, sort_keys=True)
