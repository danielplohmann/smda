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


def getBitnessFromFilename(filename):
    return 32 if "i686" in filename else 64


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


if __name__ == "__main__":
    REPORT = {}
    input_path = "/data/professional/multiplatform_groundtruth"
    output_path = "/data/professional/multiplatform_groundtruth/smda"
    disassembler = Disassembler(config)
    for root, subdir, files in os.walk(input_path):
        if "smda" in root:
            continue
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.exists(output_path + os.sep + filename + ".smda"):
                print("Skipping file {}".format(filepath))
                continue
            REPORT = {}
            INPUT_FILEPATH = root + os.sep + filename
            INPUT_FILENAME = os.path.basename(INPUT_FILEPATH)
            print("Analyzing file: {}".format(INPUT_FILEPATH))
            REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            if REPORT:
                family = ""
                compiler = "".join(filename.split("_")[-2:])
                version = INPUT_FILEPATH.split("/")[5]
                if "_i686" in filename:
                    family = filename.split("_i686")[0]
                else:
                    family = filename.split("_x86_64")[0]
                REPORT["meta"]["family"] = family
                REPORT["meta"]["version"] = version
                REPORT["meta"]["compiler"] = compiler
                REPORT["meta"]["filepath"] = INPUT_FILEPATH[len(input_path) + 1:]
                with open(output_path + os.sep + version + "_" + INPUT_FILENAME + ".smda", "w") as fout:
                    json.dump(REPORT, fout, indent=1, sort_keys=True)
