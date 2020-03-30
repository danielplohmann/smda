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


def getAllReportFilenames(output_path):
    report_filenames = set([])
    for root, subdir, files in os.walk(output_path):
        for filename in files:
            report_filenames.add(filename)
    return report_filenames


if __name__ == "__main__":
    REPORT = {}
    malpedia_path = "/data/malpedia"
    output_path = "/data//smda_reports"
    finished_reports = getAllReportFilenames(output_path)
    dump_file_pattern = re.compile("dump7?_0x[0-9a-fA-F]{8,16}")
    unpacked_file_pattern = re.compile("_unpacked(_x64)?$")
    disassembler = Disassembler(config)
    for root, subdir, files in os.walk(malpedia_path):
        for filename in files:
            filepath = root + os.sep + filename
            if filename + ".smda" in finished_reports:
                print("Skipping file {}".format(filepath))
                continue
            REPORT = {}
            INPUT_FILEPATH = root + os.sep + filename
            INPUT_FILENAME = os.path.basename(INPUT_FILEPATH)
            if "elf." in INPUT_FILEPATH and "x86" in INPUT_FILEPATH and re.search(unpacked_file_pattern, filename):
                print("Analyzing file: {}".format(INPUT_FILEPATH))
                REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            elif "osx." in INPUT_FILEPATH and re.search(unpacked_file_pattern, filename):
                print("Analyzing file: {}".format(INPUT_FILEPATH))
                BUFFER = readFileContent(INPUT_FILEPATH)
                BASE_ADDR = parseBaseAddrFromArgs(INPUT_FILENAME)
                REPORT = disassembler.disassembleBuffer(BUFFER, BASE_ADDR)
            elif "win." in INPUT_FILEPATH and re.search(unpacked_file_pattern, filename):
                print("Analyzing file: {}".format(INPUT_FILEPATH))
                REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            elif re.search(dump_file_pattern, filename):
                print("Analyzing file: {}".format(INPUT_FILEPATH))
                BUFFER = readFileContent(INPUT_FILEPATH)
                BASE_ADDR = parseBaseAddrFromArgs(INPUT_FILENAME)
                BITNESS = getBitnessFromFilename(INPUT_FILENAME)
                REPORT = disassembler.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS)
            if REPORT:
                REPORT["metadata"]["family"] = INPUT_FILEPATH.split("/")[3]
                REPORT["metadata"]["malpedia_filepath"] = INPUT_FILEPATH[len(malpedia_path) + 1:]
                with open(output_path + os.sep + INPUT_FILENAME + ".smda", "w") as fout:
                    json.dump(REPORT, fout, indent=1, sort_keys=True)

