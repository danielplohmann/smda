import json
import logging
import os
import re
import struct
import sys
import traceback
from multiprocessing import Pool, cpu_count

import tqdm

from smda.Disassembler import Disassembler

dump_file_pattern = re.compile("dump7?_0x[0-9a-fA-F]{8,16}")
unpacked_file_pattern = re.compile("_unpacked(_x64)?$")

logger = logging.getLogger("smda-multithreaded")


def get_word(buffer, start):
    return _get_binary_data(buffer, start, 2)


def get_dword(buffer, start):
    return _get_binary_data(buffer, start, 4)


def get_qword(buffer, start):
    return _get_binary_data(buffer, start, 8)


def _get_binary_data(buffer, start, length):
    if length not in _unsigned_unpack_formats:
        raise RuntimeError("Unsupported data length")

    return struct.unpack(_unsigned_unpack_formats[length], buffer[start : start + length])[0]


_unsigned_unpack_formats = {2: "H", 4: "I", 8: "Q"}


def get_pe_offset(content):
    if len(content) >= 0x40:
        pe_offset = get_word(content, 0x3C)
        return pe_offset
    raise RuntimeError("Buffer too small to extract PE offset (< 0x40)")


def check_bitness(content):
    bitness = None
    pe_offset = get_pe_offset(content)
    if pe_offset and len(content) >= pe_offset + 6:
        bitness = get_word(content, pe_offset + 4)
        bitness_map = {0x14C: 32, 0x8664: 64}
        bitness = bitness_map.get(bitness, 0)
    return bitness


class NativeCodeIdentifier:
    family_override = []

    def _identifyDotnet(self, content):
        if not check_bitness(content):
            return False
        pe_offset = get_pe_offset(content)
        file_characteristics_offset = pe_offset + 0x18
        file_characteristics = get_word(content, file_characteristics_offset)
        field_offset = 0
        if file_characteristics == 0x10B:
            field_offset = 0xE8
        elif file_characteristics == 0x20B:
            field_offset = 0xF8
        image_dir_com_descriptor_offset = pe_offset + field_offset
        # only .NET binaries will feature a COM dscription table in the data directory
        com_descriptor_offset = get_dword(content, image_dir_com_descriptor_offset)
        return bool(field_offset > 0 and len(content) - 8 > com_descriptor_offset > 0)

    def _identifyDelphi(self, content):
        # check PE header for typical sections
        if b"CODE" in content[:0x400] and b"DATA" in content[:0x400]:
            return True
        # check CODE for typical Delphi class names
        return bool(b"\x07TObject" in content[:8192] or b"\nWideString" in content[:8192])

    def _identifyGo(self, content):
        # Go binaries should always have a build ID in their beginning
        return b"Go build ID:" in content[:5120]

    def _identifyPython(self, content):
        return bool(re.search(b"python(2|3).\\.dll", content))

    def isNativeCode(self, filepath):
        for family in self.family_override:
            if family in filepath:
                return True
        content = ""
        with open(filepath, "rb") as fin:
            content = fin.read()
        ### We want to process both Delphi and Go for this, so ensure they are not excluded.
        # identify Delphi
        # is_delphi = self._identifyDelphi(content)
        is_delphi = False
        # identify Go
        # is_go = self._identifyGo(content)
        is_go = False
        # identify .NET
        is_dotnet = self._identifyDotnet(content)
        # identify PyInstaller
        is_python = self._identifyPython(content)
        return not (is_delphi or is_go or is_dotnet or is_python)


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
    report_filenames = set()
    if not os.path.exists(output_path):
        return report_filenames
    for _root, _subdir, files in os.walk(output_path):
        for filename in files:
            report_filenames.add(filename)
    return report_filenames


def getFamilyName(input_path):
    family_name = ""
    abs_path = os.path.abspath(input_path)
    for folder in abs_path.split("/")[::-1]:
        if folder == "malpedia":
            break
        family_name = folder
    return family_name


def getSampleVersion(input_path, family):
    sample_version = ""
    abs_path = os.path.dirname(os.path.abspath(input_path))
    for folder in abs_path.split("/")[::-1]:
        if folder == family or folder == "modules":
            break
        sample_version = folder
    return sample_version


def getMalpediaFilePath(input_path):
    egg = "malpedia/"
    abs_path = os.path.abspath(input_path)
    pos = abs_path.index(egg)
    malpedia_filepath = abs_path[pos + len(egg) :]
    return malpedia_filepath


_disassembler = None


def get_disassembler():
    global _disassembler
    if _disassembler is None:
        _disassembler = Disassembler()
    return _disassembler


def work(input_element):
    if input_element["filename"] + ".smda" in input_element["finished_reports"]:
        print("Skipping file {}".format(input_element["filepath"]))
        return
    REPORT = None
    INPUT_FILEPATH = input_element["filepath"]
    INPUT_FILENAME = input_element["filename"]
    input_element["malpedia_path"]
    identifier = NativeCodeIdentifier()
    if not identifier.isNativeCode(INPUT_FILEPATH):
        return
    malpedia_relative_path = getMalpediaFilePath(INPUT_FILEPATH)
    in_family_path = os.sep.join(malpedia_relative_path.split(os.sep)[1:])
    if in_family_path.startswith("module"):
        return
    disassembler = get_disassembler()
    try:
        if (
            "elf." in INPUT_FILEPATH
            and ("x86" in INPUT_FILEPATH or "x64" in INPUT_FILEPATH)
            and re.search(unpacked_file_pattern, input_element["filename"])
        ):
            print(f"Analyzing file: {INPUT_FILEPATH}")
            try:
                REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            except AttributeError:
                logger.error("exception for: " + str(INPUT_FILENAME))
        elif "win." in INPUT_FILEPATH and re.search(unpacked_file_pattern, input_element["filename"]):
            print(f"Analyzing file: {INPUT_FILEPATH}")
            try:
                REPORT = disassembler.disassembleFile(INPUT_FILEPATH)
            except AttributeError:
                logger.error("AttributeError for: " + str(INPUT_FILENAME))
        elif re.search(dump_file_pattern, input_element["filename"]):
            print(f"Analyzing file: {INPUT_FILEPATH}")
            BUFFER = readFileContent(INPUT_FILEPATH)
            BASE_ADDR = parseBaseAddrFromArgs(INPUT_FILENAME)
            BITNESS = getBitnessFromFilename(INPUT_FILENAME)
            try:
                REPORT = disassembler.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS)
            except AttributeError:
                logger.error("AttributeError for: " + str(INPUT_FILENAME))
        if REPORT:
            REPORT.family = getFamilyName(INPUT_FILEPATH)
            REPORT.version = getSampleVersion(INPUT_FILEPATH, REPORT.family)
            REPORT.filename = os.path.basename(malpedia_relative_path)
            output_dir = input_element.get("output_dir", "finished-reports")
            with open(output_dir + os.sep + INPUT_FILENAME + ".smda", "w") as fout:
                json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
                logger.info("Wrote " + output_dir + "/" + INPUT_FILENAME + ".smda")
    except Exception:
        print("RunTimeError, we skip!")
        print("smda: " + str(INPUT_FILENAME))
        traceback.print_exc()
    return None


if __name__ == "__main__":
    logging.basicConfig(
        filename="/tmp/smda.log",
        filemode="a",
        format="[%(asctime)s:%(msecs)d] %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
    )

    formatter = logging.Formatter(
        "%(process)d - %(processName)s - %(threadName)s - %(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Add logger to stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <malpedia_root> [output_dir]")
        sys.exit(1)
    malpedia_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "finished-reports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    finished_reports = getAllReportFilenames(output_dir)
    input_queue = []
    # Find all targets (everything) to disassemble in malpedia.
    for root, _subdir, files in sorted(os.walk(malpedia_path)):
        if ".git" in root:
            continue
        for filename in sorted(files):
            if not (re.search(unpacked_file_pattern, filename) or re.search(dump_file_pattern, filename)):
                continue
            filepath = root + os.sep + filename
            input_element = {
                "filename": filename,
                "finished_reports": finished_reports,
                "filepath": filepath,
                "malpedia_path": malpedia_path,
                "output_dir": output_dir,
            }
            input_queue.append(input_element)
    results = []
    # Use Pooling for parallel processing
    with Pool(cpu_count() - 2) as pool:
        for result in tqdm.tqdm(pool.imap_unordered(work, input_queue), total=len(input_queue)):
            results.append(result)
    print("DONE, shutting down")
