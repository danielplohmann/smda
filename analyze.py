import argparse
import json
import logging
import os
import re
import sys

from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.DexFileLoader import DexFileLoader


def parseBaseAddrFromArgs(args, silent=False):
    if args.base_addr:
        parsed_base_addr = int(args.base_addr, 16) if args.base_addr.startswith("0x") else int(args.base_addr)
        logging.info("using provided base address: 0x%08x", parsed_base_addr)
        return parsed_base_addr
    # try to infer base addr from filename:
    baddr_match = re.search(re.compile("_0x(?P<base_addr>[0-9a-fA-F]{8,16})"), args.input_path)
    if baddr_match:
        parsed_base_addr = int(baddr_match.group("base_addr"), 16)
        logging.info("Parsed base address from file name: 0x%08x", parsed_base_addr)
        return parsed_base_addr
    if not silent:
        logging.warning("No base address recognized, using 0.")
    return 0


def parseOepFromArgs(args, silent=False):
    if args.oep and args.oep != "":
        parsed_oep = int(args.oep, 16) if args.oep.startswith("0x") else int(args.oep)
        logging.info("using provided OEP(RVA): 0x%08x", parsed_oep)
        return parsed_oep
    if not silent:
        logging.warning("No OEP recognized, skipping.")
    return None


def _printDalvikSummary(report, output_path, input_filename):
    """Structured one-screen summary printed to stdout after Dalvik/DEX analysis."""
    size_bytes = report.binary_size or 0
    size_str = f"{size_bytes / 1024 / 1024:.1f} MB" if size_bytes >= 1024 * 1024 else f"{size_bytes / 1024:.1f} KB"

    dex_version = report.version if report.version else "?"
    bitness_str = f".{report.bitness}bit" if report.bitness else ""
    stats = report.statistics

    # Aggregate heuristic tags and string-ref count across all functions
    heuristic_counts = {}
    string_ref_total = 0
    for fn in report.getFunctions():
        for tag in (fn.architecture_metadata or {}).get("heuristics", []):
            heuristic_counts[tag] = heuristic_counts.get(tag, 0) + 1
        string_ref_total += len(fn.stringrefs or {})

    print(f"[*] File:       {input_filename}  ({size_str})")
    print(f"[*] Architecture: {report.architecture}{bitness_str}")
    print(f"[*] Format:     Dalvik DEX v{dex_version}")
    print(f"[*] Time:       {report.execution_time:.3f}s")
    print(f"[*] Functions:  {stats.num_functions:,}")
    print(f"[*] CFG:        {stats.num_basic_blocks:,} blocks  /  {stats.num_instructions:,} instructions")
    print(f"[*] Refs:       api={stats.num_api_calls:,}   strings={string_ref_total:,}")

    if heuristic_counts:
        # Sort by count descending, wrap at ~52 chars per continuation line
        tags = sorted(heuristic_counts.items(), key=lambda kv: -kv[1])
        tag_strs = [f"{k}={v}" for k, v in tags]
        lines, current = [], ""
        for ts in tag_strs:
            if current and len(current) + 2 + len(ts) > 52:
                lines.append(current)
                current = ts
            else:
                current = (current + "  " + ts).lstrip()
        if current:
            lines.append(current)
        print(f"[!] Heuristics: {lines[0]}")
        for line in lines[1:]:
            print(f"                {line}")

    if output_path and os.path.isdir(output_path):
        print(f"[+] Saved:      {os.path.join(output_path, input_filename + '.smda')}")


def _getInteractiveStream(stream):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(errors="backslashreplace")
    return stream


def readFileContent(file_path):
    file_content = b""
    with open(file_path, "rb") as fin:
        file_content = fin.read()
    return file_content


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        description="Demo: Use SMDA to disassemble a given file (loaded memory view), optionally map it first and/or write the output to a file."
    )
    PARSER.add_argument(
        "-p",
        "--parse_header",
        action="store_true",
        default=False,
        help="Parse header/symbols and perform mapping of the file as normalization.",
    )
    PARSER.add_argument(
        "-d",
        "--pdb_path",
        type=str,
        default="",
        help="If available, use a PDB file to enhance disassembly (function offsets and names).",
    )
    PARSER.add_argument(
        "-r",
        "--architecture",
        type=str,
        default="",
        help="Use the disassembler for the following architecture if available (default:auto, options: [intel, cil, dalvik]).",
    )
    PARSER.add_argument(
        "-a",
        "--base_addr",
        type=str,
        default="",
        help="When analyzing a buffer, set base address to given value (int or 0x-hex format).",
    )
    PARSER.add_argument(
        "-b",
        "--bitness",
        type=int,
        default=0,
        help="Optionally force bitness to [32, 64] when processing dumps.",
    )
    PARSER.add_argument(
        "-i",
        "--oep",
        type=str,
        default="",
        help="Force OEP for buffers, defined as RVA.",
    )
    PARSER.add_argument(
        "-o",
        "--output_path",
        type=str,
        default="",
        help="Optionally write the output to a file (JSON format).",
    )
    PARSER.add_argument(
        "-s",
        "--strings",
        action="store_true",
        default=False,
        help="Enable string extraction.",
    )
    PARSER.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug logging.",
    )
    PARSER.add_argument("input_path", type=str, default="", help="Path to file to analyze.")

    ARGS = PARSER.parse_args()

    if not ARGS.input_path:
        PARSER.print_help()
        sys.exit(1)

    # optionally create and set up a config, e.g. when using ApiScout profiles for WinAPI import usage discovery
    config = SmdaConfig()
    if ARGS.strings:
        config.WITH_STRINGS = True
    if ARGS.verbose:
        config.LOG_LEVEL = logging.DEBUG
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s.%(msecs)03d %(levelname).1s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
            stream=_getInteractiveStream(sys.stdout),
        )
    else:
        logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
    SMDA_REPORT = None
    INPUT_FILENAME = ""
    BITNESS = ARGS.bitness if (ARGS.bitness in [32, 64]) else None
    if os.path.isfile(ARGS.input_path):
        print(f"now analyzing {ARGS.input_path}")
        INPUT_FILENAME = os.path.basename(ARGS.input_path)
        if ARGS.parse_header:
            DISASSEMBLER = Disassembler(config, backend=ARGS.architecture)
            SMDA_REPORT = DISASSEMBLER.disassembleFile(ARGS.input_path, pdb_path=ARGS.pdb_path)
        else:
            BUFFER = readFileContent(ARGS.input_path)
            treat_as_dalvik = ARGS.architecture in {"", "dalvik"} and DexFileLoader.isCompatible(BUFFER)
            if treat_as_dalvik:
                BASE_ADDR = DexFileLoader.getBaseAddress(BUFFER)
                OEP = None
            else:
                BASE_ADDR = parseBaseAddrFromArgs(ARGS)
                OEP = parseOepFromArgs(ARGS)
            config.API_COLLECTION_FILES = {
                "win_7": os.sep.join([config.PROJECT_ROOT, "data", "apiscout_win7_prof-n_sp1.json"])
            }
            DISASSEMBLER = Disassembler(config, backend=ARGS.architecture)
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS, oep=OEP)
            SMDA_REPORT.filename = os.path.basename(ARGS.input_path)
        if SMDA_REPORT.architecture == "dalvik":
            _printDalvikSummary(SMDA_REPORT, ARGS.output_path, INPUT_FILENAME)
        else:
            print(SMDA_REPORT)
    if SMDA_REPORT and ARGS.output_path and os.path.isdir(ARGS.output_path):
        output_file = os.path.join(ARGS.output_path, INPUT_FILENAME + ".smda")
        with open(output_file, "w") as fout:
            json.dump(SMDA_REPORT.toDict(), fout, indent=1, sort_keys=True)
