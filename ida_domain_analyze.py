"""Headless SMDA export using the modern ``ida-domain`` backend.

This opens an IDA database (``.idb``/``.i64``) or any input binary IDA supports
*without* a running IDA GUI, collects the disassembly via ``ida-domain`` and
writes a ``.smda`` report - the headless counterpart to ``export.py`` (which
must be run from inside IDA).

Requirements:
    pip install "smda[ida]"   # pulls in ida-domain >= 0.5.0
    IDA Pro 9.1+ with IDADIR configured (see
    https://ida-domain.docs.hex-rays.com/getting_started/)

Usage:
    python ida_domain_analyze.py /path/to/sample.i64 [-o report.smda]
"""

import argparse
import json
import sys

from smda.Disassembler import Disassembler
from smda.ida.IdaExporter import IdaExporter
from smda.ida.IdaInterface import IdaInterface
from smda.SmdaConfig import SmdaConfig


def analyze(input_path, output_path=None):
    config = SmdaConfig()
    disassembler = Disassembler(config)
    with IdaInterface.fromPath(input_path) as ida_interface:
        # inject the ida-domain backed interface into the exporter and mark the
        # backend explicit so buffer disassembly does not try to auto-detect.
        disassembler.disassembler = IdaExporter(config, ida_interface=ida_interface)
        disassembler._explicit_backend = True
        binary = ida_interface.getBinary()
        base_addr = ida_interface.getBaseAddr()
        report = disassembler.disassembleBuffer(binary, base_addr)
    if output_path is None:
        output_path = input_path + ".smda"
    with open(output_path, "w") as fout:
        json.dump(report.toDict(), fout, indent=1, sort_keys=True)
    print(f"Disassembled {report.num_functions} functions.")
    print(f"Output saved to: {output_path}")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Headless SMDA export via the ida-domain backend.")
    parser.add_argument("input_path", help="Path to the IDA database (.idb/.i64) or input binary to analyze.")
    parser.add_argument("-o", "--output", help="Output .smda path (default: <input_path>.smda).")
    args = parser.parse_args(argv)
    try:
        analyze(args.input_path, args.output)
    except ImportError:
        print(
            "ida-domain is not available. Install it with 'pip install \"smda[ida]\"' "
            "and configure IDADIR for an IDA Pro 9.1+ installation.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
