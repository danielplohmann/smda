"""Export Binary Ninja's analysis to a SMDA report.

Inside Binary Ninja, run this file through *Run Script...* to export the open view to a
``.smda`` file next to the open file (the database, when one is open). From a shell, it opens a binary or a Binary Ninja database
(``.bndb``) headlessly, the counterpart to ``ida_domain_export.py``:

    PYTHONPATH="/Applications/Binary Ninja.app/Contents/Resources/python" python binja_export.py /path/to/sample [-o report.smda]
"""

import argparse
import json
import sys

from smda.binja.BinjaExporter import exportBinaryView, loadBinaryView
from smda.binja.BinjaInterface import BinjaInterface


def export_view(bv, output_path=None):
    report = exportBinaryView(bv)
    output_path = output_path or BinjaInterface(bv).getFilePath() + ".smda"
    with open(output_path, "w") as fout:
        json.dump(report.toDict(), fout, indent=1, sort_keys=True)
    print(f"Exported {report.num_functions} Binary Ninja functions.")
    print(f"Output saved to: {output_path}")
    return report


def export_file(input_path, output_path=None):
    with loadBinaryView(input_path) as bv:
        return export_view(bv, output_path or input_path + ".smda")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Headless SMDA export from Binary Ninja's analysis.")
    parser.add_argument("input_path", help="Path to the binary or Binary Ninja database (.bndb) to export.")
    parser.add_argument("-o", "--output", help="Output .smda path (default: <input_path>.smda).")
    args = parser.parse_args(argv)
    try:
        export_file(args.input_path, args.output)
    except ImportError:
        print(
            "binaryninja is not importable. Point PYTHONPATH at the python directory of a licensed "
            "Binary Ninja installation (see https://docs.binary.ninja/dev/batch.html).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    if globals().get("bv") is not None:
        export_view(globals()["bv"])
    else:
        raise SystemExit(main())
