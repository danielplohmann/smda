"""Run from inside IDA (File -> Script file...) to export the currently open
database as a SMDA report, using the ida-domain backend (IDA Pro 9.1+).

For headless export (no GUI) use ``ida_domain_analyze.py`` instead.
"""

import json

from smda.Disassembler import Disassembler
from smda.ida.IdaExporter import IdaExporter
from smda.ida.IdaInterface import IdaInterface
from smda.SmdaConfig import SmdaConfig


def detectBackend():
    """Return ("IDA", "ida-domain") when the ida-domain backend is importable."""
    backend = ""
    version = ""
    try:
        import ida_domain  # noqa: F401

        backend = "IDA"
        version = getattr(ida_domain, "__version__", "ida-domain")
    except ImportError:
        pass
    return (backend, version)


if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        config = SmdaConfig()
        disassembler = Disassembler(config)
        ida_interface = IdaInterface()
        disassembler.disassembler = IdaExporter(config, ida_interface=ida_interface)
        disassembler._explicit_backend = True
        binary = ida_interface.getBinary()
        base_addr = ida_interface.getBaseAddr()
        REPORT = disassembler.disassembleBuffer(binary, base_addr)
        output_filepath = ida_interface.getIdbDir() + "ConvertedFromIdb.smda"
        with open(output_filepath, "w") as fout:
            json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
            print(f"Output saved to: {output_filepath}")
    else:
        raise Exception("No supported backend found (ida-domain is required, IDA Pro 9.1+).")
