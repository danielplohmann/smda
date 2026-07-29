import logging
import sys

import atheris

with atheris.instrument_imports():
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig

logging.disable(logging.CRITICAL)

VALID_STATUS = {"ok", "timeout", "error"}

CONFIG = SmdaConfig()
CONFIG.TIMEOUT = 5
DISASSEMBLER = Disassembler(CONFIG)


def TestOneInput(data):
    report = DISASSEMBLER.disassembleUnmappedBuffer(data)
    if report is None:
        raise AssertionError("disassembleUnmappedBuffer returned None")
    if report.status not in VALID_STATUS:
        raise AssertionError(f"invalid report status: {report.status}")


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
