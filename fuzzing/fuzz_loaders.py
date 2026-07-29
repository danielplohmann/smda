import logging
import sys

import atheris

with atheris.instrument_imports():
    from smda.common.ExceptionHandling import reraise_non_operational_exception
    from smda.utility.MemoryFileLoader import MemoryFileLoader

logging.disable(logging.CRITICAL)


def TestOneInput(data):
    try:
        loader = MemoryFileLoader(data, map_file=True)
        loader.getData()
        loader.getRawData()
        loader.getBaseAddress()
        loader.getBitness()
        loader.getArchitecture()
        loader.getAbi()
        loader.getCodeAreas()
        loader.getHasBackend()
    except Exception as exc:
        reraise_non_operational_exception(exc)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
