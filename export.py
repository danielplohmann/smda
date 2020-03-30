import json
import logging
import os

import config
from smda.Disassembler import Disassembler

LOGGER = logging.getLogger(__name__)


def detectBackend():
    backend = ""
    version = ""
    try:
        import idaapi
        import idc
        import idautils
        backend = "IDA"
        version = idaapi.IDA_SDK_VERSION
    except:
        pass
    return (backend, version)


if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        DISASSEMBLER = Disassembler(config, backend=BACKEND)
        REPORT = DISASSEMBLER.disassembleBuffer(None, None)
        output_path = idautils.GetIdbDir()
        with open(output_path + ".smda", "wb") as fout:
            json.dump(REPORT, fout, indent=1, sort_keys=True)
            LOGGER.info("Output saved to: %s.smda", output_path)
    else:
        raise Exception("No supported backend found.")
