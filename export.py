import json
import logging
import os

from smda.Disassembler import Disassembler


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
        DISASSEMBLER = Disassembler(backend=BACKEND)
        REPORT = DISASSEMBLER.disassembleBuffer(None, None)
        output_path = idautils.GetIdbDir()
        with open(output_path + ".smda", "wb") as fout:
            json.dump(REPORT, fout, indent=1, sort_keys=True)
            logging.info("Output saved to: %s.smda", output_path)
    else:
        raise Exception("No supported backend found.")
