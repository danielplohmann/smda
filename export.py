import json

from smda.Disassembler import Disassembler


def detectBackend():
    backend = ""
    version = ""
    try:
        import idaapi

        backend = "IDA"
        version = idaapi.IDA_SDK_VERSION
    except ImportError:
        pass
    return (backend, version)


if __name__ == "__main__":
    BACKEND, VERSION = detectBackend()
    if BACKEND == "IDA":
        from smda.ida.IdaInterface import IdaInterface

        ida_interface = IdaInterface()
        binary = ida_interface.getBinary()
        base_addr = ida_interface.getBaseAddr()
        DISASSEMBLER = Disassembler(backend=BACKEND)
        REPORT = DISASSEMBLER.disassembleBuffer(binary, base_addr)
        output_path = ida_interface.getIdbDir()
        output_filepath = output_path + "ConvertedFromIdb.smda"
        with open(output_filepath, "w") as fout:
            json.dump(REPORT.toDict(), fout, indent=1, sort_keys=True)
            print(f"Output saved to: {output_filepath}")
    else:
        raise Exception("No supported backend found.")
