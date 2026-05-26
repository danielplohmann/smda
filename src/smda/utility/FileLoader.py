import os

from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader
from smda.utility.DexFileLoader import DexFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.PeFileLoader import PeFileLoader


class FileLoader:
    _file_path = None
    _map_file = False
    _data = b""
    _raw_data = b""
    _base_addr = 0
    _bitness = 0
    _abi = ""
    _architecture = ""
    _code_areas = None
    file_loaders = [PeFileLoader, ElfFileLoader, MachoFileLoader, DelphiKbFileLoader, DexFileLoader]

    def __init__(self, file_path, load_file=True, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        self._code_areas = []
        if load_file:
            self._loadFile()

    def _loadRawFileContent(self):
        binary = b""
        if os.path.isfile(self._file_path):
            with open(self._file_path, "rb") as inf:
                binary = inf.read()
        return binary

    def _loadFile(self, buffer=None):
        self._raw_data = buffer if buffer is not None else self._loadRawFileContent()
        if self._map_file:
            for loader in self.file_loaders:
                if loader.isCompatible(self._raw_data):
                    # PE/ELF/MachO loaders expose parseBinary() so we can
                    # share a single lief.parse(...) across every accessor
                    # and skip multiple redundant re-parses per binary
                    # load. Delphi/Dex loaders don't need lief, so kw
                    # stays empty for them. We always pass parsed= (even
                    # when None) so a failed parse short-circuits each
                    # accessor — the loader-side sentinel default
                    # distinguishes "caller did not supply" from
                    # "caller already tried and got None".
                    kw = {"parsed": loader.parseBinary(self._raw_data)} if hasattr(loader, "parseBinary") else {}
                    self._data = loader.mapBinary(self._raw_data, **kw)
                    self._base_addr = loader.getBaseAddress(self._raw_data, **kw)
                    self._bitness = loader.getBitness(self._raw_data, **kw)
                    self._code_areas = loader.getCodeAreas(self._raw_data, **kw)
                    self._architecture = loader.getArchitecture(self._raw_data, **kw)
                    self._abi = loader.getAbi(self._raw_data, **kw)
                    break
        else:
            self._data = self._raw_data

    def getData(self):
        return self._data

    def getRawData(self):
        return self._raw_data

    def getBaseAddress(self):
        return self._base_addr

    def getAbi(self):
        return self._abi

    def getArchitecture(self):
        return self._architecture

    def getBitness(self):
        return self._bitness

    def getCodeAreas(self):
        return self._code_areas
