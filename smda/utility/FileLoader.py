import os
from smda.utility.PeFileLoader import PeFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader

class FileLoader(object):

    _file_path = None
    _map_file = False
    _data = b""
    _raw_data = b""
    _base_addr = 0
    _bitness = 0
    _code_areas = []
    file_loaders = [PeFileLoader, ElfFileLoader, MachoFileLoader, DelphiKbFileLoader]

    def __init__(self, file_path, load_file=True, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        if load_file:
            self._loadFile()

    def _loadRawFileContent(self):
        binary = ""
        if os.path.isfile(self._file_path):
            with open(self._file_path, "rb") as inf:
                binary = inf.read()
        return binary

    def _loadFile(self, buffer=None):
        self._raw_data = buffer if buffer is not None else self._loadRawFileContent()
        if self._map_file:
            for loader in self.file_loaders:
                if loader.isCompatible(self._raw_data):
                    self._data = loader.mapBinary(self._raw_data)
                    self._base_addr = loader.getBaseAddress(self._raw_data)
                    self._bitness = loader.getBitness(self._raw_data)
                    self._code_areas = loader.getCodeAreas(self._raw_data)
                    break
        else:
            self._data = self._raw_data

    def getData(self):
        return self._data

    def getRawData(self):
        return self._raw_data

    def getBaseAddress(self):
        return self._base_addr

    def getBitness(self):
        return self._bitness

    def getCodeAreas(self):
        return self._code_areas
