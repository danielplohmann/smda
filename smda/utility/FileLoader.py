import os
from smda.utility.PeFileLoader import PeFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader


class FileLoader(object):

    def __init__(self, file_path, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        self._data = b""
        self._raw_data = b""
        self._base_addr = 0
        self._bitness = 0
        self._code_areas = []
        self.file_loaders = [PeFileLoader, ElfFileLoader]
        self._loadFile()

    def _loadRawFileContent(self):
        binary = ""
        if os.path.isfile(self._file_path):
            with open(self._file_path, "rb") as inf:
                binary = inf.read()
        return binary

    def _loadFile(self):
        self._raw_data = self._loadRawFileContent()
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
