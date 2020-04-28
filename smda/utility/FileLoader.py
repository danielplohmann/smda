import os
from smda.utility.PeFileLoader import PeFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader


class FileLoader(object):

    def __init__(self, file_path, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        self._data = b""
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
        data = self._loadRawFileContent()
        if self._map_file:
            for loader in self.file_loaders:
                if loader.isCompatible(data):
                    self._data = loader.mapBinary(data)
                    self._base_addr = loader.getBaseAddress(data)
                    self._bitness = loader.getBitness(data)
                    self._code_areas = loader.getCodeAreas(data)
                    break
        else:
            self._data = data

    def getData(self):
        return self._data

    def getBaseAddress(self):
        return self._base_addr

    def getBitness(self):
        return self._bitness

    def getCodeAreas(self):
        return self._code_areas
