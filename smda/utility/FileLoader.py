import os
from smda.utility.PeFileLoader import PeFileLoader
from smda.utility.ElfFileLoader import ElfFileLoader


class FileLoader(object):

    def __init__(self, file_path, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        self.file_loaders = [PeFileLoader, ElfFileLoader]
        self._loadFile()
        
    def _loadRawFileContent(self):
        binary = ""
        if os.path.isfile(self._file_path):
            with open(self._file_path, "rb") as inf:
                binary = inf.read()
        return binary
        
    def _loadFile(self):
        if self._map_file:
            data = self._loadRawFileContent()
            for loader in self.file_loaders:
                if loader.isCompatible(data):
                    self._data = loader.mapData(data)
                    break
        else:
            self._data = self._loadRawFileContent()
        
    def getData(self):
        return self._data

