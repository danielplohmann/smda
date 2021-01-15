from smda.utility.FileLoader import FileLoader


class MemoryFileLoader(FileLoader):

    def __init__(self, buffer, load_file=True, map_file=False):
        super().__init__("", load_file=False, map_file=map_file)
        self._loadFile(buffer=buffer)
