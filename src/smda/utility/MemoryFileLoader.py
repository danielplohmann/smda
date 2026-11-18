from smda.utility.FileLoader import FileLoader


class MemoryFileLoader(FileLoader):
    def __init__(self, buffer, load_file=True, map_file=False, config=None):
        super().__init__("", load_file=False, map_file=map_file, config=config)
        self._loadFile(buffer=buffer)
