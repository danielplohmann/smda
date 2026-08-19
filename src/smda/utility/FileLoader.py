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
    _has_backend = False
    _format_recognized = False
    _code_areas = None
    file_loaders = [PeFileLoader, ElfFileLoader, MachoFileLoader, DelphiKbFileLoader, DexFileLoader]

    def __init__(self, file_path, load_file=True, map_file=False):
        self._file_path = file_path
        self._map_file = map_file
        self._code_areas = []
        self._has_backend = False
        if load_file:
            self._loadFile()

    def _loadRawFileContent(self):
        binary = b""
        file_path = self._file_path
        if file_path and os.path.isfile(file_path):
            with open(file_path, "rb") as inf:
                binary = inf.read()
        return binary

    def _loadFile(self, buffer=None):
        # A loader instance can be reused by tests and callers. Clear every
        # format-derived field before dispatch so an unrecognized or failed
        # subsequent load cannot expose metadata from the previous binary.
        self._data = b""
        self._base_addr = 0
        self._bitness = 0
        self._abi = ""
        self._architecture = ""
        self._has_backend = False
        self._format_recognized = False
        self._code_areas = []
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
                    if hasattr(loader, "getHasBackend"):
                        self._has_backend = loader.getHasBackend(self._raw_data, **kw)
                    else:
                        self._has_backend = bool(self._architecture)
                    self._format_recognized = True
                    break
            else:
                # No format loader claimed the input, so there is no mapping to apply and
                # the bytes are already whatever they are. Returning them keeps getData()
                # honest; every format-derived field stays unset, which is what tells the
                # caller the instruction set and load address are unknown.
                self._data = self._raw_data
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

    def getHasBackend(self):
        return self._has_backend

    def getFormatRecognized(self):
        """Whether a format loader claimed the input, regardless of what it read from it.

        A recognized container whose machine type SMDA has no backend for and an input
        no loader claims at all both end up with an empty architecture, and they need
        opposite advice."""
        return self._format_recognized

    def getBitness(self):
        return self._bitness

    def getCodeAreas(self):
        return self._code_areas
