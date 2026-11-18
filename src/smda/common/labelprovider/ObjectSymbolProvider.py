from smda.common.labelprovider.AbstractLabelProvider import AbstractLabelProvider
from smda.common.labelprovider.PeSymbolProvider import _readable_name


class ObjectSymbolProvider(AbstractLabelProvider):
    def __init__(self, config):
        super().__init__(config)
        self.image = None
        self.functions = {}

    def update(self, binary_info):
        self.image = getattr(binary_info, "object_image", None)
        self.functions = (
            {address: _readable_name(name) for address, name in self.image.functions.items()}
            if self.image is not None
            else {}
        )

    def getApi(self, to_addr, absolute_addr=None):
        if self.image is not None:
            name = self.image.imports.get(to_addr) or self.image.imports.get(absolute_addr)
            if name:
                return "", name
        return None, None

    def getSymbol(self, address):
        return self.functions.get(address, "")

    def getFunctionSymbols(self):
        return self.functions

    def isApiProvider(self):
        return True

    def isSymbolProvider(self):
        return True

    def is_active(self):
        return self.image is not None
