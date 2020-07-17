import hashlib

class BinaryInfo(object):
    """ simple DTO to contain most information related to the binary/buffer to be analyzed """

    architecture = ""
    base_addr = 0
    binary = b""
    raw_data = b""
    binary_size = 0
    bitness = None
    code_areas = []
    component = ""
    family = ""
    file_path = ""
    is_library = False
    is_buffer = False
    sha256 = ""
    version = ""

    def __init__(self, binary):
        self.binary = binary
        self.raw_data = binary
        self.binary_size = len(binary)
        self.sha256 = hashlib.sha256(binary).hexdigest()
