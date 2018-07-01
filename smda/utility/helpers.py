import os
import re

def load_file(path):
    binary = ""
    if os.path.isfile(path):
        with open(path, "rb") as inf:
            binary = inf.read()
    return binary


def get_base_addr_from_path(path):
    base_addr = 0
    base_addr_match = re.search(r"0x[a-fA-F0-9]{8,16}", path)
    if base_addr_match:
        base_addr = int(base_addr_match.group(), 16)
    return base_addr
