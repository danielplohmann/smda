import bisect
import itertools
from typing import Any, Dict, List, Optional

from smda.common.SmdaBasicBlock import SmdaBasicBlock


class BlockLocator:
    """Class that finds a block by any address within.
    When instantiated, creates the required data structures.
    """

    sorted_blocks_addresses: Optional[List[Any]] = None
    blocks_dict: Optional[Dict[Any, SmdaBasicBlock]] = None

    def __init__(self, functions):
        # Instantiate the datastructures required :
        # 1. get a flat list of all the blocks in all the functions
        blocks = list(itertools.chain(*[f.getBlocks() for f in functions]))
        self.sorted_blocks_addresses = sorted(b.offset for b in blocks)

        # 2 a dict of blocks by addresses
        self.blocks_dict = {b.offset: b for b in blocks}

    def _get_block_end(self, block):
        last_ins = block.instructions[-1]
        return last_ins.offset + len(last_ins.bytes) // 2  # bytes is actuall a hex string

    def findBlockByContainedAddress(self, inner_address) -> Optional[SmdaBasicBlock]:
        sorted_addresses = self.sorted_blocks_addresses
        if sorted_addresses is None:
            return None
        # do a binary search to find the closest address to the left of inner_address
        block_num = bisect.bisect(sorted_addresses, inner_address) - 1

        if block_num == -1:
            # target address is smaller than first block. return none
            return None

        block_start = sorted_addresses[block_num]
        blocks_dict = self.blocks_dict
        if blocks_dict is None:
            return None
        block = blocks_dict[block_start]
        block_end = self._get_block_end(block)

        # make sure inner_address falls within the selected block
        if block.offset <= inner_address < block_end:
            return block

        return None
