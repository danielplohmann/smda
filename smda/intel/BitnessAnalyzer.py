import re
import struct
import logging
from collections import Counter

from .definitions import COMMON_START_BYTES

LOGGER = logging.getLogger(__name__)


class BitnessAnalyzer(object):

    def determineBitnessFromFile(self, filepath):
        LOGGER.debug("Running Bitness test on %s", filepath)
        with open(filepath, "rb") as infile:
            if re.search(r"[0-9a-fA-F]{64}_dump_0x[0-9a-fA-F]+$", filepath):
                return self.determineBitness(binary=infile.read())
        return 0

    def determineBitnessFromDisassembly(self, disassembly):
        LOGGER.debug("Running Bitness test on binary data of DisassemblyResult")
        return self.determineBitness(binary=disassembly.binary_info.binary)

    def determineBitness(self, binary):
        candidate_first_bytes = {"32": Counter(), "64": Counter()}
        # check for potential call instructions and collect their first bytes
        for bitness in ["32", "64"]:
            for call_match in re.finditer(b"\xE8", binary):
                if len(binary) - call_match.start() > 5:
                    packed_call = binary[call_match.start() + 1:call_match.start() + 5]
                    rel_call_offset = struct.unpack("i", packed_call)[0]
                    call_destination = (rel_call_offset + call_match.start() + 5)  # & bitmask
                    if call_destination > 0 and call_destination < len(binary):
                        first_byte = binary[call_destination]
                        candidate_first_bytes[bitness][first_byte] += 1
        score = {"32": 0, "64": 0}
        for bitness in ["32", "64"]:
            for candidate_sequence in candidate_first_bytes[bitness]:
                if isinstance(candidate_sequence, int):
                    candidate_sequence = "%02x" % candidate_sequence
                elif isinstance(candidate_sequence, str):
                    candidate_sequence = candidate_sequence.encode("hex")
                for common_sequence, sequence_score in COMMON_START_BYTES[bitness].items():
                    if candidate_sequence == str(common_sequence):
                        score[bitness] += sequence_score * 1.0
        total_score = max(score["32"] + score["64"], 1)
        score["32"] /= total_score
        score["64"] /= total_score
        LOGGER.debug("Bitness scores: %5.2f (32bit), %5.2f (64bit)", score["32"], score["64"])
        return 64 if score["32"] < score["64"] else 32
