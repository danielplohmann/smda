import logging
import re
import struct

from .definitions import COMMON_START_BYTES

LOGGER = logging.getLogger(__name__)

# Opcodes a REX.W prefix legitimately introduces in ordinary compiler output: the
# 64-bit pointer arithmetic, moves and compares that dominate an amd64 text section.
REX_W_OPCODES = frozenset(
    {
        0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B,
        0x63, 0x69, 0x6B, 0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x8F,
        0xC1, 0xC7, 0xD1, 0xD3, 0xF7, 0xFF,
    }
)  # fmt: skip
REX_W_PREFIX = 0x48
# 0x48 is REX.W in 64-bit mode and "dec eax" in 32-bit mode. In 64-bit code almost
# every 0x48 introduces one of the opcodes above; in 32-bit code the byte that follows
# is unrelated, so the share lands near the 29/256 a uniform byte would give. Measured
# across PE/ELF/Mach-O images from Go, gcc, clang, mingw-Rust and 32-bit malware:
# 32-bit stays at or below 0.36, 64-bit at or above 0.74.
REX_W_SHARE_THRESHOLD = 0.5
# Below this many observations the share is noise; fall back to the first-byte tables.
REX_W_MIN_SAMPLES = 64
# Bounds the probe on a pathological input without biasing it: an image with more
# occurrences than this is sampled far past the point where the share stabilises.
REX_W_MAX_SAMPLES = 1 << 16


class BitnessAnalyzer:
    def determineBitnessFromFile(self, filepath):
        LOGGER.debug("Running Bitness test on %s", filepath)
        with open(filepath, "rb") as infile:
            if re.search(r"[0-9a-fA-F]{64}_dump_0x[0-9a-fA-F]+$", filepath):
                return self.determineBitness(binary=infile.read())
        return 0

    def determineBitnessFromDisassembly(self, disassembly):
        LOGGER.debug("Running Bitness test on binary data of DisassemblyResult")
        return self.determineBitness(binary=disassembly.binary_info.binary)

    def _rexWShare(self, binary):
        """Share of 0x48 bytes that introduce a REX.W-compatible opcode."""
        observed = 0
        introducing = 0
        index = binary.find(REX_W_PREFIX)
        limit = len(binary) - 1
        while 0 <= index < limit and observed < REX_W_MAX_SAMPLES:
            observed += 1
            if binary[index + 1] in REX_W_OPCODES:
                introducing += 1
            index = binary.find(REX_W_PREFIX, index + 1)
        if observed < REX_W_MIN_SAMPLES:
            return None, observed
        return introducing / observed, observed

    def _scoreCommonStartBytes(self, binary):
        candidate_first_bytes = set()
        # check for potential call instructions and collect their first bytes
        for call_match in re.finditer(b"\xe8", binary):
            if len(binary) - call_match.start() >= 5:
                packed_call = binary[call_match.start() + 1 : call_match.start() + 5]
                rel_call_offset = struct.unpack("<i", packed_call)[0]
                call_destination = rel_call_offset + call_match.start() + 5  # & bitmask
                if call_destination > 0 and call_destination < len(binary):
                    first_byte = binary[call_destination]
                    candidate_first_bytes.add(f"{first_byte:02x}")
        score = {"32": 0.0, "64": 0.0}
        for bitness in ["32", "64"]:
            for candidate_sequence in candidate_first_bytes:
                sequence_score = COMMON_START_BYTES[bitness].get(candidate_sequence)
                if sequence_score is not None:
                    score[bitness] += sequence_score * 1.0
        total_score = max(score["32"] + score["64"], 1.0)
        score["32"] = score["32"] / total_score
        score["64"] = score["64"] / total_score
        LOGGER.debug("Bitness scores: %5.2f (32bit), %5.2f (64bit)", score["32"], score["64"])
        return 64 if score["32"] < score["64"] else 32

    def determineBitness(self, binary):
        share, observed = self._rexWShare(binary)
        if share is None:
            LOGGER.debug(
                "Only %d REX.W-candidate bytes, falling back to function-start bytes",
                observed,
            )
            return self._scoreCommonStartBytes(binary)
        bitness = 64 if share > REX_W_SHARE_THRESHOLD else 32
        LOGGER.debug(
            "Bitness probed as %d: %.3f of %d 0x48 bytes introduce a REX.W opcode",
            bitness,
            share,
            observed,
        )
        return bitness
