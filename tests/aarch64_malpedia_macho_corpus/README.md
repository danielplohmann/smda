# Malpedia AArch64 Mach-O Corpus Fixtures

These fixtures are malware-derived samples from Malpedia, stored only in the
repository's XOR-obfuscated test-fixture format.

Do not execute these files. Tests de-XOR bytes in memory only, use them for
Mach-O loader and AArch64 disassembly validation, and never write raw sample
bytes back to disk.

The selected subset was produced by the fork-only Malpedia validation workflow
from the Malpedia commit recorded in `manifest.json`.
