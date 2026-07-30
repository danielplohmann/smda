"""Build a seed corpus for one fuzz target from the committed test fixtures.

Fixtures live in the repository's XOR-obfuscated form only; they are decoded in
memory and truncated to a header-sized prefix, which is where the interesting
parsing decisions are made. Missing fixtures are a hard error: a silently
degraded corpus would leave the fuzzer exploring almost nothing while CI stayed
green.

Profiles mirror the per-target input encodings in targets.py, prefixing the
selector bytes that pick a loader or an architecture.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"

FIXTURE_SEEDS = [
    "cutwail_xored",
    "bashlite_xored",
    "komplex_xored",
    "njrat_xored",
    "blockblast_classes_xored",
    "mirai_x64_xored",
    "mirai_i386_xored",
    "aarch64_static_xored",
    "pe_export_label_test_xored",
]

MAGIC_SEEDS = [
    b"MZ" + b"\x00" * 62,
    b"\x7fELF\x02\x01\x01" + b"\x00" * 57,
    b"\x7fELF\x01\x01\x01" + b"\x00" * 57,
    b"\xcf\xfa\xed\xfe" + b"\x00" * 60,
    b"\xce\xfa\xed\xfe" + b"\x00" * 60,
    b"dex\n035\x00" + b"\x00" * 104,
]

# Fixture used to produce a realistic report-JSON seed; smallest of the set.
REPORT_SEED_FIXTURE = "bashlite_xored"

# Selector-byte counts consumed by the parameter-carrying targets.
SELECTOR_BYTES = {"binary": 0, "formats": 1, "buffer": 4}


def decode_fixture(path):
    data = path.read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _write(corpus_dir, name, payload):
    (corpus_dir / name).write_bytes(payload)


def _binary_seeds(head_size):
    seeds = []
    missing = []
    for fixture_name in FIXTURE_SEEDS:
        fixture_path = TESTS_DIR / fixture_name
        if not fixture_path.is_file():
            missing.append(fixture_name)
            continue
        seeds.append((f"{fixture_name}_head", decode_fixture(fixture_path)[:head_size]))
    if missing:
        raise SystemExit(f"missing fixtures, corpus would be degraded: {', '.join(missing)}")
    for payload in MAGIC_SEEDS:
        seeds.append((f"magic_{hashlib.sha256(payload).hexdigest()[:16]}", payload))
    return seeds


def _prefixed_seeds(seeds, selector_count):
    """Emit one variant per selector value so every backend/loader gets a seed."""
    if not selector_count:
        return seeds
    prefixed = []
    for selector in range(6):
        prefix = bytes([selector]) + bytes(selector_count - 1)
        for name, payload in seeds:
            prefixed.append((f"sel{selector}_{name}", prefix + payload))
    return prefixed


def _report_seeds():
    """Disassemble one fixture and dump the report as JSON.

    A hand-written skeleton would only reach the first few field lookups in
    fromDict(); a real report reaches the function/block/instruction rebuild.
    """
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig

    fixture_path = TESTS_DIR / REPORT_SEED_FIXTURE
    if not fixture_path.is_file():
        raise SystemExit(f"missing fixture for report seed: {REPORT_SEED_FIXTURE}")
    config = SmdaConfig()
    config.TIMEOUT = 60
    report = Disassembler(config).disassembleUnmappedBuffer(decode_fixture(fixture_path))
    if report is None or report.status == "error":
        raise SystemExit("could not produce a report seed from the fixture")
    payload = json.dumps(report.toDict()).encode()
    return [("report_full", payload), ("report_minimal", json.dumps({"architecture": "intel"}).encode())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_dir", nargs="?", default="corpus", type=Path)
    parser.add_argument("--profile", choices=(*SELECTOR_BYTES, "report"), default="binary")
    parser.add_argument("--head-size", type=int, default=8192)
    args = parser.parse_args()

    args.corpus_dir.mkdir(parents=True, exist_ok=True)
    if args.profile == "report":
        seeds = _report_seeds()
    else:
        seeds = _prefixed_seeds(_binary_seeds(args.head_size), SELECTOR_BYTES[args.profile])
    for name, payload in seeds:
        _write(args.corpus_dir, name, payload)
    print(f"wrote {len(seeds)} {args.profile} seeds to {args.corpus_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
