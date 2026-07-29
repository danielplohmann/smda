import hashlib
import sys
from pathlib import Path

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


def decode_fixture(path):
    data = path.read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def main():
    corpus_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus")
    head_size = int(sys.argv[2]) if len(sys.argv) > 2 else 8192
    corpus_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = Path(__file__).resolve().parent.parent / "tests"
    written = 0
    for fixture_name in FIXTURE_SEEDS:
        fixture_path = tests_dir / fixture_name
        if not fixture_path.is_file():
            continue
        seed = decode_fixture(fixture_path)[:head_size]
        (corpus_dir / f"{fixture_name}_head").write_bytes(seed)
        written += 1
    for seed in MAGIC_SEEDS:
        digest = hashlib.sha256(seed).hexdigest()[:16]
        (corpus_dir / f"magic_{digest}").write_bytes(seed)
        written += 1
    print(f"wrote {written} seeds to {corpus_dir}")


if __name__ == "__main__":
    main()
