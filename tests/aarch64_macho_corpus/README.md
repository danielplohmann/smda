# AArch64 Mach-O Corpus Fixtures

Curated XOR-obfuscated AArch64 Mach-O malware samples for loader and disassembly
regression tests. Fixtures are grouped by upstream source:

- `objective-see/` — samples from [Objective-See/Malware](https://github.com/objective-see/Malware)
- `malpedia/` — samples from [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)

## Safety

- Do not execute fixture contents.
- De-XOR only in memory during tests.
- Never write raw sample bytes back to disk.

## Layout

```text
aarch64_macho_corpus/
  manifest.json
  objective-see/*.xored
  malpedia/*.xored
```

`manifest.json` records upstream commits in `sources`, per-fixture hashes and
expectations in `fixtures`, and source-specific metadata under each fixture's
`provenance` object.

## Adding a fixture

1. XOR-obfuscate the raw Mach-O with `byte ^ (index % 256)`.
2. Place the `.xored` file in the correct source subdirectory.
3. Append a fixture entry to `manifest.json` with `id`, `source`, `path`,
   hashes, `feature_tags`, and `provenance`.
4. Run `pytest tests/testAArch64MachoCorpus.py -q`.
