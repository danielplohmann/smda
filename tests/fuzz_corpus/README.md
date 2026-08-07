# Committed fuzz corpus floor

One directory per fuzz target, holding a small pruned set of inputs that every fuzzing
run starts from. The accumulating corpus lives in the GitHub Actions cache, which
evicts after 7 days without a hit — without this floor a quiet fortnight would reset
coverage progress to whatever `generate_seeds.py` produces at that moment.

Entries are stored XOR-obfuscated with `byte ^ (index % 256)`, the same scheme as the
malware fixtures under `tests/`. Most of these inputs are derived from those samples and
must be inert at rest. **Never execute them.**

Restore them into a working corpus directory with:

```bash
python fuzzing/restore_corpus.py report corpus
```

`tests/testFuzzCorpus.py` asserts the floor stays obfuscated, replays every entry
through its target, and is what keeps this directory honest. Real reproducers from a
triaged finding belong in `tests/fuzz_regressions/`, not here.
