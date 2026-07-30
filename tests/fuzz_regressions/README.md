# Pinned fuzz crash reproducers

Crash, OOM, and timeout artifacts found by the `Fuzzing` workflow are committed
here so the defect they found can never regress silently.

Rules:

- Store the artifact XOR-obfuscated with the repository fixture scheme
  (`byte ^ (index % 256)`), never as a raw sample.
- Name it `<target>_<short-slug>_xored`, where `<target>` is one of the keys in
  `fuzzing/targets.py` (`loaders`, `formats`, `disassembler`, `buffer`,
  `report`) — `tests/testFuzzRegressions.py` dispatches on that prefix.
- Keep it minimized (`python fuzzing/minimize.py <target> <artifact>`) and small;
  these run on every test invocation.

To reproduce one locally, no atheris required:

```
python fuzzing/replay.py loaders tests/fuzz_regressions/loaders_example_xored
```
