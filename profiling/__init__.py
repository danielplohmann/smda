"""SMDA profiling toolkit (CPU + memory).

Dual-use: run locally for cProfile/line_profiler/memray, or in CI (Linux) for
py-spy/memray native flamegraphs. See profiling/README.md.

This package only adds a *profiling* layer. Benchmarking and base-vs-PR
regression comparison already live in .github/workflows/scripts/ and are reused
as-is.
"""
