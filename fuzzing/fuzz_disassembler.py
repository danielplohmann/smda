"""Fuzz entry point for the disassembler target; body lives in targets.py."""

from harness import run

if __name__ == "__main__":
    run("disassembler")
