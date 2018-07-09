SMDA
====

SMDA is a minimalist recursive disassembler library that is optimized for accurate Control Flow Graph (CFG) recovery from memory dumps.
It is based on Capstone (http://www.capstone-engine.org/) and currently supports x86/x64 Intel machine code.
As input, arbitrary memory dumps (ideally with known base address) can be processed.
The output is a collection of functions, basic blocks, and instructions with their respective edges between blocks and functions (in/out).
Optionally, references to the Windows API can be inferred by using the ApiScout method.

To get an impression how to work with the library, check the demo script:

* analyze.py -- example usage: perform disassembly and optionally store results in JSON to a given output path.

The code should be fully compatible with Python 2 and 3.
Further explanation on the innerworkings follow in separate publications but will be referenced here.

Version History
---------------

 * 2018-07-09: Performance improvements.
 * 2018-07-01: Initial Release.


Credits
=======

Thanks to Steffen Enders for his extensive contributions to this project.

Pull requests welcome! :)
