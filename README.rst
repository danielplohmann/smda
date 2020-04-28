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

To take full advantage of SMDA's capabilities, optionally install:
* lief 
* pdbparse (currently as fork from https://github.com/VPaulV/pdbparse to support Python3)

Version History
---------------
 * 2020-04-28: several 
 * 2020-03-10: Various minor fixes and QoL improvements.
 * 2019-08-20: IdaExporter is now handling failed instruction conversion via capstone properly.
 * 2019-08-19: Minor fix for crashes caused by PDB parser.
 * 2019-08-05: SMDA can now export reports from IDA Pro (requires capstone to be available for idapython).
 * 2019-06-13: PDB symbols for functions are now resolved if given a PDB file using parameter "-d" (THX to @VPaulV).
 * 2019-05-15: Fixed a bug in PE mapper where buffer would be shortened because of misinterpretation of section sizes.
 * 2019-01-28: ELF symbols for functions are now resolved, if present in the file. Also "-m" parameter changed to "-p" to imply parsing instead of just mapping (THX: @VPaulV).
 * 2018-12-12: all gcc jump table styles are now parsed correctly. 
 * 2018-11-26: Better handling of multibyte NOPs, ELF loader now provides base addr.
 * 2018-09-28: We now have functional PE/ELF loaders.
 * 2018-07-09: Performance improvements.
 * 2018-07-01: Initial Release.


Credits
=======

Thanks to Steffen Enders for his extensive contributions to this project.
Thanks to Paul Hordiienko for adding symbol parsing support (ELF PDB).

Pull requests welcome! :)
