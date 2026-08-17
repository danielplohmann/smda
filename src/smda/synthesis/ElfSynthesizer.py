import struct

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.SmdaReport import MAX_ADDRESS_VALUE
from smda.SmdaConfig import SmdaConfig
from smda.synthesis.BinarySynthesizer import BinarySynthesizer, align_down, align_up

PT_LOAD = 1
PT_DYNAMIC = 2

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19

ET_EXEC = 2

EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183

R_386_JUMP_SLOT = 7
R_X86_64_JUMP_SLOT = 7
R_AARCH64_JUMP_SLOT = 1026

STB_GLOBAL_STT_FUNC = 0x12

EXEC_SECTION_NAMES = {".text", ".init", ".fini", ".plt", ".plt.got", ".plt.sec"}
WRITE_SECTION_NAMES = {
    ".data",
    ".bss",
    ".got",
    ".got.plt",
    ".data.rel.ro",
    ".ctors",
    ".dtors",
    ".dynamic",
    ".tdata",
    ".tbss",
    ".sbss",
    ".sdata",
}
NOBITS_SECTION_NAMES = {".bss", ".tbss", ".sbss"}

PAGE_SIZE = 0x1000
# how far above the image base the first segment may sit before we stop reserving the gap
# for the header. A real header region is a few pages; a report claiming megabytes of empty
# space below its first section would otherwise pad the file out by that much.
MAX_BASE_PROLOGUE = 0x100000


class ElfSynthesizer(BinarySynthesizer):
    """Rebuilds an ELF file from an SmdaReport.

    Section layout comes from the report's code_sections (name/VA ranges);
    program headers are rebuilt around them. Imports are fused into synthetic
    .dynsym/.dynstr/.rela(dyn)/.dynamic tables so analysis tools resolve named
    imports at their original relocation slot addresses. Reports without
    sections (headerless buffers) get a minimal single-segment ELF.
    """

    def synthesize(self, function_offsets=None, with_imports=True, with_strings=True) -> bytes:
        offsets = self._resolveFunctionOffsets(function_offsets)
        if not offsets:
            raise ValueError("synthesis requires at least one function in the report")
        try:
            sections = self._collectSections()
            if not sections:
                return self._synthesizeMinimal(offsets)
            return self._synthesizeFromSections(sections, offsets, with_imports, with_strings)
        except Exception as exc:
            reraise_non_operational_exception(exc)
            self._warn("ELF synthesis from sections failed (%s), falling back to minimal layout", exc)
            return self._synthesizeMinimal(offsets)

    def _getBitness(self):
        return 64 if self.report.bitness == 64 else 32

    def _hasElfHeader(self, min_length):
        """True only when the stored header is long enough AND is itself an ELF header.

        A report keeps the header of the binary it came from, whatever format that was, so
        reading these fields off a PE or Mach-O header yields whatever those bytes happen to
        hold -- an e_type of 0xb8, say, which is not a defined ELF type at all.
        """
        return self._hasHeader(min_length) and bytes(self.report.xheader[0:4]) == b"\x7fELF"

    def _getMachine(self):
        if self._hasElfHeader(0x14):
            machine = struct.unpack("<H", self.report.xheader[0x12:0x14])[0]
            if machine:
                return machine
        if self.report.architecture == "aarch64":
            return EM_AARCH64
        return EM_X86_64 if self._getBitness() == 64 else EM_386

    def _getJumpSlotType(self):
        machine = self._getMachine()
        if machine == EM_AARCH64:
            return R_AARCH64_JUMP_SLOT
        return R_X86_64_JUMP_SLOT if self._getBitness() == 64 else R_386_JUMP_SLOT

    def _collectSections(self):
        sections = []
        # only named sections reach the section header table, and a serialized report carries
        # no section names at all - without a fabricated name the file would describe its
        # PT_LOADs with no sections, which re-loads with base 0
        taken = {name for name, _, _ in self.report.code_sections or [] if name}
        index = 0
        for name, start, end in sorted(self.report.code_sections or [], key=lambda entry: entry[1]):
            if not start or not end or end <= start:
                continue
            if end - start > SmdaConfig.MAX_IMAGE_SIZE:
                # the extents come from the report, and the span is what gets allocated: a
                # section claiming 0x13DAF6E5B0 bytes asked for 10GB from a 611-byte report
                self._warn("synthesis: dropping section spanning 0x%x bytes", end - start)
                continue
            if not name:
                while f".smda{index}" in taken:
                    index += 1
                name = f".smda{index}"
                taken.add(name)
            sections.append({"name": name, "va_start": start, "va_end": end})
        return sections

    def _classifySection(self, section, function_offsets):
        name = section["name"].lower()
        contains_code = any(section["va_start"] <= offset < section["va_end"] for offset in function_offsets)
        executable = contains_code or name in EXEC_SECTION_NAMES
        writable = not executable and name in WRITE_SECTION_NAMES
        return executable, writable

    def _prepareSections(self, sections, offsets, with_strings):
        for section in sections:
            executable, writable = self._classifySection(section, offsets)
            section["executable"] = executable
            section["writable"] = writable
            section["nobits"] = section["name"].lower() in NOBITS_SECTION_NAMES and not executable
            size = section["va_end"] - section["va_start"]
            if section["nobits"]:
                section["raw"] = bytearray()
            elif executable:
                section["raw"] = bytearray(self._nopFill(size))
            else:
                section["raw"] = bytearray(size)

        uncovered = [
            offset
            for offset in offsets
            if not any(section["va_start"] <= offset < section["va_end"] for section in sections)
        ]
        if uncovered:
            self._warn("%d functions are outside all known sections, adding synthetic .smda section", len(uncovered))
            va_start, va_end = self._syntheticSpan(uncovered, PAGE_SIZE)
            sections.append(
                {
                    "name": ".smda",
                    "va_start": va_start,
                    "va_end": va_end,
                    "executable": True,
                    "writable": False,
                    "nobits": False,
                    "raw": bytearray(self._nopFill(va_end - va_start)),
                }
            )
            sections.sort(key=lambda section: section["va_start"])

        self._plantFunctionChunks(sections, offsets)

        if with_strings:
            for data_addr, content in self._iterStringRefs():
                for section in sections:
                    if (
                        not section["executable"]
                        and not section["nobits"]
                        and section["va_start"] <= data_addr
                        and data_addr + len(content) <= section["va_end"]
                    ):
                        start = data_addr - section["va_start"]
                        section["raw"][start : start + len(content)] = content
                        break
        return sections

    def _buildImportTables(self, import_map, sections, bitness):
        """Builds synthetic .dynstr/.dynsym/.rela(dyn)/.dynamic sections for the imports."""
        is_64 = bitness == 64
        names = sorted({name for _, name in import_map.values()})
        dynstr = bytearray(b"\x00")
        name_offsets = {}
        for name in names:
            name_offsets[name] = len(dynstr)
            dynstr += name.encode("ascii", errors="replace") + b"\x00"

        libs = sorted({lib for lib, _ in import_map.values() if lib})
        lib_offsets = {}
        for lib in libs:
            lib_offsets[lib] = len(dynstr)
            dynstr += lib.encode("ascii", errors="replace") + b"\x00"

        sym_indices = {name: index + 1 for index, name in enumerate(names)}
        dynsym = bytearray(24 if is_64 else 16)
        for name in names:
            if is_64:
                dynsym += struct.pack("<IBBHQQ", name_offsets[name], STB_GLOBAL_STT_FUNC, 0, 0, 0, 0)
            else:
                dynsym += struct.pack("<IIIBBH", name_offsets[name], 0, 0, STB_GLOBAL_STT_FUNC, 0, 0)

        jump_slot = self._getJumpSlotType()
        relocs = bytearray()
        for slot_va, (_, name) in sorted(import_map.items()):
            sym_index = sym_indices[name]
            if is_64:
                relocs += struct.pack("<QQq", slot_va, (sym_index << 32) | jump_slot, 0)
            else:
                relocs += struct.pack("<II", slot_va, (sym_index << 8) | jump_slot)

        dynamic_entries = [(DT_NEEDED, lib_offsets[lib]) for lib in libs]
        va_cursor = align_up(max(section["va_end"] for section in sections), PAGE_SIZE)
        dynstr_va = va_cursor
        va_cursor += align_up(len(dynstr), 16)
        dynsym_va = va_cursor
        va_cursor += align_up(len(dynsym), 16)
        relocs_va = va_cursor
        va_cursor += align_up(len(relocs), 16)
        dynamic_va = va_cursor

        rel_ent = 24 if is_64 else 8
        dynamic_entries += [
            (DT_STRTAB, dynstr_va),
            (DT_SYMTAB, dynsym_va),
            (DT_STRSZ, len(dynstr)),
            (DT_SYMENT, 24 if is_64 else 16),
            (DT_RELA if is_64 else DT_REL, relocs_va),
            (DT_RELASZ if is_64 else DT_RELSZ, len(relocs)),
            (DT_RELAENT if is_64 else DT_RELENT, rel_ent),
            (0, 0),
        ]
        dynamic = bytearray()
        for tag, value in dynamic_entries:
            if is_64:
                dynamic += struct.pack("<qQ", tag, value)
            else:
                dynamic += struct.pack("<iI", tag, value)

        import_sections = [
            (".dynstr", dynstr_va, dynstr, SHT_STRTAB, SHF_ALLOC, None, 0, 1),
            (".dynsym", dynsym_va, dynsym, SHT_DYNSYM, SHF_ALLOC, ".dynstr", 1, 24 if is_64 else 16),
            (
                ".rela.dyn" if is_64 else ".rel.dyn",
                relocs_va,
                relocs,
                SHT_RELA if is_64 else SHT_REL,
                SHF_ALLOC,
                ".dynsym",
                0,
                rel_ent,
            ),
            (".dynamic", dynamic_va, dynamic, SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, ".dynstr", 0, 16 if is_64 else 8),
        ]
        for name, va, raw, shtype, flags, shlink_name, shinfo, entsize in import_sections:
            sections.append(
                {
                    "name": name,
                    "va_start": va,
                    "va_end": va + len(raw),
                    "executable": False,
                    "writable": bool(flags & SHF_WRITE),
                    "nobits": False,
                    "raw": bytearray(raw),
                    "shtype": shtype,
                    "shlink_name": shlink_name,
                    "shinfo": shinfo,
                    "entsize": entsize,
                }
            )
        sections.sort(key=lambda section: section["va_start"])
        return dynamic_va, len(dynamic)

    def _mergeSegments(self, sections):
        """Merges same-permission sections living on the same/adjacent page into PT_LOAD
        segments. Segment starts are exact section VAs (no page align-down) so segments
        with different permissions never claim each other's bytes."""
        segments = []
        for section in sections:
            if section["nobits"] or not section["raw"]:
                continue
            flags = 4 | (1 if section["executable"] else 0) | (2 if section["writable"] else 0)
            if (
                segments
                and segments[-1]["flags"] == flags
                and section["va_start"] <= align_up(segments[-1]["va_end"], PAGE_SIZE)
            ):
                segments[-1]["sections"].append(section)
                segments[-1]["va_end"] = max(segments[-1]["va_end"], section["va_end"])
            else:
                segments.append(
                    {
                        "flags": flags,
                        "va_start": section["va_start"],
                        "va_end": section["va_end"],
                        "sections": [section],
                    }
                )
        return segments

    def _assembleFile(self, sections, segments, bitness, dynamic_range=None):
        is_64 = bitness == 64
        ehdr_size = 64 if is_64 else 52
        phent_size = 56 if is_64 else 32
        shent_size = 64 if is_64 else 40
        phnum = len(segments) + (1 if dynamic_range else 0)
        # readers derive the image base from min(sh_addr - sh_offset), so a segment must take
        # the LOWEST page-congruent file offset that still clears what precedes it. Only the
        # ELF header does: the program header table goes to the end of the file, where its
        # size cannot push the first segment a page further down than its own VA allows.
        file_cursor = ehdr_size
        # ...and the base the readers should arrive at is the one the report recorded, which
        # means reserving the gap between it and the first segment rather than anchoring on
        # that segment's own page. The two agree only when the first content happens to start
        # a whole number of pages above the base; where it does not - a Mach-O __TEXT at
        # base + 0x12b0 - anchoring on its page reports a base one page high. Reserving here
        # puts the header at the base exactly as __TEXT does for the Mach-O path.
        base_addr = self.report.base_addr or 0
        if segments and not base_addr % PAGE_SIZE:
            prologue = segments[0]["va_start"] - base_addr
            if ehdr_size <= prologue <= MAX_BASE_PROLOGUE:
                file_cursor = prologue

        for segment in segments:
            file_off = align_down(file_cursor, PAGE_SIZE) + segment["va_start"] % PAGE_SIZE
            if file_off < file_cursor:
                file_off += PAGE_SIZE
            segment["file_off"] = file_off
            segment["raw"] = bytearray(segment["va_end"] - segment["va_start"])
            for section in segment["sections"]:
                start = section["va_start"] - segment["va_start"]
                segment["raw"][start : start + len(section["raw"])] = section["raw"]
                section["file_off"] = file_off + start
            file_cursor = file_off + len(segment["raw"])

        file_cursor = align_up(file_cursor, 8)
        phoff = file_cursor
        file_cursor += phnum * phent_size

        shstrtab = bytearray(b"\x00")
        shstr_offsets = {}
        named_sections = [section for section in sections if section["name"]]
        for section in named_sections:
            shstr_offsets[section["name"]] = len(shstrtab)
            shstrtab += section["name"].encode("ascii", errors="replace") + b"\x00"
        shstrtab += b".shstrtab\x00"
        shstrtab_name_offset = len(shstrtab) - len(b".shstrtab\x00")

        file_cursor = align_up(file_cursor, 16)
        shstrtab_off = file_cursor
        file_cursor += len(shstrtab)
        file_cursor = align_up(file_cursor, 8)
        shoff = file_cursor
        file_cursor += (len(named_sections) + 2) * shent_size

        ehdr = bytearray(ehdr_size)
        ehdr[0:4] = b"\x7fELF"
        ehdr[4] = 2 if is_64 else 1
        ehdr[5] = 1
        ehdr[6] = 1
        if self._hasElfHeader(16):
            ehdr[7:16] = self.report.xheader[7:16]
        e_type = struct.unpack("<H", self.report.xheader[16:18])[0] if self._hasElfHeader(18) else ET_EXEC
        machine = self._getMachine()
        entry = 0
        if self.report.oep:
            entry = (
                self.report.oep if self.report.oep >= self.report.base_addr else self.report.base_addr + self.report.oep
            )
        else:
            entry = min((s["va_start"] for s in sections if s["executable"]), default=0)
        if not 0 <= entry < MAX_ADDRESS_VALUE:
            raise ValueError(f"synthesized entry point 0x{entry:x} does not fit a 64-bit address space")
        if is_64:
            struct.pack_into(
                "<HHIQQQIHHHHHH",
                ehdr,
                16,
                e_type,
                machine,
                1,
                entry,
                phoff,
                shoff,
                0,
                ehdr_size,
                phent_size,
                phnum,
                shent_size,
                len(named_sections) + 2,
                len(named_sections) + 1,
            )
        else:
            struct.pack_into(
                "<HHIIIIIHHHHHH",
                ehdr,
                16,
                e_type,
                machine,
                1,
                entry & 0xFFFFFFFF,
                phoff,
                shoff,
                0,
                ehdr_size,
                phent_size,
                phnum,
                shent_size,
                len(named_sections) + 2,
                len(named_sections) + 1,
            )

        program_headers = bytearray()
        for segment in segments:
            flags = segment["flags"]
            filesz = len(segment["raw"])
            memsz = segment["va_end"] - segment["va_start"]
            if is_64:
                phdr = struct.pack(
                    "<IIQQQQQQ",
                    PT_LOAD,
                    flags,
                    segment["file_off"],
                    segment["va_start"],
                    segment["va_start"],
                    filesz,
                    memsz,
                    PAGE_SIZE,
                )
            else:
                phdr = struct.pack(
                    "<IIIIIIII",
                    PT_LOAD,
                    segment["file_off"],
                    segment["va_start"],
                    segment["va_start"],
                    filesz,
                    memsz,
                    flags,
                    PAGE_SIZE,
                )
            program_headers += phdr
        if dynamic_range:
            dynamic_va, dynamic_size = dynamic_range
            dynamic_section = next(s for s in sections if s["name"] == ".dynamic")
            if is_64:
                program_headers += struct.pack(
                    "<IIQQQQQQ",
                    PT_DYNAMIC,
                    6,
                    dynamic_section["file_off"],
                    dynamic_va,
                    dynamic_va,
                    dynamic_size,
                    dynamic_size,
                    8,
                )
            else:
                program_headers += struct.pack(
                    "<IIIIIIII",
                    PT_DYNAMIC,
                    dynamic_section["file_off"],
                    dynamic_va,
                    dynamic_va,
                    dynamic_size,
                    dynamic_size,
                    6,
                    4,
                )

        output = bytearray(ehdr)
        for segment in segments:
            output += b"\x00" * (segment["file_off"] - len(output))
            output += segment["raw"]
        output += b"\x00" * (phoff - len(output))
        output += program_headers
        output += b"\x00" * (shstrtab_off - len(output))
        output += shstrtab
        output += b"\x00" * (shoff - len(output))

        output += b"\x00" * shent_size
        shndx_by_name = {section["name"]: index + 1 for index, section in enumerate(named_sections)}
        for section in named_sections:
            sh_type = section.get("shtype", SHT_NOBITS if section["nobits"] else SHT_PROGBITS)
            sh_flags = (
                SHF_ALLOC | (SHF_EXECINSTR if section["executable"] else 0) | (SHF_WRITE if section["writable"] else 0)
            )
            sh_offset = 0 if section["nobits"] else section.get("file_off", 0)
            sh_size = section["va_end"] - section["va_start"] if section["nobits"] else len(section["raw"])
            entsize = section.get("entsize", 0)
            sh_link = shndx_by_name.get(section.get("shlink_name"), 0)
            sh_info = section.get("shinfo", 0)
            if is_64:
                output += struct.pack(
                    "<IIQQQQIIQQ",
                    shstr_offsets[section["name"]],
                    sh_type,
                    sh_flags,
                    section["va_start"],
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    16,
                    entsize,
                )
            else:
                output += struct.pack(
                    "<IIIIIIIIII",
                    shstr_offsets[section["name"]],
                    sh_type,
                    sh_flags,
                    section["va_start"],
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    16,
                    entsize,
                )
        if is_64:
            output += struct.pack(
                "<IIQQQQIIQQ", shstrtab_name_offset, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0
            )
        else:
            output += struct.pack(
                "<IIIIIIIIII", shstrtab_name_offset, SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0
            )
        return bytes(output)

    def _synthesizeFromSections(self, sections, offsets, with_imports, with_strings):
        bitness = self._getBitness()
        sections = self._prepareSections(sections, offsets, with_strings)
        import_map = self._getImportMap() if with_imports else {}
        dynamic_range = None
        if import_map:
            dynamic_range = self._buildImportTables(import_map, sections, bitness)
        segments = self._mergeSegments(sections)
        return self._assembleFile(sections, segments, bitness, dynamic_range)

    def _synthesizeMinimal(self, offsets):
        bitness = self._getBitness()
        va_start, va_end = self._syntheticSpan(offsets, PAGE_SIZE)
        section = {
            "name": ".text",
            "va_start": va_start,
            "va_end": va_end,
            "executable": True,
            "writable": False,
            "nobits": False,
            "raw": bytearray(self._nopFill(va_end - va_start)),
        }
        for offset in offsets:
            for block_offset, chunk in self._iterFunctionChunks(self.report.xcfg[offset]):
                start = block_offset - va_start
                # va_start derives from function entries only, so a block below its own entry
                # yields a negative start that would wrap to the end of the bytearray, and an
                # over-long chunk would grow it - desynchronizing va_end from len(raw).
                # Every other planting site in the repo has this containment check.
                if start < 0 or start + len(chunk) > len(section["raw"]):
                    continue
                section["raw"][start : start + len(chunk)] = chunk
        segments = self._mergeSegments([section])
        return self._assembleFile([section], segments, bitness)
