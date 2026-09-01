import struct
from typing import Any, Dict, List

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.SmdaConfig import SmdaConfig
from smda.synthesis.BinarySynthesizer import BinarySynthesizer, align_down, align_up

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE

MH_EXECUTE = 2
MH_DYLDLINK = 0x4
MH_TWOLEVEL = 0x80
MH_PIE = 0x200000

CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028

SECTION_TYPE_MASK = 0x000000FF
S_ZEROFILL = 0x1
S_CSTRING_LITERALS = 0x2
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

INDIRECT_SYMBOL_LOCAL = 0x80000000

N_UNDF_EXT = 0x01

VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

PAGE_SIZE = 0x1000

DATA_SECTION_NAMES = {
    "__data",
    "__got",
    "__la_symbol_ptr",
    "__nl_symbol_ptr",
    "__bss",
    "__common",
    "__mod_init_func",
    "__mod_term_func",
    "__objc_data",
    "__objc_selrefs",
    "__objc_classlist",
    "__objc_classrefs",
    "__objc_protolist",
    "__objc_imageinfo",
    "__objc_protorefs",
    "__objc_superrefs",
    "__objc_catlist",
    "__objc_nlclslist",
    "__objc_nlcatlist",
    "__cfstring",
}

POINTER_SECTION_NAMES = {"__la_symbol_ptr", "__nl_symbol_ptr", "__got"}
STUBS_SECTION_NAMES = {"__stubs", "__objc_stubs"}
ZEROFILL_SECTION_NAMES = {"__bss", "__common"}


class MachoSynthesizer(BinarySynthesizer):
    """Rebuilds a thin Mach-O file from an SmdaReport.

    When the report carries an xheader, the original load commands are parsed and
    section-to-segment assignment, section flags, and segment bounds are reused
    verbatim (only file offsets are relaid out). Without an xheader, sections are
    grouped into __TEXT (r-x)/__DATA (rw-) runs by name heuristics. Imports are
    wired through LC_SYMTAB (undefined symbols), LC_DYSYMTAB plus an indirect
    symbol table (stubs and symbol-pointer sections), and LC_LOAD_DYLIB entries.
    Reports without sections (headerless buffers) get a minimal one-segment Mach-O.
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
            self._warn("Mach-O synthesis from sections failed (%s), falling back to minimal layout", exc)
            return self._synthesizeMinimal(offsets)

    def _hasMachoHeader(self, min_length):
        """True only when the stored header is long enough AND is itself a Mach-O header.

        A report keeps the header of the binary it came from, whatever format that was, so
        reading these fields off a PE or ELF header yields whatever those bytes happen to hold.
        """
        if not self._hasHeader(min_length):
            return False
        magic = struct.unpack("<I", self.report.xheader[0:4])[0]
        return magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64)

    def _is64(self):
        if self._hasMachoHeader(4):
            magic = struct.unpack("<I", self.report.xheader[0:4])[0]
            return magic in (MH_MAGIC_64, MH_CIGAM_64)
        return self.report.bitness != 32

    def _getCpuType(self):
        if self._hasMachoHeader(8):
            cpu_type = struct.unpack("<I", self.report.xheader[4:8])[0]
            if cpu_type:
                return cpu_type
        if self.report.architecture == "aarch64":
            return CPU_TYPE_ARM64
        return CPU_TYPE_X86_64 if self._is64() else CPU_TYPE_I386

    def _getCpuSubtype(self):
        if self._hasMachoHeader(12):
            return struct.unpack("<I", self.report.xheader[8:12])[0]
        return 0

    def _getFiletype(self):
        if self._hasMachoHeader(16):
            return struct.unpack("<I", self.report.xheader[12:16])[0]
        return MH_EXECUTE

    def _collectSections(self):
        sections = []
        for name, start, end in sorted(self.report.code_sections or [], key=lambda entry: entry[1]):
            if not start or not end or end <= start:
                continue
            if end - start > SmdaConfig.MAX_IMAGE_SIZE:
                # the extents come from the report, and the span is what gets allocated: a
                # section claiming 0x13DAF6E5B0 bytes asked for 10GB from a 611-byte report
                self._warn("synthesis: dropping section spanning 0x%x bytes", end - start)
                continue
            sections.append({"name": name or "", "va_start": start, "va_end": end})
        return sections

    def _parseXheaderLayout(self):
        """Parses LC_SEGMENT(_64) commands from the stored xheader.

        Returns (segments, section_metas) where segments keeps the original
        vmaddr/vmsize/perms and section_metas maps section VA to its original
        segname/flags/stub size. Tolerates an xheader whose trailing zeros were
        trimmed into the last load command. None when unavailable/unparseable.
        """
        if not self._hasHeader(28):
            return None
        magic = struct.unpack("<I", self.report.xheader[0:4])[0]
        if magic in (MH_MAGIC_64, MH_CIGAM_64):
            is_64 = True
        elif magic in (MH_MAGIC, MH_CIGAM):
            is_64 = False
        else:
            return None
        header_size = 32 if is_64 else 28
        ncmds = struct.unpack("<I", self.report.xheader[16:20])[0]
        data = self.report.xheader
        segments = []
        section_metas = {}
        pos = header_size
        for _ in range(min(ncmds, 1024)):
            if pos + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack("<II", data[pos : pos + 8])
            if cmdsize < 8:
                break
            is_segment = (is_64 and cmd == LC_SEGMENT_64) or (not is_64 and cmd == LC_SEGMENT)
            if is_segment:
                seg_fixed = 72 if is_64 else 56
                sec_size = 80 if is_64 else 68
                if pos + seg_fixed <= len(data):
                    segname = data[pos + 8 : pos + 24].rstrip(b"\x00").decode("ascii", errors="replace")
                    if is_64:
                        vmaddr, vmsize, _, _, _, initprot, nsects, _ = struct.unpack(
                            "<QQQQiiII", data[pos + 24 : pos + 72]
                        )
                    else:
                        vmaddr, vmsize, _, _, _, initprot, nsects, _ = struct.unpack(
                            "<IIIIiiII", data[pos + 24 : pos + 56]
                        )
                    segments.append(
                        {"name": segname, "vmaddr": vmaddr, "vmsize": vmsize, "perms": initprot & 0xFF, "sections": []}
                    )
                    sec_pos = pos + seg_fixed
                    for _ in range(min(nsects, 4096)):
                        if sec_pos + sec_size > len(data):
                            break
                        sectname = data[sec_pos : sec_pos + 16].rstrip(b"\x00").decode("ascii", errors="replace")
                        if is_64:
                            addr, size = struct.unpack("<QQ", data[sec_pos + 32 : sec_pos + 48])
                            flags, reserved1, reserved2 = struct.unpack("<III", data[sec_pos + 64 : sec_pos + 76])
                        else:
                            addr, size = struct.unpack("<II", data[sec_pos + 32 : sec_pos + 40])
                            flags, reserved1, reserved2 = struct.unpack("<III", data[sec_pos + 56 : sec_pos + 68])
                        section_metas[addr] = {
                            "segname": segname,
                            "sectname": sectname,
                            "flags": flags,
                            "stub_size": reserved2,
                            "size": size,
                        }
                        if segments:
                            segments[-1]["sections"].append(addr)
                        sec_pos += sec_size
            pos += cmdsize
        if not segments or not section_metas:
            return None
        return segments, section_metas

    def _applyXheaderLayout(self, sections, layout):
        """Transfers original segment membership and section flags onto report sections.
        Section VAs may be shifted (fat-slice/base adjustment); a constant delta is
        derived from matching addresses."""
        segments, section_metas = layout
        rep_addrs = sorted(section["va_start"] for section in sections)
        xh_addrs = sorted(section_metas.keys())
        adjustment = rep_addrs[0] - xh_addrs[0]
        matched = 0
        for section in sections:
            meta = section_metas.get(section["va_start"] - adjustment)
            if meta is None or (meta["sectname"] and section["name"] and meta["sectname"] != section["name"]):
                continue
            matched += 1
            section["segment"] = meta["segname"] or "__TEXT"
            section["flags"] = meta["flags"]
            section["stub_size"] = meta["stub_size"]
        if matched < max(1, len(sections) // 2):
            return None
        for segment in segments:
            segment["vmaddr"] += adjustment
        return segments

    def _classifySections(self, sections, offsets):
        """Heuristic fallback: assign segment/flags by section name when no usable
        xheader layout exists."""
        for section in sections:
            name = section["name"].lower()
            contains_code = any(section["va_start"] <= offset < section["va_end"] for offset in offsets)
            executable = contains_code or name in STUBS_SECTION_NAMES or name in ("__text", "__stub_helper")
            if "flags" not in section:
                attrs = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS if executable else 0
                if name in STUBS_SECTION_NAMES:
                    flags = S_SYMBOL_STUBS | attrs
                elif name == "__la_symbol_ptr":
                    flags = S_LAZY_SYMBOL_POINTERS
                elif name in ("__nl_symbol_ptr", "__got"):
                    flags = S_NON_LAZY_SYMBOL_POINTERS
                elif name in ZEROFILL_SECTION_NAMES:
                    flags = S_ZEROFILL
                elif name == "__cstring":
                    flags = S_CSTRING_LITERALS
                else:
                    flags = attrs
                section["flags"] = flags
            if "segment" not in section:
                section["segment"] = "__DATA" if (not executable and name in DATA_SECTION_NAMES) else "__TEXT"

    def _buildSegmentsHeuristic(self, sections):
        """Groups sections into same-class VA runs; sections sharing a page with a
        different class are merged into one segment with unioned permissions."""
        segments: List[Dict[str, Any]] = []
        for section in sections:
            # a section is executable because it holds recovered function bytes, not because
            # of the segment name it was grouped under: code placed anywhere else would
            # otherwise be mapped writable-but-not-executable
            perms = VM_PROT_READ | (VM_PROT_EXECUTE if section["executable"] else VM_PROT_WRITE)
            if segments and (
                segments[-1]["segment"] == section["segment"] or section["va_start"] < segments[-1]["page_end"]
            ):
                segment = segments[-1]
                segment["sections"].append(section)
                segment["perms"] |= perms
                segment["va_end"] = max(segment["va_end"], section["va_end"])
                segment["page_end"] = align_up(segment["va_end"], PAGE_SIZE)
            else:
                segments.append(
                    {
                        "name": section["segment"],
                        "segment": section["segment"],
                        "perms": perms,
                        "va_start": section["va_start"],
                        "va_end": section["va_end"],
                        "page_end": align_up(section["va_end"], PAGE_SIZE),
                        "sections": [section],
                    }
                )
        return segments

    def _buildSegmentsFromLayout(self, sections, layout_segments):
        by_name = {}
        for segment in layout_segments:
            by_name.setdefault(segment["name"], []).append(segment)
            segment["sections"] = []
            segment["va_start"] = segment["vmaddr"]
            segment["va_end"] = segment["vmaddr"] + segment["vmsize"]
            segment["page_end"] = align_up(segment["va_end"], PAGE_SIZE)
        segments = []
        for segment in layout_segments:
            segments.append(segment)
        for section in sections:
            candidates = by_name.get(section["segment"])
            target = None
            if candidates:
                for candidate in candidates:
                    if candidate["va_start"] <= section["va_start"] < candidate["va_end"]:
                        target = candidate
                        break
                if target is None:
                    target = min(candidates, key=lambda candidate: abs(candidate["va_start"] - section["va_start"]))
            if target is None:
                self._warn(
                    "section %s (0x%x) matches no original segment, adding synthetic __SMDA segment",
                    section["name"],
                    section["va_start"],
                )
                target = {
                    "name": "__SMDA",
                    "segment": "__SMDA",
                    "perms": VM_PROT_READ | (VM_PROT_EXECUTE if section["executable"] else VM_PROT_WRITE),
                    "va_start": section["va_start"],
                    "va_end": section["va_end"],
                    "page_end": align_up(section["va_end"], PAGE_SIZE),
                    "sections": [],
                }
                segments.append(target)
                segments.sort(key=lambda segment: segment["va_start"])
            target["sections"].append(section)
        return [segment for segment in segments if segment["sections"]]

    def _prepareSections(self, sections, offsets, with_strings):
        layout = self._parseXheaderLayout()
        layout_segments = self._applyXheaderLayout(sections, layout) if layout else None
        self._classifySections(sections, offsets)

        uncovered = [
            offset
            for offset in offsets
            if not any(section["va_start"] <= offset < section["va_end"] for section in sections)
        ]
        if uncovered:
            self._warn("%d functions are outside all known sections, adding synthetic __smda section", len(uncovered))
            va_start, va_end = self._syntheticSpan(uncovered, PAGE_SIZE)
            sections.append(
                {
                    "name": "__smda",
                    "va_start": va_start,
                    "va_end": va_end,
                    "segment": "__SMDA",
                    "flags": S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                    "stub_size": 0,
                }
            )
            sections.sort(key=lambda section: section["va_start"])

        for section in sections:
            section["executable"] = bool(section["flags"] & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
            section["executable"] = section["executable"] or any(
                section["va_start"] <= offset < section["va_end"] for offset in offsets
            )
            section["zerofill"] = (section["flags"] & SECTION_TYPE_MASK) == S_ZEROFILL and not section["executable"]
            size = section["va_end"] - section["va_start"]
            if section["zerofill"]:
                section["raw"] = bytearray()
            elif section["executable"]:
                section["raw"] = bytearray(self._nopFill(size))
            else:
                section["raw"] = bytearray(size)

        self._plantFunctionChunks(sections, offsets)

        if with_strings:
            for data_addr, content in self._iterStringRefs():
                for section in sections:
                    if (
                        not section["executable"]
                        and not section["zerofill"]
                        and section["va_start"] <= data_addr
                        and data_addr + len(content) <= section["va_end"]
                    ):
                        start = data_addr - section["va_start"]
                        section["raw"][start : start + len(content)] = content
                        break

        if layout_segments is not None:
            return self._buildSegmentsFromLayout(sections, layout_segments)
        return self._buildSegmentsHeuristic(sections)

    @staticmethod
    def _isPointerSection(section):
        section_type = section["flags"] & SECTION_TYPE_MASK
        if section_type in (S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS):
            return True
        return section["name"].lower() in POINTER_SECTION_NAMES

    @staticmethod
    def _isStubsSection(section):
        section_type = section["flags"] & SECTION_TYPE_MASK
        if section_type == S_SYMBOL_STUBS:
            return True
        return section["name"].lower() in STUBS_SECTION_NAMES

    @staticmethod
    def _slotsInSection(section, import_map, ptr_size):
        count = (section["va_end"] - section["va_start"]) // ptr_size
        return [va for va in (section["va_start"] + index * ptr_size for index in range(count)) if va in import_map]

    @staticmethod
    def _findPartnerPointerSection(stubs_section, pointer_sections):
        """Associates a stubs section with the pointer section holding its targets:
        lazy pointer sections win (stubs are lazy by definition), then even
        division of the stubs range, then closest address."""
        best = None
        stubs_size = stubs_section["va_end"] - stubs_section["va_start"]
        for section in pointer_sections:
            count = len(section.get("slots") or [])
            if count == 0:
                continue
            stub_size = stubs_size / count
            is_lazy = (section["flags"] & SECTION_TYPE_MASK) == S_LAZY_SYMBOL_POINTERS
            score = (not is_lazy, stub_size != int(stub_size), abs(section["va_start"] - stubs_section["va_start"]))
            if best is None or score < best[0]:
                best = (score, section)
        return best[1] if best else None

    def _buildImportTables(self, import_map, sections, is_64):
        """Builds string pool, undefined symbol table and indirect symbol table for imports."""
        names = sorted({name for _, name in import_map.values()})
        strtab = bytearray(b"\x00")
        name_offsets = {}
        for name in names:
            name_offsets[name] = len(strtab)
            strtab += name.encode("ascii", errors="replace") + b"\x00"
        sym_indices = {name: index for index, name in enumerate(names)}

        symtab = bytearray()
        for name in names:
            if is_64:
                symtab += struct.pack("<IBBHQ", name_offsets[name], N_UNDF_EXT, 0, 0, 0)
            else:
                symtab += struct.pack("<IBBHI", name_offsets[name], N_UNDF_EXT, 0, 0, 0)

        ptr_size = 8 if is_64 else 4
        pointer_sections = [
            section
            for section in sections
            if section["raw"]
            and not section["executable"]
            and (
                self._isPointerSection(section)
                or any(section["va_start"] <= va < section["va_end"] for va in import_map)
            )
        ]
        for section in pointer_sections:
            if (section["flags"] & SECTION_TYPE_MASK) not in (
                S_LAZY_SYMBOL_POINTERS,
                S_NON_LAZY_SYMBOL_POINTERS,
            ):
                section["flags"] = (section["flags"] & ~SECTION_TYPE_MASK) | S_NON_LAZY_SYMBOL_POINTERS
            section["slots"] = self._slotsInSection(section, import_map, ptr_size)

        stubs_sections = [section for section in sections if self._isStubsSection(section) and section["raw"]]
        indirect = []
        default_stub_size = 12 if self.report.architecture == "aarch64" else 6
        for section in stubs_sections:
            section["indirect_start"] = len(indirect)
            partner = self._findPartnerPointerSection(section, pointer_sections)
            count = len(partner["slots"]) if partner else 0
            if count:
                stub_size = (section["va_end"] - section["va_start"]) // count
            else:
                stub_size = section.get("stub_size") or default_stub_size
                count = (section["va_end"] - section["va_start"]) // stub_size if stub_size else 0
            if not section.get("stub_size"):
                section["stub_size"] = stub_size
            for index in range(count):
                if partner and index < len(partner["slots"]):
                    indirect.append(sym_indices[import_map[partner["slots"][index]][1]])
                else:
                    indirect.append(INDIRECT_SYMBOL_LOCAL)

        for section in pointer_sections:
            section["indirect_start"] = len(indirect)
            count = (section["va_end"] - section["va_start"]) // ptr_size
            for index in range(count):
                slot_va = section["va_start"] + index * ptr_size
                if slot_va in import_map:
                    indirect.append(sym_indices[import_map[slot_va][1]])
                else:
                    indirect.append(INDIRECT_SYMBOL_LOCAL)

        indirect_blob = b"".join(struct.pack("<I", entry) for entry in indirect)
        libs = sorted({lib for lib, _ in import_map.values() if lib})
        return strtab, symtab, indirect_blob, libs, len(indirect)

    def _synthesizeFromSections(self, sections, offsets, with_imports, with_strings) -> bytes:
        is_64 = self._is64()
        segments = self._prepareSections(sections, offsets, with_strings)
        sections = [section for segment in segments for section in segment["sections"]]
        import_map = self._getImportMap() if with_imports else {}

        strtab, symtab, indirect_blob, libs, nindirect = (bytearray(b"\x00"), bytearray(), b"", [], 0)
        if import_map:
            strtab, symtab, indirect_blob, libs, nindirect = self._buildImportTables(import_map, sections, is_64)

        header_size = 32 if is_64 else 28
        load_commands = []

        ncmds = len(segments)
        if import_map:
            ncmds += 2 + len(libs)
        entry_va = None
        if self.report.oep:
            entry_va = (
                self.report.oep if self.report.oep >= self.report.base_addr else self.report.base_addr + self.report.oep
            )
            text_segment = next((segment for segment in segments if segment["perms"] & VM_PROT_EXECUTE), None)
            if text_segment and text_segment["va_start"] <= entry_va < text_segment["page_end"]:
                ncmds += 1
            else:
                entry_va = None

        sizeofcmds = 0
        for segment in segments:
            sizeofcmds += (72 if is_64 else 56) + len(segment["sections"]) * (80 if is_64 else 68)
        if import_map:
            sizeofcmds += 24 + 80
            for lib in libs:
                sizeofcmds += align_up(24 + len(lib.encode("ascii", errors="replace")) + 1, 8)
        if entry_va is not None:
            sizeofcmds += 24

        # __TEXT maps from file offset 0, so the mach header and load commands sit at the image
        # base, ahead of its first section. Readers derive the base from min(vmaddr - fileoff),
        # which lands a page low for every segment when __TEXT starts past the header instead.
        prologue = header_size + sizeofcmds
        first_content = min(
            (section["va_start"] for section in segments[0]["sections"] if not section["zerofill"]),
            default=segments[0]["va_end"],
        )
        file_cursor = 0 if first_content - segments[0]["va_start"] >= prologue else prologue
        for segment in segments:
            file_off = align_down(file_cursor, PAGE_SIZE) + segment["va_start"] % PAGE_SIZE
            if file_off < file_cursor:
                file_off += PAGE_SIZE
            segment["fileoff"] = file_off
            segment["filesize"] = segment["va_end"] - segment["va_start"]
            for section in segment["sections"]:
                section["fileoff"] = file_off + (section["va_start"] - segment["va_start"])
            file_cursor = file_off + segment["filesize"]

        symoff = stroff = indirectoff = 0
        if import_map:
            file_cursor = align_up(file_cursor, 8)
            symoff = file_cursor
            file_cursor += len(symtab)
            file_cursor = align_up(file_cursor, 4)
            indirectoff = file_cursor
            file_cursor += len(indirect_blob)
            stroff = file_cursor
            file_cursor += len(strtab)

        for segment in segments:
            cmd = LC_SEGMENT_64 if is_64 else LC_SEGMENT
            cmdsize = (72 if is_64 else 56) + len(segment["sections"]) * (80 if is_64 else 68)
            if is_64:
                lc = struct.pack(
                    "<II16sQQQQiiII",
                    cmd,
                    cmdsize,
                    segment["name"].encode("ascii")[:16],
                    segment["va_start"],
                    segment["va_end"] - segment["va_start"],
                    segment["fileoff"],
                    segment["filesize"],
                    7,
                    segment["perms"],
                    len(segment["sections"]),
                    0,
                )
                for section in segment["sections"]:
                    lc += struct.pack(
                        "<16s16sQQIIIIIIII",
                        section["name"].encode("ascii")[:16],
                        segment["name"].encode("ascii")[:16],
                        section["va_start"],
                        section["va_end"] - section["va_start"],
                        0 if section["zerofill"] else section["fileoff"],
                        4,
                        0,
                        0,
                        section["flags"],
                        section.get("indirect_start", 0),
                        section.get("stub_size", 0),
                        0,
                    )
            else:
                lc = struct.pack(
                    "<II16sIIIIiiII",
                    cmd,
                    cmdsize,
                    segment["name"].encode("ascii")[:16],
                    segment["va_start"] & 0xFFFFFFFF,
                    (segment["va_end"] - segment["va_start"]) & 0xFFFFFFFF,
                    segment["fileoff"],
                    segment["filesize"] & 0xFFFFFFFF,
                    7,
                    segment["perms"],
                    len(segment["sections"]),
                    0,
                )
                for section in segment["sections"]:
                    lc += struct.pack(
                        "<16s16sIIIIIIIII",
                        section["name"].encode("ascii")[:16],
                        segment["name"].encode("ascii")[:16],
                        section["va_start"] & 0xFFFFFFFF,
                        (section["va_end"] - section["va_start"]) & 0xFFFFFFFF,
                        0 if section["zerofill"] else section["fileoff"],
                        4,
                        0,
                        0,
                        section["flags"],
                        section.get("indirect_start", 0),
                        section.get("stub_size", 0),
                    )
            load_commands.append(lc)

        if import_map:
            nsyms = len(symtab) // (16 if is_64 else 12)
            load_commands.append(struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, nsyms, stroff, len(strtab)))
            load_commands.append(
                struct.pack(
                    "<II18I",
                    LC_DYSYMTAB,
                    80,
                    0,
                    0,
                    0,
                    0,
                    0,
                    nsyms,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    indirectoff,
                    nindirect,
                    0,
                    0,
                    0,
                    0,
                )
            )
            for lib in libs:
                name = lib.encode("ascii", errors="replace") + b"\x00"
                cmdsize = align_up(24 + len(name), 8)
                load_commands.append(
                    struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 0, 0x10000, 0x10000)
                    + name
                    + b"\x00" * (cmdsize - 24 - len(name))
                )
        if entry_va is not None:
            text_segment = next(segment for segment in segments if segment["perms"] & VM_PROT_EXECUTE)
            entryoff = text_segment["fileoff"] + (entry_va - text_segment["va_start"])
            load_commands.append(struct.pack("<IIQQ", LC_MAIN, 24, entryoff, 0))

        header = self._buildMachHeader(is_64, ncmds, sizeofcmds)
        output = bytearray(header)
        for lc in load_commands:
            output += lc
        if len(output) != header_size + sizeofcmds:
            raise ValueError("internal error: load command size mismatch in Mach-O synthesis")

        for segment in segments:
            output += b"\x00" * (segment["fileoff"] - len(output))
            segment_raw = bytearray(segment["filesize"])
            for section in segment["sections"]:
                if section["zerofill"]:
                    continue
                start = section["va_start"] - segment["va_start"]
                # clamp to the segment's own filesize and use the same length on both sides:
                # a section whose extent runs past it would otherwise grow segment_raw
                # through the slice assignment and shift every following segment's fileoff
                raw = section["raw"]
                copy_length = min(len(raw), max(0, len(segment_raw) - start))
                segment_raw[start : start + copy_length] = raw[:copy_length]
            # the header and load commands already cover the front of a segment mapped from
            # file offset 0; only the bytes past them are the segment's own
            output += segment_raw[max(0, len(output) - segment["fileoff"]) :]

        if import_map:
            output += b"\x00" * (symoff - len(output))
            output += symtab
            output += b"\x00" * (indirectoff - len(output))
            output += indirect_blob
            output += b"\x00" * (stroff - len(output))
            output += strtab
        return bytes(output)

    def _buildMachHeader(self, is_64, ncmds, sizeofcmds):
        flags = MH_PIE | MH_DYLDLINK | MH_TWOLEVEL
        if is_64:
            return struct.pack(
                "<IIIIIIII",
                MH_MAGIC_64,
                self._getCpuType(),
                self._getCpuSubtype(),
                self._getFiletype(),
                ncmds,
                sizeofcmds,
                flags,
                0,
            )
        return struct.pack(
            "<IIIIIII",
            MH_MAGIC,
            self._getCpuType(),
            self._getCpuSubtype(),
            self._getFiletype(),
            ncmds,
            sizeofcmds,
            flags,
        )

    def _synthesizeMinimal(self, offsets) -> bytes:
        va_start, va_end = self._syntheticSpan(offsets, PAGE_SIZE)
        section = {"name": "__text", "va_start": va_start, "va_end": va_end}
        return self._synthesizeFromSections([section], offsets, False, False)
