import struct

import lief

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.synthesis.BinarySynthesizer import BinarySynthesizer, align_down, align_up

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

SECTION_CHARS_CODE = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
SECTION_CHARS_DATA = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
SECTION_CHARS_DATA_RW = SECTION_CHARS_DATA | IMAGE_SCN_MEM_WRITE

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_32BIT_MACHINE = 0x0100

OPT_HDR_SIZE_OF_CODE = 4
OPT_HDR_SIZE_OF_INIT_DATA = 8
OPT_HDR_SIZE_OF_IMAGE = 56
OPT_HDR_SIZE_OF_HEADERS = 60
DATA_DIR_BASE_PE32 = 96
DATA_DIR_BASE_PE32_PLUS = 112

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

MAX_SYNTHETIC_SECTION_SPAN = 0x2000000


class PeSynthesizer(BinarySynthesizer):
    """Rebuilds a PE file from an SmdaReport.

    With a stored xheader, the original section layout and optional header are
    reused; function bytes are planted into executable sections and imports are
    fused into a synthetic .bspack section. Without an xheader (e.g. headerless
    shellcode dumps), a minimal PE is fabricated around a synthetic .text plus
    import/data sections as needed.
    """

    def synthesize(self, function_offsets=None, with_imports=True, with_strings=True) -> bytes:
        offsets = self._resolveFunctionOffsets(function_offsets)
        if not offsets:
            raise ValueError("synthesis requires at least one function in the report")
        if self._hasHeader(512):
            try:
                return self._synthesizeFromHeader(offsets, with_imports, with_strings)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                self._warn("PE synthesis from xheader failed (%s), falling back to minimal header", exc)
        return self._synthesizeMinimal(offsets, with_imports, with_strings)

    def _getBitness(self):
        return 64 if self.report.bitness == 64 else 32

    def _getMachine(self):
        if self.report.architecture == "aarch64":
            return MACHINE_ARM64
        return MACHINE_AMD64 if self._getBitness() == 64 else MACHINE_I386

    def _plantFunctions(self, regions, offsets, base):
        for offset in offsets:
            for block_offset, chunk in self._iterFunctionChunks(self.report.xcfg[offset]):
                rva = block_offset - base
                for region in regions:
                    if (
                        region["executable"]
                        and region["vaddr"] <= rva
                        and rva + len(chunk) <= region["vaddr"] + len(region["raw"])
                    ):
                        file_offset = rva - region["vaddr"]
                        region["raw"][file_offset : file_offset + len(chunk)] = chunk
                        break
                else:
                    self._warn("block 0x%x of function 0x%x fits no executable section, skipped", block_offset, offset)

    def _plantStrings(self, regions, base):
        for data_addr, content in self._iterStringRefs():
            rva = data_addr - base
            for region in regions:
                if region["executable"]:
                    continue
                if region["vaddr"] <= rva and rva + len(content) <= region["vaddr"] + len(region["raw"]):
                    region["raw"][rva - region["vaddr"] : rva - region["vaddr"] + len(content)] = content
                    break

    @staticmethod
    def _parseOrdinal(name):
        if name.startswith("#") and name[1:].isdigit():
            return int(name[1:])
        return None

    def _buildImportTables(self, import_rvas, ptr_size):
        """Groups imports by DLL and builds descriptor/hint/dll-name blobs.

        Returns (dll_funcs, hint_buf, dll_strs, hint_offsets) where dll_funcs is
        an ordered list of (dll_name, [(rva, func_name)]) and thunk resolution
        happens against hint_offsets or ordinal flags.
        """
        dll_funcs = []
        seen_dlls = {}
        for rva, (dll, func) in sorted(import_rvas.items()):
            dll_key = dll or "unknown.dll"
            if dll_key not in seen_dlls:
                seen_dlls[dll_key] = []
                dll_funcs.append((dll_key, seen_dlls[dll_key]))
            seen_dlls[dll_key].append((rva, func))

        hint_offsets = {}
        hint_buf = bytearray()
        dll_strs = bytearray()
        dll_str_offsets = {}
        for dll_name, funcs in dll_funcs:
            dll_str_offsets[dll_name] = len(dll_strs)
            dll_strs += dll_name.encode("ascii", errors="replace") + b"\x00"
            for _rva, func in funcs:
                if self._parseOrdinal(func) is not None:
                    continue
                if (dll_name, func) in hint_offsets:
                    continue
                hint_offsets[(dll_name, func)] = len(hint_buf)
                hint_buf += struct.pack("<H", 0) + func.encode("ascii", errors="replace") + b"\x00"
                if len(hint_buf) % 2:
                    hint_buf += b"\x00"
        idescs = bytearray(20 * (len(dll_funcs) + 1))
        return dll_funcs, idescs, hint_buf, dll_strs, dll_str_offsets, hint_offsets

    def _writeThunkAt(self, regions, rva, value, ptr_size):
        for region in regions:
            if region["vaddr"] <= rva and rva + ptr_size <= region["vaddr"] + len(region["raw"]):
                struct.pack_into("<I" if ptr_size == 4 else "<Q", region["raw"], rva - region["vaddr"], value)
                return True
        return False

    def _writeThunks(self, regions, import_rvas, dll_funcs, sec_vaddr, hint_off, hint_offsets, ptr_size):
        ordinal_flag = 1 << (ptr_size * 8 - 1)
        for rva, (dll, func) in import_rvas.items():
            ordinal = self._parseOrdinal(func)
            if ordinal is not None:
                thunk_value = ordinal_flag | ordinal
            else:
                thunk_value = sec_vaddr + hint_off + hint_offsets[(dll or "unknown.dll", func)]
            if not self._writeThunkAt(regions, rva, thunk_value, ptr_size):
                self._warn("import thunk 0x%x (%s.%s) outside all sections", rva, dll, func)

        all_rvas = set(import_rvas.keys())
        for dll_name, funcs in dll_funcs:
            if not funcs:
                continue
            first = min(rva for rva, _ in funcs)
            last = max(rva for rva, _ in funcs)
            padded = 0
            va = first
            while va <= last:
                if va in all_rvas:
                    va += ptr_size
                    continue
                if self._writeThunkAt(regions, va, ordinal_flag, ptr_size):
                    padded += 1
                va += ptr_size
            if padded:
                self._warn("%d gap slot(s) in IAT group for %s padded with ordinal-0 thunks", padded, dll_name)
            terminator = last + ptr_size
            if terminator not in all_rvas:
                self._writeThunkAt(regions, terminator, 0, ptr_size)

    def _patchDescriptors(self, raw, dll_funcs, sec_vaddr, idesc_off, dll_off, dll_str_offsets, hint_off):
        for index, (dll_name, funcs) in enumerate(dll_funcs):
            first_iat_rva = funcs[0][0]
            name_rva = sec_vaddr + dll_off + dll_str_offsets[dll_name]
            struct.pack_into("<I", raw, idesc_off + index * 20 + 0, first_iat_rva)
            struct.pack_into("<I", raw, idesc_off + index * 20 + 12, name_rva)
            struct.pack_into("<I", raw, idesc_off + index * 20 + 16, first_iat_rva)

    def _buildImportSection(self, regions, import_map, base, ptr_size, section_alignment, file_alignment):
        """Appends a synthetic import section (.bspack) holding descriptors, hint/name
        entries and DLL names; patches thunks into their owning sections. Returns
        (import_dir_rva, import_dir_size) or None."""
        import_rvas = {}
        for addr, (dll, func) in sorted(import_map.items()):
            rva = addr - base
            if rva < 0:
                self._warn("import slot 0x%x below image base, skipped", addr)
                continue
            import_rvas[rva] = (dll, func)
        if not import_rvas:
            return None

        dll_funcs, idescs, hint_buf, dll_strs, dll_str_offsets, hint_offsets = self._buildImportTables(
            import_rvas, ptr_size
        )

        last = max(regions, key=lambda region: region["vaddr"] + region["vsize"])
        sec_vaddr = align_up(last["vaddr"] + last["vsize"], section_alignment)
        hint_off = align_up(len(idescs), 4)
        dll_off = hint_off + len(hint_buf)
        content_size = dll_off + len(dll_strs)
        raw_size = align_up(content_size, file_alignment)
        raw = bytearray(raw_size)
        raw[0 : len(idescs)] = idescs
        raw[hint_off : hint_off + len(hint_buf)] = hint_buf
        raw[dll_off : dll_off + len(dll_strs)] = dll_strs
        self._patchDescriptors(raw, dll_funcs, sec_vaddr, 0, dll_off, dll_str_offsets, hint_off)
        self._writeThunks(regions, import_rvas, dll_funcs, sec_vaddr, hint_off, hint_offsets, ptr_size)

        regions.append(
            {
                "name": ".bspack",
                "vaddr": sec_vaddr,
                "vsize": align_up(content_size, section_alignment),
                "chars": SECTION_CHARS_DATA,
                "raw": raw,
                "executable": False,
            }
        )
        return sec_vaddr, len(idescs)

    def _buildHeader(self, regions, optional_header, machine, characteristics, size_of_headers):
        header = bytearray(0x40)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x40)
        header += b"PE\x00\x00"
        header += struct.pack("<HHIIIHH", machine, len(regions), 0, 0, 0, len(optional_header), characteristics)
        header += optional_header
        for region in regions:
            name = region["name"].encode("ascii", errors="replace").ljust(8, b"\x00")[:8]
            header += struct.pack(
                "<8sIIIIIIHHI",
                name,
                region["vsize"],
                region["vaddr"],
                len(region["raw"]),
                region["ptr"],
                0,
                0,
                0,
                0,
                region["chars"],
            )
        if len(header) > size_of_headers:
            raise ValueError("section table does not fit into SizeOfHeaders")
        header += b"\x00" * (size_of_headers - len(header))
        return header

    def _synthesizeFromHeader(self, offsets, with_imports, with_strings):
        base = self.report.base_addr
        pe_src = lief.parse(bytes(self.report.xheader))
        if not isinstance(pe_src, lief.PE.Binary):
            raise ValueError("xheader does not parse as PE")
        optional = pe_src.optional_header
        file_alignment = optional.file_alignment or 0x200
        section_alignment = optional.section_alignment or 0x1000
        is_pe32_plus = optional.magic == lief.PE.PE_TYPE.PE32_PLUS
        ptr_size = 8 if is_pe32_plus else 4

        regions: list[dict] = []
        for section in pe_src.sections:
            raw_size = section.sizeof_raw_data
            if raw_size == 0 and section.virtual_size > 0:
                raw_size = align_up(section.virtual_size, file_alignment)
            executable = bool(int(section.characteristics) & IMAGE_SCN_MEM_EXECUTE)
            if raw_size == 0:
                raw = bytearray()
            elif executable:
                raw = bytearray(self._nopFill(raw_size))
            else:
                raw = bytearray(raw_size)
            regions.append(
                {
                    "name": section.name.rstrip("\x00"),
                    "vaddr": section.virtual_address,
                    "vsize": section.virtual_size,
                    "chars": int(section.characteristics),
                    "raw": raw,
                    "executable": executable,
                }
            )

        self._plantFunctions(regions, offsets, base)
        if with_strings:
            self._plantStrings(regions, base)

        import_dir = None
        if with_imports:
            import_dir = self._buildImportSection(
                regions, self._getImportMap(), base, ptr_size, section_alignment, file_alignment
            )

        e_lfanew = struct.unpack("<I", self.report.xheader[0x3C:0x40])[0]
        size_opt = struct.unpack("<H", self.report.xheader[e_lfanew + 20 : e_lfanew + 22])[0]
        optional_header = bytearray(self.report.xheader[e_lfanew + 24 : e_lfanew + 24 + size_opt])
        if len(optional_header) < size_opt:
            optional_header += b"\x00" * (size_opt - len(optional_header))

        size_of_code = sum(len(r["raw"]) for r in regions if r["executable"])
        size_init_data = sum(len(r["raw"]) for r in regions if int(r["chars"]) & IMAGE_SCN_CNT_INITIALIZED_DATA)
        struct.pack_into("<I", optional_header, OPT_HDR_SIZE_OF_CODE, size_of_code)
        struct.pack_into("<I", optional_header, OPT_HDR_SIZE_OF_INIT_DATA, size_init_data)
        image_end = align_up(max(r["vaddr"] + r["vsize"] for r in regions), section_alignment)
        struct.pack_into("<I", optional_header, OPT_HDR_SIZE_OF_IMAGE, image_end)

        needed_headers = align_up(0x40 + 4 + 20 + size_opt + 40 * len(regions), file_alignment)
        size_of_headers = max(optional.sizeof_headers or 0, needed_headers)
        struct.pack_into("<I", optional_header, OPT_HDR_SIZE_OF_HEADERS, size_of_headers)

        if import_dir is not None:
            dir_base = DATA_DIR_BASE_PE32_PLUS if is_pe32_plus else DATA_DIR_BASE_PE32
            struct.pack_into("<I", optional_header, dir_base + 8 * IMAGE_DIRECTORY_ENTRY_IMPORT, import_dir[0])
            struct.pack_into("<I", optional_header, dir_base + 8 * IMAGE_DIRECTORY_ENTRY_IMPORT + 4, import_dir[1])

        raw_offset = size_of_headers
        for region in regions:
            region["ptr"] = raw_offset
            raw_offset += len(region["raw"])

        header = self._buildHeader(
            regions, optional_header, int(pe_src.header.machine), int(pe_src.header.characteristics), size_of_headers
        )
        return bytes(header) + b"".join(bytes(r["raw"]) for r in regions)

    def _buildMinimalOptionalHeader(self, regions, bitness, size_of_headers, image_end, entry_rva, import_dir):
        is_64 = bitness == 64
        dir_base = DATA_DIR_BASE_PE32_PLUS if is_64 else DATA_DIR_BASE_PE32
        size = 0xF0 if is_64 else 0xE0
        opt = bytearray(size)
        struct.pack_into("<H", opt, 0, 0x20B if is_64 else 0x10B)
        size_of_code = sum(len(r["raw"]) for r in regions if r["executable"])
        size_init_data = sum(len(r["raw"]) for r in regions if not r["executable"])
        struct.pack_into("<I", opt, OPT_HDR_SIZE_OF_CODE, size_of_code)
        struct.pack_into("<I", opt, OPT_HDR_SIZE_OF_INIT_DATA, size_init_data)
        struct.pack_into("<I", opt, 16, entry_rva)
        text_rva = min((r["vaddr"] for r in regions if r["executable"]), default=0)
        struct.pack_into("<I", opt, 20, text_rva)
        if is_64:
            struct.pack_into("<Q", opt, 24, self.report.base_addr)
        else:
            struct.pack_into("<I", opt, 28, self.report.base_addr & 0xFFFFFFFF)
            data_rva = min((r["vaddr"] for r in regions if not r["executable"]), default=0)
            struct.pack_into("<I", opt, 24, data_rva)
        struct.pack_into("<II", opt, 32, 0x1000, 0x200)
        struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
        struct.pack_into("<I", opt, OPT_HDR_SIZE_OF_IMAGE, image_end)
        struct.pack_into("<I", opt, OPT_HDR_SIZE_OF_HEADERS, size_of_headers)
        struct.pack_into("<H", opt, 68, 3)
        struct.pack_into("<H", opt, 70, 0x8000)
        if is_64:
            struct.pack_into("<QQQQ", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
            struct.pack_into("<I", opt, 108, 16)
        else:
            struct.pack_into("<IIII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
            struct.pack_into("<I", opt, 92, 16)
        if import_dir is not None:
            struct.pack_into("<I", opt, dir_base + 8, import_dir[0])
            struct.pack_into("<I", opt, dir_base + 12, import_dir[1])
        return opt

    def _synthesizeMinimal(self, offsets, with_imports, with_strings):
        base = self.report.base_addr
        bitness = self._getBitness()
        ptr_size = 8 if bitness == 64 else 4
        section_alignment = 0x1000
        file_alignment = 0x200

        regions: list[dict] = []
        min_rva = min(offset - base for offset in offsets)
        max_rva = max(self._functionExtentEnd(self.report.xcfg[offset]) - base for offset in offsets)
        text_vaddr = max(align_down(min_rva, section_alignment), section_alignment)
        text_size = align_up(max_rva, section_alignment) - text_vaddr
        if text_size <= 0:
            raise ValueError("functions do not fit into a synthetic .text section")
        regions.append(
            {
                "name": ".text",
                "vaddr": text_vaddr,
                "vsize": text_size,
                "chars": SECTION_CHARS_CODE,
                "raw": bytearray(self._nopFill(text_size)),
                "executable": True,
            }
        )

        import_map = self._getImportMap() if with_imports else {}
        string_addrs = [data_addr for data_addr, _ in self._iterStringRefs()] if with_strings else []

        if import_map:
            iat_rvas = [addr - base for addr in import_map]
            iat_vaddr = align_down(min(iat_rvas), section_alignment)
            iat_end = align_up(max(iat_rvas) + ptr_size, 16)
            iat_size = align_up(iat_end, section_alignment) - iat_vaddr
            overlaps = any(
                region["vaddr"] < iat_vaddr + iat_size and iat_vaddr < region["vaddr"] + region["vsize"]
                for region in regions
            )
            if overlaps:
                self._warn("IAT range overlaps the synthetic .text section, thunks are planted into .text")
            else:
                regions.append(
                    {
                        "name": ".smdaIAT",
                        "vaddr": iat_vaddr,
                        "vsize": iat_size,
                        "chars": SECTION_CHARS_DATA_RW,
                        "raw": bytearray(iat_size),
                        "executable": False,
                    }
                )

        uncovered_strings = []
        for data_addr in string_addrs:
            rva = data_addr - base
            if any(r["vaddr"] <= rva and rva < r["vaddr"] + r["vsize"] for r in regions):
                continue
            uncovered_strings.append(data_addr)
        if uncovered_strings:
            min_s = min(uncovered_strings) - base
            max_s = max(uncovered_strings) - base + 0x100
            if max_s - min_s > MAX_SYNTHETIC_SECTION_SPAN:
                self._warn(
                    "string refs span 0x%x bytes, too sparse for a synthetic section; strings skipped", max_s - min_s
                )
            else:
                str_vaddr = align_down(min_s, section_alignment)
                str_size = align_up(max_s, section_alignment) - str_vaddr
                regions.append(
                    {
                        "name": ".rdata",
                        "vaddr": str_vaddr,
                        "vsize": str_size,
                        "chars": SECTION_CHARS_DATA,
                        "raw": bytearray(str_size),
                        "executable": False,
                    }
                )

        regions.sort(key=lambda region: region["vaddr"])

        self._plantFunctions(regions, offsets, base)
        if with_strings:
            self._plantStrings(regions, base)

        import_dir = None
        if import_map:
            import_dir = self._buildImportSection(
                regions, import_map, base, ptr_size, section_alignment, file_alignment
            )
            regions.sort(key=lambda region: region["vaddr"])

        size_opt = 0xF0 if bitness == 64 else 0xE0
        size_of_headers = align_up(0x40 + 4 + 20 + size_opt + 40 * len(regions), file_alignment)
        image_end = align_up(max(r["vaddr"] + r["vsize"] for r in regions), section_alignment)
        entry_rva = text_vaddr
        if self.report.oep:
            entry_rva = self.report.oep - base if self.report.oep >= base else self.report.oep

        optional_header = self._buildMinimalOptionalHeader(
            regions, bitness, size_of_headers, image_end, entry_rva, import_dir
        )

        raw_offset = size_of_headers
        for region in regions:
            region["ptr"] = raw_offset
            raw_offset += len(region["raw"])

        characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED
        characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE if bitness == 64 else IMAGE_FILE_32BIT_MACHINE
        header = self._buildHeader(regions, optional_header, self._getMachine(), characteristics, size_of_headers)
        return bytes(header) + b"".join(bytes(r["raw"]) for r in regions)
