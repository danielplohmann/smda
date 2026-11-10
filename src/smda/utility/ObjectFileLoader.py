import struct
from bisect import bisect_right
from dataclasses import dataclass, field

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.SmdaConfig import SmdaConfig

_MAX_PADDING_BYTES = 64


def _slice(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("Truncated object table or section")
    return data[offset : offset + size]


def _unpack(fmt, data, offset):
    return struct.unpack(fmt, _slice(data, offset, struct.calcsize(fmt)))


def _string(data, offset):
    if offset < 0 or offset >= len(data):
        raise ValueError("Invalid object string-table offset")
    limit = SmdaConfig.MAX_OBJECT_NAME_LENGTH
    end = data.find(b"\0", offset, offset + limit + 1) if limit > 0 else data.find(b"\0", offset)
    if end < 0:
        raise ValueError("Unterminated or oversized object symbol name")
    return data[offset:end].decode("utf-8", errors="replace")


def _check_record_count(count, maximum, kind):
    if maximum > 0 and count > maximum:
        raise ValueError(f"Object {kind} count exceeds configured limit")


@dataclass
class ObjectSection:
    index: int
    name: str
    size: int
    alignment: int
    content: bytes
    executable: bool = False
    address: int = 0


@dataclass
class ObjectSymbol:
    name: str
    section: int
    value: int
    size: int = 0
    function: bool = False
    address: int = 0


@dataclass
class ObjectImage:
    format: str
    bitness: int
    sections: dict = field(default_factory=dict)
    symbols: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)
    aliases: dict = field(default_factory=dict)
    function_sizes: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)
    relocations: list = field(default_factory=list)
    base: int = 0x10000000
    data: bytearray = field(default_factory=bytearray)
    got: int = 0
    _got_slots: dict = field(default_factory=dict)
    _function_intervals: list = field(default_factory=list)
    _function_interval_starts: list = field(default_factory=list)

    def allocate(self, size, alignment=1):
        if alignment < 1 or alignment & (alignment - 1):
            raise ValueError("Invalid object section alignment")
        offset = (len(self.data) + alignment - 1) & -alignment
        if size < 0 or offset + size > SmdaConfig.MAX_IMAGE_SIZE:
            raise ValueError("Object image larger than MAX_IMAGE_SIZE")
        self.data.extend(bytes(offset + size - len(self.data)))
        return self.base + offset

    def place(self):
        for section in self.sections.values():
            if len(section.content) > section.size:
                raise ValueError("Object section content exceeds its declared size")
            section.address = self.allocate(section.size, section.alignment)
            offset = section.address - self.base
            self.data[offset : offset + len(section.content)] = section.content
        decoder = Cs(CS_ARCH_X86, CS_MODE_64 if self.bitness == 64 else CS_MODE_32)
        function_starts = {(s.section, s.value) for s in self.symbols.values() if s.function}
        for symbol in self.symbols.values():
            if symbol.section in self.sections:
                section = self.sections[symbol.section]
                if symbol.value < 0 or symbol.value > section.size or symbol.size > section.size - symbol.value:
                    raise ValueError("Object symbol outside its section")
                symbol.address = section.address + symbol.value
                if symbol.function and section.executable and symbol.value < section.size:
                    self.aliases.setdefault(symbol.address, []).append(symbol.name)
                    consumed = 0
                    padding = (
                        0 < symbol.size <= _MAX_PADDING_BYTES
                        and (symbol.section, symbol.value + symbol.size) in function_starts
                    )
                    body = section.content[symbol.value : symbol.value + symbol.size] if padding else b""
                    padding = padding and bool(body)
                    if padding:
                        for _address, size, mnemonic, _operands in decoder.disasm_lite(body, symbol.address):
                            if mnemonic != "nop":
                                padding = False
                                break
                            consumed += size
                    if not padding or consumed != symbol.size:
                        self.functions.setdefault(symbol.address, symbol.name)
                        self.function_sizes[symbol.address] = max(
                            self.function_sizes.get(symbol.address, 0), symbol.size
                        )
            elif symbol.section == -1:
                symbol.address = symbol.value
            elif symbol.section == -2:
                symbol.address = self.allocate(symbol.size, symbol.value or 1)
        for start, size in sorted(self.function_sizes.items()):
            if not size:
                continue
            end = start + size
            if self._function_intervals and start <= self._function_intervals[-1][1]:
                self._function_intervals[-1][1] = max(end, self._function_intervals[-1][1])
            else:
                self._function_intervals.append([start, end])
        self._function_interval_starts = [start for start, _end in self._function_intervals]
        self.got = self.allocate(self.bitness // 8, self.bitness // 8)
        imports_by_name = {}
        for symbol in self.symbols.values():
            if symbol.section == 0 and symbol.name:
                if symbol.name == "_GLOBAL_OFFSET_TABLE_":
                    symbol.address = self.got
                    continue
                existing = imports_by_name.get(symbol.name)
                symbol.address = (
                    existing
                    if existing is not None
                    else self.base + SmdaConfig.MAX_IMAGE_SIZE + 0x1000 + len(self.imports) * 16
                )
                self.imports[symbol.address] = symbol.name
                imports_by_name[symbol.name] = symbol.address

    def is_function_interior(self, address):
        if address in self.functions:
            return False
        index = bisect_right(self._function_interval_starts, address) - 1
        return index >= 0 and address < self._function_intervals[index][1]

    def got_slot(self, symbol):
        if symbol.address not in self._got_slots:
            address = self.allocate(self.bitness // 8, self.bitness // 8)
            self.write(address, self.bitness // 8, symbol.address)
            self._got_slots[symbol.address] = address
        return self._got_slots[symbol.address]

    def write(self, address, width, value, signed=False):
        offset = address - self.base
        if offset < 0 or width > len(self.data) - offset:
            raise ValueError("Object relocation outside mapped image")
        try:
            encoded = value.to_bytes(width, "little", signed=signed)
        except OverflowError as exc:
            raise ValueError("Object relocation value does not fit its encoding") from exc
        self.data[offset : offset + width] = encoded

    @property
    def code_areas(self):
        return sorted((s.address, s.address + s.size) for s in self.sections.values() if s.executable and s.size)

    def metadata(self):
        return {
            "format": self.format,
            "layout": "section-order-v1",
            "base_address": self.base,
            "sections": [
                {"index": s.index, "name": s.name, "address": s.address, "size": s.size, "executable": s.executable}
                for s in self.sections.values()
            ],
            "symbol_aliases": self.aliases,
            "function_sizes": self.function_sizes,
            "unresolved_symbols": self.imports,
            "relocations": self.relocations,
        }


def _elf_object(data):
    if data[5] != 1 or data[4] not in (1, 2):
        raise ValueError("Only little-endian ELF32/ELF64 relocatable objects are supported")
    is64 = data[4] == 2
    header = _unpack("<HHIQQQIHHHHHH" if is64 else "<HHIIIIIHHHHHH", data, 16)
    machine, shoff, shentsize, shnum, shstr = header[1], header[5], header[10], header[11], header[12]
    if (machine, is64) not in ((3, False), (62, True)):
        raise ValueError("Unsupported ELF relocatable machine; only x86/x64 are supported")
    section_fmt = "<IIQQQQIIQQ" if is64 else "<IIIIIIIIII"
    if shentsize < struct.calcsize(section_fmt) or not shnum or shstr >= shnum:
        raise ValueError("Unsupported or invalid ELF section table")
    _slice(data, shoff, shnum * shentsize)
    sections = [_unpack(section_fmt, data, shoff + i * shentsize) for i in range(shnum)]
    names = _slice(data, sections[shstr][4], sections[shstr][5])
    image = ObjectImage("ELF_REL", 64 if is64 else 32)
    for index, (name, kind, flags, _addr, offset, size, _link, _info, alignment, _entsize) in enumerate(sections):
        if not flags & 2:
            continue
        if index == 0:
            raise ValueError("ELF null section cannot be allocated")
        if flags & (0x400 | 0x800):
            raise ValueError("TLS and compressed ELF object sections are not supported")
        content = b"" if kind == 8 else _slice(data, offset, size)
        image.sections[index] = ObjectSection(
            index, _string(names, name), size, alignment or 1, content, bool(flags & 4)
        )
    for table_index, section in enumerate(sections):
        if section[1] != 2:
            continue
        offset, size, link, entsize = section[4], section[5], section[6], section[9]
        symbol_fmt = "<IBBHQQ" if is64 else "<IIIBBH"
        if link >= shnum or entsize < struct.calcsize(symbol_fmt) or size % entsize:
            raise ValueError("Invalid ELF object symbol table")
        strings = _slice(data, sections[link][4], sections[link][5])
        _slice(data, offset, size)
        _check_record_count(len(image.symbols) + size // entsize, SmdaConfig.MAX_OBJECT_SYMBOLS, "symbol")
        for index in range(size // entsize):
            values = _unpack(symbol_fmt, data, offset + index * entsize)
            if is64:
                name, info, _other, shndx, value, sym_size = values
            else:
                name, value, sym_size, info, _other, shndx = values
            if shndx >= 0xFF00 and shndx not in (0xFFF1, 0xFFF2):
                raise ValueError("Unsupported ELF special symbol section index")
            if shndx < 0xFF00 and shndx >= shnum:
                raise ValueError("Invalid ELF symbol section index")
            mapped_section = {0xFFF1: -1, 0xFFF2: -2}.get(shndx, shndx)
            image.symbols[table_index, index] = ObjectSymbol(
                _string(strings, name), mapped_section, value, sym_size, (info & 15) == 2
            )
    image.place()
    relocation_count = 0
    for section in sections:
        kind, offset, size, link, target, entsize = (
            section[1],
            section[4],
            section[5],
            section[6],
            section[7],
            section[9],
        )
        if kind not in (4, 9) or target not in image.sections:
            continue
        fmt = ("<QQq" if kind == 4 else "<QQ") if is64 else ("<IIi" if kind == 4 else "<II")
        if entsize < struct.calcsize(fmt) or size % entsize:
            raise ValueError("Invalid ELF object relocation table")
        _slice(data, offset, size)
        relocation_count += size // entsize
        _check_record_count(relocation_count, SmdaConfig.MAX_OBJECT_RELOCATIONS, "relocation")
        for index in range(size // entsize):
            fields = _unpack(fmt, data, offset + index * entsize)
            place, info = fields[:2]
            symbol_index, relocation = (info >> 32, info & 0xFFFFFFFF) if is64 else (info >> 8, info & 255)
            if relocation == 0:
                continue
            symbol = image.symbols.get((link, symbol_index))
            if symbol is None or (symbol.section > 0 and symbol.section not in image.sections):
                raise ValueError("ELF relocation references an unavailable symbol section")
            widths = (
                {1: 8, 2: 4, 4: 4, 9: 4, 10: 4, 11: 4, 24: 8, 41: 4, 42: 4}
                if is64
                else {1: 4, 2: 4, 3: 4, 9: 4, 10: 4, 43: 4}
            )
            width = widths.get(relocation)
            if width is None:
                raise ValueError(f"Unsupported ELF{image.bitness} object relocation {relocation}")
            target_section = image.sections[target]
            if place > target_section.size or width > target_section.size - place:
                raise ValueError("ELF relocation outside its target section")
            address = target_section.address + place
            addend = (
                fields[2]
                if kind == 4
                else int.from_bytes(
                    image.data[address - image.base : address - image.base + width], "little", signed=True
                )
            )
            value = symbol.address + addend
            signed = False
            if is64:
                if relocation in (2, 4, 24):
                    value -= address
                    signed = True
                elif relocation in (9, 41, 42):
                    value = image.got_slot(symbol) + addend - address
                    signed = True
                elif relocation == 11:
                    signed = True
            elif relocation == 2:
                value -= address
                signed = True
            elif relocation in (3, 43):
                value = image.got_slot(symbol) - image.got + addend
            elif relocation == 9:
                value -= image.got
                signed = True
            elif relocation == 10:
                value = image.got + addend - address
                signed = True
            image.write(address, width, value, signed)
            image.relocations.append(
                {
                    "address": address,
                    "width": width,
                    "addend": addend,
                    "type": relocation,
                    "symbol": symbol.name,
                    "target": symbol.address,
                }
            )
    return image


def _coff_object(data):
    machine, count, _timestamp, symoff, symcount, optional, _flags = _unpack("<HHIIIHH", data, 0)
    if optional or not count:
        raise ValueError("Invalid COFF object header")
    if symcount and not symoff:
        raise ValueError("Invalid COFF symbol-table offset")
    _slice(data, 20, count * 40)
    _slice(data, symoff, symcount * 18)
    _check_record_count(symcount, SmdaConfig.MAX_OBJECT_SYMBOLS, "symbol")
    strings_start = symoff + symcount * 18
    string_size = _unpack("<I", data, strings_start)[0] if symoff else 0
    strings = _slice(data, strings_start, string_size) if string_size else b""
    if strings and len(strings) < 4:
        raise ValueError("Invalid COFF string table")

    def name(raw):
        if raw[:4] == bytes(4):
            offset = int.from_bytes(raw[4:], "little")
            return _string(strings, offset) if offset else ""
        return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")

    image = ObjectImage("COFF", 32 if machine == 0x14C else 64)
    relocations = []
    for index in range(1, count + 1):
        raw_name, _vsize, _vaddr, size, offset, reloff, _lineoff, relcount, _linecount, flags = _unpack(
            "<8sIIIIIIHHI", data, 20 + (index - 1) * 40
        )
        section_name = name(raw_name)
        if section_name.startswith("/"):
            try:
                section_name = _string(strings, int(section_name[1:]))
            except ValueError as exc:
                raise ValueError("Invalid COFF long section name") from exc
        if flags & 0xA00 or section_name.startswith((".debug", ".drectve", ".llvm")):
            continue
        if section_name.startswith(".tls"):
            raise ValueError("COFF TLS object sections are not supported")
        if not flags & (0xE0 | 0xE0000000):
            continue
        if flags & 0x01000000:
            raise ValueError("COFF relocation overflow tables are not supported")
        alignment_bits = (flags >> 20) & 15
        alignment = 1 << (alignment_bits - 1) if alignment_bits else 16
        content = b"" if not offset else _slice(data, offset, size)
        image.sections[index] = ObjectSection(index, section_name, size, alignment, content, bool(flags & 0x20000020))
        _slice(data, reloff, relcount * 10)
        _check_record_count(len(relocations) + relcount, SmdaConfig.MAX_OBJECT_RELOCATIONS, "relocation")
        relocations.extend((index, *_unpack("<IIH", data, reloff + i * 10)) for i in range(relcount))
    index = 0
    weak_aliases = {}
    while index < symcount:
        raw_name, value, section, kind, storage, aux = _unpack("<8sIhHBB", data, symoff + index * 18)
        if aux >= symcount - index:
            raise ValueError("Truncated COFF auxiliary symbol records")
        symbol = ObjectSymbol(name(raw_name), section, value, function=bool(kind & 0x20))
        if section > count or section < -2:
            raise ValueError("Invalid COFF symbol section index")
        if symbol.function and aux:
            symbol.size = _unpack("<I", data, symoff + (index + 1) * 18 + 4)[0]
        if section == 0 and value:
            symbol.section, symbol.size, symbol.value = -2, value, image.bitness // 8
        if storage == 105 and aux:
            target, search = _unpack("<II", data, symoff + (index + 1) * 18)
            if search != 3:
                raise ValueError("Unsupported COFF weak external search mode")
            weak_aliases[index] = target
        image.symbols[index] = symbol
        index += aux + 1
    image.place()
    for index, target in weak_aliases.items():
        visited = {index}
        while target in weak_aliases:
            if target in visited:
                raise ValueError("Cyclic COFF weak external aliases")
            visited.add(target)
            target = weak_aliases[target]
        if target not in image.symbols:
            raise ValueError("Invalid COFF weak external symbol index")
        image.symbols[index].address = image.symbols[target].address
    for section_index, offset, symbol_index, kind in relocations:
        if kind == 0:
            continue
        symbol = image.symbols.get(symbol_index)
        if symbol is None or (symbol.section > 0 and symbol.section not in image.sections):
            raise ValueError("COFF relocation references an unavailable symbol")
        relative = (machine == 0x8664 and 4 <= kind <= 9) or (machine == 0x14C and kind == 0x14)
        width = 8 if machine == 0x8664 and kind == 1 else 2 if kind == 10 else 4
        section = image.sections[section_index]
        if offset > section.size or width > section.size - offset:
            raise ValueError("COFF relocation outside its target section")
        place = section.address + offset
        addend = int.from_bytes(image.data[place - image.base : place - image.base + width], "little", signed=relative)
        if relative:
            value = symbol.address + addend - place - 4 - (kind - 4 if machine == 0x8664 else 0)
        elif (machine == 0x8664 and kind in (1, 2)) or (machine == 0x14C and kind == 6):
            value = symbol.address + addend
        elif (machine == 0x8664 and kind == 3) or (machine == 0x14C and kind == 7):
            value = symbol.address + addend - image.base
        elif kind == 10 and symbol.section in image.sections:
            value = symbol.section + addend
        elif kind == 11 and symbol.section in image.sections:
            value = symbol.value + addend
        else:
            raise ValueError(f"Unsupported COFF object relocation {kind}")
        image.write(place, width, value, signed=relative)
        image.relocations.append(
            {
                "address": place,
                "width": width,
                "addend": addend,
                "type": kind,
                "symbol": symbol.name,
                "target": symbol.address,
            }
        )
    return image


def load_object(data):
    if data[:4] == b"\x7fELF" and len(data) >= 18:
        endian = "little" if data[5] == 1 else "big"
        if int.from_bytes(data[16:18], endian) == 1:
            return _elf_object(data)
    if data[:2] in (b"\x4c\x01", b"\x64\x86"):
        return _coff_object(data)
    return None
