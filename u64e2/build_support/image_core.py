# SPDX-License-Identifier: GPL-3.0-or-later
# Modified for current source distribution, 2026-11-05.
"""Validate the bounded high-RAM image and its one-record CFW container."""
import hashlib
import struct
RAM_START = 50331648
RAM_END = 62914560
FAMILY = b'U64MK2'
FINGERPRINT = 1091939806
FIXED = {'__kernal_area': 15368192, '__drive_b_sound': 15400960, '__drive_a_sound': 15466496, '__drive_b_area': 15532032, '__drive_a_area': 15597568, '__cart_ram_start': 15663104, '__cart_ram_limit': 15728640, '__reu_ram_start': 16777216, '__reu_ram_limit': 33554432, '__ram_disk_start': 33554432, '__ram_disk_limit': 50331648, '__updater_start': 50331648, '__updater_limit': 62914560, '__cart_rom_start': 62914560, '__cart_rom_limit': 67108864}

class InvalidImage(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise InvalidImage(reason)

def bounded(data, offset, length, label):
    require(0 <= offset <= len(data) and 0 <= length <= len(data) - offset, label + ' exceeds file bounds')
    return data[offset:offset + length]

def inspect_elf(elf):
    require(len(elf) >= 52, 'truncated ELF header')
    fields = struct.unpack_from('<16sHHIIIIIHHHHHH', elf)
    ident, etype, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    require(ident[:7] == b'\x7fELF\x01\x01\x01', 'expected ELF32 little-endian version1')
    require(etype == 2 and machine == 243 and (version == 1) and (ehsize == 52), 'expected executable RISC-V ELF')
    require(flags & 15 == 0, 'compressed/floating-point/RVE ABI is not permitted')
    require(phentsize == 32 and 1 <= phnum <= 16, 'unexpected program header layout')
    require(shentsize == 40 and 1 <= shnum <= 256 and (shstrndx < shnum), 'unexpected section header layout')
    ph = [struct.unpack('<IIIIIIII', bounded(elf, phoff + i * 32, 32, 'program header')) for i in range(phnum)]
    loads = [p for p in ph if p[0] == 1]
    require(len(loads) == 1, 'the normalized image requires exactly one PT_LOAD segment')
    _, offset, vaddr, paddr, filesz, memsz, loadflags, align = loads[0]
    require(vaddr == paddr == entry == RAM_START, 'load address and entry must be 0x03000000')
    require(0 < filesz <= memsz <= RAM_END - RAM_START, 'file or BSS exceeds reserved RAM execution area')
    require(loadflags & 1, 'entry segment is not executable')
    payload = bounded(elf, offset, filesz, 'ELF payload')
    sections = [struct.unpack('<IIIIIIIIII', bounded(elf, shoff + i * 40, 40, 'section header')) for i in range(shnum)]
    names = bounded(elf, sections[shstrndx][4], sections[shstrndx][5], 'section names')

    def cstr(table, at):
        require(0 <= at < len(table), 'string offset outside table')
        end = table.find(b'\x00', at)
        require(end >= 0, 'unterminated string')
        return table[at:end].decode('ascii', 'strict')
    alloc_sections = []
    symbols = {}
    for sec in sections:
        name, stype, sflags, addr, off, size, link, info, alignment, entsize = sec
        if sflags & 2 and size:
            require(RAM_START <= addr and size <= RAM_END - addr, 'allocated section outside reserved RAM area')
            if stype != 8:
                content = bounded(elf, off, size, 'allocated section')
                relative = addr - vaddr
                require(relative + size <= filesz and payload[relative:relative + size] == content, 'allocated section is not represented by PT_LOAD')
            alloc_sections.append({'name': cstr(names, name), 'address': addr, 'size': size, 'type': stype})
        if stype == 2:
            require(entsize == 16 and size % 16 == 0 and (link < len(sections)), 'invalid symbol table')
            strings = bounded(elf, sections[link][4], sections[link][5], 'symbol strings')
            table = bounded(elf, off, size, 'symbol table')
            for at in range(0, size, 16):
                symname, value, symsize, syminfo, other, shindex = struct.unpack_from('<IIIBBH', table, at)
                if symname and shindex:
                    label = cstr(strings, symname)
                    symbols[label] = {'value': value, 'size': symsize, 'info': syminfo, 'section': shindex}
    for label in ('_start', '__crt0_stack_begin', '__heap_start', '__heap_end', '__BSS_START__', '__BSS_END__', 'freertos_risc_v_trap_handler', 'ucHeap', 'p05_ram_target_rejected', 'p05_ram_target_accepted'):
        require(label in symbols, 'required symbol is absent: ' + label)
    require(symbols['_start']['value'] == entry, 'ELF entry is not _start')
    require(entry < symbols['p05_ram_target_rejected']['value'] < symbols['p05_ram_target_accepted']['value'] < entry + 256, 'early hardware guard is absent or outside the reviewed startup position')
    require(payload[:4] == bytes.fromhex('73700430'), 'first instruction must disable mstatus.MIE')
    require(symbols['ucHeap']['size'] == 5128192, 'expected the current 0x4E4000 heap')
    require('_sbrk' not in symbols and '_sbrk_r' not in symbols, 'unexpected fallback libc heap implementation remains linked')
    require(symbols['__crt0_stack_begin']['value'] == RAM_END - 4, 'startup stack outside expected boundary')
    require(symbols['__heap_end']['value'] == RAM_END, 'libc heap end outside expected boundary')
    require(RAM_START <= symbols['__BSS_START__']['value'] <= symbols['__BSS_END__']['value'] < RAM_END - 65536, 'BSS leaves less than64KiB before startup stack')
    require(symbols['__heap_start']['value'] >= symbols['__BSS_END__']['value'], 'libc heap overlaps BSS')
    require(RAM_START <= symbols['freertos_risc_v_trap_handler']['value'] < RAM_START + filesz, 'interrupt vector outside executable payload')
    fixed_symbols = {}
    for label, address in FIXED.items():
        if label in symbols:
            require(symbols[label]['value'] == address, 'fixed hardware region moved: ' + label)
            fixed_symbols[label] = address
    require('__drive_a_area' in fixed_symbols and '__drive_b_area' in fixed_symbols, 'drive memory symbols missing')
    return ({'entry': entry, 'load_address': vaddr, 'file_size': filesz, 'memory_size': memsz, 'static_end': vaddr + memsz, 'reserved_end': RAM_END, 'free_rtos_heap_bytes': symbols['ucHeap']['size'], 'early_guard': {'accepted': symbols['p05_ram_target_accepted']['value'], 'rejected': symbols['p05_ram_target_rejected']['value']}, 'startup_stack': symbols['__crt0_stack_begin']['value'], 'static_to_stack_gap': symbols['__crt0_stack_begin']['value'] - (vaddr + memsz), 'fixed_symbols': fixed_symbols, 'allocated_sections': alloc_sections}, payload)

def build_cfw(elf, app):
    report, payload = inspect_elf(elf)
    require(len(app) == 12 + len(payload), 'APP is not exactly one complete load record')
    load, size, entry = struct.unpack_from('<III', app)
    require((load, size, entry) == (RAM_START, len(payload), RAM_START), 'APP header disagrees with ELF')
    require(app[12:] == payload, 'APP bytes disagree with ELF PT_LOAD')
    header = struct.pack('<I16s16s', FINGERPRINT, FAMILY, b'')
    cfw = header + app
    report.update({'cfw_fingerprint': hex(FINGERPRINT), 'product_family': FAMILY.decode(), 'product_name': '', 'cfw_bytes': len(cfw), 'elf_sha256': hashlib.sha256(elf).hexdigest(), 'app_sha256': hashlib.sha256(app).hexdigest(), 'cfw_sha256': hashlib.sha256(cfw).hexdigest(), 'hardware_execution': 'NOT_RUN', 'container_adds_executable_code': False, 'scope': 'Static ELF/APP/container validation only; no proof of hardware startup or cache behavior.'})
    return (cfw, report)
