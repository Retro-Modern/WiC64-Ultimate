# SPDX-License-Identifier: GPL-3.0-or-later
# Modified for current source distribution, 2026-11-05.
"""Validate cached math, initialized ESP heap, and physical LOAD layout."""
import hashlib
import struct
try:
    from . import image_core as original
except ImportError:
    import image_core as original
InvalidImage = original.InvalidImage
RAM_START, RAM_END = (original.RAM_START, original.RAM_END)
CACHE_START, CACHE_END = (196608, 458752)
HEAP_BYTES = 5128192
RESOURCE_BYTES = 1043296
RESOURCE_SHA256 = '20b69f913eeda1d59fe86c7436ec34837edcbcfbd118e91559201485c48d77c3'
SEED_OFFSET = 32
PROFILE_MACRO = 'cached-code_CACHED_MATH=1'
PRODUCER_SYMBOL = 'p17f_cache_profile_sp_math'
MATH_SYMBOLS = ('__p17f_math_start', '__p17f_math_end', '__p17f_math_load_start', '__p17f_math_load_end')
SWEEP_SYMBOLS = ('p17f_cache_evict', '__p17f_evict_start', '__p17f_evict_end')

def _decode_call(payload, at, pc):
    word = struct.unpack_from('<I', payload, at)[0]

    def signed(value, bits):
        return value - (1 << bits) if value & 1 << bits - 1 else value
    if word & 127 == 111 and word >> 7 & 31 == 1:
        imm = word >> 31 << 20 | (word >> 12 & 255) << 12
        imm |= (word >> 20 & 1) << 11 | (word >> 21 & 1023) << 1
        return pc + signed(imm, 21)
    if word & 4095 == 151 and at + 8 <= len(payload):
        second = struct.unpack_from('<I', payload, at + 4)[0]
        if second & 1048575 == 32999:
            return pc + signed(word & 4294963200, 32) + signed(second >> 20, 12) & 4294967295
    return None

def check_initialized_heap(elf, high, sections, allocated, symbols):
    require = original.require
    heap = symbols.get('ucHeap')
    seed = symbols.get('p18m_esp_resource_seed')
    data = [s for s in allocated if s['name'] == '.data']
    require(len(data) == 1 and heap is not None and (seed is not None), 'embedded ESP initialized heap/data/seed is missing')
    data = data[0]
    require(data['type'] == 1 and data['flags'] == 3 and (heap['section'] == seed['section'] == data['index']) and (heap['info'] >> 4 == seed['info'] >> 4 == 1) and (heap['info'] & 15 == seed['info'] & 15 == 1), 'embedded ESP heap and seed must be global objects in initialized writable data')
    start, size = (heap['value'], heap['size'])
    require(size == HEAP_BYTES and start % 16 == 0 and (data['address'] <= start) and (start + size <= data['address'] + data['size']) and (high[2] <= start) and (start + size <= high[2] + high[4]), 'embedded ESP initialized heap escaped exact file-backed data bounds')
    require(seed['value'] == start + SEED_OFFSET and seed['size'] == RESOURCE_BYTES and (SEED_OFFSET + RESOURCE_BYTES < size), 'embedded ESP ESP seed offset or exact length changed')
    offset = high[1] + start - high[2]
    content = original.bounded(elf, offset, size, 'embedded ESP initialized heap')
    require(content[:SEED_OFFSET] == bytes(SEED_OFFSET), 'embedded ESP allocator header prefix is not zero')
    require(hashlib.sha256(content[SEED_OFFSET:SEED_OFFSET + RESOURCE_BYTES]).hexdigest() == RESOURCE_SHA256, 'embedded ESP embedded ESP application differs from approved raw image')
    require(not any(content[SEED_OFFSET + RESOURCE_BYTES:]), 'embedded ESP initialized heap remainder is not zero')
    call = symbols.get('__p18m_resource_bootstrap_call')
    target = symbols.get('p18m_esp_resource_bootstrap')
    clear = symbols.get('__crt0_clear_bss_loop_end')
    constructors = symbols.get('__crt0_call_constructors')
    require(all((x is not None for x in (call, target, clear, constructors))) and high[2] <= clear['value'] <= call['value'] < constructors['value'] <= high[2] + high[4] and (high[2] <= target['value'] < high[2] + high[4]), 'embedded ESP bootstrap is not explicitly between BSS clearing and constructors')
    position = call['value'] - high[2]
    high_content = original.bounded(elf, high[1], high[4], 'high LOAD')
    require(position + 4 <= len(high_content) and _decode_call(high_content, position, call['value']) == target['value'], 'embedded ESP preconstructor instruction does not call resource bootstrap')
    return {'bytes': RESOURCE_BYTES, 'sha256': RESOURCE_SHA256, 'heap_bytes': size, 'heap_address': start, 'seed_address': seed['value'], 'seed_offset': SEED_OFFSET, 'heap_file_offset': offset, 'temporary_malloc_reservation_bytes': RESOURCE_BYTES + SEED_OFFSET, 'allocator_header_bytes': 16, 'malloc_header_bytes': 16, 'bootstrap_call': call['value'], 'bootstrap_function': target['value'], 'ownership': 'First malloc before constructors; take transfers once; free releases; no permanent reservation.', 'encoding': 'raw ESP32-S3 application, no extra APP records or trailing bytes'}

def require(condition, reason):
    original.require(condition, reason)

def cstr(data, at):
    require(0 <= at < len(data), 'string offset outside table')
    end = data.find(b'\x00', at)
    require(end >= 0, 'unterminated ELF string')
    try:
        return data[at:end].decode('ascii', 'strict')
    except UnicodeDecodeError as error:
        raise InvalidImage('non-ASCII ELF string') from error

def parse_real(elf):
    require(len(elf) >= 52, 'truncated ELF header')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', elf)
    ident, etype, machine, version, entry, phoff, shoff, flags, ehsize, phstep, phnum, shstep, shnum, shstr = h
    require(ident[:7] == b'\x7fELF\x01\x01\x01' and etype == 2 and (machine == 243) and (version == 1) and (ehsize == 52) and (flags & 15 == 0), 'expected uncompressed integer executable RV32 ELF')
    require(entry == RAM_START, 'real ELF entry must remain high RAM')
    require(phstep == 32 and 1 <= phnum <= 16 and (shstep == 40) and (1 <= shnum <= 256) and (shstr < shnum), 'unexpected real ELF header layout')
    ph = [list(struct.unpack('<IIIIIIII', original.bounded(elf, phoff + i * 32, 32, 'program header'))) for i in range(phnum)]
    sections = [list(struct.unpack('<IIIIIIIIII', original.bounded(elf, shoff + i * 40, 40, 'section header'))) for i in range(shnum)]
    names = original.bounded(elf, sections[shstr][4], sections[shstr][5], 'section names')
    loads = [(i, p) for i, p in enumerate(ph) if p[0] == 1]
    require(len(loads) == 3, 'cached-code requires exactly three real PT_LOAD segments')
    high = [(i, p) for i, p in loads if p[2] == p[3] == RAM_START]
    cached = [(i, p) for i, p in loads if p[2] == CACHE_START]
    zero = [(i, p) for i, p in loads if p[4] == 0 and p[5] > 0]
    require(len(high) == len(cached) == len(zero) == 1, 'real LOAD roles are missing, duplicated or ambiguous')
    high_i, high = high[0]
    cached_i, cached = cached[0]
    zero_i, zero = zero[0]
    require(len({high_i, cached_i, zero_i}) == 3, 'real LOAD roles overlap')
    require(high[6] == 7 and 0 < high[4] == high[5] <= RAM_END - RAM_START, 'high code/data LOAD flags or exact file/memory span differ')
    require(cached[6] == 5 and 0 < cached[4] == cached[5] <= CACHE_END - CACHE_START, 'cached math LOAD must be bounded executable read-only file bytes')
    require(cached[3] == RAM_START + high[4], 'cached math LMA is not the exact contiguous high staging continuation')
    require(zero[2] == zero[3] == cached[3] + cached[4] and zero[6] == 6 and (zero[5] <= RAM_END - zero[2]), 'high NOBITS LOAD is not the exact bounded staging continuation')
    require(cached[3] + cached[4] <= RAM_END, 'cached math staging exceeds high RAM')
    require((high[2] | high[3] | high[4] | cached[2] | cached[3] | cached[4] | zero[2] | zero[3] | zero[5]) & 3 == 0, 'real code, cached copy and BSS bounds must be word aligned')
    for p in (high, cached, zero):
        require(p[7] and p[7] & p[7] - 1 == 0 and (p[7] <= 65536), 'LOAD alignment is not a bounded power of two')
        require(p[1] % p[7] == p[2] % p[7], 'LOAD file/VMA alignment mismatch')
    require(high[1] + high[4] <= cached[1] or cached[1] + cached[4] <= high[1], 'file-backed real LOAD ranges overlap')
    high_bytes = original.bounded(elf, high[1], high[4], 'high LOAD bytes')
    cached_bytes = original.bounded(elf, cached[1], cached[4], 'cached LOAD bytes')
    allocated, symbols, symbol_offsets = ([], {}, {})
    for index, sec in enumerate(sections):
        name, kind, attrs, address, offset, size, link, info, alignment, step = sec
        label = cstr(names, name)
        if attrs & 2 and size:
            require(alignment == 0 or alignment & alignment - 1 == 0, 'allocated section alignment is not a power of two')
            require(alignment <= 1 or address % alignment == 0, 'allocated section address does not satisfy its declared alignment')
            if label == '.cached_math':
                require(kind == 1 and attrs == 6 and (address == CACHE_START) and (size == cached[4]) and (offset == cached[1]), 'cached math section differs from its exact AX LOAD')
            elif label == '.bss':
                require(kind == 8 and attrs == 3 and (address == zero[2]) and (size == zero[5]), 'high BSS section differs from its exact NOBITS LOAD')
            else:
                require(kind != 8 and RAM_START <= address and (size <= RAM_START + high[4] - address), 'non-math allocated section escaped high file-backed RAM')
                content = original.bounded(elf, offset, size, 'allocated high section')
                relative = address - RAM_START
                require(high_bytes[relative:relative + size] == content, 'high allocated bytes differ from their LOAD')
            allocated.append({'index': index, 'name': label, 'address': address, 'size': size, 'type': kind, 'flags': attrs, 'offset': offset})
        if kind == 2:
            require(step == 16 and size % 16 == 0 and (link < shnum), 'invalid real ELF symbol table')
            strings = original.bounded(elf, sections[link][4], sections[link][5], 'symbol strings')
            table = original.bounded(elf, offset, size, 'symbol table')
            for at in range(0, size, 16):
                n, value, count, sym_info, other, section = struct.unpack_from('<IIIBBH', table, at)
                if n and section:
                    symbol = cstr(strings, n)
                    require(sym_info >> 4 == 0 or symbol not in symbols or symbols[symbol] == {'value': value, 'size': count, 'info': sym_info, 'section': section}, 'duplicate real ELF symbol has conflicting values: ' + symbol)
                    symbols[symbol] = {'value': value, 'size': count, 'info': sym_info, 'section': section}
                    symbol_offsets[symbol] = offset + at
    require(sum((x['name'] == '.cached_math' for x in allocated)) == 1 and sum((x['name'] == '.bss' for x in allocated)) == 1, 'exact cached math and high BSS sections are required')
    intervals = sorted(((x['address'], x['address'] + x['size']) for x in allocated))
    require(all((a[1] <= b[0] for a, b in zip(intervals, intervals[1:]))), 'real allocated sections overlap')
    require(PRODUCER_SYMBOL in symbols and symbols[PRODUCER_SYMBOL]['info'] >> 4 == 1 and ((symbols[PRODUCER_SYMBOL]['value'], symbols[PRODUCER_SYMBOL]['size'], symbols[PRODUCER_SYMBOL]['section']) == (CACHE_START, 0, 65521)), 'cached-code cache profile ABS producer is missing or mismatched')
    expected = dict(zip(MATH_SYMBOLS, (CACHE_START, CACHE_START + cached[4], cached[3], cached[3] + cached[4])))
    for name, value in expected.items():
        require(name in symbols and symbols[name]['info'] >> 4 == 1 and (symbols[name]['value'] == value), 'runtime cached math boundary differs from real LOAD: ' + name)
    for name in SWEEP_SYMBOLS:
        require(name in symbols, 'high instruction-cache eviction symbol missing: ' + name)
    sweep = symbols['__p17f_evict_start']['value']
    end = symbols['__p17f_evict_end']['value']
    require(sweep == symbols['p17f_cache_evict']['value'] and sweep % 2048 == 0 and (end - sweep == 2048) and (RAM_START <= sweep) and (end + 8 <= RAM_START + high[4]), 'eviction sweep is not exactly one aligned high 2KiB instruction block')
    require(high_bytes[sweep - RAM_START:end - RAM_START] == bytes.fromhex('13000000') * 512 and high_bytes[end - RAM_START:end - RAM_START + 8] == bytes.fromhex('0f10000067800000'), 'eviction sweep must execute exactly 512 RV32 NOP words followed by fence.i and ret')
    for name in ('sp_ecc_verify_256', 'sp_ecc_verify_384', 'sp_ecc_verify_521', 'sp_RsaPublic_4096'):
        require(name in symbols and CACHE_START <= symbols[name]['value'] < CACHE_START + cached[4], 'required SP math entry is not in the cached section: ' + name)
    check_initialized_heap(elf, high, sections, allocated, symbols)
    require('__global_pointer$' in symbols and RAM_START <= symbols['__global_pointer$']['value'] < RAM_END, 'runtime global pointer is not in high RAM')
    return {'header': h, 'program_headers': ph, 'sections': sections, 'loads': (high, cached, zero), 'load_indices': (high_i, cached_i, zero_i), 'allocated': allocated, 'symbols': symbols, 'symbol_offsets': symbol_offsets, 'payload': high_bytes + cached_bytes}

def normalize_elf(elf):
    parsed = parse_real(elf)
    h = parsed['header']
    high, cached, zero = parsed['loads']
    normalized = bytearray(elf)
    start = len(normalized) + 4095 & ~4095
    normalized.extend(b'\x00' * (start - len(normalized)))
    normalized.extend(parsed['payload'])
    physical = list(high)
    physical[1] = start
    physical[4] = len(parsed['payload'])
    physical[5] = zero[2] + zero[5] - RAM_START
    high_i, cached_i, zero_i = parsed['load_indices']
    struct.pack_into('<IIIIIIII', normalized, h[5] + high_i * 32, *physical)
    for index in (cached_i, zero_i):
        struct.pack_into('<I', normalized, h[5] + index * 32, 0)
    cached_section = next((x for x in parsed['allocated'] if x['name'] == '.cached_math'))
    struct.pack_into('<I', normalized, h[6] + cached_section['index'] * 40 + 12, cached[3])
    info = {'real_elf_sha256': hashlib.sha256(elf).hexdigest(), 'guard_only_normalized_elf_sha256': hashlib.sha256(normalized).hexdigest(), 'physical_payload_sha256': hashlib.sha256(parsed['payload']).hexdigest(), 'real_load_segments': [{'vma': p[2], 'lma': p[3], 'file_bytes': p[4], 'memory_bytes': p[5], 'flags': p[6]} for p in parsed['loads']], 'cached_section_vma': CACHE_START, 'cached_section_lma': cached[3], 'cached_section_bytes': cached[4], 'runtime_boundary_symbols': {n: parsed['symbols'][n]['value'] for n in MATH_SYMBOLS + SWEEP_SYMBOLS}, 'method': 'Exact physical LOAD bytes appended; one high guard-only LOAD replaces three real LOADs; cached section address maps solely to its checked physical LMA. Runtime symbol values and every other section/header byte are retained.', 'normalized_ELF_is_never_executed_or_delivered': True}
    return (bytes(normalized), parsed, info)
