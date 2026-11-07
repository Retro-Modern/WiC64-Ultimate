#!/usr/bin/env python3
"""Validate current C64U RAM layout, Core49 instructions and startup calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import elf_validation as BASE
import startup_validation as TRAP
sys.dont_write_bytecode = True
HEAP_BYTES = 0x480000
SEED_BYTES = 960656
SEED_SHA256 = '08871caa35e36928d034cae377f67e86bf64f44e7c4090bb16d0ea380337f3d1'
ERRORS = (BASE.Invalid, TRAP.base.Invalid, OSError, ValueError, struct.error, UnicodeError)
need = BASE.need


def sha(data):
    return hashlib.sha256(data).hexdigest()


def symbol_value(elf, name):
    return elf.symbol(name)['value']


def decode_call(elf, pc):
    word = elf.word(pc)
    op, rd = word & 127, (word >> 7) & 31
    if op == 0x6f and rd == 1:
        return (pc+BASE.jump_immediate(word)) & 0xffffffff, pc+4, [word]
    if op == 0x17 and rd not in (0, 2):
        second = elf.word(pc+4)
        need(second & 127 == 0x67 and (second >> 7) & 31 == 1 and
             (second >> 12) & 7 == 0 and (second >> 15) & 31 == rd,
             'Bootstrap AUIPC is not followed by matching JALR ra')
        target = (pc+(word & 0xfffff000)+BASE.sx(second >> 20, 12)) & 0xffffffff
        return target & ~1, pc+8, [word, second]
    raise BASE.Invalid('Resource label does not contain an actual JAL/AUIPC-JALR call')


def writes_sp(word):
    # Branch/store/immediate fields are not register destinations.
    op, rd = word & 127, (word >> 7) & 31
    return rd == 2 and op in (0x37, 0x17, 0x6f, 0x67, 0x03, 0x13, 0x33, 0x73)


def check_initialized_heap(elf, app):
    heap, seed = elf.symbol('ucHeap'), elf.symbol('p18m_esp_resource_seed')
    profile = elf.symbol('p18m_ram_profile_initialized_esp_heap')
    need(profile['value'] == HEAP_BYTES and profile['shndx'] == 0xfff1,
         'Initialized-heap absolute producer must be 0x480000')
    need(heap['info'] == seed['info'] == 0x11, 'Heap/seed must be global OBJECT symbols')
    need(heap['value'] % 16 == 0 and heap['size'] == HEAP_BYTES, 'Heap size/alignment mismatch')
    need(seed['value'] == heap['value']+32 and seed['size'] == SEED_BYTES,
         'Resource length and address must match the selected ESP input')
    need(heap['shndx'] == seed['shndx'] < len(elf.sections), 'Heap/seed section mismatch')
    section = elf.sections[heap['shndx']]
    need(section['name'] == '.data' and section['type'] == 1 and section['flags'] & 3 == 3 and not section['flags'] & 4,
         'Initialized heap must be writable allocated non-code .data PROGBITS')
    end = heap['value']+HEAP_BYTES
    need(section['addr'] <= heap['value'] < end <= section['addr']+section['size'],
         'Whole heap is not inside .data')
    loads = [p for p in elf.programs if p['type'] == 1 and p['vaddr'] <= heap['value'] and end <= p['vaddr']+p['filesz']]
    need(len(loads) == 1 and loads[0]['flags'] & 2, 'Whole initialized arena must be inside one writable PT_LOAD filesz')
    offset = section['offset']+heap['value']-section['addr']
    need(offset == loads[0]['offset']+heap['value']-loads[0]['vaddr'], 'Heap file offsets disagree')
    data = elf.data[offset:offset+HEAP_BYTES]
    need(len(data) == HEAP_BYTES, 'Truncated initialized arena')
    image = data[32:32+SEED_BYTES]
    need(data[:32] == bytes(32), 'Allocator prefix is not zero initialized')
    need(sha(image) == SEED_SHA256, 'Embedded ESP image SHA256 mismatch')
    need(image[0] == 0xe9 and int.from_bytes(image[12:14], 'little') == 9, 'Embedded app is not raw ESP32-S3/chip9')
    need(data[32+SEED_BYTES:] == bytes(HEAP_BYTES-32-SEED_BYTES), 'Initialized heap tail padding is not zero')
    need(elf.data.count(image) == 1 and app[12:].count(image) == 1, 'ESP raw image must occur exactly once in ELF and APP payload')
    bss_start, bss_end = symbol_value(elf, '__crt0_bss_start'), symbol_value(elf, '__BSS_END__')
    need(end <= bss_start <= bss_end, 'Initialized heap overlaps or follows BSS')
    for s in elf.sections:
        if s['type'] == 8 and s['flags'] & 2 and s['size']:
            need(s['addr']+s['size'] <= heap['value'] or end <= s['addr'], 'Initialized arena overlaps a NOBITS section')
    for name, rows in elf.symbols.items():
        for row in rows:
            if row['size'] == HEAP_BYTES and row['info'] & 15 == 1 and row['shndx'] < len(elf.sections):
                need(elf.sections[row['shndx']]['type'] != 8,
                     'A second heap-sized OBJECT remains in NOBITS: ' + name)
    need(symbol_value(elf, '__crt0_copy_data_src_begin') == symbol_value(elf, '__DATA_BEGIN__') ==
         symbol_value(elf, '__crt0_copy_data_dst_begin'), 'Initialized .data is not loaded in place')
    return {'status': 'PASS', 'heap_address': heap['value'], 'heap_bytes': HEAP_BYTES,
            'heap_section': section['name'], 'heap_file_offset': offset, 'seed_address': seed['value'],
            'seed_offset': 32, 'seed_bytes': SEED_BYTES, 'seed_sha256': SEED_SHA256,
            'zero_prefix_bytes': 32, 'zero_tail_bytes': HEAP_BYTES-32-SEED_BYTES,
            'one_image_copy_in_elf_and_app': True, 'bss_start': bss_start, 'bss_end': bss_end,
            'producer_symbol': profile, 'temporary_malloc_reservation_bytes': SEED_BYTES+32,
            'free_heap_before_constructors': HEAP_BYTES-16-SEED_BYTES-32}


def check_bootstrap(elf):
    sym = lambda name: symbol_value(elf, name)
    stage, hook, target = sym('c64u_boot_stage'), sym('__p18m_resource_bootstrap_call'), sym('p18m_esp_resource_bootstrap')
    bss, ctor = sym('__crt0_clear_bss_loop_end'), sym('__crt0_call_constructors')
    need(bss < hook < ctor, 'Bootstrap is not after BSS and before constructors')
    called, returned, words = decode_call(elf, hook)
    need(called == target and returned == ctor, 'Bootstrap call target/return-to-constructors mismatch')
    # Interpret actual accepted startup and stop at the first C boundary.
    first = TRAP.CPU(elf, sym('_start'))
    first.until({stage}, 150)
    sp, gp, stage1_return = first.reg[2], first.reg[3], first.reg[1]
    need(first.reg[10:12] == [1, 0] and sp % 16 == 0 and gp == sym('__global_pointer$'),
         'Stage1 startup C ABI/SP/GP proof failed')
    need(stage1_return < bss, 'Stage1 return lies outside the expected CRT range')
    early_calls = []
    for pc in range(sym('_start'), stage1_return, 4):
        word = elf.word(pc); op, rd = word & 127, (word >> 7) & 31
        if op in (0x6f, 0x67) and rd:
            call_pc = pc-4 if op == 0x67 else pc
            destination, return_pc, _ = decode_call(elf, call_pc)
            need(destination == stage and return_pc == stage1_return,
                 'Another C call precedes the first startup Stage1 boundary')
            early_calls.append(call_pc)
    need(len(early_calls) == 1, 'Expected exactly one early Stage1 C call')
    # CPU intentionally has no store implementation. Check the entire copying /
    # BSS-clearing range structurally: no SP writes, calls or outside branches.
    scan = []
    for pc in range(stage1_return, bss, 4):
        word = elf.word(pc); op, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
        need(not writes_sp(word), 'CRT changes SP between Stage1 and BSS end')
        need(op != 0x67 and not (op == 0x6f and rd), 'Unexpected C call/indirect jump in CRT data/BSS path')
        if op in (0x63, 0x6f):
            destination = pc+(BASE.branch_immediate(word) if op == 0x63 else BASE.jump_immediate(word))
            need(stage1_return <= destination <= bss, 'CRT copy/BSS branch exits its proven range')
        scan.append({'pc': pc, 'word': word})
    stage2 = TRAP.CPU(elf, bss)
    stage2.reg[2], stage2.reg[3] = sp, gp
    stage2.until({stage}, 30)
    need(stage2.reg[10:12] == [2, 0] and stage2.reg[2] == sp and stage2.reg[3] == gp,
         'Stage2 does not preserve the proven aligned startup SP/GP')
    stage2_return = stage2.reg[1]
    need(stage2_return == hook, 'Stage2 C return must directly reach the resource call label')
    for pc in range(bss, ctor, 4):
        need(not writes_sp(elf.word(pc)), 'SP changed from BSS end through resource C boundary')
    boundary_runs = []
    for poison in (0, 0xd0000000, 0xffffffff):
        c = TRAP.CPU(elf, stage2_return)
        c.reg = stage2.reg.copy()
        for n in (1, 5, 6, 7, *range(10, 18), *range(28, 32)):
            c.reg[n] = (poison+n*0x10101) & 0xffffffff
        c.pc = stage2_return
        c.until({target}, 8)
        need(c.reg[2] == sp and c.reg[2] % 16 == 0 and c.reg[3] == gp and c.reg[1] == ctor,
             'Resource caller C ABI fails after Stage2 caller-saved clobber')
        need(not c.memory, 'Resource call transition unexpectedly accesses memory')
        boundary_runs.append({'caller_poison': poison, 'steps': c.steps, 'sp': c.reg[2],
                              'gp': c.reg[3], 'return_pc': c.reg[1], 'target_pc': c.pc})
    return {'status': 'PASS', 'bootstrap_call_pc': hook, 'bootstrap_call_words': words,
            'bootstrap_target': target, 'bootstrap_return': returned, 'stage1_return_pc': stage1_return,
            'first_c_call_guard': early_calls,
            'stage2_return_pc': stage2_return, 'aligned_sp': sp, 'gp': gp,
            'crt_no_sp_write_or_hidden_call_scan': scan, 'abi_boundary_runs': boundary_runs,
            'limits': ['The actual linked RV32 startup/call words are interpreted; C stage and allocator bodies are not executed.',
                       'C stage return preserves SP/GP/callee-saved registers by the RISC-V ABI; caller-saved values are deliberately destroyed.',
                       'Data-copy and BSS-store loops are statically checked for SP writes/calls/branch exits, not executed by the store-free CPU model.']}


def validate(elf_path, app_path, prefix, report):
    BASE.validate(elf_path, app_path, prefix, report)
    elf = BASE.ELF(elf_path)
    # Core49 rejects all opcode0F words, including FENCE.I. Data is excluded.
    scanned, sections = 0, []
    for section in elf.sections:
        if not section['flags'] & 4 or not section['size']:
            continue
        sections.append(section['name'])
        for offset in range(0, section['size'], 4):
            word = struct.unpack_from('<I', elf.data, section['offset']+offset)[0]
            need(word & 0x7f != 0x0f, 'Core49 executable opcode0F forbidden at0x%08x' % (section['addr']+offset))
            scanned += 1
    report['core49_ordering_gate'] = {'status': 'PASS', 'opcode0F_count': 0,
                                     'instruction_count': scanned, 'executable_sections_only': sections}
    report['initialized_heap'] = check_initialized_heap(elf, app_path.read_bytes())
    report['resource_startup'] = check_bootstrap(elf)
    report['boot_trap_proof'] = TRAP.check(elf)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--tool-prefix', default=BASE.DEFAULT_PREFIX)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = {'schema': 1, 'validator': 'C64U_CORE49_NATIVE_LAYOUT', 'status': 'FAIL',
              'validator_sha256': sha(Path(__file__).read_bytes()), 'hardware_execution': 'NOT_RUN'}
    try:
        validate(args.elf.resolve(), (args.app or args.elf.with_suffix('.app')).resolve(), args.tool_prefix, report)
        report['status'] = 'PASS'
    except ERRORS as error:
        report['error'] = str(error)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1

if __name__ == "__main__":
    sys.exit(main())
