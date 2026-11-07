#!/usr/bin/env python3
"""Independently validate the linked C64U API22 RV32I ELF and UE2.

No source, linker script, prior report or caller-supplied expected hash is used
as proof. ELF structures and instructions are decoded here, while the actual
cross readelf, objdump and objcopy independently inspect the same final file.
The guard is interpreted, never executed on the host or on a C64 Ultimate.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

RAM_START = 0x03000000
RAM_LIMIT = 0x03C00000
MMIO = collections.OrderedDict([
    (0x1000000B, 0x22), (0x1000000C, 0x2F),
    (0x1000000D, 0xEC), (0x1000000E, 0x6F),
    (0x1000000F, 0xBF), (0x10180010, 0x49),
])
DEFAULT_PREFIX = str(Path(__file__).resolve().parents[1] /
    '.deps/toolchain/xpack-riscv-none-elf-gcc-11.3.0-1/bin/riscv-none-elf-')


class Invalid(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Invalid(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sx(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def in_ram(address, size):
    return size >= 0 and RAM_START <= address < RAM_LIMIT and address + size <= RAM_LIMIT


class ELF:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        need(len(self.data) >= 52, 'ELF header truncated')
        ident = self.data[:16]
        need(ident[:4] == b'\x7fELF', 'Not an ELF file')
        need(ident[4:7] == bytes([1, 1, 1]), 'Expected ELF32 little endian version 1')
        h = struct.unpack_from('<HHIIIIIHHHHHH', self.data, 16)
        (kind, machine, version, self.entry, phoff, shoff, self.flags,
         ehsize, phsize, phnum, shsize, shnum, shstrndx) = h
        need((kind, machine, version, ehsize) == (2, 243, 1, 52),
             'Expected RISC-V ELF32 ET_EXEC')
        need(self.entry == RAM_START, 'ELF entry must be 0x03000000')
        need(self.flags == 0, 'ELF flags advertise RVC/float/RVE or another unsupported ABI')
        need(phnum > 0 and phsize == 32, 'Missing/unsupported program header table')
        need(shnum > 0 and shsize == 40 and shstrndx < shnum,
             'Missing/unsupported section header table')
        need(phoff + phnum * phsize <= len(self.data), 'Program headers truncated')
        need(shoff + shnum * shsize <= len(self.data), 'Section headers truncated')
        self.programs = []
        for i in range(phnum):
            p = struct.unpack_from('<IIIIIIII', self.data, phoff + i * phsize)
            row = dict(zip(('type', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'flags', 'align'), p))
            need(row['offset'] + row['filesz'] <= len(self.data), 'Program payload truncated')
            self.programs.append(row)
        self.sections = []
        for i in range(shnum):
            s = struct.unpack_from('<IIIIIIIIII', self.data, shoff + i * shsize)
            row = dict(zip(('name_offset', 'type', 'flags', 'addr', 'offset', 'size',
                            'link', 'info', 'align', 'entsize'), s))
            if row['type'] != 8:  # SHT_NOBITS has no file bytes.
                need(row['offset'] + row['size'] <= len(self.data), 'Section payload truncated')
            self.sections.append(row)
        names = self.section_bytes(self.sections[shstrndx])
        for s in self.sections:
            s['name'] = self.string(names, s['name_offset'])
        self.symbols = collections.defaultdict(list)
        for s in self.sections:
            if s['type'] != 2:  # Require the full SYMTAB, including local ucHeap.
                continue
            need(s['entsize'] == 16 and s['size'] % 16 == 0,
                 'Unexpected ELF32 symbol entry size')
            need(s['link'] < len(self.sections), 'Invalid symbol string table')
            strings = self.section_bytes(self.sections[s['link']])
            for offset in range(s['offset'], s['offset'] + s['size'], 16):
                name, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', self.data, offset)
                if name and shndx:
                    self.symbols[self.string(strings, name)].append({
                        'value': value, 'size': size, 'info': info, 'other': other, 'shndx': shndx})

    @staticmethod
    def string(data, offset):
        need(offset < len(data), 'ELF string offset outside table')
        end = data.find(b'\x00', offset)
        need(end >= 0, 'Unterminated ELF string')
        return data[offset:end].decode('utf-8', errors='strict')

    def section_bytes(self, section):
        need(section['type'] != 8, 'Attempt to read NOBITS bytes')
        return self.data[section['offset']:section['offset'] + section['size']]

    def symbol(self, name):
        rows = self.symbols.get(name, [])
        need(len(rows) == 1, 'Expected one defined symbol: ' + name)
        return rows[0]

    def word(self, address):
        rows = [s for s in self.sections if s['flags'] & 4 and
                s['addr'] <= address and address + 4 <= s['addr'] + s['size']]
        need(len(rows) == 1 and address % 4 == 0, 'Instruction outside aligned executable ELF section')
        s = rows[0]
        return struct.unpack_from('<I', self.data, s['offset'] + address - s['addr'])[0]


def run_tool(prefix, suffix, arguments):
    tool = Path(prefix + suffix)
    need(tool.is_file(), 'Missing real cross tool: ' + str(tool))
    version = subprocess.run([str(tool), '--version'], capture_output=True, text=True)
    need(version.returncode == 0, suffix + ' --version failed')
    result = subprocess.run([str(tool), *arguments], capture_output=True, text=True)
    need(result.returncode == 0, suffix + ' failed: ' + result.stderr[-2000:])
    return result.stdout, {'tool': str(tool), 'version': version.stdout.splitlines()[0],
                           'arguments': arguments, 'output_sha256': sha(result.stdout.encode())}


def classify(word):
    """Reject every instruction not RV32I, with Stock CSR/privileged support."""
    need(word & 3 == 3, 'Compressed/short or invalid instruction encoding')
    op, f3, f7 = word & 127, (word >> 12) & 7, word >> 25
    if op in (0x37, 0x17, 0x6F):
        return 'integer'
    if op == 0x67 and f3 == 0:
        return 'integer'
    if op == 0x63 and f3 in (0, 1, 4, 5, 6, 7):
        return 'integer'
    if op == 0x03 and f3 in (0, 1, 2, 4, 5):
        return 'integer'
    if op == 0x23 and f3 in (0, 1, 2):
        return 'integer'
    if op == 0x13:
        if f3 == 1:
            need(f7 == 0, 'Non-RV32I shift instruction')
        elif f3 == 5:
            need(f7 in (0, 0x20), 'Non-RV32I shift instruction')
        return 'integer'
    if op == 0x33 and (f7 == 0 or (f7 == 0x20 and f3 in (0, 5))):
        return 'integer'
    if op == 0x0F and f3 in (0, 1):
        return 'fence' if f3 == 0 else 'fence_i'
    if op == 0x73:
        if f3 in (1, 2, 3, 5, 6, 7):
            return 'csr'
        if word in (0x00000073, 0x00100073, 0x30200073, 0x10500073):
            return 'privileged'
    raise Invalid('Non-RV32I/unknown opcode (M/A/F/D/C/V and custom instructions forbidden)')


def branch_immediate(word):
    return sx(((word >> 31) << 12) | (((word >> 7) & 1) << 11) |
              (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1), 13)


def jump_immediate(word):
    return sx(((word >> 31) << 20) | (((word >> 12) & 255) << 12) |
              (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1), 21)


def guard_run(elf, values):
    start = elf.symbol('_start')['value']
    accept = elf.symbol('p05_ram_target_accepted')['value']
    reject = elf.symbol('p05_ram_target_rejected')['value']
    regs = [0] * 32
    origins = [('constant', 0)] * 32
    pc, trace, reads, branches = start, [], [], []
    for step in range(80):
        if pc == accept:
            return 'accept', trace, reads, branches
        if pc == reject:
            return 'reject', trace, reads, branches
        need(start <= pc < accept, 'Guard escapes entry/acceptance range')
        word = elf.word(pc)
        trace.append({'pc': pc, 'word': word})
        op, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
        rs1, rs2 = (word >> 15) & 31, (word >> 20) & 31
        next_pc = pc + 4
        if step == 0:
            need(word == 0x30047073, 'Entry must disable machine interrupts before guard')
        elif op == 0x37:
            need(rd in (5, 6, 7), 'Guard writes stack/global/other unexpected register')
            regs[rd], origins[rd] = word & 0xFFFFF000, ('constant', word & 0xFFFFF000)
        elif op == 0x13 and f3 == 0:
            need(rd in (5, 6, 7), 'Guard writes stack/global/other unexpected register')
            need(origins[rs1][0] == 'constant', 'Guard transforms MMIO byte before comparison')
            regs[rd] = (regs[rs1] + sx(word >> 20, 12)) & 0xFFFFFFFF
            origins[rd] = ('constant', regs[rd])
        elif op == 0x03 and f3 == 4:
            need(rd in (5, 6, 7), 'Guard writes stack/global/other unexpected register')
            need(origins[rs1][0] == 'constant', 'Guard MMIO address is not constant')
            address = (regs[rs1] + sx(word >> 20, 12)) & 0xFFFFFFFF
            need(address in MMIO, 'Guard reads non-whitelisted MMIO/RAM')
            regs[rd], origins[rd] = values[address], ('mmio', address)
            reads.append(address)
        elif op == 0x63 and f3 in (0, 1):
            target = (pc + branch_immediate(word)) & 0xFFFFFFFF
            a, b = origins[rs1], origins[rs2]
            if a[0] == 'constant':
                a, b = b, a
            need(a[0] == 'mmio' and b[0] == 'constant', 'Guard branch must compare MMIO to constant')
            need(b[1] == MMIO[a[1]], 'Guard compares against wrong target signature')
            branches.append({'address': a[1], 'expected': b[1], 'function': f3, 'target': target})
            equal = regs[rs1] == regs[rs2]
            if equal == (f3 == 0):
                next_pc = target
        elif op == 0x6F and rd == 0:
            next_pc = (pc + jump_immediate(word)) & 0xFFFFFFFF
        else:
            raise Invalid('Guard contains unexpected instruction/store/call/stack operation at 0x%08x' % pc)
        regs[0], origins[0] = 0, ('constant', 0)
        pc = next_pc
    raise Invalid('Guard did not terminate in an acceptance/rejection label')


def validate_guard(elf):
    start = elf.symbol('_start')['value']
    accept = elf.symbol('p05_ram_target_accepted')['value']
    reject = elf.symbol('p05_ram_target_rejected')['value']
    need(start == RAM_START and start < reject < accept <= start + 512,
         'Guard labels have unexpected placement')
    need(elf.word(reject) == 0x0000006F, 'Rejected target must be a JAL x0 self-loop')
    if '__crt0_pointer_init' in elf.symbols:
        need(elf.symbol('__crt0_pointer_init')['value'] == accept,
             'Stack initialization must begin at accepted target')
    result, trace, reads, branches = guard_run(elf, dict(MMIO))
    need(result == 'accept', 'Measured API22/Core49/capabilities signature rejected')
    need(reads == list(MMIO), 'Accepted guard must read each exact signature byte once in order')
    need(len(branches) == 6, 'Guard must independently compare all six signature bytes')
    for i, b in enumerate(branches):
        need(b['address'] == list(MMIO)[i], 'Guard comparison order mismatch')
        need((b['function'], b['target']) == ((1, reject) if i < 5 else (0, accept)),
             'Guard comparison does not reject mismatches before startup')
    negative = 0
    for address, expected in MMIO.items():
        for wrong in range(256):
            if wrong == expected:
                continue
            values = dict(MMIO)
            values[address] = wrong
            need(guard_run(elf, values)[0] == 'reject',
                 'Guard accepted negative byte vector at 0x%08x=%02x' % (address, wrong))
            negative += 1
    for vector in ({a: 0 for a in MMIO}, {a: 255 for a in MMIO},
                   {**MMIO, 0x1000000B: 0x25, 0x10180010: 0x4F}):
        need(guard_run(elf, vector)[0] == 'reject', 'Guard accepted combined negative vector')
    return {'status': 'PASS', 'positive_vectors': 1, 'single_byte_negative_vectors': negative,
            'combined_negative_vectors': 3, 'mmio_signature': dict(MMIO),
            'reject': reject, 'accept': accept, 'positive_instruction_trace': trace}


def canonical_payload(elf, loads):
    """Model the upstream objcopy-ihex -> hex2bin -r APP producer exactly.

    Every allocated initialized section byte is mandatory. Only address holes
    between those sections receive hex2bin.c's fixed 0xff fill; neither zeros
    nor arbitrary APP bytes are accepted in their place. NOBITS is not payload.
    """
    sections = []
    for s in elf.sections:
        if not s['flags'] & 2 or s['type'] == 8 or not s['size']:
            continue
        matching = [p for p in loads if p['vaddr'] <= s['addr'] and
                    s['addr'] + s['size'] <= p['vaddr'] + p['filesz']]
        need(len(matching) == 1, 'Initialized allocated section not backed by one PT_LOAD')
        p = matching[0]
        need(s['offset'] == p['offset'] + s['addr'] - p['vaddr'],
             'Allocated section file offset disagrees with PT_LOAD')
        address = p['paddr'] + s['addr'] - p['vaddr']
        sections.append((address, s))
    sections.sort(key=lambda pair: pair[0])
    need(sections and sections[0][0] == RAM_START, 'Canonical APP section base mismatch')
    end = max(address + s['size'] for address, s in sections)
    need(in_ram(RAM_START, end - RAM_START), 'Canonical APP payload exceeds high RAM')
    output = bytearray([255]) * (end - RAM_START)
    intervals, holes, cursor = [], [], RAM_START
    for address, s in sections:
        need(address >= cursor, 'Overlapping initialized allocated sections')
        if address > cursor:
            holes.append({'start': cursor, 'end': address, 'bytes': address - cursor, 'fill': 255})
        output[address - RAM_START:address - RAM_START + s['size']] = elf.section_bytes(s)
        intervals.append({'name': s['name'], 'address': address, 'bytes': s['size'],
                          'sha256': sha(elf.section_bytes(s))})
        cursor = address + s['size']
    return bytes(output), intervals, holes


def validate(elf_path, app_path, prefix, report):
    elf = ELF(elf_path)
    report['elf'] = {'path': str(elf_path), 'sha256': sha(elf.data),
                     'entry': elf.entry, 'flags': elf.flags, 'size': len(elf.data)}
    readelf, readelf_meta = run_tool(prefix, 'readelf', ['-h', '-l', '-A', str(elf_path)])
    need('ELF32' in readelf and 'RISC-V' in readelf and 'little endian' in readelf,
         'Cross readelf disagrees with ELF32 little endian RISC-V identity')
    report['tools'] = {'readelf': readelf_meta}
    loads = [p for p in elf.programs if p['type'] == 1]
    need(loads, 'ELF has no PT_LOAD')
    for p in loads:
        need(p['filesz'] <= p['memsz'], 'PT_LOAD filesz exceeds memsz')
        need(in_ram(p['vaddr'], p['memsz']) and in_ram(p['paddr'], p['memsz']),
             'PT_LOAD lies outside [0x03000000,0x03c00000)')
        need(p['vaddr'] == p['paddr'], 'Unexpected PT_LOAD load/run relocation')
    for a, b in zip(sorted(loads, key=lambda p: p['vaddr']), sorted(loads, key=lambda p: p['vaddr'])[1:]):
        need(a['vaddr'] + a['memsz'] <= b['vaddr'], 'Overlapping PT_LOAD memory ranges')
    report['load_segments'] = loads
    absolute = {'__cart_rom_start': 0x00F00000, '__cart_rom_limit': 0x01000000,
                'c64u_api22_alpha_profile': 0x2249,
                '__p17i_wd_dma_start': 0x00070000, '__p17i_wd_dma_end': 0x00074000}
    for name, expected in absolute.items():
        s = elf.symbol(name)
        need(s['value'] == expected, name + ' value mismatch')
        need(s['shndx'] == 0xFFF1, name + ' must be an absolute linker symbol')
    heap, bss_end, stack = elf.symbol('ucHeap'), elf.symbol('__BSS_END__'), elf.symbol('__crt0_stack_begin')
    need(heap['size'] == 0x480000 and heap['info'] & 15 == 1,
         'ucHeap must be the 0x480000-byte OBJECT')
    need(in_ram(heap['value'], heap['size']), 'ucHeap outside high RAM')
    need(heap['value'] + heap['size'] <= bss_end['value'], 'ucHeap not contained before BSS end')
    need(in_ram(stack['value'], 4) and bss_end['value'] + 65536 < stack['value'],
         'BSS leaves less than the required strict 64KiB stack clearance')
    need(heap['shndx'] < len(elf.sections) and elf.sections[heap['shndx']]['type'] == 1,
         'ucHeap must be in file-backed PROGBITS')
    report['profile_symbols'] = {name: elf.symbol(name) for name in
        [*absolute, 'ucHeap', '__BSS_END__', '__crt0_stack_begin']}
    instructions, kinds, exec_sections = {}, collections.Counter(), []
    for s in elf.sections:
        if not s['flags'] & 4 or s['size'] == 0:
            continue
        need(s['flags'] & 2 and s['type'] == 1, 'Executable section is not loaded PROGBITS')
        need(in_ram(s['addr'], s['size']) and s['addr'] % 4 == 0 and s['size'] % 4 == 0,
             'Executable section is outside/aligned differently from high RAM RV32I')
        need(any(p['flags'] & 1 and p['vaddr'] <= s['addr'] and
                 s['addr'] + s['size'] <= p['vaddr'] + p['filesz'] for p in loads),
             'Executable section not backed by executable PT_LOAD file bytes')
        exec_sections.append({k: s[k] for k in ('name', 'addr', 'size')})
        for offset in range(0, s['size'], 4):
            address = s['addr'] + offset
            word = struct.unpack_from('<I', elf.data, s['offset'] + offset)[0]
            try:
                kinds[classify(word)] += 1
            except Invalid as error:
                raise Invalid('%s at 0x%08x: 0x%08x' % (error, address, word))
            need(address not in instructions, 'Overlapping executable sections')
            instructions[address] = word
    need(instructions, 'No executable RV32I code')
    # -D also decodes explicit NOP alignment emitted with a $d mapping symbol.
    # Restrict it to executable sections, so ordinary data is never treated as code.
    section_arguments = [arg for s in exec_sections for arg in ('-j', s['name'])]
    disassembly, objdump_meta = run_tool(prefix, 'objdump',
        ['-D', *section_arguments, '-z', '-M', 'no-aliases,numeric', str(elf_path)])
    decoded = {}
    for line in disassembly.splitlines():
        m = re.match(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(\S+)', line)
        if m:
            address, word = int(m[1], 16), int(m[2], 16)
            if address in instructions:
                need(address not in decoded, 'Objdump repeats executable address')
                need(word == instructions[address], 'Objdump instruction bytes disagree with ELF')
                need(not m[3].startswith('.') and m[3] not in ('unimp', 'unknown'),
                     'Objdump cannot decode executable word')
                decoded[address] = word
    need(decoded == instructions, 'Cross objdump did not decode every executable RV32I word')
    report['tools']['objdump'] = objdump_meta
    report['instruction_scan'] = {'status': 'PASS', 'instruction_count': len(instructions),
        'classes': dict(kinds), 'sections': exec_sections,
        'policy': 'RV32I plus Stock CSR/privileged/fence.i support; no M/A/F/D/C/V/custom opcodes; every executable word checked'}
    report['guard'] = validate_guard(elf)
    need(app_path.is_file(), 'APP file missing: ' + str(app_path))
    app = app_path.read_bytes()
    need(len(app) >= 12, 'APP header truncated')
    load, length, entry = struct.unpack_from('<III', app)
    need((load, entry) == (RAM_START, RAM_START), 'APP load/entry must be 0x03000000')
    need(length == len(app) - 12 and length > 0 and load + length <= RAM_LIMIT,
         'APP payload length/range mismatch')
    with tempfile.TemporaryDirectory(prefix='c64u-payload-') as tmp:
        binary = Path(tmp) / 'elf-payload.bin'
        _, objcopy_meta = run_tool(prefix, 'objcopy', ['-O', 'binary', '--gap-fill', '0xff', str(elf_path), str(binary)])
        payload = binary.read_bytes()
    reconstructed, initialized_sections, gaps = canonical_payload(elf, loads)
    need(payload == reconstructed, 'Real cross objcopy disagrees with exact ELF section reconstruction')
    need(app[12:] == reconstructed, 'APP payload is not the exact canonical ELF sections plus fixed FF gap fill')
    file_loads = [p for p in loads if p['filesz']]
    need(min(p['paddr'] for p in file_loads) == load, 'APP base differs from ELF load base')
    report['tools']['objcopy'] = objcopy_meta
    report['app'] = {'path': str(app_path), 'sha256': sha(app), 'size': len(app),
        'load': load, 'entry': entry, 'payload_length': length, 'payload_sha256': sha(payload),
        'exact_elf_payload': True, 'initialized_sections': initialized_sections,
        'section_gap_fill': gaps,
        'producer_contract': 'Upstream objcopy -O ihex -> hex2bin -r: exact allocated initialized section bytes, fixed 0xff only between those sections'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--app', type=Path, help='Defaults to the ELF path with .app suffix')
    parser.add_argument('--tool-prefix', default=DEFAULT_PREFIX)
    parser.add_argument('--report', type=Path, help='Optional JSON report path; stdout always reports status')
    args = parser.parse_args()
    report = {'schema': 1, 'validator': 'C64U_API22_RV32I',
              'validator_sha256': sha(Path(__file__).read_bytes()), 'status': 'FAIL',
              'hardware_execution': 'NOT_RUN'}
    try:
        validate(args.elf.resolve(), (args.app or args.elf.with_suffix('.app')).resolve(),
                 args.tool_prefix, report)
        report['status'] = 'PASS'
    except (Invalid, OSError, ValueError, struct.error, UnicodeError) as error:
        report['error'] = str(error)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
