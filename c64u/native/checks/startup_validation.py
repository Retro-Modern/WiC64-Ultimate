#!/usr/bin/env python3
"""Bounded software proofs of the final linked boot diagnostic assembly.

Interprets real linked RV32 words. C stage/constructor bodies are explicit ABI
boundaries, not hardware simulations. No device code is executed on the host.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

import elf_validation as base


class CPU:
    def __init__(self, elf, pc):
        self.elf, self.pc = elf, pc
        self.reg = [0] + [(0xA5000000 + n * 0x10101) & 0xFFFFFFFF for n in range(1, 32)]
        self.reg[2] = 0xDEADBEEF
        self.csr = {0x300: 0x1888, 0x340: 0xBAD00000, 0x341: 0x03012344,
                    0x342: 2, 0x343: 0xDEADCAFE}
        self.memory = []
        self.steps = 0

    def load(self, address, count):
        self.memory.append(('read', address, count))
        if address in base.MMIO and count == 1:
            return base.MMIO[address]
        sections = [s for s in self.elf.sections if s['type'] != 8 and s['flags'] & 2
                    and s['addr'] <= address and address + count <= s['addr'] + s['size']]
        base.need(len(sections) == 1, 'Proof tried to access unbacked memory at 0x%x' % address)
        s = sections[0]
        offset = s['offset'] + address - s['addr']
        return int.from_bytes(self.elf.data[offset:offset + count], 'little')

    def step(self):
        pc, r = self.pc, self.reg
        word = self.elf.word(pc)
        op, rd, f3 = word & 127, (word >> 7) & 31, (word >> 12) & 7
        rs1, rs2 = (word >> 15) & 31, (word >> 20) & 31
        value, next_pc = None, pc + 4
        if op == 0x37:
            value = word & 0xFFFFF000
        elif op == 0x17:
            value = pc + (word & 0xFFFFF000)
        elif op == 0x13 and f3 == 0:
            value = r[rs1] + base.sx(word >> 20, 12)
        elif op == 0x13 and f3 == 7:
            value = r[rs1] & base.sx(word >> 20, 12)
        elif op == 0x6F:
            value, next_pc = pc + 4, pc + base.jump_immediate(word)
        elif op == 0x67 and f3 == 0:
            value, next_pc = pc + 4, (r[rs1] + base.sx(word >> 20, 12)) & ~1
        elif op == 0x63 and f3 in (0, 1, 4, 5):
            take = {0: r[rs1] == r[rs2], 1: r[rs1] != r[rs2],
                    4: base.sx(r[rs1], 32) < base.sx(r[rs2], 32),
                    5: base.sx(r[rs1], 32) >= base.sx(r[rs2], 32)}[f3]
            if take:
                next_pc = pc + base.branch_immediate(word)
        elif op == 0x03 and f3 in (2, 4):
            address = (r[rs1] + base.sx(word >> 20, 12)) & 0xFFFFFFFF
            value = self.load(address, 4 if f3 == 2 else 1)
        elif op == 0x73 and f3 in (1, 2, 3, 5, 6, 7):
            csr = word >> 20
            value = self.csr.get(csr, 0)
            operand = rs1 if f3 >= 5 else r[rs1]
            action = f3 & 3
            if action == 1:
                self.csr[csr] = operand
            elif operand:
                self.csr[csr] = value | operand if action == 2 else value & ~operand
        else:
            raise base.Invalid('Unsupported proof instruction at 0x%x: %08x' % (pc, word))
        if value is not None and rd:
            r[rd] = value & 0xFFFFFFFF
        r[0], self.pc = 0, next_pc & 0xFFFFFFFF
        self.steps += 1

    def until(self, targets, limit=100):
        for _ in range(limit):
            if self.pc in targets:
                return self.pc
            self.step()
        raise base.Invalid('Bounded proof did not reach its target')


def check(elf):
    sym = lambda name: elf.symbol(name)['value']
    trap, fault, handler = sym('c64u_boot_trap_entry'), sym('c64u_boot_fault'), sym('freertos_risc_v_trap_handler')
    start, end = sym('__c64u_boot_emergency_stack_start'), sym('__c64u_boot_emergency_stack_end')
    arena = elf.symbol('__c64u_boot_emergency_stack_start')
    base.need(end - start == arena['size'] == 4096 and start % 16 == end % 16 == 0,
              'Emergency arena must be exactly 4096 bytes and aligned 16')
    base.need(elf.sections[arena['shndx']]['type'] == 8 and base.in_ram(start, 4096),
              'Emergency arena must be high-RAM NOBITS')
    gp = sym('__global_pointer$')
    normal = None
    for offset in range(0, 64, 4):
        w = elf.word(handler + offset)
        if w & 0xFFFFF == 0x10113 and base.sx(w >> 20, 12) == -120:
            normal = handler + offset
            break
    base.need(normal is not None and normal > handler, 'Missing diagnostic prefix before original RTOS frame')
    dispatch_count = 0
    causes = list(range(256)) + [0x7FFFFFFF] + [0x80000000 | n for n in range(256)] + [0xFFFFFFFF]
    for cause in causes:
        c = CPU(elf, handler)
        c.csr[0x342] = cause
        original, old_csr = c.reg.copy(), c.csr.copy()
        reached = c.until({normal, trap}, 20)
        want_normal = bool(cause & 0x80000000) or cause == 11
        base.need(reached == (normal if want_normal else trap), 'Wrong IRQ/ECALL/fault dispatch')
        base.need(c.reg == original and not c.memory, 'Trap prefix touched stack/memory or changed a register')
        base.need(all(c.csr[k] == v for k, v in old_csr.items() if k != 0x340),
                  'Trap prefix changed a CSR other than its reserved mscratch')
        base.need(c.csr[0x340] == original[5], 'Original t0 not saved to reserved mscratch')
        dispatch_count += 1
    capture_count = 0
    for original_sp in (0, 1, 0xDEADBEEF, 0x03BFFFFC):
        for cause in (0, 2, 5, 7, 0x8000000B):
            c = CPU(elf, trap)
            c.reg[2], c.csr[0x342] = original_sp, cause
            pc, value = c.csr[0x341], c.csr[0x343]
            c.until({fault}, 30)
            base.need(c.reg[10:14] == [cause, pc, value, original_sp], 'Fatal C API argument mismatch')
            base.need(c.reg[2] == end and c.reg[2] % 16 == 0 and c.reg[3] == gp,
                      'Fatal entry did not install independent GP/emergency SP')
            base.need(not c.memory and not c.csr[0x300] & 8, 'Fatal entry touched interrupted stack or left MIE enabled')
            capture_count += 1
    capture_bytes = elf.symbol('c64u_boot_trap_entry')['size']
    base.need(all(elf.word(trap + n) != 0x30200073 for n in range(0, capture_bytes, 4)),
              'Fatal entry may not MRET past a fault')

    stage = sym('c64u_boot_stage')
    def stage_from(address, expected):
        c = CPU(elf, address)
        c.reg[2], c.reg[3] = sym('__crt0_stack_begin'), gp
        c.until({stage}, 150)
        base.need(c.reg[10:12] == [expected, 0], 'CRT stage number/detail mismatch')
        return c
    first = CPU(elf, sym('_start'))
    first.until({stage}, 150)
    base.need(first.reg[10:12] == [1, 0] and first.reg[2] % 16 == 0 and first.reg[3] == gp,
              'Stage 1 C ABI/SP/GP mismatch')
    base.need(first.csr.get(0x305) == trap, 'Early MTVEC does not target the fatal capture entry')
    stage_from(sym('__crt0_clear_bss_loop_end'), 2)
    stage_from(sym('__crt0_main_entry'), 5)
    for name in ('__crt0_copy_data_src_begin', '__crt0_copy_data_dst_begin'):
        base.need(sym(name) == sym('__DATA_BEGIN__'), 'Boot record requires in-place data copy')
    record = elf.symbol('c64u_boot_record')
    record_section = elf.sections[record['shndx']]
    base.need(record_section['name'] == '.data' and record_section['type'] == 1 and record['size'] == 48,
              'Boot record is not the initialized 48-byte .data object')
    reader = CPU(elf, 0)
    record_words = [reader.load(record['value'] + i * 4, 4) for i in range(12)]
    base.need(record_words == [0x42435431, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
              'Boot record initial contents mismatch')

    # Exercise actual constructor dispatch with caller-saved registers deliberately
    # destroyed at the C-stage and constructor ABI boundaries.
    ctor_begin = sym('__init_array_start')
    ctor_targets = [reader.load(ctor_begin + i * 4, 4) for i in range(2)]
    c = CPU(elf, sym('__crt0_call_constructors_loop'))
    c.reg[2], c.reg[3], c.reg[19], c.reg[20] = end, gp, ctor_begin, ctor_begin + 8
    events = []
    boundaries = {stage, *ctor_targets}
    stop = sym('__crt0_call_constructors_loop_end')
    for _ in range(100):
        c.until(boundaries | {stop}, 30)
        if c.pc == stop:
            break
        return_pc = c.reg[1]
        if c.pc == stage:
            events.append(('stage', c.reg[10], c.reg[11]))
        else:
            events.append(('constructor', c.pc))
        for n in [1, 5, 6, 7, *range(10, 18), *range(28, 32)]:
            c.reg[n] = (0xD0000000 + n) & 0xFFFFFFFF
        c.pc = return_pc
    else:
        raise base.Invalid('Constructor boundary proof did not terminate')
    expected = []
    for target in ctor_targets:
        expected += [('stage', 3, target), ('constructor', target), ('stage', 4, target)]
    base.need(events == expected and c.reg[19] == ctor_begin + 8,
              'Constructor stage calls clobber/skip/change their targets')
    return {'status': 'PASS', 'dispatch_vectors': dispatch_count, 'capture_vectors': capture_count,
            'normal_irq_and_ecall11_preserve_all_gprs': True, 'normal_prefix_memory_accesses': 0,
            'capture_before_c_memory_accesses': 0, 'emergency_stack': [start, end],
            'boot_record': record, 'boot_record_initialized_words': record_words,
            'stage1_early_mtvec_sp_gp': 'PASS', 'stages2_and5': 'PASS',
            'ctor_abi_boundary_simulation': events,
            'limits': ['No hardware execution', 'C renderer/constructor bodies are not executed by this proof',
                       'mscratch is explicitly reserved by the trace prefix; other CSRs and every GPR are preserved on IRQ/ECALL normal dispatch']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('elf', type=Path)
    p.add_argument('--report', type=Path)
    args = p.parse_args()
    report = {'schema': 1, 'status': 'FAIL', 'hardware_execution': 'NOT_RUN',
              'proof_script_sha256': base.sha(Path(__file__).read_bytes())}
    try:
        elf = base.ELF(args.elf.resolve())
        report['elf_sha256'] = base.sha(elf.data)
        report['proof'] = check(elf)
        report['status'] = 'PASS'
    except (base.Invalid, OSError, ValueError, struct.error) as error:
        report['error'] = str(error)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
