#!/usr/bin/env python3
"""Check current crypto archive opcodes and preservation of secure memory wipes."""
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
ROOT = Path(__file__).resolve().parents[1]
PREFIX = str(ROOT / '.deps/toolchain/xpack-riscv-none-elf-gcc-11.3.0-1/bin/riscv-none-elf-')
SETTINGS = ROOT / 'crypto/user_settings.h'
OUTPUT = ROOT / 'build/crypto'
AUDIT = OUTPUT / 'logs/crypto'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable_words(data):
    """Decode ELF32LE section metadata, then inspect actual executable words."""
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    assert header[0][:6] == b'\x7fELF\x01\x01' and header[2] == 243
    found = []
    for index in range(header[12]):
        section = struct.unpack_from('<10I', data, header[6] + index * header[11])
        if not section[2] & 4 or not section[5]:
            continue
        assert section[1] == 1 and section[5] % 4 == 0
        for offset in range(0, section[5], 4):
            word = struct.unpack_from('<I', data, section[4] + offset)[0]
            assert word & 3 == 3, 'Unexpected compressed/non-RV32I executable word'
            if word & 127 in (0x0F, 0x2F):
                found.append({'section': index, 'offset': offset, 'word': '%08x' % word,
                              'class': 'MISC_MEM_FENCE' if word & 127 == 15 else 'AMO'})
    return found


def scan_archive(archive):
    names = subprocess.check_output([PREFIX + 'ar', 't', str(archive)], text=True).splitlines()
    assert names and len(names) == len(set(names))
    findings = []
    for name in names:
        data = subprocess.check_output([PREFIX + 'ar', 'p', str(archive), name])
        findings += [dict(row, object=name) for row in executable_words(data)]
    return {'archive_sha256': sha(archive), 'members_checked': len(names),
            'misc_mem_fence_count': sum(row['class'] == 'MISC_MEM_FENCE' for row in findings),
            'amo_count': sum(row['class'] == 'AMO' for row in findings), 'findings': findings}


def run(command, stem):
    process = subprocess.run(command, capture_output=True, text=True, timeout=120)
    (AUDIT / (stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
    (AUDIT / (stem + '.stdout')).write_text(process.stdout)
    (AUDIT / (stem + '.stderr')).write_text(process.stderr)
    assert process.returncode == 0, stem + ': ' + process.stderr[-5000:]
    return process.stdout


def model_dead_local(lines):
    """Execute only the emitted leaf proof, never target code on the host.

    Distinguish the 37-byte secret wipe from a weak barrier's one-byte local.
    The reviewed GCC11.3 -O3 layout is asserted, not inferred from SB counts.
    """
    code = {}
    for line in lines:
        match = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', line)
        if match:
            code[int(match[1], 16)] = int(match[2], 16)
    entry = min(code)
    assert code[entry] == 0xFD010113  # addi sp,sp,-48
    assert code[entry + 4] == 0x00810593  # addi a1,sp,8: 37-byte array
    initial_sp = 0x100000
    secret = set(range(initial_sp - 40, initial_sp - 3))
    def signed(value, bits):
        return (value ^ (1 << (bits - 1))) - (1 << (bits - 1))
    for seed in (0, 47, 165, 255):
        registers = [0xABCDEF01] * 32
        registers[0], registers[1], registers[2], registers[10] = 0, 0xFFFFFFFC, initial_sp, seed
        pc, memory, zero_targets, writes = entry, {}, set(), set()
        for step in range(500):
            assert pc in code
            word = code[pc]
            op, rd, rs1, rs2 = word & 127, word >> 7 & 31, word >> 15 & 31, word >> 20 & 31
            funct3, funct7 = word >> 12 & 7, word >> 25
            next_pc, result = pc + 4, None
            if op == 0x13 and funct3 == 0:
                result = registers[rs1] + signed(word >> 20, 12)
            elif op == 0x13 and funct3 == 7:
                result = registers[rs1] & signed(word >> 20, 12)
            elif op == 0x33 and funct3 == 0 and funct7 in (0, 32):
                result = registers[rs1] + registers[rs2] if funct7 == 0 else registers[rs1] - registers[rs2]
            elif op == 0x23 and funct3 in (0, 1, 2):
                offset = signed((word >> 25) << 5 | (word >> 7 & 31), 12)
                address = (registers[rs1] + offset) & 0xFFFFFFFF
                for byte in range(1 << funct3):
                    assert address + byte in secret, 'Proof wrote outside the actual secret array'
                    memory[address + byte] = (registers[rs2] >> (byte * 8)) & 255
                    writes.add(address + byte)
                    if rs2 == 0:
                        zero_targets.add(address + byte)
            elif op == 0x63 and funct3 == 1:
                offset = ((word >> 31) << 12 | (word >> 7 & 1) << 11 |
                          (word >> 25 & 63) << 5 | (word >> 8 & 15) << 1)
                if registers[rs1] != registers[rs2]:
                    next_pc = pc + signed(offset, 13)
            elif op == 0x67 and funct3 == 0:
                next_pc = (registers[rs1] + signed(word >> 20, 12)) & 0xFFFFFFFE
                result = pc + 4
            else:
                raise AssertionError('Unsupported proof instruction: %08x' % word)
            if result is not None and rd:
                registers[rd] = result & 0xFFFFFFFF
            if next_pc == 0xFFFFFFFC:
                assert registers[2] == initial_sp and registers[10] == 0
                assert writes == zero_targets == secret
                assert all(memory[address] == 0 for address in secret)
                break
            pc = next_pc
        else:
            raise AssertionError('Dead-local proof did not return')
    return {'cases': 4, 'secret_bytes_zeroed_each_case': 37,
            'zero_register_stores_cover_exact_secret_array': True,
            'stores_outside_secret_array': 0, 'stack_pointer_restored': True}


def forcezero_proof(directory, report):
    source = AUDIT / 'forcezero_proof.c'
    source.write_text('''/* The wipe implementation below is the unchanged upstream misc.c. */
#define WOLFSSL_MISC_INCLUDED
#include "wolfcrypt/src/misc.c"
#include <string.h>
__attribute__((noinline,used)) void core49_wipe_external(void *p, size_t n) {
    ForceZero(p,n);
}
__attribute__((noinline,used)) unsigned core49_wipe_dead_local(unsigned seed) {
    unsigned char secret[37];
    for (unsigned i=0;i<sizeof(secret);++i) secret[i]=(unsigned char)(seed+i);
    ForceZero(secret,sizeof(secret));
    return 0;
}
#ifdef CORE49_FORCEZERO_HOST_PROOF
int main(void) {
    unsigned char memory[80];
    for(unsigned offset=0;offset<8;++offset) {
        for(unsigned size=0;size<=56;++size) {
            memset(memory,0xa5,sizeof(memory));
            core49_wipe_external(memory+offset,size);
            for(unsigned i=0;i<sizeof(memory);++i) {
                unsigned char expected=i>=offset&&i<offset+size?0:0xa5;
                if(memory[i]!=expected) return 1;
            }
        }
    }
    return core49_wipe_dead_local(47);
}
#endif
''')
    common = ['-std=gnu99', '-O3', '-DWOLFSSL_USER_SETTINGS', '-DC64U_CORE49_FENCELESS=1',
              '-I' + str(SETTINGS.parent), '-I' + str(directory),
              '-DP14_WOLFSSL_BUILD_INPUT_SHA256=' + report['build_input_sha256'],
              '-include', str(OUTPUT / 'build_identity.h')]
    obj = AUDIT / 'forcezero_proof.o'
    run([PREFIX + 'gcc', *common, '-march=rv32i', '-mabi=ilp32', '-c', str(source), '-o', str(obj)], 'forcezero_native_compile')
    run([PREFIX + 'gcc', *common, '-march=rv32i', '-mabi=ilp32', '-S', str(source), '-o', str(AUDIT / 'forcezero_proof.s')], 'forcezero_native_assembly')
    disassembly = run([PREFIX + 'objdump', '-d', str(obj)], 'forcezero_disassembly')
    assert not executable_words(obj.read_bytes()), 'ForceZero proof emits FENCE/AMO'
    functions = {}
    active = None
    for line in disassembly.splitlines():
        match = re.match(r'^[0-9a-f]+ <([^>]+)>:', line)
        if match and not match[1].startswith('.'):
            active = match[1]
            functions[active] = []
        elif active:
            functions[active].append(line)
    for name in ('core49_wipe_external', 'core49_wipe_dead_local'):
        assert name in functions
        assert any(re.search(r'\b(?:sb|sh|sw)\s+zero,', line) for line in functions[name]), name + ' lost its zero stores'
    native_wipe_model = model_dead_local(functions['core49_wipe_dead_local'])
    host = AUDIT / 'forcezero_host_proof'
    run(['gcc', *common, '-DCORE49_FORCEZERO_HOST_PROOF', str(source), '-o', str(host)], 'forcezero_host_compile')
    run([str(host)], 'forcezero_host_run')
    # A second preprocessing check proves all three named hooks retain real
    # GNU compiler barriers, rather than an empty function-like macro.
    macros = run([PREFIX + 'gcc', *common, '-march=rv32i', '-mabi=ilp32', '-dM', '-E', str(source)], 'configured_macros')
    selected = [line for line in macros.splitlines() if re.match(r'#define (?:XFENCE|WC_BARRIER|WC_BARRIER_DATA)\(', line)]
    assert len(selected) == 3 and all('__volatile__' in line and '"memory"' in line for line in selected)
    assert any('"r"(ptr)' in line for line in selected if 'WC_BARRIER_DATA(' in line)
    assert not re.search(r'^#define (?:WOLFSSL_NO_FENCE|WOLFSSL_NO_FORCE_ZERO)\b', macros, re.M)
    return {'implementation': 'Unmodified real wolfcrypt/src/misc.c, WOLFSSL_MISC_INCLUDED',
            'native_optimization': '-O3', 'native_fence_or_amo_count': 0,
            'external_and_dead_local_zero_stores_retained': True,
            'native_dead_local_wipe_model': native_wipe_model,
            'host_cases': 8 * 57, 'host_canaries_and_zero_bytes': 'PASS',
            'compiler_barrier_macros': selected, 'hardware_execution': 'NOT_RUN'}
