#!/usr/bin/env python3
"""Post-link checks for the current native C64U application."""
import layout_validation as gate

def memory_windows(gate, elf):
    need = gate.need
    expected = {
        '__p17i_wd_dma_start': 0x00070000, '__p17i_wd_dma_end': 0x00074000,
        '__drive_b_sound': 0x00eb0000, '__drive_a_sound': 0x00ec0000,
        '__drive_b_area': 0x00ed0000, '__drive_a_area': 0x00ee0000,
        '__cart_rom_start': 0x00f00000, '__cart_rom_limit': 0x01000000,
        '__reu_ram_start': 0x01000000, '__reu_ram_limit': 0x02000000,
        '__ram_disk_start': 0x02000000, '__ram_disk_limit': 0x03000000,
    }
    actual = {}
    for name, value in expected.items():
        symbol = elf.symbol(name)
        need(symbol['value'] == value and symbol['shndx'] == 0xfff1,
             'Stock memory ABI differs for ' + name)
        actual[name] = value
    regions = [
        ('WD DMA', 0x00070000, 0x00074000),
        ('drive B sound', 0x00eb0000, 0x00ec0000),
        ('drive A sound', 0x00ec0000, 0x00ed0000),
        ('drive B RAM/ROM', 0x00ed0000, 0x00ee0000),
        ('drive A RAM/ROM', 0x00ee0000, 0x00ef0000),
        ('cart RAM', 0x00ef0000, 0x00f00000),
        ('cart ROM', 0x00f00000, 0x01000000),
        ('complete16MiB REU', 0x01000000, 0x02000000),
        ('RAM disk', 0x02000000, 0x03000000),
        ('native application and initialized ESP heap', 0x03000000, 0x03c00000),
    ]
    for index, (name, start, end) in enumerate(regions):
        need(start < end, 'Empty memory window: ' + name)
        for other, low, high in regions[index+1:]:
            need(end <= low or high <= start, 'Memory overlap: '+name+' / '+other)
    bss = elf.symbol('__BSS_END__')['value']
    stack = elf.symbol('__crt0_stack_begin')['value']
    need(bss + 65536 < stack, 'Less than strict64KiB startup stack clearance')
    return {'status': 'PASS', 'actual_absolute_symbols': actual,
            'regions': [{'name': n, 'start': s, 'end_exclusive': e} for n, s, e in regions],
            'BSS_end': bss, 'startup_stack_top': stack,
            'startup_headroom_bytes': stack-bss,
            'complete_REU_bytes': 0x1000000,
            'no_REU_drive_or_RAM_disk_region_reused': True,
            'limit': 'Static native/linker allocation proof; does not execute REU DMA or a physical D81 disk operation.'}

def validate(elf_path, app_path, prefix, image):
    gate.SEED_BYTES = image['bytes']
    gate.SEED_SHA256 = image['sha256']
    report = {'status': 'FAIL', 'hardware_execution': 'NOT_RUN'}
    gate.validate(elf_path, app_path, prefix, report)
    elf = gate.BASE.ELF(elf_path)
    role = elf.symbol('p18m_c64u_esp_image_role')
    gate.need(role['shndx'] == 0xfff1 and role['value'] == 1,
              'The linked ESP image role must be the native main application')
    report['selected_esp_input'] = image
    bindings = {}
    for suffix, expected in [('tls_sha256', image['sha256']),
                             ('return_sha256', image['stock_return']['sha256'])]:
        copies = []
        for name, rows in elf.symbols.items():
            if not name.endswith(suffix):
                continue
            for row in rows:
                if row['size'] != 32 or row['shndx'] >= len(elf.sections):
                    continue
                section = elf.sections[row['shndx']]
                gate.need(section['flags'] & 2 and not section['flags'] & 4 and
                          section['type'] in (1, 14, 15, 16) and
                          section['addr'] <= row['value'] and
                          row['value'] + 32 <= section['addr'] + section['size'],
                          'Installer digest must be allocated file-backed data')
                offset = section['offset'] + row['value'] - section['addr']
                digest = elf.data[offset:offset+32].hex()
                gate.need(digest == expected, 'Linked installer digest differs from selected fresh input: ' + suffix)
                copies.append(row['value'])
        gate.need(bool(copies), 'No linked installer allowlist digest found: ' + suffix)
        bindings[suffix] = {'sha256': expected, 'linked_copies': copies}
    report['installer_allowlist_bindings'] = bindings
    report['D81_REU_memory_windows'] = memory_windows(gate, elf)
    report['status'] = 'PASS'
    return report
