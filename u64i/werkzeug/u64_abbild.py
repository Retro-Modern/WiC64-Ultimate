#!/usr/bin/env python3
"""RAM-Abbild für "Run Update" auf dem Ultimate 64 der ersten Generation.

Format wie Gideons Updater: drei Wörter (little endian) Ladeadresse,
Länge, Einsprung, danach die Bytes. Die Firmware lädt sie nach
0x03000000 und springt hinein; der Flash bleibt unverändert.

Aufruf: u64_abbild.py <ultimate.elf> <ultimate.bin> <ziel.u64>
"""
import struct
import sys

LADEADRESSE = 0x03000000


def einsprung(elf):
    kopf = open(elf, 'rb').read(52)
    if kopf[:4] != b'\x7fELF' or kopf[4] != 1 or kopf[5] != 1:
        sys.exit('kein 32-Bit-ELF (little endian): ' + elf)
    return struct.unpack_from('<I', kopf, 24)[0]


def main():
    elf, binaer, ziel = sys.argv[1:4]
    daten = open(binaer, 'rb').read()
    start = einsprung(elf)
    if not LADEADRESSE <= start < LADEADRESSE + len(daten):
        sys.exit('Einsprung 0x%08x liegt nicht im Abbild' % start)
    with open(ziel, 'wb') as f:
        f.write(struct.pack('<III', LADEADRESSE, len(daten), start) + daten)
    print('%s: %d Bytes, Einsprung 0x%08x' % (ziel, len(daten), start))


if __name__ == '__main__':
    main()
